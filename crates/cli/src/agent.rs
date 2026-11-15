//! Per-grant `ssh-agent` lifecycle and the grant's local metadata.
//!
//! Each grant gets its own directory `<state>/grants/<grant_id>` (0700)
//! holding `grant.json` and `known_hosts` (0600, no secrets), and its own
//! `ssh-agent` listening on a socket in a short private directory
//! `$TMPDIR/warden-<uid>/` (Unix socket paths are limited to 104 bytes on
//! macOS). The grant's private key exists only in this process's memory and
//! then in that agent's memory.

use std::ffi::OsStr;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use ssh_key::{Certificate, PrivateKey, PublicKey};
use warden_broker_proto::{Id, TargetName, UnixUser};

use crate::ssh_agent::{AgentClient, NewIdentity};

/// Longest Unix socket path, NUL excluded, accepted everywhere (macOS
/// `sun_path` holds 104 bytes; Linux 108).
const MAX_SOCKET_PATH: usize = 103;

/// Name of the grant metadata file.
const GRANT_FILE: &str = "grant.json";

/// A running per-grant `ssh-agent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantAgent {
    /// `<state>/grants/<grant_id>`, mode 0700.
    pub dir: PathBuf,
    /// The agent's socket.
    pub socket: PathBuf,
    /// The agent's process id.
    pub pid: u32,
}

/// How a grant reaches its target.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Route {
    /// Straight to the target, which trusts the grant's certificate.
    /// Records written before relay grants existed have no route and are
    /// direct.
    #[default]
    Direct,
    /// Through the broker's relay, logging in as the target's name with the
    /// grant's plain key; the relay logs in to the target as the user.
    Relay,
}

/// What `grant.json` records about a grant. Holds no secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRecord {
    /// Grant identifier.
    pub grant_id: Id,
    /// Target name the grant was requested for.
    pub target: TargetName,
    /// How ssh reaches the target.
    #[serde(default)]
    pub route: Route,
    /// Host to connect to, from the grant: the target's, or the relay's.
    pub host: String,
    /// Port to connect to.
    pub port: u16,
    /// Unix account the grant logs in to on the target.
    pub user: UnixUser,
    /// End of validity, Unix seconds.
    pub not_after: i64,
    /// The agent's socket.
    pub socket: PathBuf,
    /// The agent's process id.
    pub pid: u32,
}

/// Create `dir` (and parents) if needed and make sure it is a real
/// directory owned by us with mode 0700.
///
/// # Errors
/// If it cannot be created, is not a directory, or belongs to someone else.
pub fn private_dir(dir: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("cannot create {}", dir.display()))?;
    let meta =
        fs::symlink_metadata(dir).with_context(|| format!("cannot inspect {}", dir.display()))?;
    ensure!(meta.is_dir(), "{} is not a directory", dir.display());
    ensure!(
        meta.uid() == rustix::process::getuid().as_raw(),
        "{} is owned by another user",
        dir.display()
    );
    if meta.mode() & 0o777 != 0o700 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot restrict {}", dir.display()))?;
    }
    Ok(())
}

/// Write `contents` to a new file `path` with mode 0600, atomically: they
/// go to a temporary file in the same directory, which is synced and then
/// renamed to `path` only if nothing is there yet. A reader therefore sees
/// either no file or the whole file. If `path` already holds exactly
/// `contents`, there is nothing to do.
///
/// # Errors
/// If `path` holds other contents or the file cannot be written.
pub fn write_new_private(path: &Path, contents: &[u8]) -> Result<()> {
    let (dir, temp) = temp_beside(path)?;
    let written = write_temp(&temp, contents).and_then(|()| publish(&temp, path, dir, contents));
    if written.is_err() {
        // Best effort: the temporary file may not exist, and the error that
        // matters is the one being returned.
        let _ = fs::remove_file(&temp);
    }
    written
}

/// The directory holding `path`, and a fresh temporary file name in it,
/// `.<name>.<random>.tmp`, for writing `path` atomically.
///
/// # Errors
/// If `path` has no file name.
pub fn temp_beside(path: &Path) -> Result<(&Path, PathBuf)> {
    let name = path
        .file_name()
        .with_context(|| format!("{} is not a file path", path.display()))?;
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temp = dir.join(format!(".{}.{}.tmp", name.to_string_lossy(), Id::random()));
    Ok((dir, temp))
}

/// Create `temp` (0600, which must not exist) holding `contents`, synced.
/// `create_new` never follows a symlink at `temp`.
///
/// # Errors
/// If `temp` exists or cannot be written.
pub fn write_temp(temp: &Path, contents: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp)
        .with_context(|| format!("cannot create {}", temp.display()))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("cannot write {}", temp.display()))
}

/// Rename `temp` to `path` unless `path` exists, and sync `dir`, which
/// holds both. An existing `path` with the same contents counts as written.
fn publish(temp: &Path, path: &Path, dir: &Path, contents: &[u8]) -> Result<()> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    match renameat_with(CWD, temp, CWD, path, RenameFlags::NOREPLACE) {
        Ok(()) => fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .with_context(|| format!("cannot sync {}", dir.display())),
        Err(rustix::io::Errno::EXIST) => {
            fs::remove_file(temp).with_context(|| format!("cannot remove {}", temp.display()))?;
            let existing =
                fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
            ensure!(
                existing == contents,
                "{} already exists with other contents",
                path.display()
            );
            Ok(())
        }
        Err(e) => Err(std::io::Error::from(e))
            .with_context(|| format!("cannot create {}", path.display())),
    }
}

/// The CLI's state directory: `$XDG_STATE_HOME/warden` when set, otherwise
/// the platform's state directory (Linux `~/.local/state/warden`) or data
/// directory (macOS `~/Library/Application Support/warden`). Created 0700.
///
/// # Errors
/// If no location is known or it cannot be created privately.
pub fn state_dir() -> Result<PathBuf> {
    let dir = state_dir_path()?;
    private_dir(&dir)?;
    Ok(dir)
}

/// Where [`state_dir`] is, without creating or changing anything: for
/// readers that must not touch the disk.
///
/// # Errors
/// If no state directory can be determined.
pub fn state_dir_path() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_STATE_HOME").map(PathBuf::from) {
        Some(dir) if dir.is_absolute() => dir,
        _ => dirs::state_dir()
            .or_else(dirs::data_dir)
            .context("cannot determine a state directory")?,
    };
    Ok(base.join("warden"))
}

/// `<state>/grants`, created 0700.
///
/// # Errors
/// As [`state_dir`].
pub fn grants_dir() -> Result<PathBuf> {
    let dir = state_dir()?.join("grants");
    private_dir(&dir)?;
    Ok(dir)
}

/// `$TMPDIR/warden-<uid>`: short enough for agent sockets.
pub(crate) fn socket_dir() -> PathBuf {
    std::env::temp_dir().join(format!("warden-{}", rustix::process::getuid().as_raw()))
}

/// Socket path for `grant_id` under `sockets`.
fn socket_path(sockets: &Path, grant_id: &Id) -> Result<PathBuf> {
    let socket = sockets.join(format!("{}.sock", &grant_id.as_str()[..12]));
    ensure!(
        socket.as_os_str().len() <= MAX_SOCKET_PATH,
        "agent socket path {} is longer than {MAX_SOCKET_PATH} bytes; set TMPDIR to a shorter directory",
        socket.display()
    );
    Ok(socket)
}

/// Start a per-grant agent: `ssh-agent -s -a <socket> -t <secs>`.
///
/// # Errors
/// If the directories cannot be prepared or the agent does not start.
pub fn start(grant_id: &Id, lifetime: Duration) -> Result<GrantAgent> {
    start_in(&grants_dir()?, &socket_dir(), grant_id, lifetime)
}

fn start_in(
    grants: &Path,
    sockets: &Path,
    grant_id: &Id,
    lifetime: Duration,
) -> Result<GrantAgent> {
    let secs = lifetime_secs(lifetime)?;
    private_dir(grants)?;
    private_dir(sockets)?;
    let dir = grants.join(grant_id.as_str());
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .with_context(|| format!("cannot create {}", dir.display()))?;
    let socket = socket_path(sockets, grant_id)?;
    let out = Command::new("ssh-agent")
        .arg("-s")
        .arg("-a")
        .arg(&socket)
        .arg("-t")
        .arg(secs.to_string())
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_AGENT_PID")
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("cannot run ssh-agent")?;
    if !out.status.success() {
        let _ = fs::remove_dir(&dir);
        bail!(
            "ssh-agent failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let pid = String::from_utf8(out.stdout)
        .ok()
        .and_then(|s| parse_agent_pid(&s))
        .ok_or_else(|| anyhow!("cannot read SSH_AGENT_PID from ssh-agent output"))?;
    Ok(GrantAgent { dir, socket, pid })
}

/// The pid in `ssh-agent -s` output (`SSH_AGENT_PID=1234; export …`).
fn parse_agent_pid(output: &str) -> Option<u32> {
    output.lines().find_map(|line| {
        line.strip_prefix("SSH_AGENT_PID=")?
            .split(';')
            .next()?
            .parse()
            .ok()
    })
}

fn lifetime_secs(lifetime: Duration) -> Result<u32> {
    let secs = u32::try_from(lifetime.as_secs()).context("grant lifetime out of range")?;
    ensure!(secs > 0, "grant has already ended");
    Ok(secs)
}

/// Add `key` with its certificate `cert` to `agent`, constrained to
/// `lifetime` (on top of the agent's own default lifetime).
///
/// # Errors
/// If `key` is not Ed25519, does not match `cert`, or the agent refuses.
pub async fn add_cert(
    agent: &GrantAgent,
    key: &PrivateKey,
    cert: &Certificate,
    lifetime: Duration,
) -> Result<()> {
    let secs = lifetime_secs(lifetime)?;
    ensure!(
        cert.public_key() == key.public_key().key_data(),
        "certificate is not for this request's key"
    );
    let key = key
        .key_data()
        .ed25519()
        .ok_or_else(|| anyhow!("only Ed25519 keys are supported"))?;
    add_identity(
        agent,
        NewIdentity::Certificate {
            key,
            certificate: cert,
        },
        secs,
    )
    .await
}

/// Add `key` alone (no certificate) to `agent`, constrained to `lifetime`:
/// the relay accepts it because it is the key bound to the approved request.
///
/// # Errors
/// If `key` is not Ed25519 or the agent refuses.
pub async fn add_key(agent: &GrantAgent, key: &PrivateKey, lifetime: Duration) -> Result<()> {
    let secs = lifetime_secs(lifetime)?;
    let key = key
        .key_data()
        .ed25519()
        .ok_or_else(|| anyhow!("only Ed25519 keys are supported"))?;
    add_identity(agent, NewIdentity::Key(key), secs).await
}

/// Add `identity` to `agent` with a lifetime of `secs`.
async fn add_identity(agent: &GrantAgent, identity: NewIdentity<'_>, secs: u32) -> Result<()> {
    let stream = tokio::net::UnixStream::connect(&agent.socket)
        .await
        .with_context(|| format!("cannot connect to ssh-agent at {}", agent.socket.display()))?;
    AgentClient::new(stream)
        .add_constrained(identity, "warden grant", secs)
        .await
        .map_err(|e| anyhow!("ssh-agent refused the key: {e}"))
}

/// True if `host` is safe to hand to ssh and to write into `known_hosts`:
/// a DNS name or IP address, never starting with `-`.
#[must_use]
pub fn is_safe_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('-')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
}

/// Write `<dir>/known_hosts` (0600) pinning `keys` for `host:port`. Lines
/// are `host key` on port 22 and `[host]:port key` otherwise. Every key is
/// parsed and re-encoded, so markers, comments or extra lines from the server
/// never reach the file.
///
/// # Errors
/// If the host or a key is invalid, there are no keys, or the file cannot be
/// written.
pub fn write_known_hosts(dir: &Path, host: &str, port: u16, keys: &[String]) -> Result<PathBuf> {
    ensure!(
        is_safe_host(host),
        "grant host {host:?} is not a valid host name"
    );
    ensure!(!keys.is_empty(), "grant has no host keys");
    let pattern = if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    };
    let mut contents = String::new();
    for raw in keys {
        let mut key = PublicKey::from_openssh(raw)
            .map_err(|e| anyhow!("grant has an invalid host key: {e}"))?;
        key.set_comment("");
        let line = key
            .to_openssh()
            .map_err(|e| anyhow!("cannot encode host key: {e}"))?;
        contents.push_str(&pattern);
        contents.push(' ');
        contents.push_str(line.trim_end());
        contents.push('\n');
    }
    let path = dir.join("known_hosts");
    write_new_private(&path, contents.as_bytes())?;
    Ok(path)
}

/// Write `<agent.dir>/grant.json` (0600).
///
/// # Errors
/// If the file cannot be written.
pub fn record(agent: &GrantAgent, record: &GrantRecord) -> Result<()> {
    write_new_private(
        &agent.dir.join(GRANT_FILE),
        &serde_json::to_vec_pretty(record)?,
    )
}

/// Every grant directory under `grants` with its record, or the error that
/// prevented reading it.
#[must_use]
pub fn load_grants(grants: &Path) -> Vec<(PathBuf, Result<GrantRecord>)> {
    let Ok(entries) = fs::read_dir(grants) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| {
            let dir = e.path();
            let record = fs::read(dir.join(GRANT_FILE))
                .with_context(|| format!("cannot read {}", dir.join(GRANT_FILE).display()))
                .and_then(|raw| serde_json::from_slice(&raw).context("invalid grant.json"));
            (dir, record)
        })
        .collect()
}

/// Stop the agent behind `socket`/`pid` with `ssh-agent -k` and remove the
/// socket. The pid is signalled only while an agent still answers on the
/// socket, so a recycled pid is never signalled; a stale socket left by an
/// agent that already exited is just removed.
fn kill(socket: &Path, pid: u32) -> Result<()> {
    if fs::symlink_metadata(socket).is_err() {
        return Ok(());
    }
    if is_listening(socket) {
        let status = Command::new("ssh-agent")
            .arg("-k")
            .env("SSH_AGENT_PID", pid.to_string())
            .env("SSH_AUTH_SOCK", socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("cannot run ssh-agent -k")?;
        ensure!(status.success(), "ssh-agent -k failed ({status})");
    }
    match fs::remove_file(socket) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("cannot remove {}", socket.display())),
    }
}

fn is_listening(socket: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(socket).is_ok()
}

/// Stop a grant's agent and delete its directory.
///
/// # Errors
/// If the agent cannot be stopped or the directory removed.
pub fn discard(dir: &Path, socket: &Path, pid: u32) -> Result<()> {
    kill(socket, pid)?;
    fs::remove_dir_all(dir).with_context(|| format!("cannot remove {}", dir.display()))
}

/// Stop and delete the grant `grant_id`, if this machine holds it.
///
/// # Errors
/// If its state cannot be read or removed.
pub fn discard_grant(grant_id: &Id) -> Result<bool> {
    let dir = grants_dir()?.join(grant_id.as_str());
    if !dir.exists() {
        return Ok(false);
    }
    let rec: GrantRecord = serde_json::from_slice(
        &fs::read(dir.join(GRANT_FILE))
            .with_context(|| format!("cannot read {}", dir.display()))?,
    )?;
    discard(&dir, &rec.socket, rec.pid)?;
    Ok(true)
}

/// How old an abandoned temporary file must be before it is removed: far
/// longer than any write takes, so another CLI mid-write is never affected.
const STALE_TEMP_AGE: Duration = Duration::from_mins(10);

/// Remove the temporary files of [`write_new_private`] in `dir` that were
/// last written at least ten minutes before `now` (Unix seconds): left by
/// a CLI that crashed between creating one and renaming it. Fresher ones
/// may belong to a write in progress and stay, as does everything else.
///
/// # Errors
/// If `dir` cannot be listed or a stale file cannot be removed; every one
/// is still attempted.
pub fn remove_stale_temps(dir: &Path, now: i64) -> Result<()> {
    let cutoff = UNIX_EPOCH + Duration::from_secs(u64::try_from(now).unwrap_or(0));
    let mut failures = Vec::new();
    for entry in fs::read_dir(dir)
        .with_context(|| format!("cannot read {}", dir.display()))?
        .flatten()
    {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // `file_type` does not follow symlinks: only regular files qualify.
        let is_temp = name.starts_with('.') && name.ends_with(".tmp");
        if !is_temp || !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let Ok(modified) = entry.metadata().and_then(|m| m.modified()) else {
            continue;
        };
        if modified
            .checked_add(STALE_TEMP_AGE)
            .is_some_and(|ripe| ripe <= cutoff)
        {
            match fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => failures.push(format!("{}: {e}", entry.path().display())),
            }
        }
    }
    ensure!(
        failures.is_empty(),
        "cannot remove stale temporary files: {}",
        failures.join("; ")
    );
    Ok(())
}

/// Stop the agents of grants ended by `now` and delete their directories;
/// remove stale temporary files beside the live grants and in the grants
/// directory.
///
/// # Errors
/// If the state directory is unusable or some grant cannot be cleaned up;
/// every grant is still attempted.
pub fn cleanup_expired(now: i64) -> Result<()> {
    cleanup_expired_in(&grants_dir()?, now)
}

fn cleanup_expired_in(grants: &Path, now: i64) -> Result<()> {
    let mut failures = Vec::new();
    for (dir, record) in load_grants(grants) {
        let outcome = match record {
            Ok(rec) if rec.not_after <= now => discard(&dir, &rec.socket, rec.pid),
            Ok(_) => remove_stale_temps(&dir, now),
            Err(e) => Err(e),
        };
        if let Err(e) = outcome {
            failures.push(format!(
                "{}: {e:#}",
                dir.file_name().map_or_else(
                    || dir.display().to_string(),
                    |n| OsStr::to_string_lossy(n).into_owned()
                )
            ));
        }
    }
    if let Err(e) = remove_stale_temps(grants, now) {
        failures.push(format!("{e:#}"));
    }
    ensure!(
        failures.is_empty(),
        "cannot clean up grants: {}",
        failures.join("; ")
    );
    Ok(())
}

#[cfg(test)]
mod tests;
