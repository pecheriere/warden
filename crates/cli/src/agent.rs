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
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use ssh_agent_lib::agent::Session as _;
use ssh_agent_lib::proto::{
    AddIdentity, AddIdentityConstrained, KeyConstraint, PrivateCredential, PrivateKeyData,
};
use ssh_key::{Algorithm, Certificate, PrivateKey, PublicKey};
use warden_broker_proto::{Id, TargetName, UnixUser};

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

/// What `grant.json` records about a grant. Holds no secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRecord {
    /// Grant identifier.
    pub grant_id: Id,
    /// Target name the grant was requested for.
    pub target: TargetName,
    /// Host to connect to, from the signed grant.
    pub host: String,
    /// Port to connect to.
    pub port: u16,
    /// Unix account the certificate is valid for.
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
    let name = path
        .file_name()
        .with_context(|| format!("{} is not a file path", path.display()))?;
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temp = dir.join(format!(".{}.{}.tmp", name.to_string_lossy(), Id::random()));
    let written = write_temp(&temp, contents).and_then(|()| publish(&temp, path, dir, contents));
    if written.is_err() {
        // Best effort: the temporary file may not exist, and the error that
        // matters is the one being returned.
        let _ = fs::remove_file(&temp);
    }
    written
}

/// Create `temp` (0600, which must not exist) holding `contents`, synced.
fn write_temp(temp: &Path, contents: &[u8]) -> Result<()> {
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
    let base = match std::env::var_os("XDG_STATE_HOME").map(PathBuf::from) {
        Some(dir) if dir.is_absolute() => dir,
        _ => dirs::state_dir()
            .or_else(dirs::data_dir)
            .context("cannot determine a state directory")?,
    };
    let dir = base.join("warden");
    private_dir(&dir)?;
    Ok(dir)
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
fn socket_dir() -> PathBuf {
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
    let keypair = key
        .key_data()
        .ed25519()
        .ok_or_else(|| anyhow!("only Ed25519 keys are supported"))?
        .clone();
    let stream = tokio::net::UnixStream::connect(&agent.socket)
        .await
        .with_context(|| format!("cannot connect to ssh-agent at {}", agent.socket.display()))?;
    let mut client = ssh_agent_lib::client::Client::new(stream);
    client
        .add_identity_constrained(AddIdentityConstrained {
            identity: AddIdentity {
                credential: PrivateCredential::Cert {
                    algorithm: Algorithm::Ed25519,
                    certificate: Box::new(cert.clone()),
                    privkey: PrivateKeyData::Ed25519(keypair),
                    comment: "warden grant".to_owned(),
                },
            },
            constraints: vec![KeyConstraint::Lifetime(secs)],
        })
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
        let mut key = PublicKey::from_openssh(raw).context("grant has an invalid host key")?;
        key.set_comment("");
        let line = key.to_openssh().context("cannot encode host key")?;
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

/// Stop the agents of grants ended by `now` and delete their directories.
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
            Ok(_) => Ok(()),
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
    ensure!(
        failures.is_empty(),
        "cannot clean up grants: {}",
        failures.join("; ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;
    use std::time::Duration;

    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey};
    use warden_broker_proto::Id;

    use super::{
        GrantRecord, cleanup_expired_in, is_safe_host, kill, load_grants, parse_agent_pid, record,
        socket_dir, socket_path, start_in, write_known_hosts, write_new_private,
    };

    fn host_key() -> String {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap()
    }

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// Short private roots for grants and sockets.
    fn roots() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("wdnu")
            .tempdir_in("/tmp")
            .unwrap()
    }

    #[test]
    fn known_hosts_brackets_non_default_port() {
        let dir = tempfile::tempdir().unwrap();
        let key = host_key();
        let path =
            write_known_hosts(dir.path(), "127.0.0.1", 2222, std::slice::from_ref(&key)).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("[127.0.0.1]:2222 {key}\n")
        );

        let other = tempfile::tempdir().unwrap();
        let path =
            write_known_hosts(other.path(), "pi.lan", 22, std::slice::from_ref(&key)).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("pi.lan {key}\n")
        );
    }

    #[test]
    fn known_hosts_drops_comments_and_rejects_injection() {
        let dir = tempfile::tempdir().unwrap();
        let key = host_key();
        let path = write_known_hosts(dir.path(), "h", 22, &[format!("{key} root@box")]).unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), format!("h {key}\n"));

        let dir = tempfile::tempdir().unwrap();
        let injected = format!("{key}\n@cert-authority * {key}");
        assert!(write_known_hosts(dir.path(), "h", 22, &[injected]).is_err());
        assert!(write_known_hosts(dir.path(), "h", 22, &["@revoked x".to_owned()]).is_err());
        assert!(write_known_hosts(dir.path(), "h", 22, &[]).is_err());
        assert!(
            write_known_hosts(
                dir.path(),
                "-oProxyCommand=x",
                22,
                std::slice::from_ref(&key)
            )
            .is_err()
        );
        assert!(write_known_hosts(dir.path(), "a,b", 22, std::slice::from_ref(&key)).is_err());
        assert!(write_known_hosts(dir.path(), "*", 22, &[key]).is_err());
    }

    #[test]
    fn safe_hosts() {
        assert!(is_safe_host("192.0.2.2"));
        assert!(is_safe_host("pi.example.ts.net"));
        assert!(is_safe_host("::1"));
        assert!(!is_safe_host(""));
        assert!(!is_safe_host("-p"));
        assert!(!is_safe_host("a b"));
        assert!(!is_safe_host("user@host"));
        assert!(!is_safe_host("h\n"));
    }

    #[test]
    fn agent_pid_is_parsed_from_ssh_agent_output() {
        let out = "SSH_AUTH_SOCK=/tmp/a.sock; export SSH_AUTH_SOCK;\n\
                   SSH_AGENT_PID=72517; export SSH_AGENT_PID;\necho Agent pid 72517;\n";
        assert_eq!(parse_agent_pid(out), Some(72517));
        assert_eq!(parse_agent_pid("echo nothing\n"), None);
        assert_eq!(parse_agent_pid("SSH_AGENT_PID=x; export\n"), None);
    }

    #[test]
    fn socket_path_fits_sun_path_under_default_tmpdir() {
        let id = Id::random();
        let path = socket_path(&socket_dir(), &id).unwrap();
        assert!(path.as_os_str().len() <= 103, "{}", path.display());
        assert!(socket_path(&Path::new("/").join("x".repeat(100)), &id).is_err());
    }

    /// Stops a test agent even if the test panics.
    struct StopOnDrop(std::path::PathBuf, u32);

    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            let _ = kill(&self.0, self.1);
        }
    }

    #[test]
    fn grant_dir_is_0700_and_files_0600() {
        let root = roots();
        let grants = root.path().join("grants");
        let sockets = root.path().join("s");
        let id = Id::random();
        let agent = start_in(&grants, &sockets, &id, Duration::from_secs(60)).unwrap();
        let _stop = StopOnDrop(agent.socket.clone(), agent.pid);
        let rec = GrantRecord {
            grant_id: id.clone(),
            target: "pi".parse().unwrap(),
            host: "127.0.0.1".to_owned(),
            port: 22,
            user: "alice".parse().unwrap(),
            not_after: 10,
            socket: agent.socket.clone(),
            pid: agent.pid,
        };
        record(&agent, &rec).unwrap();
        let kh = write_known_hosts(&agent.dir, "127.0.0.1", 22, &[host_key()]).unwrap();

        assert_eq!(agent.dir, grants.join(id.as_str()));
        assert_eq!(mode(&grants), 0o700);
        assert_eq!(mode(&agent.dir), 0o700);
        assert_eq!(mode(&sockets), 0o700);
        assert_eq!(mode(&agent.dir.join("grant.json")), 0o600);
        assert_eq!(mode(&kh), 0o600);
        assert!(agent.socket.exists());

        let loaded = load_grants(&grants);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1.as_ref().unwrap(), &rec);

        // Expired by `now = 10`: the agent is stopped and the directory gone.
        cleanup_expired_in(&grants, 9).unwrap();
        assert!(agent.dir.exists());
        cleanup_expired_in(&grants, 10).unwrap();
        assert!(!agent.dir.exists());
        assert!(!agent.socket.exists());
    }

    /// A reader never sees a written file partially: the final path appears
    /// only once the whole contents are on disk, with mode 0600, and no
    /// temporary file is left behind.
    #[test]
    fn record_write_is_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let contents = vec![b'x'; 8 * 1024 * 1024];
        for round in 0..8 {
            let path = dir.path().join(format!("{round}.json"));
            let reader = {
                let path = path.clone();
                std::thread::spawn(move || {
                    loop {
                        if let Ok(seen) = std::fs::read(&path) {
                            return seen.len();
                        }
                        std::thread::yield_now();
                    }
                })
            };
            write_new_private(&path, &contents).unwrap();
            assert_eq!(reader.join().unwrap(), contents.len(), "round {round}");
            assert_eq!(mode(&path), 0o600);
        }
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with('.'))
            .collect();
        assert!(names.is_empty(), "left behind: {names:?}");
    }

    #[test]
    fn new_private_file_never_replaces_other_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.json");
        write_new_private(&path, b"one").unwrap();
        // The same contents again are already there: nothing to do.
        write_new_private(&path, b"one").unwrap();
        let err = write_new_private(&path, b"two").unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err:#}");
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn kill_ignores_missing_socket() {
        // A pid that is certainly not ours to signal: kill must not try.
        kill(Path::new("/nonexistent/warden.sock"), 1).unwrap();
    }

    #[test]
    fn kill_removes_stale_socket_without_signalling() {
        let root = roots();
        let stale = root.path().join("stale.sock");
        // A socket file nobody listens on, as left by a crashed agent.
        drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
        assert!(stale.exists());
        // pid 1 would fail to be signalled; kill must not try.
        kill(&stale, 1).unwrap();
        assert!(!stale.exists());
    }

    #[test]
    fn foreign_permissions_on_existing_dir_are_tightened() {
        let root = roots();
        let dir = root.path().join("loose");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        super::private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
    }
}
