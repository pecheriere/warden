//! `warden ssh-config`: an `ssh_config` `Host` block for a target's active
//! grant, for tools that run ssh themselves. It carries exactly the options
//! `warden ssh` passes (both come from [`ssh::connection`]), and points at the
//! grant's agent and pinned `known_hosts`: no key or certificate is written.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use jiff::{SignedDuration, Timestamp};
use serde::Serialize;
use warden_broker_proto::{Id, TargetName};

use crate::ssh::{self, ActiveGrant};
use crate::{EXIT_NO_GRANT, Exit, agent, guidance, unix_now};

/// What `warden ssh-config` was asked for: its command line.
#[derive(Debug, Args)]
pub struct Request {
    /// Target name, which is also the Host name.
    pub target: TargetName,
    /// Write the block to this file (0600, replaced atomically; a symlink is
    /// refused) instead of standard output.
    #[arg(long, value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Print JSON on standard output: target, grant, host, port, user,
    /// `not_after` (Unix seconds), socket, `known_hosts` and config.
    #[arg(long)]
    pub json: bool,
    /// Exit 5 unless the grant stays valid at least this long, such as 10m
    /// or 1h30m.
    #[arg(long, value_name = "DURATION", value_parser = parse_min_remaining)]
    pub min_remaining: Option<SignedDuration>,
}

/// The block and what it was made from, as `--json` prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostConfig {
    /// Target name, which is also the `Host` name.
    pub target: TargetName,
    /// Grant identifier.
    pub grant: Id,
    /// `HostName`: the target's address, or the relay's.
    pub host: String,
    /// `Port`.
    pub port: u16,
    /// `User`: the grant's user, or the target's name for a relay grant.
    pub user: String,
    /// End of the grant, Unix seconds.
    pub not_after: i64,
    /// The grant agent's socket (`IdentityAgent`), unquoted.
    pub socket: String,
    /// The grant's pinned `known_hosts` (`UserKnownHostsFile`), unquoted.
    pub known_hosts: String,
    /// The `ssh_config` text.
    pub config: String,
}

/// Parses `--min-remaining`: a duration such as `10m`, `1h30m` or `90s` (or
/// ISO 8601, `PT10M`), not negative.
///
/// # Errors
/// If it does not parse or is negative.
pub fn parse_min_remaining(text: &str) -> Result<SignedDuration, String> {
    let duration: SignedDuration = text
        .parse()
        .map_err(|e| format!("not a duration such as 10m or 1h30m: {e}"))?;
    if duration.is_negative() {
        return Err("must not be negative".to_owned());
    }
    Ok(duration)
}

/// Runs `warden ssh-config`.
///
/// # Errors
/// [`Exit`] with [`EXIT_NO_GRANT`] when there is no usable grant, or any
/// failure to build or write the block.
pub fn run(request: &Request) -> Result<()> {
    let grants = agent::grants_dir()?;
    let config = host_config(&grants, &request.target, unix_now(), request.min_remaining)?;
    emit(request, &config, &mut std::io::stdout().lock())
}

/// Writes the block to `--output` if given, then prints the JSON or, without
/// `--output`, the block to `out`.
fn emit(request: &Request, config: &HostConfig, out: &mut impl std::io::Write) -> Result<()> {
    if let Some(path) = &request.output {
        replace_private(path, config.config.as_bytes())?;
    }
    if request.json {
        serde_json::to_writer(&mut *out, config).context("cannot write the JSON")?;
        writeln!(out).context("cannot write the JSON")?;
    } else if request.output.is_none() {
        out.write_all(config.config.as_bytes())
            .context("cannot write the block")?;
    }
    out.flush().context("cannot write to standard output")
}

/// The [`HostConfig`] for the grant `warden ssh` would use for `target` at
/// `now`, if it stays valid for `min_remaining` more.
///
/// # Errors
/// [`Exit`] with [`EXIT_NO_GRANT`] when there is no active grant whose socket
/// exists, or it ends too soon; otherwise as [`ssh::connection`].
pub fn host_config(
    grants: &Path,
    target: &TargetName,
    now: i64,
    min_remaining: Option<SignedDuration>,
) -> Result<HostConfig> {
    let Some(grant) = ssh::active_grant(grants, target, now) else {
        return Err(Exit::new(EXIT_NO_GRANT, guidance::no_ssh_grant(target)).into());
    };
    if let Some(wanted) = min_remaining {
        let remaining = SignedDuration::from_secs(grant.record.not_after.saturating_sub(now));
        if remaining < wanted {
            let message = guidance::ssh_grant_ends_too_soon(
                target,
                &grant.record.grant_id,
                remaining,
                wanted,
            );
            return Err(Exit::new(EXIT_NO_GRANT, message).into());
        }
    }
    let conn = ssh::connection(&grant)?;
    let config = block(&grant, &conn)?;
    Ok(HostConfig {
        target: grant.record.target,
        grant: grant.record.grant_id,
        host: conn.host,
        port: conn.port,
        user: conn.login,
        not_after: grant.record.not_after,
        socket: conn.socket,
        known_hosts: conn.known_hosts,
        config,
    })
}

/// The `ssh_config` text: a comment naming the grant and its end, then a
/// `Host` block named after the target. Every value in it was validated
/// ([`ssh::connection`], and the types of the target and grant id), so none
/// can start a new line or keyword.
///
/// # Errors
/// If `not_after` is not a representable time.
fn block(grant: &ActiveGrant, conn: &ssh::Connection) -> Result<String> {
    let rec = &grant.record;
    let end = Timestamp::from_second(rec.not_after)
        .with_context(|| format!("grant end {} is not a valid time", rec.not_after))?;
    let mut text = format!(
        "# warden grant {id} for {target}, not_after={secs} ({end})\n\
         Host {target}\n  HostName {host}\n  Port {port}\n  User {login}\n",
        id = rec.grant_id,
        target = rec.target,
        secs = rec.not_after,
        host = conn.host,
        port = conn.port,
        login = conn.login,
    );
    for (key, value) in &conn.options {
        // Writing to a String cannot fail.
        let _ = writeln!(text, "  {key} {value}");
    }
    Ok(text)
}

/// Replace `path` with a 0600 file holding `contents`, atomically: a
/// temporary file in the same directory, synced, renamed over `path`. A
/// symlink or anything else that is not a regular file at `path` is refused,
/// and the rename replaces the name itself, so a link is never followed.
///
/// # Errors
/// If `path` is not a regular file, or the file cannot be written.
fn replace_private(path: &Path, contents: &[u8]) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => ensure!(
            meta.file_type().is_file(),
            "{} exists and is not a regular file (warden does not write through a symlink); \
             remove it or choose another --output",
            path.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("cannot inspect {}", path.display())),
    }
    let (dir, temp) = agent::temp_beside(path)?;
    let written = agent::write_temp(&temp, contents).and_then(|()| {
        fs::rename(&temp, path).with_context(|| format!("cannot write {}", path.display()))?;
        fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .with_context(|| format!("cannot sync {}", dir.display()))
    });
    if written.is_err() {
        // Best effort: the temporary file may be gone already, and the error
        // that matters is the one being returned.
        let _ = fs::remove_file(&temp);
    }
    written
}

#[cfg(test)]
mod tests;
