//! GitHub tokens for git and `gh`: `warden github token`, and the cache it shares
//! with the git credential helper.
//!
//! The broker mints a GitHub App installation token under this agent's active
//! `github_token` grant. GitHub ends it after an hour; the CLI keeps it in
//! `<state>/github-token.json` and mints again once less than
//! [`MIN_REMAINING_SECS`] remain. The file necessarily holds the token in clear, so
//! it is served only while it is a regular file of this user with mode exactly
//! 0600 that parses: anything else is replaced, never trusted.
//!
//! When the agent has no active grant, the CLI asks the owner itself, says on
//! stderr that it waits, and goes on once the owner approves. Nothing but the token
//! ever goes to stdout, which git and the `gh` wrapper read.

use std::ffi::OsString;
use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow};
use serde::{Deserialize, Serialize};
use warden_broker_proto::github_token::{
    APP_CHANGED, GithubTokenResponse, HOURLY_LIMIT, NO_ACTIVE_GRANT, NOT_CONFIGURED,
};
use warden_broker_proto::release::RepoName;
use warden_broker_proto::{Goal, Id};
use zeroize::Zeroizing;

use crate::client::{CallError, Client};
use crate::config::Config;
use crate::github_repo;
use crate::{EXIT_ERROR, EXIT_NO_GRANT, Exit, agent, request, unix_now};

/// A cached token is served only while it has at least this long left, in seconds.
pub const MIN_REMAINING_SECS: i64 = 300;

/// The cache's name in the state directory.
const CACHE_FILE: &str = "github-token.json";

/// The largest cache file read, in bytes.
const MAX_CACHE_BYTES: usize = 16 * 1024;

/// The longest token accepted, in bytes.
const MAX_TOKEN_BYTES: usize = 1024;

/// Which program wants the token, for the goal of a request made on its behalf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    /// `warden git-credential get`.
    CredentialHelper,
    /// `warden github token`, which the `gh` wrapper runs.
    GhWrapper,
}

impl Caller {
    /// The fixed goal of the request filed for this caller.
    const fn requester(self) -> &'static str {
        match self {
            Self::CredentialHelper => "the git credential helper",
            Self::GhWrapper => "the gh wrapper",
        }
    }
}

/// The goal of a request filed for `caller` for `repository` from `dir`: the fixed
/// text, and the directory when it fits in a goal.
///
/// # Errors
/// Never in practice: the fixed text with a repository name is a valid goal.
fn goal_for(caller: Caller, repository: &RepoName, dir: Option<&Path>) -> Result<Goal> {
    let base = format!(
        "GitHub token for {repository}, requested automatically by {}",
        caller.requester()
    );
    let with_dir = dir
        .and_then(Path::to_str)
        .filter(|dir| !dir.chars().any(char::is_control))
        .and_then(|dir| Goal::try_from(format!("{base}, in {dir}")).ok());
    match with_dir {
        Some(goal) => Ok(goal),
        None => Goal::try_from(base).map_err(|e| anyhow!("{e}")),
    }
}

/// Whom a token was minted for: the agent and its broker, as configured. A cache
/// minted for another is never served, so that a new `warden login` does not keep
/// using the previous identity's token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    /// The agent's name.
    pub agent: String,
    /// The broker's agent API URL.
    pub server: String,
}

impl Identity {
    /// The identity `config` logs in as.
    pub fn of(config: &Config) -> Self {
        Self {
            agent: config.agent.to_string(),
            server: config.server.to_string(),
        }
    }
}

/// A token in memory that is wiped when dropped.
struct Held {
    token: Zeroizing<String>,
    expires_at: i64,
    grant_id: Id,
    identity: Identity,
}

impl Held {
    fn new(response: GithubTokenResponse, identity: Identity) -> Self {
        let GithubTokenResponse {
            token,
            expires_at,
            grant_id,
        } = response;
        Self {
            token: Zeroizing::new(token),
            expires_at,
            grant_id,
            identity,
        }
    }
}

/// The cache file as read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    token: String,
    expires_at: i64,
    grant_id: Id,
    agent: String,
    server: String,
}

/// The cache file as written.
#[derive(Serialize)]
struct StoredRef<'a> {
    token: &'a str,
    expires_at: i64,
    grant_id: &'a Id,
    agent: &'a str,
    server: &'a str,
}

/// Whether `token` can go on a line of git's credential protocol and into an
/// environment variable as it is: printable ASCII without spaces, of a sane length.
fn well_formed(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token.bytes().all(|b| b.is_ascii_graphic())
}

/// `<state>/github-token.json`.
fn cache_path() -> Result<PathBuf> {
    Ok(agent::state_dir()?.join(CACHE_FILE))
}

/// The cache at `path`, if it is a regular file of this user with mode exactly
/// 0600, at most [`MAX_CACHE_BYTES`], that parses. A symlink is never followed and a
/// FIFO never waited on.
fn read_stored(path: &Path) -> Option<Held> {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = fs::File::from(rustix::fs::open(path, flags, Mode::empty()).ok()?);
    let meta = file.metadata().ok()?;
    if !meta.is_file()
        || meta.uid() != rustix::process::getuid().as_raw()
        || meta.mode() & 0o7777 != 0o600
    {
        return None;
    }
    // Room for one byte more than allowed, so that reading never grows the buffer
    // and leaves a copy behind.
    let mut raw = Zeroizing::new(Vec::with_capacity(MAX_CACHE_BYTES + 1));
    let limit = u64::try_from(MAX_CACHE_BYTES + 1).ok()?;
    file.take(limit).read_to_end(&mut raw).ok()?;
    if raw.len() > MAX_CACHE_BYTES {
        return None;
    }
    let Stored {
        token,
        expires_at,
        grant_id,
        agent,
        server,
    } = serde_json::from_slice(&raw).ok()?;
    let token = Zeroizing::new(token);
    well_formed(&token).then_some(Held {
        token,
        expires_at,
        grant_id,
        identity: Identity { agent, server },
    })
}

/// The cached token at `path` if it was minted for `identity` and has at least
/// [`MIN_REMAINING_SECS`] left at `now`.
fn read_cache(path: &Path, now: i64, identity: &Identity) -> Option<Held> {
    read_stored(path).filter(|t| {
        t.identity == *identity && t.expires_at.saturating_sub(now) >= MIN_REMAINING_SECS
    })
}

/// Replace the cache at `path` with `token`: written to a new 0600 file beside it,
/// which is renamed over whatever was there (a rename replaces a symlink, never
/// what it points to).
fn write_cache(path: &Path, token: &Held) -> Result<()> {
    let stored = StoredRef {
        token: &token.token,
        expires_at: token.expires_at,
        grant_id: &token.grant_id,
        agent: &token.identity.agent,
        server: &token.identity.server,
    };
    // Sized up front, so that writing never grows the buffer and leaves a copy.
    let mut contents = Zeroizing::new(Vec::with_capacity(token.token.len() + 256));
    serde_json::to_writer(&mut *contents, &stored).context("cannot encode the token cache")?;
    let (_, temp) = agent::temp_beside(path)?;
    let written = agent::write_temp(&temp, &contents)
        .and_then(|()| {
            // Whatever the umask took away, the mode is exactly 0600, or the cache
            // would never be served.
            fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("cannot restrict {}", temp.display()))
        })
        .and_then(|()| {
            fs::rename(&temp, path).with_context(|| format!("cannot write {}", path.display()))
        });
    if written.is_err() {
        // Best effort: the error that matters is the one returned.
        let _ = fs::remove_file(&temp);
    }
    written
}

/// The token cached at `path` if it was minted for `identity` and is good for at
/// least [`MIN_REMAINING_SECS`] at `now`, or else one from `mint`, which then
/// replaces the cache. A cache that
/// cannot be written is reported on stderr and does not stop the token.
///
/// # Errors
/// What `mint` failed with, as a [`CallError`], or a token that is not well formed.
async fn serve_from<F, Fut>(
    path: &Path,
    now: i64,
    identity: &Identity,
    mint: F,
) -> Result<Zeroizing<String>>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<GithubTokenResponse, CallError>>,
{
    if let Some(cached) = read_cache(path, now, identity) {
        return Ok(cached.token);
    }
    let fresh = Held::new(mint().await?, identity.clone());
    if !well_formed(&fresh.token) {
        return Err(anyhow!("the broker sent a token that is not well formed"));
    }
    if let Err(e) = write_cache(path, &fresh) {
        eprintln!(
            "warden: warning: cannot cache the GitHub token, so it is minted anew next time: {e:#}"
        );
    }
    Ok(fresh.token)
}

/// The cached token, or a new one from the broker of `config` when the cache holds
/// no good one for its agent.
///
/// # Errors
/// If the state directory is unusable, or as [`serve_from`].
pub async fn cached_or_mint(
    config: &Config,
    client: &Client,
    now: i64,
) -> Result<Zeroizing<String>> {
    serve_from(&cache_path()?, now, &Identity::of(config), || {
        client.github_token()
    })
    .await
}

/// Delete the cached token if it was minted under `grant`, as when the grant is
/// revoked from here. Returns whether one was.
///
/// # Errors
/// If the state directory is unusable or the file cannot be removed.
pub fn discard(grant: &Id) -> Result<bool> {
    let path = cache_path()?;
    if !read_stored(&path).is_some_and(|t| t.grant_id == *grant) {
        return Ok(false);
    }
    fs::remove_file(&path).with_context(|| format!("cannot remove {}", path.display()))?;
    Ok(true)
}

/// Whether `e` says this agent has no active grant.
fn is_no_grant(e: &anyhow::Error) -> bool {
    e.downcast_ref::<CallError>()
        .is_some_and(|e| matches!(e, CallError::Refused(m) if m.contains(NO_ACTIVE_GRANT)))
}

/// A token for `caller`, for `repository`. Without an active grant, a request is filed for it and the
/// owner's decision awaited first, as `warden request` waits.
///
/// # Errors
/// [`Exit`] with [`EXIT_NO_GRANT`] when the owner does not approve or no grant is
/// usable, and otherwise as [`explain`] says.
pub async fn obtain(caller: Caller, repository: &RepoName) -> Result<Zeroizing<String>> {
    let (config, client) = crate::client()?;
    match cached_or_mint(&config, &client, unix_now()).await {
        Ok(token) => Ok(token),
        Err(e) if is_no_grant(&e) => {
            let dir = std::env::current_dir().ok();
            let goal = goal_for(caller, repository, dir.as_deref())?;
            request::request_github_for_tool(&config, &client, goal).await?;
            cached_or_mint(&config, &client, unix_now())
                .await
                .map_err(explain)
        }
        Err(e) => Err(explain(e)),
    }
}

/// What to tell the agent about a failed mint: what happened, and a next step that
/// never goes around the owner.
fn explain(e: anyhow::Error) -> anyhow::Error {
    let Some(call) = e.downcast_ref::<CallError>() else {
        return e.context("cannot get a GitHub token");
    };
    let (code, message) = match call {
        CallError::Refused(m) if m.contains(NO_ACTIVE_GRANT) => (
            EXIT_NO_GRANT,
            format!(
                "cannot get a GitHub token: {m}, although the owner approved one: it may have \
                 been revoked since. Do not retry around this: ask the owner"
            ),
        ),
        CallError::Refused(m) if m.contains(APP_CHANGED) => (
            EXIT_NO_GRANT,
            format!(
                "cannot get a GitHub token: {m}. Ask the owner for a new grant with: warden \
                 request github --goal \"<why this agent uses GitHub>\""
            ),
        ),
        CallError::Refused(m) if m.contains(HOURLY_LIMIT) => (
            EXIT_ERROR,
            format!(
                "cannot get a GitHub token: {m}. Something is asking for far more tokens than git \
                 and gh need: do not retry in a loop; if it goes on, tell the owner"
            ),
        ),
        CallError::Refused(m) if m.contains(NOT_CONFIGURED) => (
            EXIT_ERROR,
            format!("cannot get a GitHub token: {m}. Ask the owner whether it should be"),
        ),
        CallError::Revoked(m) | CallError::Expired(m) => (
            EXIT_NO_GRANT,
            format!(
                "cannot get a GitHub token: the grant ended while the token was minted ({m}). \
                 If the owner has just approved a new grant, running the command once more uses \
                 it; otherwise do not retry: ask the owner"
            ),
        ),
        CallError::Unavailable(m) | CallError::CallStopped(m) => (
            EXIT_ERROR,
            format!(
                "cannot get a GitHub token: {m}. GitHub tokens come from the broker: `warden \
                 doctor` checks the connection"
            ),
        ),
        CallError::Refused(m) => (EXIT_ERROR, format!("cannot get a GitHub token: {m}")),
    };
    Exit::new(code, message).into()
}

/// The repository `warden github token` is for. With `gh_args`, `-R`/`--repo` in
/// `args` is the explicit one and refusal speaks of `-R`; otherwise `repo` is, and it
/// speaks of `--repo`. Then `GH_REPO` (unset or empty counts as unset, as for `gh`),
/// then the `origin` remote of the current directory.
///
/// # Errors
/// [`Exit`] with [`EXIT_ERROR`] when the repository cannot be told, so that nothing
/// reaches stdout.
pub fn repository_for(
    repo: Option<RepoName>,
    gh_args: bool,
    args: &[OsString],
) -> Result<RepoName> {
    let explicit = if gh_args {
        github_repo::repo_flag(args)
            .map_err(|_| Exit::new(EXIT_ERROR, github_repo::UNDETERMINED_GH))?
    } else {
        repo
    };
    let gh_repo = std::env::var_os("GH_REPO")
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string_lossy().into_owned());
    github_repo::choose(explicit, gh_repo.as_deref(), || {
        github_repo::origin_url(&std::env::current_dir().ok()?)
    })
    .map_err(|github_repo::Undetermined| {
        let message = if gh_args {
            github_repo::UNDETERMINED_GH
        } else {
            github_repo::UNDETERMINED_TOKEN
        };
        Exit::new(EXIT_ERROR, message).into()
    })
}

/// `warden github token`: print a token for `repository`, and nothing else, on stdout.
///
/// # Errors
/// As [`obtain`], or if stdout cannot be written.
pub async fn print_token(repository: &RepoName) -> Result<()> {
    let token = obtain(Caller::GhWrapper, repository).await?;
    let mut out = std::io::stdout().lock();
    out.write_all(token.as_bytes())
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush())
        .context("cannot write the token")
}

#[cfg(test)]
mod tests;
