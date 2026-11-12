//! GitHub tokens for git and `gh`: `warden github token`, and the cache it shares
//! with the git credential helper.
//!
//! The broker mints a GitHub App installation token for one repository under this
//! agent's active `github_token` grant that covers it. GitHub ends it after an
//! hour; the CLI keeps it in `<state>/github-token.json` (see [`cache`]), one entry
//! per repository, and mints again once less than [`MIN_REMAINING_SECS`] remain.
//!
//! When the agent has no active grant for the repository, the CLI asks the owner
//! itself, naming that repository, says on stderr that it waits, and goes on once
//! the owner approves. Nothing but the token
//! ever goes to stdout, which git and the `gh` wrapper read.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, anyhow};
use serde::{Deserialize, Serialize};
use warden_broker_proto::Goal;
use warden_broker_proto::github_token::{
    AMBIGUOUS_GRANT, APP_CHANGED, AutomaticCaller, GithubTokenResponse, HOURLY_LIMIT,
    NO_ACTIVE_GRANT, NOT_CONFIGURED, OLD_CLIENT, REPOSITORY_UNREACHABLE,
};
use warden_broker_proto::release::RepoName;
use zeroize::Zeroizing;

use crate::client::{CallError, Client, require_scoped};
use crate::config::Config;
use crate::github_repo;
use crate::{EXIT_ERROR, EXIT_NO_GRANT, Exit, request, unix_now};

mod cache;

pub use cache::discard;
use cache::{Cache, Entry};

/// A cached token is served only while it has at least this long left, in seconds.
pub const MIN_REMAINING_SECS: i64 = 300;

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

/// The token for `repository` cached at `path` if it was minted for `identity` and
/// is good for at least [`MIN_REMAINING_SECS`] at `now`, or else one from `mint`,
/// which then joins the cache. A cache that cannot be written is reported on stderr
/// and does not stop the token. The answer of `mint` must be for `repository`.
///
/// # Errors
/// What `mint` failed with; a token that is not well formed; or
/// a token for another repository.
async fn serve_from<F, Fut>(
    path: &Path,
    now: i64,
    identity: &Identity,
    repository: &RepoName,
    mint: F,
) -> Result<Zeroizing<String>>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<GithubTokenResponse>>,
{
    let loaded = Cache::load(path).filter(|cache| cache.identity == *identity);
    if let Some(entry) = loaded.as_ref().and_then(|c| c.lookup(repository, now)) {
        return Ok(entry.token.clone());
    }
    let entry = Entry::new(mint().await?);
    if !entry.repository.matches(repository) {
        return Err(anyhow!("the broker sent a token for another repository"));
    }
    if !cache::well_formed(&entry.token) {
        return Err(anyhow!("the broker sent a token that is not well formed"));
    }
    let token = entry.token.clone();
    let mut cache = loaded.unwrap_or_else(|| Cache::empty(identity.clone()));
    cache.drop_expired(now);
    cache.put(entry);
    if let Err(e) = cache.write(path) {
        eprintln!(
            "warden: warning: cannot cache the GitHub token, so it is minted anew next time: {e:#}"
        );
    }
    Ok(token)
}

/// The cached token for `repository`, or a new one from the broker of `config` when
/// the cache holds no good one for it. A new one is minted only from a broker that
/// scopes GitHub grants to repositories.
///
/// # Errors
/// If the state directory is unusable, the broker does not scope GitHub grants, or
/// as [`serve_from`].
pub async fn cached_or_mint(
    config: &Config,
    client: &Client,
    repository: &RepoName,
    now: i64,
) -> Result<Zeroizing<String>> {
    let path = cache::cache_path()?;
    let identity = Identity::of(config);
    serve_from(&path, now, &identity, repository, || async {
        require_scoped(&config.server).await?;
        Ok(client.github_token(repository).await?)
    })
    .await
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
    match cached_or_mint(&config, &client, repository, unix_now()).await {
        Ok(token) => Ok(token),
        Err(e) if is_no_grant(&e) => {
            let dir = std::env::current_dir().ok();
            let goal = goal_for(caller, repository, dir.as_deref())?;
            let by = match caller {
                Caller::CredentialHelper => AutomaticCaller::GitCredential,
                Caller::GhWrapper => AutomaticCaller::GhWrapper,
            };
            request::request_github_for_tool(
                &config,
                &client,
                goal,
                by,
                repository,
                dir.as_deref(),
            )
            .await?;
            cached_or_mint(&config, &client, repository, unix_now())
                .await
                .map_err(explain)
        }
        Err(e) => Err(explain(e)),
    }
}

/// What to tell the agent about a failed mint: what happened, and a next step that
/// never goes around the owner.
fn explain(e: anyhow::Error) -> anyhow::Error {
    if e.downcast_ref::<Exit>().is_some() {
        return e;
    }
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
                 request github <owner/name> --goal \"<why this agent uses GitHub>\""
            ),
        ),
        CallError::Refused(m) if m.contains(REPOSITORY_UNREACHABLE) => (
            EXIT_ERROR,
            format!(
                "cannot get a GitHub token: {m}. Something is wrong with that repository's \
                 access, so do not retry; ask the owner whether the App still reaches it"
            ),
        ),
        CallError::Refused(m) if m.contains(AMBIGUOUS_GRANT) => (
            EXIT_ERROR,
            format!("cannot get a GitHub token: {m}. Do not retry: ask the owner"),
        ),
        CallError::Refused(m) if m.contains(OLD_CLIENT) => (
            EXIT_ERROR,
            format!("cannot get a GitHub token: {m}. Upgrade warden on this machine"),
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
