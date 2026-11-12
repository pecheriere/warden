//! `warden request github` and the requests git and `gh` make by themselves: the
//! owner approves GitHub tokens for the repositories named.

use std::path::Path;

use anyhow::{Context as _, Result, bail};
use warden_broker_proto::github_token::{AutomaticCaller, AutomaticRequest};
use warden_broker_proto::release::RepoName;
use warden_broker_proto::{
    Access, CreateRequest, GithubTokenAccess, Goal, GrantAccess, GrantView, SessionLabel,
    SessionLink, Window,
};

use super::{Pending, announce, not_granted, request_grant, resolve_context};
use crate::client::{Client, fetch_info, require_scoped, scoped_or_refuse};
use crate::config::Config;
use crate::request_context::RequestContext;
use crate::{EXIT_USAGE, Exit, client, local_time};

/// What completes "a request …" for a GitHub token request.
const SUBJECT: &str = "for a github token";

pub(crate) async fn request_github(
    repositories: Vec<RepoName>,
    window: Window,
    goal: Goal,
    context: RequestContext,
) -> Result<()> {
    let access = GithubTokenAccess::new(repositories.clone(), None)
        .map_err(|e| Exit::new(EXIT_USAGE, format!("{e}")))?;
    let (session, link) = resolve_context(context)?;
    let (config, client) = client()?;
    require_scoped(&config.server).await?;
    if let Some(notice) = several_notice(repositories.len()) {
        eprintln!("{notice}");
    }
    let req = github_request(goal, window, access, session, link);
    let grant = request_grant(&config, &client, &req, SUBJECT, Pending::Same).await?;
    check_github_grant(&grant, &repositories)?;
    announce(&grant);
    println!(
        "git and gh get GitHub tokens under it until then. Set them up with `warden setup \
         github` if they are not yet set up."
    );
    Ok(())
}

/// What is said when a request names more than one repository: the owner approves
/// them together.
fn several_notice(count: usize) -> Option<String> {
    (count > 1)
        .then(|| format!("this request covers {count} repositories, and the owner sees it as such"))
}

/// Ask the owner for a GitHub token grant for `repository` on behalf of git or
/// `gh`, which found none, and wait for the decision as `warden request` does: the
/// longest window up to 30 days that the broker allows, the session label from the
/// environment, and `dir` as the directory the tool ran in. Writes only to stderr,
/// as git and the `gh` wrapper read stdout. A pending GitHub token request of this
/// agent for the same repository, made some other way, is waited on instead: the
/// broker keeps one per agent and set of repositories, and any of them grants the same.
///
/// # Errors
/// [`Exit`] with [`EXIT_NO_GRANT`](crate::EXIT_NO_GRANT) when the request ends
/// without a grant (denied, expired, cancelled, revoked, or no decision in time),
/// saying not to work around it; a broker that cannot be reached, does not scope
/// GitHub grants to repositories, or refuses the request as it is.
pub(crate) async fn request_github_for_tool(
    config: &Config,
    client: &Client,
    goal: Goal,
    caller: AutomaticCaller,
    repository: &RepoName,
    dir: Option<&Path>,
) -> Result<()> {
    let info = fetch_info(&config.server).await;
    let max = info
        .as_ref()
        .ok()
        .and_then(|info| info.github_token_max_window);
    scoped_or_refuse(info)?;
    let (session, link) = resolve_context(RequestContext::default())?;
    let access = tool_access(caller, repository, dir)?;
    let req = github_request(goal, tool_window(max), access, session, link);
    eprintln!(
        "warden: this agent has no active GitHub token grant for {repository}; asking the owner \
         for one"
    );
    let grant = request_grant(config, client, &req, SUBJECT, Pending::AnyOfKind)
        .await
        .map_err(not_granted)?;
    check_github_grant(&grant, std::slice::from_ref(repository))?;
    eprintln!(
        "warden: approved: grant {} until {}",
        grant.grant_id,
        local_time(grant.not_after)
    );
    Ok(())
}

/// The window of a request made for git or `gh`, given the broker's longest: the
/// longest GitHub token window up to it, and 30 days from a broker that does not
/// say, as one older than this setting allows that.
pub(super) fn tool_window(max: Option<Window>) -> Window {
    max.map_or(Window::GITHUB_TOKEN_DEFAULT, |max| {
        Window::GITHUB_TOKEN
            .into_iter()
            .filter(|window| *window <= max && *window <= Window::GITHUB_TOKEN_DEFAULT)
            .max()
            .unwrap_or(Window::D1)
    })
}

/// The access of a request made for git or `gh`: the one repository they found,
/// and the directory they ran in when it is usable as free text.
fn tool_access(
    caller: AutomaticCaller,
    repository: &RepoName,
    dir: Option<&Path>,
) -> Result<GithubTokenAccess> {
    let dir = dir.and_then(Path::to_str).map(str::to_owned);
    let automatic = |dir| Some(AutomaticRequest { by: caller, dir });
    GithubTokenAccess::new(vec![repository.clone()], automatic(dir))
        .or_else(|_| GithubTokenAccess::new(vec![repository.clone()], automatic(None)))
        .context("cannot build the GitHub token request")
}

fn github_request(
    goal: Goal,
    window: Window,
    access: GithubTokenAccess,
    session: Option<SessionLabel>,
    link: Option<SessionLink>,
) -> CreateRequest {
    CreateRequest {
        goal,
        access: Access::GithubToken(access),
        window,
        session,
        link,
    }
}

/// Whether `grant` is a GitHub token grant that covers every one of `repositories`,
/// as a broker that scopes grants approves.
///
/// # Errors
/// If it is another kind of grant, a grant stored before scoping, or one that does
/// not cover a repository asked for.
pub(super) fn check_github_grant(grant: &GrantView, repositories: &[RepoName]) -> Result<()> {
    let GrantAccess::GithubToken(access) = &grant.access else {
        bail!("the broker returned another kind of grant for a github token request");
    };
    if access.repositories.is_legacy() {
        bail!("the broker approved an unscoped GitHub grant: upgrade the broker");
    }
    for repository in repositories {
        if access.repositories.covering(repository).is_none() {
            bail!("the broker approved a grant that does not cover {repository}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
