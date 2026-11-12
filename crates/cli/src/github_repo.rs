//! Which GitHub repository a token is for.
//!
//! The git credential helper learns it from the `path` git sends (with
//! `credential.useHttpPath`), the `gh` wrapper from `-R`/`--repo`, `GH_REPO` or the
//! `origin` remote of the current directory. Every parser is strict and returns
//! `None` or an error rather than guess: a token is scoped to what is named here, so
//! a repository read wrongly is a token for the wrong repository.

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Stdio};

use thiserror::Error;
use warden_broker_proto::release::RepoName;

/// The only host repositories are read for.
const HOST: &str = "github.com";

/// Said when no repository can be told for `warden github token`.
pub const UNDETERMINED_TOKEN: &str =
    "cannot tell which repository this token is for; pass --repo owner/name";

/// Said when no repository can be told for the `gh` wrapper.
pub const UNDETERMINED_GH: &str = "cannot tell which repository; pass -R owner/name";

/// Why a repository argument was refused. The messages do not quote the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RepoArgError {
    /// A repository on a host other than github.com.
    #[error("only repositories on github.com are supported")]
    OtherHost,
    /// Not `owner/name`, or two different repositories were given.
    #[error("the repository must be given as owner/name")]
    Invalid,
}

/// No repository could be told from any source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Undetermined;

/// The repository named by the `path` git sends to a credential helper: `owner/name`
/// with one optional trailing `/`, then one optional `.git`. Anything else, such as
/// the `/info/lfs` paths git-lfs sends, is `None`.
pub fn from_helper_path(path: &str) -> Option<RepoName> {
    let path = path.strip_suffix('/').unwrap_or(path);
    let path = path.strip_suffix(".git").unwrap_or(path);
    path.parse().ok()
}

/// The repository a remote URL names: `https://github.com/<o>/<r>[.git][/]` or
/// `git@github.com:<o>/<r>[.git]`. Any other host, scheme, port or user is `None`.
pub fn from_remote_url(url: &str) -> Option<RepoName> {
    if let Some(rest) = url.strip_prefix("https://github.com/") {
        return from_helper_path(rest);
    }
    let rest = url.strip_prefix("git@github.com:")?;
    if rest.ends_with('/') {
        return None;
    }
    from_helper_path(rest)
}

/// The repository `gh` is told with `-R` or `GH_REPO`: `OWNER/REPO`,
/// `github.com/OWNER/REPO` or `https://github.com/OWNER/REPO`.
///
/// # Errors
/// [`RepoArgError::OtherHost`] for another host, [`RepoArgError::Invalid`] otherwise.
pub fn from_gh_value(value: &str) -> Result<RepoName, RepoArgError> {
    let (rest, had_scheme) = value
        .strip_prefix("https://")
        .map_or((value, false), |rest| (rest, true));
    let parts: Vec<&str> = rest.split('/').collect();
    match parts.as_slice() {
        [owner, name] if !had_scheme => parse_pair(owner, name),
        [host, owner, name] if host.contains('.') => {
            if host.eq_ignore_ascii_case(HOST) {
                parse_pair(owner, name)
            } else {
                Err(RepoArgError::OtherHost)
            }
        }
        _ => Err(RepoArgError::Invalid),
    }
}

fn parse_pair(owner: &str, name: &str) -> Result<RepoName, RepoArgError> {
    format!("{owner}/{name}")
        .parse()
        .map_err(|_| RepoArgError::Invalid)
}

/// The repository given as `-R X`, `-RX`, `--repo X` or `--repo=X` before a `--`.
/// Nothing else of `gh`'s command line is read.
///
/// # Errors
/// If a value is not a usable repository, is missing, or two flags name different
/// repositories.
pub fn repo_flag(args: &[OsString]) -> Result<Option<RepoName>, RepoArgError> {
    let mut found: Option<RepoName> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            break;
        }
        let Some(arg) = arg.to_str() else {
            continue;
        };
        let value = if arg == "-R" || arg == "--repo" {
            iter.next()
                .and_then(|v| v.to_str())
                .ok_or(RepoArgError::Invalid)?
        } else if let Some(value) = arg.strip_prefix("--repo=") {
            value
        } else if let Some(value) = arg.strip_prefix("-R") {
            value
        } else {
            continue;
        };
        let repo = from_gh_value(value)?;
        match &found {
            Some(first) if !first.matches(&repo) => return Err(RepoArgError::Invalid),
            Some(_) => {}
            None => found = Some(repo),
        }
    }
    Ok(found)
}

/// The repository to use: `explicit`, else `GH_REPO`, else the `origin` remote.
/// A source that answers is final; an unusable `GH_REPO` is never skipped.
///
/// # Errors
/// [`Undetermined`] when no source gives a repository on github.com.
pub fn choose(
    explicit: Option<RepoName>,
    gh_repo: Option<&str>,
    origin: impl FnOnce() -> Option<String>,
) -> Result<RepoName, Undetermined> {
    if let Some(repo) = explicit {
        return Ok(repo);
    }
    if let Some(value) = gh_repo {
        return from_gh_value(value).map_err(|_| Undetermined);
    }
    origin()
        .and_then(|url| from_remote_url(&url))
        .ok_or(Undetermined)
}

/// The `origin` remote URL of the repository at `dir`, or `None` if there is none or
/// `git` fails.
pub fn origin_url(dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["config", "--get", "remote.origin.url"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let url = String::from_utf8(output.stdout).ok()?;
    let url = url.trim_end_matches('\n');
    (!url.is_empty()).then(|| url.to_owned())
}

#[cfg(test)]
mod tests;
