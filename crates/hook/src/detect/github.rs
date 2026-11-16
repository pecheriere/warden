//! `owner-github`: `gh` and `git push` reaching GitHub with the owner's own
//! login instead of a token from warden, when the broker offers GitHub tokens.
//!
//! A subject is the tool, `gh` or `git`, never a repository or a URL.
//!
//! Not modelled, so a command using one of these may be judged wrongly:
//! `GIT_DIR=`, `GIT_CONFIG_GLOBAL=`, `GIT_CONFIG_COUNT` and `GIT_CONFIG_KEY_n`
//! on the command; `gh --hostname` and `GH_HOST` (GitHub Enterprise); and a
//! push URL with an embedded password.

use url::Url;

use super::Match;
use super::args::{self, Item};
use super::ssh::git_call;
use crate::context::Context;
use crate::settings::Signal;

/// `gh` commands that reach no GitHub account: help, the version and shell
/// completion.
const GH_LOCAL: &[&str] = &["help", "version", "completion", "--version", "--help", "-h"];

/// `git push`'s short and long options that take a value.
const PUSH_SHORT: &str = "o";
const PUSH_LONG: &[&str] = &["push-option", "receive-pack", "exec", "repo"];

/// Whether the offers say the broker hands out GitHub tokens.
fn tokens_offered(ctx: &Context) -> bool {
    ctx.coverage.as_ref().is_some_and(|c| c.github)
}

fn owner_github(tool: &str) -> Match {
    Match {
        signal: Signal::OwnerGithub,
        subject: tool.to_owned(),
    }
}

/// `gh` with no token on the command (`token`: a non-empty `GH_TOKEN` or
/// `GITHUB_TOKEN`) and not through the wrapper of `warden setup github`.
/// `bare` is whether the program word has no `/`: only then does the shell
/// find `gh` through `PATH`, and so the wrapper. A `gh` run by path, such as
/// `/usr/local/bin/gh`, bypasses the wrapper.
pub(super) fn gh(args: &[String], token: bool, bare: bool, ctx: &Context) -> Option<Match> {
    if !tokens_offered(ctx) || token || (bare && ctx.gh_wrapped) {
        return None;
    }
    let mut words = args.iter().map(String::as_str);
    let local = match (words.next(), words.next()) {
        (Some(first), _) if GH_LOCAL.contains(&first) => true,
        // `gh auth token` is `token-read`'s, which reports it already.
        (None, _) | (Some("auth"), Some("token")) => true,
        _ => false,
    };
    (!local).then(|| owner_github("gh"))
}

/// Whether `url` is an HTTP(S) URL on github.com: an SSH remote is the
/// `owner-ssh-key` signal's.
fn is_github_https(url: &str) -> bool {
    Url::parse(url).is_ok_and(|u| {
        matches!(u.scheme(), "https" | "http")
            && u.host_str()
                .is_some_and(|host| host.eq_ignore_ascii_case("github.com"))
    })
}

/// `git push` to an HTTPS github.com URL whose first credential helper is not
/// warden's, in the checkout of the working directory. A push that `-C`,
/// `--git-dir` or `--work-tree` sends from another repository is not judged:
/// its configuration is not known.
pub(super) fn git_push(args: &[String], ctx: &Context) -> Option<Match> {
    if !tokens_offered(ctx) {
        return None;
    }
    let config = ctx.git.as_ref()?;
    let call = git_call(args);
    if call.subcommand != Some("push") || call.elsewhere {
        return None;
    }
    let mut positional = None;
    let mut repo_option = None;
    for item in args::read(call.rest, PUSH_SHORT, PUSH_LONG) {
        match item {
            Item::Positional(word) if positional.is_none() => positional = Some(word),
            Item::Opt { name, value } if name == "--repo" => repo_option = value,
            Item::Positional(_) | Item::Opt { .. } => {}
        }
    }
    // Git takes `--repo` only when no repository is named.
    config
        .push_urls(positional.or(repo_option))
        .iter()
        .any(|url| is_github_https(url) && !config.warden_helper_for(url, &call.settings))
        .then(|| owner_github("git"))
}
