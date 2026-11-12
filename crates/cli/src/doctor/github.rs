//! The doctor check of GitHub tokens: if git takes its GitHub credential from
//! warden, that it takes it from this warden alone, and whether this agent has a
//! grant.
//!
//! Git asks one list of helpers for a `https://github.com` URL: the generic
//! `credential.helper` values and those of every `credential.<url>.helper` whose
//! URL matches, in the order git reads its configuration, an empty value dropping
//! all before it (gitcredentials(7)). Git matches with the URL's path, and drops the
//! path only afterwards unless `credential.useHttpPath` is set, so an entry for one
//! repository or owner is asked too, and sent `store` with the token. Which entries
//! apply is left to git itself; when git cannot say, the check could not run.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use warden_broker_proto::doctor::Check;
use warden_broker_proto::{GrantAccess, GrantView};

use super::FIX_EARLIER;
use crate::client::CallError;
use crate::setup_github::{USE_HTTP_PATH_KEY, helper_program};

/// The check's name.
pub const NAME: &str = "github.token";

/// The host git asks about.
const GITHUB_HOST: &str = "github.com";

/// What the owner does when git's configuration could not be read.
const READ_GIT: &str = "Check that `git config --list` runs and reads the configuration, then \
                        run doctor again.";

/// What the owner does when git's setup for warden is missing or wrong.
const SETUP: &str = "Run `warden setup github`.";

/// One credential helper entry of git's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Helper {
    /// Its key, such as `credential.helper` or `credential.https://github.com.helper`.
    pub key: String,
    /// Its value: the helper, or empty to drop the helpers before it.
    pub value: String,
}

/// How git is set up to get GitHub credentials.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GithubSetup {
    /// The helpers git asks for some `https://github.com` URL, in order.
    pub helpers: Vec<Helper>,
    /// This program's path as `warden setup github` writes it, if it can tell.
    pub this_program: Option<String>,
    /// Whether `credential.https://github.com.useHttpPath` is true, so that git sends
    /// the repository to the helper.
    pub use_http_path: bool,
}

/// Run `git` with `args`, set up by `configure`, with `stdin` as its input. `None`
/// if it could not run.
fn git(
    configure: &impl Fn(&mut Command),
    args: &[&str],
    stdin: Option<&[u8]>,
) -> Option<std::process::Output> {
    let mut cmd = Command::new("git");
    configure(&mut cmd);
    let mut child = cmd
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let Some(input) = stdin {
        child.stdin.take()?.write_all(input).ok()?;
    }
    child.wait_with_output().ok()
}

/// The fixed reason for git failing to read its configuration.
fn unreadable(code: Option<i32>) -> String {
    match code {
        Some(code) => format!("git could not read its configuration (exit {code})"),
        None => "git could not read its configuration (stopped by a signal)".to_owned(),
    }
}

/// Every `credential.*helper` entry of git's configuration, in the order git reads
/// them. Only git's "nothing matches" (exit 1) means none.
fn helper_entries(configure: &impl Fn(&mut Command)) -> Result<Vec<Helper>, String> {
    let args = [
        "config",
        "--null",
        "--get-regexp",
        r"^credential\.(.*\.)?helper$",
    ];
    let out = git(configure, &args, None).ok_or_else(|| "git could not be run".to_owned())?;
    match out.status.code() {
        Some(0) => {}
        Some(1) => return Ok(Vec::new()),
        code => return Err(unreadable(code)),
    }
    Ok(out
        .stdout
        .split(|b| *b == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let entry = String::from_utf8_lossy(entry);
            let (key, value) = entry.split_once('\n').unwrap_or((&entry, ""));
            Helper {
                key: key.to_owned(),
                value: value.to_owned(),
            }
        })
        .collect())
}

/// The section to give git for `pattern`, and the `https://github.com` URL that
/// `pattern` matches if any does: the pattern's own user and path on github.com. A
/// pattern without a scheme is a partial URL, which matches any scheme; it is
/// written as an https one.
fn probe(pattern: &str) -> (String, String) {
    let (section, rest) = match pattern.split_once("://") {
        Some((_, rest)) => (pattern.to_owned(), rest),
        None => (format!("https://{pattern}"), pattern),
    };
    let (authority, path) = rest.find('/').map_or((rest, ""), |at| rest.split_at(at));
    let user = authority
        .rsplit_once('@')
        .map_or_else(String::new, |(user, _)| format!("{user}@"));
    (section, format!("https://{user}{GITHUB_HOST}{path}"))
}

/// Whether git applies `credential.<pattern>.*` to some `https://github.com` URL,
/// as git's own URL matching says.
fn pattern_matches(pattern: &str, configure: &impl Fn(&mut Command)) -> Result<bool, String> {
    let (section, url) = probe(pattern);
    let section = section.replace('\\', r"\\").replace('"', "\\\"");
    let config = format!("[credential \"{section}\"]\n\thelper = x\n");
    let args = [
        "config",
        "--file",
        "-",
        "--get-urlmatch",
        "credential.helper",
        &url,
    ];
    let out = git(configure, &args, Some(config.as_bytes()))
        .ok_or_else(|| "git could not be run".to_owned())?;
    match out.status.code() {
        Some(0) => Ok(out.stdout == b"x\n"),
        Some(1) => Ok(false),
        code => Err(unreadable(code)),
    }
}

/// The entries git asks for some GitHub URL, in order: the generic ones and those
/// whose URL `matches`.
fn github_helpers(
    entries: Vec<Helper>,
    matches: impl Fn(&str) -> Result<bool, String>,
) -> Result<Vec<Helper>, String> {
    let mut helpers = Vec::new();
    for helper in entries {
        let pattern = helper
            .key
            .strip_prefix("credential.")
            .and_then(|rest| rest.strip_suffix(".helper"));
        let applies = match pattern {
            _ if helper.key == "credential.helper" => true,
            Some(pattern) => matches(pattern)?,
            None => false,
        };
        if applies {
            helpers.push(helper);
        }
    }
    Ok(helpers)
}

/// Whether git reads [`USE_HTTP_PATH_KEY`] as true for `https://github.com`, the way
/// it resolves the setting: a generic value counts, and a `github.com` one wins.
fn use_http_path(configure: &impl Fn(&mut Command)) -> Result<bool, String> {
    let args = [
        "config",
        "--type=bool",
        "--get-urlmatch",
        "credential.useHttpPath",
        "https://github.com",
    ];
    let out = git(configure, &args, None).ok_or_else(|| "git could not be run".to_owned())?;
    match out.status.code() {
        Some(0) => Ok(out.stdout == b"true\n"),
        // 1: the key is not set.
        Some(1) => Ok(false),
        code => Err(unreadable(code)),
    }
}

/// How git is set up here, as `configure` points it.
fn setup_with(configure: impl Fn(&mut Command)) -> Result<GithubSetup, String> {
    let entries = helper_entries(&configure)?;
    Ok(GithubSetup {
        helpers: github_helpers(entries, |pattern| pattern_matches(pattern, &configure))?,
        this_program: crate::setup_github::this_program(),
        use_http_path: use_http_path(&configure)?,
    })
}

/// How git is set up here, or why that could not be told.
pub fn live_setup() -> Result<GithubSetup, String> {
    setup_with(|_| {})
}

/// Whether `grants` hold a GitHub token grant.
pub fn has_grant(grants: &[GrantView]) -> bool {
    grants
        .iter()
        .any(|grant| matches!(grant.access, GrantAccess::GithubToken(_)))
}

/// What a helper value is to this check.
#[derive(Debug, PartialEq, Eq)]
enum Kind {
    /// This program.
    This,
    /// Another program called `warden`.
    OtherWarden,
    /// A value naming warden in a form this check cannot read.
    Unreadable,
    /// Anything else, an empty value included.
    Other,
}

/// Whether two paths name the same program: the same text, or the same file once
/// symlinks are resolved. A helper written by `warden setup github` names the path
/// warden was started from, which doctor may not have been.
fn same_program(a: &str, b: &str) -> bool {
    a == b
        || matches!(
            (std::fs::canonicalize(a), std::fs::canonicalize(b)),
            (Ok(a), Ok(b)) if a == b
        )
}

fn kind(value: &str, this_program: Option<&str>) -> Kind {
    match helper_program(value) {
        Some(program) if this_program.is_some_and(|this| same_program(&program, this)) => {
            Kind::This
        }
        Some(program)
            if Path::new(&program)
                .file_name()
                .is_some_and(|n| n == "warden") =>
        {
            Kind::OtherWarden
        }
        None if value.contains("warden") => Kind::Unreadable,
        Some(_) | None => Kind::Other,
    }
}

/// Whether git takes its GitHub credential from a warden, among others or not.
pub fn through_warden(setup: &GithubSetup) -> bool {
    setup.helpers.iter().any(|helper| {
        matches!(
            kind(&helper.value, setup.this_program.as_deref()),
            Kind::This | Kind::OtherWarden
        )
    })
}

/// The failure for `used`, the helpers that count, when they are not this warden
/// alone.
fn not_alone(used: &[Helper], this: Option<&str>) -> Check {
    if let [only] = used
        && kind(&only.value, this) == Kind::OtherWarden
    {
        return Check::fail(
            NAME,
            format!("{} runs another warden than this one.", only.key),
            SETUP,
        );
    }
    let others: Vec<&str> = used
        .iter()
        .filter(|helper| kind(&helper.value, this) != Kind::This)
        .map(|helper| helper.key.as_str())
        .collect();
    let detail = if others.is_empty() {
        "Git asks no credential helper for some https://github.com URLs: an empty value comes \
         after warden's."
            .to_owned()
    } else {
        format!(
            "Git asks other credential helpers for https://github.com URLs as well as warden's, \
             and hands them the token to store: {}.",
            others.join(", ")
        )
    };
    Check::fail(NAME, detail, SETUP)
}

/// The check: `setup` is how git asks for GitHub credentials, or why that could not
/// be told; `grant` is whether this agent has an active grant, `None` when the
/// broker was not asked.
pub fn check(setup: &Result<GithubSetup, String>, grant: Option<Result<bool, CallError>>) -> Check {
    let setup = match setup {
        Ok(setup) => setup,
        Err(reason) => return Check::could_not_check(NAME, reason.clone(), READ_GIT),
    };
    let this = setup.this_program.as_deref();
    if let Some(odd) = setup
        .helpers
        .iter()
        .find(|helper| kind(&helper.value, this) == Kind::Unreadable)
    {
        return Check::could_not_check(
            NAME,
            format!(
                "{} names warden in a form this check cannot read, so it cannot tell which \
                 helpers git asks.",
                odd.key
            ),
            "Run `warden setup github`.",
        );
    }
    if !through_warden(setup) {
        return Check::pass(
            NAME,
            "Git does not take GitHub credentials from warden here; `warden setup github` would \
             set that up.",
        );
    }
    // An empty value drops the helpers before it, so what counts follows the last.
    let helpers = &setup.helpers;
    let used = helpers
        .iter()
        .rposition(|helper| helper.value.is_empty())
        .map_or(&helpers[..], |last| &helpers[last + 1..]);
    if !matches!(used, [only] if kind(&only.value, this) == Kind::This) {
        return not_alone(used, this);
    }
    if !setup.use_http_path {
        return Check::fail(
            NAME,
            format!("git does not send the repository to warden ({USE_HTTP_PATH_KEY} is not true)"),
            SETUP,
        );
    }
    match grant {
        None => Check::could_not_check(
            NAME,
            "Not checked: the credential is not available.",
            FIX_EARLIER,
        ),
        Some(Err(CallError::Unavailable(reason) | CallError::CallStopped(reason))) => {
            Check::could_not_check(
                NAME,
                reason,
                "Get the broker answering, then run doctor again. git and gh get no GitHub \
                 token until it does.",
            )
        }
        Some(Err(e)) => Check::fail(
            NAME,
            e.to_string(),
            "Ask the owner whether GitHub tokens are configured on the broker.",
        ),
        Some(Ok(true)) => Check::pass(
            NAME,
            "Git takes GitHub tokens from warden, and this agent has an active grant.",
        ),
        Some(Ok(false)) => Check::pass(
            NAME,
            "Git takes GitHub tokens from warden. This agent has no active grant yet: the first \
             git or gh call to GitHub asks the owner for one and waits.",
        ),
    }
}

#[cfg(test)]
mod tests;
