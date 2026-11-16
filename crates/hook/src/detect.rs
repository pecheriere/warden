//! Decides whether a shell command goes around warden.
//!
//! [`check`] looks at every simple command in the text, reports the signals
//! that fire as [`Match`]es (a signal and a subject: a host, an origin or a
//! tool, never more of the command) and renders the message from them alone.

mod args;
mod github;
mod http;
mod secrets;
mod ssh;
#[cfg(test)]
mod tests;

use crate::context::Context;
use crate::message;
use crate::settings::{Setting, Settings, Signal};
use crate::shell::{self, SimpleCommand};

/// Every subject an `owner-ssh-key` match can have: the tool.
pub const OWNER_SSH_KEY_SUBJECTS: &[&str] = &[
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "git",
    "ssh-copy-id",
    "autossh",
    "mosh",
];

/// Every subject a `secret-store` match can have: the tool.
pub const SECRET_STORE_SUBJECTS: &[&str] = &["op", "security", "pass", "gopass", "bw"];

/// Every subject a `token-read` match can have: the kind of credential file
/// (`gh hosts.yml` has a space), or `gh` for `gh auth token`.
pub const TOKEN_READ_SUBJECTS: &[&str] = &[".netrc", "gh hosts.yml", ".env", "gh"];

/// Every subject an `owner-github` match can have: the tool.
pub const OWNER_GITHUB_SUBJECTS: &[&str] = &["gh", "git"];

/// One signal that fired, with what it is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    /// The signal.
    pub signal: Signal,
    /// The host, origin or tool the signal names: for `covered-ssh` the
    /// target's name from the offers; for `covered-api` and `uncovered-host`
    /// the host as written; for `owner-ssh-key`, `secret-store` and
    /// `token-read` the tool, or the kind of credential file; for
    /// `owner-github` the tool, `gh` or `git`. Never a path,
    /// a URL, a header or any other part of the command.
    pub subject: String,
}

/// What the hook decides about a command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The strongest setting among the matches; `Off` when there are none.
    pub setting: Setting,
    /// The signals that fired, whose setting is not `Off`, without repeats.
    pub matches: Vec<Match>,
    /// What to tell the agent; empty when there are no matches.
    pub message: String,
    /// A note about invalid settings. `check` leaves it `None`: the caller
    /// reads the settings table and appends the note as its own line.
    pub settings_note: Option<String>,
}

/// The value of the `NAME=` word among the wrapper words `effective_argv`
/// removed.
fn wrapper_value(command: &SimpleCommand, effective: &[String], name: &str) -> Option<String> {
    let skipped = command.argv.len().saturating_sub(effective.len());
    command.argv[..skipped]
        .iter()
        .rev()
        .filter_map(|word| word.split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_owned()))
}

/// The value of the environment variable `name` for the command: its own
/// assignments, else those of an `env` wrapper.
fn env_value(command: &SimpleCommand, effective: &[String], name: &str) -> Option<String> {
    command
        .env
        .iter()
        .rev()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
        .or_else(|| wrapper_value(command, effective, name))
}

fn matches_of(command: &SimpleCommand, ctx: &Context) -> Vec<Match> {
    let words = shell::effective_argv(command);
    let Some((first, rest)) = words.split_first() else {
        return Vec::new();
    };
    let program = args::program_name(first);
    let socket = env_value(command, words, "SSH_AUTH_SOCK");
    let socket = socket.as_deref();
    // `warden ssh` and `warden http` are no match: the program is `warden`.
    let mut found = match program {
        "ssh" | "scp" | "sftp" | "ssh-copy-id" | "autossh" | "mosh" => {
            ssh::ssh_like(program, rest, socket, ctx)
        }
        "rsync" => {
            let rsh = env_value(command, words, "RSYNC_RSH");
            ssh::rsync(rest, socket, rsh.as_deref(), ctx)
        }
        "git" => {
            let ssh_command = env_value(command, words, "GIT_SSH_COMMAND");
            let mut found = ssh::git(rest, socket, ssh_command.as_deref(), ctx);
            found.extend(github::git_push(rest, ctx));
            found
        }
        "gh" => {
            let token = ["GH_TOKEN", "GITHUB_TOKEN"]
                .iter()
                .any(|name| env_value(command, words, name).is_some_and(|v| !v.is_empty()));
            github::gh(rest, token, !first.contains('/'), ctx)
                .into_iter()
                .collect()
        }
        "curl" | "wget" | "http" | "https" | "xh" | "xhs" => http::detect(program, rest, ctx),
        _ => Vec::new(),
    };
    found.extend(secrets::secret_store_use(program, rest));
    found.extend(secrets::token_read_use(program, rest));
    found
}

/// Checks `command` against what warden covers and the `settings`. It makes
/// no I/O besides the context's small-file reader, and never panics.
#[must_use]
pub fn check(command: &str, ctx: &Context, settings: &Settings) -> Verdict {
    let mut matches: Vec<Match> = Vec::new();
    for simple in shell::simple_commands(command) {
        for found in matches_of(&simple, ctx) {
            if settings.get(found.signal) != Setting::Off && !matches.contains(&found) {
                matches.push(found);
            }
        }
    }
    let setting = matches
        .iter()
        .map(|found| settings.get(found.signal))
        .max()
        .unwrap_or(Setting::Off);
    let message = message::render(&matches, ctx.coverage.as_ref());
    Verdict {
        setting,
        matches,
        message,
        settings_note: None,
    }
}
