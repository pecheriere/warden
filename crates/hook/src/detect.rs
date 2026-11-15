//! Decides whether a shell command goes around warden.
//!
//! [`check`] looks at every simple command in the text, reports the signals
//! that fire as [`Match`]es (a signal and a subject: a host, an origin or a
//! tool, never more of the command) and renders the message from them alone.

mod args;
mod http;
mod secrets;
mod ssh;
#[cfg(test)]
mod tests;

use crate::context::Context;
use crate::message;
use crate::settings::{Setting, Settings, Signal};
use crate::shell::{self, SimpleCommand};

/// One signal that fired, with what it is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    /// The signal.
    pub signal: Signal,
    /// The host, origin or tool the signal names: for `covered-ssh` the
    /// target's name from the offers; for `covered-api` and `uncovered-host`
    /// the host as written; for `owner-ssh-key`, `secret-store` and
    /// `token-read` the tool, or the kind of credential file. Never a path,
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

/// The word `SSH_AUTH_SOCK=…` among the wrapper words `effective_argv` removed.
fn wrapper_socket(command: &SimpleCommand, effective: &[String]) -> Option<String> {
    let skipped = command.argv.len().saturating_sub(effective.len());
    command.argv[..skipped]
        .iter()
        .find_map(|word| word.strip_prefix("SSH_AUTH_SOCK="))
        .map(str::to_owned)
}

fn matches_of(command: &SimpleCommand, ctx: &Context) -> Vec<Match> {
    let words = shell::effective_argv(command);
    let Some((first, rest)) = words.split_first() else {
        return Vec::new();
    };
    let program = args::program_name(first);
    if program == "warden" {
        return Vec::new();
    }
    let socket = command
        .env
        .iter()
        .find(|(name, _)| name == "SSH_AUTH_SOCK")
        .map(|(_, value)| value.clone())
        .or_else(|| wrapper_socket(command, words));
    let socket = socket.as_deref();
    let mut found = match program {
        "ssh" | "scp" | "sftp" => ssh::ssh_like(program, rest, socket, ctx),
        "rsync" => ssh::rsync(rest, socket, ctx),
        "git" => ssh::git(rest, ctx),
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
