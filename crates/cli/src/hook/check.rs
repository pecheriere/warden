//! `warden hook check`: the command a Claude Code `PreToolUse` hook runs on
//! every shell command, to flag the ways around warden.
//!
//! It makes no network call and never fails: whatever goes wrong, it prints
//! nothing and the caller exits 0, so the hook cannot stop work by breaking.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde_json::Value;
use warden_agent_hook::context::{Context, Coverage, SshAliases};
use warden_agent_hook::detect;

use super::cache;
use super::claude::{self, Event};
use super::files::Reader;
use super::include::Includes;
use super::settings;
use crate::agent;

/// What `parse_event` accepts, plus one byte so that it can see an event that
/// is over the cap.
const STDIN_LIMIT: u64 = 65_536 + 1;

/// Reads one event from stdin and prints the answer, if there is one.
pub fn run() {
    let mut stdin = Vec::new();
    if std::io::stdin()
        .lock()
        .take(STDIN_LIMIT)
        .read_to_end(&mut stdin)
        .is_err()
    {
        return;
    }
    if let Some(answer) = respond(&stdin, SystemTime::now()) {
        // With the output closed there is nobody to tell.
        let _ = writeln!(std::io::stdout().lock(), "{answer}");
    }
}

/// The answer for the event in `stdin`, `None` when there is nothing to say.
fn respond(stdin: &[u8], now: SystemTime) -> Option<Value> {
    let event = claude::parse_event(stdin)?;
    let coverage = cache::read(now).map(|offers| Coverage::from(&offers));
    let home = dirs::home_dir();
    let context = build_context(&event, coverage, home.as_deref(), agent::socket_dir());
    let (settings, note) = settings::load();
    let verdict = detect::check(&event.command, &context, &settings);
    claude::answer(&verdict, note.as_deref(), event.permission_mode.as_deref())
}

/// What the detection library looks at besides the command.
fn build_context(
    event: &Event,
    coverage: Option<Coverage>,
    home: Option<&Path>,
    socket_dir: PathBuf,
) -> Context {
    let reader = Reader::new(event.cwd.as_deref());
    let aliases = home.map_or_else(SshAliases::default, |home| {
        let includes = Includes::new(home);
        let include = |argument: &str| includes.text(argument, &|p| reader.read(p));
        reader
            .read(&home.join(".ssh/config"))
            .map_or_else(SshAliases::default, |text| {
                SshAliases::parse(&text, &include)
            })
    });
    Context {
        coverage,
        aliases,
        warden_socket_dir_real: real_dir(&socket_dir),
        warden_socket_dir: socket_dir,
        read_small_file: Box::new(move |path: &Path| reader.read(path)),
    }
}

/// `dir` with links resolved: its parent's real path joined with its name,
/// because the directory itself may not exist yet.
fn real_dir(dir: &Path) -> Option<PathBuf> {
    let real_parent = std::fs::canonicalize(dir.parent()?).ok()?;
    Some(real_parent.join(dir.file_name()?))
}

#[cfg(test)]
mod tests;
