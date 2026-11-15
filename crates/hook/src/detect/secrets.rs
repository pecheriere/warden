//! `secret-store` and `token-read`: tools that read the owner's secrets.
//!
//! A subject is the tool's name or the kind of credential file, never a path
//! or an argument.

use super::Match;
use super::args::{self, Item};
use crate::settings::Signal;

/// `pass` and `gopass` subcommands that do not print a secret.
const PASS_QUIET: &[&str] = &[
    "ls",
    "list",
    "init",
    "git",
    "insert",
    "add",
    "edit",
    "generate",
    "rm",
    "delete",
    "remove",
    "mv",
    "rename",
    "cp",
    "copy",
    "find",
    "search",
    "grep",
    "version",
    "help",
    "sync",
    "config",
    "setup",
    "clone",
    "completion",
    "mounts",
    "audit",
    "env",
    "update",
    "templates",
    "fsck",
];
/// Programs that read a file named on their command line.
const READERS: &[&str] = &[
    "cat", "less", "more", "head", "tail", "bat", "grep", "rg", "sed", "awk", "jq", "source", ".",
];
/// Readers whose first word is a pattern or script, not a file.
const PATTERN_FIRST: &[&str] = &["grep", "rg", "sed", "awk", "jq"];

fn positionals<'a>(args: &'a [String], short_values: &str, long_values: &[&str]) -> Vec<&'a str> {
    args::read(args, short_values, long_values)
        .into_iter()
        .filter_map(|item| match item {
            Item::Positional(word) => Some(word),
            Item::Opt { .. } => None,
        })
        .collect()
}

fn secret_store(tool: &str) -> Match {
    Match {
        signal: Signal::SecretStore,
        subject: tool.to_owned(),
    }
}

/// `secret-store` matches of a program that reads a secret manager.
pub(super) fn secret_store_use(program: &str, args: &[String]) -> Option<Match> {
    match program {
        "op" => {
            let words = positionals(args, "", &["account", "config", "session", "cache"]);
            let reads = matches!(
                words.as_slice(),
                ["read" | "run" | "inject", ..] | ["item", "get", ..]
            );
            reads.then(|| secret_store("op"))
        }
        "security" => {
            let words = positionals(args, "aCcDjls", &[]);
            let finds = matches!(
                words.first().copied(),
                Some("find-generic-password" | "find-internet-password")
            );
            let prints = args::read(args, "aCcDjls", &[])
                .iter()
                .any(|item| matches!(item, Item::Opt { name, .. } if name == "-w" || name == "-g"));
            (finds && prints).then(|| secret_store("security"))
        }
        "pass" | "gopass" => {
            let words = positionals(args, "", &["clip", "password-store-dir"]);
            let reads = words
                .first()
                .is_some_and(|sub| *sub == "show" || !PASS_QUIET.contains(sub));
            reads.then(|| secret_store(program))
        }
        "bw" => {
            let words = positionals(args, "", &["session"]);
            (words.first() == Some(&"get")).then(|| secret_store("bw"))
        }
        _ => None,
    }
}

/// The kind of credential file `word` names, if it names one.
fn credential_kind(word: &str) -> Option<&'static str> {
    let parts: Vec<&str> = word.split('/').filter(|p| !p.is_empty()).collect();
    let (last, before) = parts.split_last()?;
    if *last == ".netrc" {
        return Some(".netrc");
    }
    if *last == "hosts.yml" && before.ends_with(&[".config", "gh"]) {
        return Some("gh hosts.yml");
    }
    let example = [".example", ".sample", ".template", ".dist"];
    let is_env = *last == ".env"
        || (last.starts_with(".env.") && !example.iter().any(|ext| last.ends_with(ext)));
    is_env.then_some(".env")
}

/// `token-read` matches of a program that reads a credential file, or of
/// `gh auth token`.
pub(super) fn token_read_use(program: &str, args: &[String]) -> Option<Match> {
    if program == "gh" {
        let words = positionals(args, "", &["hostname", "repo"]);
        return (words.starts_with(&["auth", "token"])).then(|| Match {
            signal: Signal::TokenRead,
            subject: "gh".to_owned(),
        });
    }
    if !READERS.contains(&program) {
        return None;
    }
    let mut words: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|w| !w.starts_with('-'))
        .collect();
    if PATTERN_FIRST.contains(&program) && words.len() >= 2 {
        words.remove(0);
    }
    words
        .into_iter()
        .find_map(credential_kind)
        .map(|kind| Match {
            signal: Signal::TokenRead,
            subject: kind.to_owned(),
        })
}
