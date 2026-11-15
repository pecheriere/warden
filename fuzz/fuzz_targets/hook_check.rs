//! The agent plugin's hook check. Its input is a command an agent chose, so it
//! is untrusted: `check` must never panic, and must never repeat the command
//! back in its message, which reaches the agent and its logs.
//!
//! The property: a command without matches gets an empty message (a); the
//! message is exactly the rendering of the matches for the coverage, so it
//! depends on the command only through them (b); and every match subject is
//! host- or tool-shaped, so no path, URL, header or value reaches the message
//! (c).
//!
//! Input: the bytes of the command, read as lossy UTF-8.

#![no_main]

use std::path::{Path, PathBuf};

use libfuzzer_sys::fuzz_target;
use warden_agent_hook::context::{ApiCover, Context, Coverage, SshAliases, SshCover};
use warden_agent_hook::detect::check;
use warden_agent_hook::message::render;
use warden_agent_hook::settings::Settings;

/// What warden offers: one SSH target with a host, one listed by name only, and
/// one API secret.
fn coverage() -> Coverage {
    Coverage {
        ssh: vec![
            SshCover {
                name: "switch-01".to_owned(),
                host: Some("switch-01.example.internal".to_owned()),
                users: vec!["build-agent".to_owned()],
            },
            SshCover {
                name: "lab-pi".to_owned(),
                host: None,
                users: Vec::new(),
            },
        ],
        api: vec![ApiCover {
            name: "home-api".to_owned(),
            origin: Some("https://home-api.example.internal".to_owned()),
        }],
        github: false,
    }
}

fn context() -> Context {
    let aliases = SshAliases::parse(
        "Host lab\n  HostName switch-01.example.internal\n",
        &|_: &str| None,
    );
    Context {
        coverage: Some(coverage()),
        aliases,
        warden_socket_dir: PathBuf::from("/tmp/warden-501"),
        read_small_file: Box::new(|_: &Path| None),
        github_helper: None,
    }
}

/// A subject names a host or a tool: ASCII letters, digits, `.`, `_`, `-`, and
/// `[`, `]`, `:` for IPv6 addresses and ports. No path, URL, header or value.
fn is_name_shaped(subject: &str) -> bool {
    !subject.is_empty()
        && subject.len() <= 253
        && subject
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '[' | ']' | ':'))
}

fuzz_target!(|data: &[u8]| {
    let command = String::from_utf8_lossy(data);
    let ctx = context();
    let verdict = check(&command, &ctx, &Settings::default());

    if verdict.matches.is_empty() {
        assert!(
            verdict.message.is_empty(),
            "hook_check: property (a) failed: a message without matches"
        );
        return;
    }
    assert!(
        verdict.message == render(&verdict.matches, ctx.coverage.as_ref()),
        "hook_check: property (b) failed: the message depends on more than the matches"
    );
    assert!(
        verdict.matches.iter().all(|m| is_name_shaped(&m.subject)),
        "hook_check: property (c) failed: a subject is not host- or tool-shaped"
    );
});
