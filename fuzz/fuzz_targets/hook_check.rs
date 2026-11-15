//! The agent plugin's hook check. Its input is a command an agent chose, so it
//! is untrusted: `check` must never panic, and must never repeat the command
//! back in its message, which reaches the agent and its logs.
//!
//! The property: a command without matches gets an empty message (a); and
//! every match subject is checked for its own signal (c), so no path, header
//! or value reaches the message: a covered subject is a name warden offers, a
//! tool or credential subject is in the closed set the library exports, and an
//! uncovered host is host-shaped.
//! Clause (c) for an uncovered host guards shape only: a host-shaped word cannot
//! be told from a host-shaped secret, so that its subject comes only from a
//! scheme-explicit URL host, `--url`, or an SSH destination or jump operand is
//! guaranteed by construction in `crates/hook/src/detect/http.rs` and
//! `detect/ssh.rs`, not by the fuzzer.
//! Failure messages name the signal only, never the command or a subject.
//!
//! Input: the bytes of the command, read as lossy UTF-8.

#![no_main]

use std::path::{Path, PathBuf};

use libfuzzer_sys::fuzz_target;
use warden_agent_hook::context::{ApiCover, Context, Coverage, SshAliases, SshCover};
use warden_agent_hook::detect::{
    OWNER_SSH_KEY_SUBJECTS, SECRET_STORE_SUBJECTS, TOKEN_READ_SUBJECTS, check,
};
use warden_agent_hook::settings::{Settings, Signal};

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
    }
}

/// A host: ASCII letters, digits, `.`, `_` (ssh aliases have it), `-`, `[`, `]`, `:`, at most 253 bytes.
fn is_host_shaped(subject: &str) -> bool {
    !subject.is_empty()
        && subject.len() <= 253
        && subject
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '[' | ']' | ':'))
}

/// Whether `subject` is right for `signal`; `false` also for a signal no
/// check produces.
fn subject_is_valid(signal: Signal, subject: &str, ctx: &Context) -> bool {
    match signal {
        Signal::CoveredSsh => ctx
            .coverage
            .as_ref()
            .is_some_and(|c| c.ssh.iter().any(|t| t.name == subject)),
        Signal::CoveredApi => ctx
            .coverage
            .as_ref()
            .is_some_and(|c| c.api_for(&format!("https://{subject}/")).is_some()),
        Signal::OwnerSshKey => OWNER_SSH_KEY_SUBJECTS.contains(&subject),
        Signal::SecretStore => SECRET_STORE_SUBJECTS.contains(&subject),
        Signal::TokenRead => TOKEN_READ_SUBJECTS.contains(&subject),
        Signal::UncoveredHost => is_host_shaped(subject),
        Signal::OwnerGithub => false,
    }
}

fuzz_target!(|data: &[u8]| {
    let command = String::from_utf8_lossy(data);
    let ctx = context();
    let verdict = check(&command, &ctx, &Settings::default());

    assert!(
        !verdict.matches.is_empty() || verdict.message.is_empty(),
        "hook_check: property (a) failed: a message without matches"
    );
    for found in &verdict.matches {
        assert!(
            subject_is_valid(found.signal, &found.subject, &ctx),
            "hook_check: property (c) failed for signal {}",
            found.signal.key()
        );
    }
});
