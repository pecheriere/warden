//! The agent plugin's hook check. Its input is a command an agent chose, so it
//! is untrusted: `check` must never panic, and must never repeat the command
//! back in its message, which reaches the agent and its logs.
//!
//! The property: a command without matches gets an empty message (a); and
//! every match subject is checked for its own signal (c), so no path, header
//! or value reaches the message: a covered subject is a name warden offers, a
//! tool or credential subject is in the closed set the library exports, and an
//! uncovered host is host-shaped and occurs in the command as a host.
//! Clause (c) for an uncovered host guards shape and provenance only: a
//! host-shaped word cannot be told from a host-shaped secret, so that
//! "only from a scheme-explicit URL host, `--url`, a destination or a jump
//! operand" holds by construction in `detect/http.rs` and `detect/ssh.rs`, not
//! by this property.
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

/// A host as the URL parser writes it, which can differ from the text: an IPv4
/// address in dotted decimal (`11` becomes `0.0.0.11`), an IPv6 address in
/// brackets, or an internationalised name in punycode (a label with `xn--`).
/// Such a subject is digits or a name's encoding, so it holds no secret.
fn is_normalised_host(subject: &str) -> bool {
    let digits_and_dots = subject.chars().all(|c| c.is_ascii_digit() || c == '.');
    let ipv6 = subject
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .is_some_and(|inner| {
            inner
                .chars()
                .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '.'))
        });
    let punycode = subject.split('.').any(|label| label.starts_with("xn--"));
    digits_and_dots || ipv6 || punycode
}

/// Whether `host` occurs in `command` right after `:/` (as in `://`) or `@`, as a whole
/// word, as the end of a word (an option value written against its flag, as in
/// `-Jhost`), or as the host part of a `host:path` word. Words end at whitespace
/// and at the shell characters that glue a word to its neighbour (redirections,
/// pipes, `=`, `,`, `$`, braces). The shell joins quotes and substitutions
/// into one word, so the text is also read with quotes, backticks, backslashes,
/// `$(` and `)` and control characters removed, and line continuations joined.
fn occurs_as_host(command: &str, host: &str) -> bool {
    let joined: String = command
        .replace("\\\n", "")
        .chars()
        .filter(|c| !matches!(c, '\'' | '"' | '`' | '\\'))
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect();
    let flat: String = joined
        .chars()
        .filter(|c| !matches!(c, '$' | '(' | ')'))
        .collect();
    [command, joined.as_str(), flat.as_str()]
        .into_iter()
        .any(|text| occurs_in(text, host))
}

/// Where a word ends: whitespace and the shell characters that glue a word to
/// its neighbour (redirections, pipes, quotes, `=`, `,`, `$`, braces).
fn is_word_end(c: char) -> bool {
    c.is_whitespace() || "<>|&;()'\"`\\=,${}".contains(c)
}

/// Whether `host` is the host `url::Url` parses from a whitespace-separated word
/// of `command` (split as in [`occurs_in`]), read as written or with `http://` before it. The parser
/// percent-decodes and lowercases, so `http://%73ecret.example.org/` has the
/// host `secret.example.org`, which does not occur in the text.
fn is_parsed_host(command: &str, host: &str) -> bool {
    command.split(is_word_end).any(|word| {
        [word.to_owned(), format!("http://{word}")]
            .iter()
            .filter_map(|text| url::Url::parse(text).ok())
            .any(|url| url.host_str() == Some(host))
    })
}

fn occurs_in(command: &str, host: &str) -> bool {
    let command = command.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    [":/", "://", ":///"]
        .iter()
        .any(|p| command.contains(&format!("{p}{host}")))
        || command.contains(&format!("@{host}"))
        || command.split(is_word_end).any(|word| {
            word.ends_with(&host)
                || word
                    .split_once(':')
                    .is_some_and(|(h, _)| h.ends_with(&host))
        })
}

/// (A command with a non-ASCII character only has to give a host-shaped
/// subject: the URL parser maps such text, as in `\u{01c9}` to `lj`.)
/// Whether `subject` is right for `signal`; `false` also for a signal no
/// check produces.
fn subject_is_valid(signal: Signal, subject: &str, command: &str, ctx: &Context) -> bool {
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
        Signal::UncoveredHost => {
            is_host_shaped(subject)
                && (is_normalised_host(subject)
                    || !command.is_ascii()
                    || occurs_as_host(command, subject)
                    || is_parsed_host(command, subject))
        }
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
            subject_is_valid(found.signal, &found.subject, &command, &ctx),
            "hook_check: property (c) failed for signal {}",
            found.signal.key()
        );
    }
});
