//! SSH signals: `covered-ssh`, `uncovered-host` for `ssh`, and
//! `owner-ssh-key`.

use super::Match;
use super::args::{self, Item, is_loopback, is_plain_host};
use crate::context::Context;
use crate::settings::Signal;

/// The short options of each tool that take a value.
const SSH_SHORT: &str = "BbcDEeFIiJLlmOopQRSWw";
const SCP_SHORT: &str = "cDFiJloPSX";
const SFTP_SHORT: &str = "BbcDFiJloPRSsX";
const RSYNC_SHORT: &str = "eBTMf";
const RSYNC_LONG: &[&str] = &[
    "rsh",
    "exclude",
    "include",
    "exclude-from",
    "include-from",
    "filter",
    "port",
    "rsync-path",
    "bwlimit",
    "partial-dir",
    "temp-dir",
    "backup-dir",
    "suffix",
    "files-from",
    "log-file",
    "password-file",
    "timeout",
    "max-size",
    "min-size",
    "chmod",
    "chown",
    "compare-dest",
    "copy-dest",
    "link-dest",
    "out-format",
    "info",
    "debug",
    "block-size",
    "address",
    "protocol",
];

/// What the options of an `ssh`-like command say about keys and routes.
#[derive(Default)]
struct SshOptions<'a> {
    /// `-i`, or an `IdentityFile` that is not `none`.
    identity: bool,
    /// The last `-F` file.
    config: Option<&'a str>,
    /// The last `-o IdentityAgent`.
    agent: Option<&'a str>,
    /// The words that are not options.
    operands: Vec<&'a str>,
}

impl<'a> SshOptions<'a> {
    fn read(args: &'a [String], short_values: &str) -> Self {
        let mut options = Self::default();
        for item in args::read(args, short_values, &[]) {
            match item {
                Item::Positional(word) => options.operands.push(word),
                Item::Opt { name, value } => match (name.as_str(), value) {
                    ("-i", _) => options.identity = true,
                    ("-F", value) => options.config = value,
                    ("-o", Some(setting)) => options.setting(setting),
                    _ => {}
                },
            }
        }
        options
    }

    /// One `-o Key=value` or `-o "Key value"`.
    fn setting(&mut self, text: &'a str) {
        let split = text.find(|c: char| c == '=' || c.is_whitespace());
        let (key, value) = match split {
            Some(at) => (
                &text[..at],
                text[at..]
                    .trim_start_matches(|c: char| c == '=' || c.is_whitespace())
                    .trim()
                    .trim_matches('"'),
            ),
            None => (text, ""),
        };
        if key.eq_ignore_ascii_case("IdentityFile") && !value.is_empty() && value != "none" {
            self.identity = true;
        } else if key.eq_ignore_ascii_case("IdentityAgent") {
            self.agent = Some(value);
        }
    }
}

/// The host of an `ssh://` style URL.
fn url_host(word: &str) -> Option<&str> {
    let (scheme, rest) = word.split_once("://")?;
    if !matches!(scheme, "ssh" | "git+ssh" | "ssh+git") {
        return None;
    }
    let authority = rest.split('/').next()?;
    let host_port = authority.rsplit('@').next()?;
    let host = host_port.split(':').next()?;
    is_plain_host(host).then_some(host)
}

/// The host of a destination word: `host`, `user@host`, `host:path` or an
/// `ssh://` URL.
fn destination_host(word: &str) -> Option<&str> {
    if word.contains("://") {
        return url_host(word);
    }
    let head = word.split(':').next()?;
    let host = head.rsplit('@').next()?;
    is_plain_host(host).then_some(host)
}

/// The host of a word that names a remote file, as `scp` and `rsync` read it:
/// `host:path`, `user@host:path` or an `ssh://` URL.
fn remote_operand(word: &str) -> Option<&str> {
    if word.contains("://") {
        return url_host(word);
    }
    let (head, path) = word.split_once(':')?;
    if head.len() < 2 || head.contains('/') || path.starts_with(':') {
        return None;
    }
    is_plain_host(head.rsplit('@').next()?)
        .then(|| head.rsplit('@').next())
        .flatten()
}

/// The agent socket the command would use: its own `-o IdentityAgent`, else
/// the environment's `SSH_AUTH_SOCK`.
fn agent_of<'a>(options: &SshOptions<'a>, env_sock: Option<&'a str>) -> Option<&'a str> {
    options.agent.or(env_sock.filter(|s| !s.is_empty()))
}

/// Whether `host` is reached through warden: with a warden agent socket, or
/// with a `-F` file `warden ssh-config` wrote for that host.
fn routed(ctx: &Context, options: &SshOptions<'_>, env_sock: Option<&str>, host: &str) -> bool {
    agent_of(options, env_sock).is_some_and(|a| ctx.is_warden_socket(a))
        || options
            .config
            .is_some_and(|file| ctx.is_warden_ssh_config(file, host))
}

/// `owner-ssh-key`: an explicit key, or an agent that is not warden's. The
/// environment's agent counts only when no warden config replaces it. An
/// explicit key counts even on a warden route: it adds the owner's key to it.
fn owner_key(
    tool: &str,
    options: &SshOptions<'_>,
    env_sock: Option<&str>,
    hosts: &[&str],
    ctx: &Context,
    found: &mut Vec<Match>,
) {
    let env_sock = env_sock.filter(|s| !s.is_empty());
    let replaced_by_config = !hosts.is_empty()
        && hosts.iter().all(|host| {
            options
                .config
                .is_some_and(|file| ctx.is_warden_ssh_config(file, host))
        });
    let foreign_agent = if let Some(own) = options.agent {
        own != "none" && !ctx.is_warden_socket(own)
    } else {
        env_sock.is_some_and(|sock| !ctx.is_warden_socket(sock)) && !replaced_by_config
    };
    if options.identity || foreign_agent {
        found.push(Match {
            signal: Signal::OwnerSshKey,
            subject: tool.to_owned(),
        });
    }
}

/// `covered-ssh` for a covered host; else `uncovered-host` when `uncovered`
/// is true, the offers are known and the host is not the machine itself.
/// The subject of `covered-ssh` is the target's name, which the offers
/// give, so the message can name the exact `warden request`.
fn coverage_match(host: &str, uncovered: bool, ctx: &Context, found: &mut Vec<Match>) {
    let Some(coverage) = &ctx.coverage else {
        return;
    };
    if let Some(cover) = coverage.ssh_target_for(host, &ctx.aliases) {
        found.push(Match {
            signal: Signal::CoveredSsh,
            subject: cover.name.clone(),
        });
    } else if uncovered && !is_loopback(host) {
        found.push(Match {
            signal: Signal::UncoveredHost,
            subject: host.to_ascii_lowercase(),
        });
    }
}

/// Matches of `ssh`, `scp` and `sftp`.
pub(super) fn ssh_like(
    program: &str,
    args: &[String],
    env_sock: Option<&str>,
    ctx: &Context,
) -> Vec<Match> {
    let short = match program {
        "scp" => SCP_SHORT,
        "sftp" => SFTP_SHORT,
        _ => SSH_SHORT,
    };
    let options = SshOptions::read(args, short);
    let hosts: Vec<&str> = if program == "scp" {
        options
            .operands
            .iter()
            .filter_map(|word| remote_operand(word))
            .collect()
    } else {
        options
            .operands
            .first()
            .and_then(|word| destination_host(word))
            .into_iter()
            .collect()
    };
    let mut found = Vec::new();
    owner_key(program, &options, env_sock, &hosts, ctx, &mut found);
    for host in hosts {
        if !routed(ctx, &options, env_sock, host) {
            coverage_match(host, program == "ssh", ctx, &mut found);
        }
    }
    found
}

/// Matches of `rsync`: a `host:path` operand is SSH, and so is an `-e ssh`.
pub(super) fn rsync(args: &[String], env_sock: Option<&str>, ctx: &Context) -> Vec<Match> {
    let mut rsh: Option<&str> = None;
    let mut operands = Vec::new();
    for item in args::read(args, RSYNC_SHORT, RSYNC_LONG) {
        match item {
            Item::Positional(word) => operands.push(word),
            Item::Opt { name, value } if name == "-e" || name == "--rsh" => rsh = value,
            Item::Opt { .. } => {}
        }
    }
    // The remote shell's own options: its words after the program.
    let shell_words: Vec<String> = rsh
        .map(|text| text.split_whitespace().skip(1).map(str::to_owned).collect())
        .unwrap_or_default();
    let options = SshOptions::read(&shell_words, SSH_SHORT);
    let hosts: Vec<&str> = operands
        .iter()
        .filter_map(|word| remote_operand(word))
        .collect();
    let mut found = Vec::new();
    owner_key("rsync", &options, env_sock, &hosts, ctx, &mut found);
    for host in hosts {
        if !routed(ctx, &options, env_sock, host) {
            coverage_match(host, false, ctx, &mut found);
        }
    }
    found
}

/// Matches of `git` with an SSH remote in its words (`ssh://…` or
/// `user@host:path`).
pub(super) fn git(args: &[String], ctx: &Context) -> Vec<Match> {
    let mut found = Vec::new();
    for word in args {
        let host = if word.contains("://") {
            url_host(word)
        } else if word.contains('@') && !word.contains(char::is_whitespace) {
            remote_operand(word)
        } else {
            None
        };
        if let Some(host) = host {
            coverage_match(host, false, ctx, &mut found);
        }
    }
    found
}
