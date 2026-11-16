//! SSH signals: `covered-ssh`, `uncovered-host` for `ssh`, and
//! `owner-ssh-key`.

use super::Match;
use super::args::{self, Item, is_loopback, is_plain_host};
use crate::context::Context;
use crate::settings::Signal;
use crate::shell;

/// The short options of each tool that take a value.
const SSH_SHORT: &str = "BbcDEeFIiJLlmOopQRSWw";
/// `ssh-copy-id`'s options that take a value.
const SSH_COPY_ID_SHORT: &str = "iopt";
/// `autossh`'s own `-M` and the `ssh` options it passes on.
const AUTOSSH_SHORT: &str = "BbcDEeFIiJLlMmOopQRSWw";
/// `mosh`'s short and long options that take a value (`--ssh` is read as an
/// `ssh` command).
const MOSH_SHORT: &str = "p";
const MOSH_LONG: &[&str] = &[
    "ssh",
    "server",
    "predict",
    "family",
    "port",
    "bind-server",
    "experimental-remote-ip",
    "client",
];
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
    config: Option<String>,
    /// The last `-o IdentityAgent`.
    agent: Option<String>,
    /// `mosh`'s `--ssh` command.
    shell_command: Option<String>,
    /// The `-J` and `ProxyJump` values, as written.
    jumps: Vec<String>,
    /// The words that are not options.
    operands: Vec<&'a str>,
}

impl<'a> SshOptions<'a> {
    fn read(args: &'a [String], short_values: &str, long_values: &[&str]) -> Self {
        let mut options = Self::default();
        for item in args::read(args, short_values, long_values) {
            match item {
                Item::Positional(word) => options.operands.push(word),
                Item::Opt { name, value } => match (name.as_str(), value) {
                    ("-i", _) => options.identity = true,
                    ("-F", value) => options.config = value.map(str::to_owned),
                    ("-J", Some(jump)) => options.jumps.push(jump.to_owned()),
                    ("--ssh", value) => options.shell_command = value.map(str::to_owned),
                    ("-o", Some(setting)) => options.setting(setting),
                    _ => {}
                },
            }
        }
        options
    }

    /// One `-o Key=value` or `-o "Key value"`.
    fn setting(&mut self, text: &str) {
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
            self.agent = Some(value.to_owned());
        } else if key.eq_ignore_ascii_case("ProxyJump") {
            self.jumps.push(value.to_owned());
        }
    }

    /// Adds what a remote-shell command string (`rsync -e`, `GIT_SSH_COMMAND`,
    /// `mosh --ssh`) says, when it runs `ssh`: the text is tokenized as a
    /// script, once. Its own `SSH_AUTH_SOCK=` counts as its agent.
    fn merge_command(&mut self, text: &str) {
        for simple in shell::simple_commands(text) {
            let words = shell::effective_argv(&simple);
            let Some((program, rest)) = words.split_first() else {
                continue;
            };
            if args::program_name(program) != "ssh" {
                continue;
            }
            let nested = SshOptions::read(rest, SSH_SHORT, &[]);
            self.identity |= nested.identity;
            if nested.config.is_some() {
                self.config = nested.config;
            }
            let own_sock = simple
                .env
                .iter()
                .rev()
                .find(|(name, _)| name == "SSH_AUTH_SOCK")
                .map(|(_, value)| value.clone());
            if let Some(agent) = nested.agent.or(own_sock) {
                self.agent = Some(agent);
            }
            self.jumps.extend(nested.jumps);
            return;
        }
    }

    /// The hosts of the jump entries (`user@host:port,ssh://host`).
    fn jump_hosts(&self) -> Vec<String> {
        self.jumps
            .iter()
            .flat_map(|jump| jump.split(','))
            .map(str::trim)
            .filter(|entry| *entry != "none")
            .filter_map(destination_host)
            .map(str::to_owned)
            .collect()
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
fn agent_of<'a>(options: &'a SshOptions<'_>, env_sock: Option<&'a str>) -> Option<&'a str> {
    options
        .agent
        .as_deref()
        .or(env_sock.filter(|s| !s.is_empty()))
}

/// Whether `host` is reached through warden: with a warden agent socket, or
/// with a `-F` file `warden ssh-config` wrote for that host.
fn routed(ctx: &Context, options: &SshOptions<'_>, env_sock: Option<&str>, host: &str) -> bool {
    agent_of(options, env_sock).is_some_and(|a| ctx.is_warden_socket(a))
        || options
            .config
            .as_deref()
            .is_some_and(|file| ctx.is_warden_ssh_config(file, host))
}

/// `owner-ssh-key`: an explicit key, or an agent that is not warden's. The
/// environment's agent counts only when no warden config replaces it. An
/// explicit key counts even on a warden route: it adds the owner's key to it.
fn owner_key(
    tool: &str,
    options: &SshOptions<'_>,
    env_sock: Option<&str>,
    hosts: &[String],
    ctx: &Context,
    found: &mut Vec<Match>,
) {
    let env_sock = env_sock.filter(|s| !s.is_empty());
    let replaced_by_config = !hosts.is_empty()
        && hosts.iter().all(|host| {
            options
                .config
                .as_deref()
                .is_some_and(|file| ctx.is_warden_ssh_config(file, host))
        });
    let foreign_agent = if let Some(own) = options.agent.as_deref() {
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

/// The matches of one command that reaches `destinations` (and the jump
/// hosts of its options) over SSH, as `tool`.
fn report(
    tool: &str,
    options: &SshOptions<'_>,
    env_sock: Option<&str>,
    mut hosts: Vec<String>,
    uncovered: bool,
    ctx: &Context,
) -> Vec<Match> {
    hosts.extend(options.jump_hosts());
    let mut found = Vec::new();
    owner_key(tool, options, env_sock, &hosts, ctx, &mut found);
    for host in &hosts {
        if !routed(ctx, options, env_sock, host) {
            coverage_match(host, uncovered, ctx, &mut found);
        }
    }
    found
}

/// Matches of `ssh`, `scp`, `sftp`, `ssh-copy-id`, `autossh` and `mosh`.
pub(super) fn ssh_like(
    program: &str,
    args: &[String],
    env_sock: Option<&str>,
    ctx: &Context,
) -> Vec<Match> {
    let (short, long) = match program {
        "scp" => (SCP_SHORT, &[][..]),
        "sftp" => (SFTP_SHORT, &[][..]),
        "ssh-copy-id" => (SSH_COPY_ID_SHORT, &[][..]),
        "autossh" => (AUTOSSH_SHORT, &[][..]),
        "mosh" => (MOSH_SHORT, MOSH_LONG),
        _ => (SSH_SHORT, &[][..]),
    };
    let mut options = SshOptions::read(args, short, long);
    if let Some(command) = options.shell_command.take() {
        options.merge_command(&command);
    }
    let hosts: Vec<String> = if program == "scp" {
        options
            .operands
            .iter()
            .filter_map(|word| remote_operand(word))
            .map(str::to_owned)
            .collect()
    } else {
        options
            .operands
            .first()
            .and_then(|word| destination_host(word))
            .map(str::to_owned)
            .into_iter()
            .collect()
    };
    report(
        program,
        &options,
        env_sock,
        hosts,
        program != "scp" && program != "sftp",
        ctx,
    )
}

/// Matches of `rsync`: a `host:path` operand is SSH, and so is an `-e ssh` or
/// an `RSYNC_RSH`.
pub(super) fn rsync(
    args: &[String],
    env_sock: Option<&str>,
    env_rsh: Option<&str>,
    ctx: &Context,
) -> Vec<Match> {
    let mut rsh: Option<&str> = None;
    let mut operands = Vec::new();
    for item in args::read(args, RSYNC_SHORT, RSYNC_LONG) {
        match item {
            Item::Positional(word) => operands.push(word),
            Item::Opt { name, value } if name == "-e" || name == "--rsh" => rsh = value,
            Item::Opt { .. } => {}
        }
    }
    let mut options = SshOptions::default();
    if let Some(command) = rsh.or(env_rsh) {
        options.merge_command(command);
    }
    let hosts = operands
        .iter()
        .filter_map(|word| remote_operand(word))
        .map(str::to_owned)
        .collect();
    report("rsync", &options, env_sock, hosts, false, ctx)
}

/// What `git`'s own options and subcommand say.
pub(super) struct GitCall<'a> {
    /// The values of `-c core.sshCommand=…`.
    ssh_commands: Vec<&'a str>,
    /// Every `-c name=value` setting, in order.
    pub(super) settings: Vec<&'a str>,
    /// Whether `-C`, `--git-dir` or `--work-tree` points git at another
    /// repository than the working directory's.
    pub(super) elsewhere: bool,
    /// The first word that is not a global option.
    pub(super) subcommand: Option<&'a str>,
    /// The words after the subcommand.
    pub(super) rest: &'a [String],
}

pub(super) fn git_call(args: &[String]) -> GitCall<'_> {
    let mut call = GitCall {
        ssh_commands: Vec::new(),
        settings: Vec::new(),
        elsewhere: false,
        subcommand: None,
        rest: &[],
    };
    let mut words = args.iter().enumerate();
    while let Some((at, word)) = words.next() {
        let config = if word == "-c" {
            words.next().map(|(_, value)| value.as_str())
        } else {
            word.strip_prefix("-c").filter(|_| !word.starts_with("--"))
        };
        if let Some(setting) = config {
            call.settings.push(setting);
            if let Some((key, value)) = setting.split_once('=')
                && key.eq_ignore_ascii_case("core.sshCommand")
            {
                call.ssh_commands.push(value);
            }
        } else if matches!(
            word.as_str(),
            "-C" | "--git-dir" | "--work-tree" | "--namespace" | "--super-prefix" | "--config-env"
        ) {
            call.elsewhere |= matches!(word.as_str(), "-C" | "--git-dir" | "--work-tree");
            words.next();
        } else if word.starts_with("--git-dir=") || word.starts_with("--work-tree=") {
            call.elsewhere = true;
        } else if !word.starts_with('-') {
            call.subcommand = Some(word);
            call.rest = args.get(at + 1..).unwrap_or_default();
            break;
        }
    }
    call
}

/// Whether `git <subcommand> <rest>` only edits configuration: nothing
/// connects, so no host in its words is reached.
fn git_is_local(call: &GitCall<'_>) -> bool {
    let first = call
        .rest
        .iter()
        .map(String::as_str)
        .find(|word| !word.starts_with('-'));
    match call.subcommand {
        Some("config") => true,
        Some("remote") => matches!(first, Some("add" | "set-url")),
        _ => false,
    }
}

/// Matches of `git`: an SSH remote in its words (`ssh://…` or
/// `user@host:path`), an agent that is not warden's, and the SSH command it
/// is told to run (`GIT_SSH_COMMAND`, `-c core.sshCommand=`).
pub(super) fn git(
    args: &[String],
    env_sock: Option<&str>,
    env_ssh_command: Option<&str>,
    ctx: &Context,
) -> Vec<Match> {
    let call = git_call(args);
    if call.subcommand.is_none() || git_is_local(&call) {
        return Vec::new();
    }
    let mut options = SshOptions::default();
    for command in env_ssh_command.iter().chain(&call.ssh_commands) {
        options.merge_command(command);
    }
    let mut hosts = Vec::new();
    for word in call.rest {
        let host = if word.contains("://") {
            url_host(word)
        } else if word.contains('@') && !word.contains(char::is_whitespace) {
            remote_operand(word)
        } else {
            None
        };
        hosts.extend(host.map(str::to_owned));
    }
    report("git", &options, env_sock, hosts, false, ctx)
}
