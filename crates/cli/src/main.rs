//! `warden` command-line client: request approval for access, then use it.

mod agent;
mod cli;
mod client;
mod commands;
mod config;
mod doctor;
mod git_signing;
mod guidance;
mod http;
mod install;
mod login;
mod recover;
mod request;
mod request_context;
mod setup_git;
mod sign;
mod ssh;
mod ssh_agent;
mod ssh_config;

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, ensure};
use clap::Parser;
use warden_broker_proto::doctor::EXIT_NOTHING_FAILED;

use crate::cli::{Cli, Cmd, RequestKind, SetupWhat};
use crate::client::Client;
use crate::commands::{HttpCall, revoke, run_http, run_setup_git, run_ssh, status};
use crate::config::Config;
use crate::login::{KeyLogin, login, login_with_key};
use crate::request::{cancel, request_api, request_signing, request_ssh};

/// Exit code: any other failure.
const EXIT_ERROR: u8 = 1;
/// Exit code: a request was denied.
const EXIT_DENIED: u8 = 2;
/// Exit code: a request expired before a decision.
const EXIT_EXPIRED: u8 = 3;
/// Exit code: the grant was revoked.
const EXIT_REVOKED: u8 = 4;
/// Exit code: `warden ssh` or `warden ssh-config` found no active grant for the
/// target (for `ssh-config --min-remaining`, none that lasts long enough).
const EXIT_NO_GRANT: u8 = 5;
/// Exit code: a request was cancelled (by the agent, from another terminal)
/// while this command waited for it.
const EXIT_CANCELLED: u8 = 6;
/// Exit code: the broker stopped a `warden http` call that was out, and cannot
/// say whether the grant holds. The upstream may have acted on the call.
const EXIT_CALL_STOPPED: u8 = 8;
/// Exit code: `warden http --fail` got an upstream status of 400 or more
/// (curl's code for the same condition).
const EXIT_HTTP_FAIL: u8 = 22;
/// Exit code: the command line did not parse (`EX_USAGE`). Not clap's default
/// of 2, which here means denied: the two call for opposite reactions.
const EXIT_USAGE: u8 = 64;
/// Exit code: interrupted with Ctrl-C (128 plus SIGINT, as shells report it).
const EXIT_INTERRUPTED: u8 = 130;

/// Failure with a specific exit code and message.
#[derive(Debug)]
struct Exit {
    code: u8,
    message: String,
}

impl Exit {
    fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Exit {}

#[tokio::main]
async fn main() -> ExitCode {
    // Called by git as its signing program, with `ssh-keygen`'s arguments.
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if git_signing::is_program_call(&args) {
        return git_signing::run(&args).await;
    }
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => return parse_failure_exit(&e),
    };
    // Doctor changes nothing, so not even the housekeeping runs before it.
    if !matches!(cli.command, Cmd::Doctor { .. }) {
        cleanup_state(unix_now());
    }
    match run(cli.command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let code = e
                .downcast_ref::<Exit>()
                .map_or(EXIT_ERROR, |exit| exit.code);
            eprintln!("warden: {e:#}");
            ExitCode::from(code)
        }
    }
}

/// Prints what the parser has to say and gives the exit code: 0 for the help
/// and version output it reports as errors, and otherwise [`EXIT_USAGE`].
fn parse_failure_exit(e: &clap::Error) -> ExitCode {
    // A failed write to stdout or stderr leaves nowhere to report it, and the
    // exit code still says what happened.
    let _ = e.print();
    if e.use_stderr() {
        ExitCode::from(EXIT_USAGE)
    } else {
        ExitCode::SUCCESS
    }
}

/// Best-effort housekeeping before every command: stop the agents of ended
/// grants, delete their records and abandoned temporary files. Failures
/// never stop the command; they are reported in one warning.
fn cleanup_state(now: i64) {
    let failures: Vec<String> = [
        agent::cleanup_expired(now),
        http::cleanup_expired(now, &mut std::io::stderr().lock()),
    ]
    .into_iter()
    .filter_map(Result::err)
    .map(|e| format!("{e:#}"))
    .collect();
    if !failures.is_empty() {
        eprintln!("warden: warning: {}", failures.join("; "));
    }
}

async fn run(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Login {
            server,
            agent,
            ssh_key: None,
            ..
        } => login(server, agent),
        Cmd::Login {
            server,
            agent,
            ssh_key: Some(ssh_key),
            ssh_agent_socket,
            audience,
        } => {
            let login = KeyLogin {
                server,
                agent,
                public_key: ssh_key,
                agent_socket: ssh_agent_socket,
                audience,
            };
            login_with_key(login).await
        }
        Cmd::Request {
            kind:
                RequestKind::Ssh {
                    target,
                    user,
                    window,
                    goal,
                    context,
                },
        } => request_ssh(target, user, window, goal, context).await,
        Cmd::Request {
            kind:
                RequestKind::Api {
                    secret,
                    methods,
                    path,
                    window,
                    goal,
                    context,
                },
        } => request_api(secret, methods, path, window, goal, context).await,
        Cmd::Request {
            kind:
                RequestKind::Signing {
                    window,
                    goal,
                    context,
                },
        } => request_signing(window, goal, context).await,
        Cmd::Setup {
            what: SetupWhat::Git { local },
        } => run_setup_git(local).await,
        Cmd::Request {
            kind: RequestKind::Cancel { id },
        } => cancel(&id).await,
        Cmd::Request {
            kind: RequestKind::Collect { grant },
        } => recover::collect(&grant).await,
        Cmd::Http {
            secret,
            method,
            url,
            headers,
            data,
            data_file,
            include,
            fail,
        } => {
            let call = HttpCall {
                secret,
                method,
                url,
                headers,
                data,
                data_file,
            };
            run_http(call, include, fail).await
        }
        Cmd::Ssh { target, command } => run_ssh(&target, &command),
        Cmd::SshConfig(request) => ssh_config::run(&request),
        Cmd::Doctor { strict } => {
            let report = doctor::examine(&doctor::Live).await;
            print!("{}", report.render(strict));
            let code = report.exit_code(strict);
            ensure!(
                code == EXIT_NOTHING_FAILED,
                Exit::new(code, "doctor: see the report above")
            );
            Ok(())
        }
        Cmd::Status => status().await,
        Cmd::Revoke { grant } => revoke(&grant).await,
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

fn local_time(unix: i64) -> String {
    jiff::Timestamp::from_second(unix).map_or_else(
        |_| format!("@{unix}"),
        |t| {
            t.to_zoned(jiff::tz::TimeZone::system())
                .strftime("%Y-%m-%d %H:%M:%S %Z")
                .to_string()
        },
    )
}

fn client() -> Result<(Config, Client)> {
    let config = config::load()?;
    let client = Client::for_config(&config)?;
    Ok((config, client))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use warden_broker_proto::doctor::{EXIT_COULD_NOT_CHECK, EXIT_FAILED, EXIT_NOTHING_FAILED};
    use warden_broker_proto::{GrantAccess, GrantView, Id, RequestStatus, SshGrant};

    use super::{
        EXIT_CALL_STOPPED, EXIT_CANCELLED, EXIT_DENIED, EXIT_ERROR, EXIT_EXPIRED, EXIT_HTTP_FAIL,
        EXIT_INTERRUPTED, EXIT_NO_GRANT, EXIT_REVOKED, EXIT_USAGE,
    };
    use crate::request::terminal_exit_code;

    /// Each code means one thing, so an agent can act on it. A failed
    /// `warden doctor` check is the one overlap: it is an error like any other.
    #[test]
    fn exit_codes_are_distinct() {
        let codes = [
            EXIT_NOTHING_FAILED,
            EXIT_ERROR,
            EXIT_DENIED,
            EXIT_EXPIRED,
            EXIT_REVOKED,
            EXIT_NO_GRANT,
            EXIT_CANCELLED,
            EXIT_COULD_NOT_CHECK,
            EXIT_CALL_STOPPED,
            EXIT_HTTP_FAIL,
            EXIT_USAGE,
            EXIT_INTERRUPTED,
        ];
        assert_eq!(BTreeSet::from(codes).len(), codes.len(), "{codes:?}");
        assert_eq!(EXIT_FAILED, EXIT_ERROR);
    }

    #[test]
    fn exit_code_mapping() {
        let grant = GrantView {
            grant_id: Id::random(),
            not_before: 0,
            not_after: 1,
            access: GrantAccess::Ssh(SshGrant {
                certificate: String::new(),
                host: "h".to_owned(),
                port: 22,
                user: "u".parse().unwrap(),
                host_keys: Vec::new(),
            }),
        };
        assert_eq!(terminal_exit_code(&RequestStatus::Pending), None);
        assert_eq!(terminal_exit_code(&RequestStatus::Approved(grant)), Some(0));
        assert_eq!(terminal_exit_code(&RequestStatus::Denied), Some(2));
        assert_eq!(terminal_exit_code(&RequestStatus::Expired), Some(3));
        assert_eq!(terminal_exit_code(&RequestStatus::Cancelled), Some(6));
        assert_eq!(terminal_exit_code(&RequestStatus::Revoked), Some(4));
        assert_eq!(
            terminal_exit_code(&RequestStatus::Error {
                message: "x".to_owned()
            }),
            Some(1)
        );
        assert_eq!(super::EXIT_NO_GRANT, 5);
    }
}
