//! `warden` command-line client: request approval for access, then use it.

mod agent;
mod client;
mod config;
mod http;
mod ssh;

use std::io::{BufRead as _, IsTerminal as _};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail, ensure};
use clap::{Parser, Subcommand};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, Certificate, PrivateKey};
use url::Url;
use warden_broker_proto::{
    Access, AgentName, CreateRequest, Goal, GrantAccess, GrantView, Id, RequestStatus, SecretName,
    TargetName, UnixUser, Window, fingerprint,
};
use zeroize::Zeroizing;

use crate::client::{CallError, Client, MAX_WAIT_SECS};
use crate::config::Config;

/// Exit code: a request was denied.
const EXIT_DENIED: u8 = 2;
/// Exit code: a request expired before a decision.
const EXIT_EXPIRED: u8 = 3;
/// Exit code: the grant was revoked.
const EXIT_REVOKED: u8 = 4;
/// Exit code: `warden ssh` found no active grant for the target.
const EXIT_NO_GRANT: u8 = 5;
/// Exit code: `warden http --fail` got an upstream status of 400 or more
/// (curl's code for the same condition).
const EXIT_HTTP_FAIL: u8 = 22;
/// Exit code: any other failure.
const EXIT_ERROR: u8 = 1;

/// How long `warden request` waits for a decision (pending requests expire
/// on the server after 10 minutes).
const DECISION_TIMEOUT: Duration = Duration::from_secs(11 * 60);

/// How long the broker keeps a request pending, in seconds.
const PENDING_EXPIRY_SECS: i64 = 600;

/// First pause before retrying an unavailable broker.
const FIRST_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Longest pause between retries.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(15);

/// Ask the owner for short-lived access, then use it.
#[derive(Debug, Parser)]
#[command(name = "warden", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Store this machine's agent key (read from stdin) in the Keychain and
    /// remember the broker URL and agent name.
    Login {
        /// Broker agent API URL (https, or http on loopback).
        #[arg(long)]
        server: Url,
        /// Agent name the key belongs to.
        #[arg(long)]
        agent: AgentName,
    },
    /// Ask the owner for access and wait for the decision.
    Request {
        #[command(subcommand)]
        kind: RequestKind,
    },
    /// Run ssh to a target through its newest active grant.
    Ssh {
        /// Target name.
        target: TargetName,
        /// Remote command, after `--`.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Call an HTTPS API through the broker, which adds the secret.
    Http {
        /// Secret name.
        secret: SecretName,
        /// HTTP method.
        method: String,
        /// Absolute https URL.
        url: String,
        /// Request header, `Name: value`; repeatable.
        #[arg(short = 'H', long = "header", value_parser = http::parse_header)]
        headers: Vec<(String, String)>,
        /// Request body.
        #[arg(short = 'd', long = "data", conflicts_with = "data_file")]
        data: Option<String>,
        /// Read the request body from a file, or from standard input for `-`.
        #[arg(long)]
        data_file: Option<String>,
        /// Print the status line and response headers to stderr.
        #[arg(short = 'i', long)]
        include: bool,
        /// Exit 22 when the status is 400 or more (the body is still written).
        #[arg(long)]
        fail: bool,
    },
    /// Show local grants and the broker's view of this agent's grants.
    Status,
    /// Revoke a grant on the broker and stop its local agent.
    Revoke {
        /// Grant identifier.
        grant: Id,
    },
}

#[derive(Debug, Subcommand)]
enum RequestKind {
    /// An SSH certificate for a user on a target.
    Ssh {
        /// Target name.
        target: TargetName,
        /// Unix account to log in as.
        #[arg(long)]
        user: UnixUser,
        /// Window length: 15m, 30m, 1h or 4h.
        #[arg(long = "for")]
        window: Window,
        /// What the access is for, shown to the owner.
        #[arg(long)]
        goal: Goal,
    },
    /// Brokered HTTPS calls that use a stored API secret.
    Api {
        /// Secret name.
        secret: SecretName,
        /// Window length: 15m, 30m, 1h or 4h.
        #[arg(long = "for")]
        window: Window,
        /// What the access is for, shown to the owner.
        #[arg(long)]
        goal: Goal,
    },
}

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
    let cli = Cli::parse();
    let now = unix_now();
    if let Err(e) = agent::cleanup_expired(now) {
        eprintln!("warden: warning: {e:#}");
    }
    if let Err(e) = http::cleanup_expired(now, &mut std::io::stderr().lock()) {
        eprintln!("warden: warning: {e:#}");
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

async fn run(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Login { server, agent } => login(server, agent),
        Cmd::Request {
            kind:
                RequestKind::Ssh {
                    target,
                    user,
                    window,
                    goal,
                },
        } => request_ssh(target, user, window, goal).await,
        Cmd::Request {
            kind:
                RequestKind::Api {
                    secret,
                    window,
                    goal,
                },
        } => request_api(secret, window, goal).await,
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
    let key = config::agent_key(&config)?;
    let client = Client::new(&config.server, key)?;
    Ok((config, client))
}

fn login(server: Url, agent: AgentName) -> Result<()> {
    config::check_server_url(&server)?;
    let config = Config { server, agent };
    let key = if std::io::stdin().is_terminal() {
        eprint!("agent key for {}: ", config.agent);
        Zeroizing::new(rpassword::read_password().context("cannot read the agent key")?)
    } else {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .context("cannot read the agent key from stdin")?;
        Zeroizing::new(line.trim().to_owned())
    };
    config::check_agent_key(&key)?;
    config::store_agent_key(&config, &key)?;
    let path = config::save(&config)?;
    eprintln!(
        "logged in as {} at {} ({})",
        config.agent,
        config.server,
        path.display()
    );
    Ok(())
}

/// The exit code for a request that reached `status`, or `None` while it is
/// still pending.
fn terminal_exit_code(status: &RequestStatus) -> Option<u8> {
    match status {
        RequestStatus::Pending => None,
        RequestStatus::Approved(_) => Some(0),
        RequestStatus::Denied => Some(EXIT_DENIED),
        RequestStatus::Expired => Some(EXIT_EXPIRED),
        RequestStatus::Revoked => Some(EXIT_REVOKED),
        RequestStatus::Error { .. } => Some(EXIT_ERROR),
    }
}

async fn request_ssh(target: TargetName, user: UnixUser, window: Window, goal: Goal) -> Result<()> {
    let (config, client) = client()?;
    let key =
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).context("cannot generate a key")?;
    let public_key = key
        .public_key()
        .to_openssh()
        .context("cannot encode the public key")?;
    let req = CreateRequest {
        goal,
        access: Access::Ssh {
            target: target.clone(),
            user: user.clone(),
            public_key,
        },
        window,
    };
    let grant = request_grant(&config, &client, &req, &format!("for {target}")).await?;
    install_grant(&target, &user, &key, &grant).await?;
    announce(&grant);
    Ok(())
}

async fn request_api(secret: SecretName, window: Window, goal: Goal) -> Result<()> {
    let (config, client) = client()?;
    let req = CreateRequest {
        goal,
        access: Access::Api {
            secret: secret.clone(),
        },
        window,
    };
    let grant = request_grant(&config, &client, &req, &format!("for api secret {secret}")).await?;
    let GrantAccess::Api(api) = &grant.access else {
        bail!("the broker returned a non-api grant for an api request");
    };
    ensure!(
        api.secret == secret,
        "the grant is for secret {}, not {secret}",
        api.secret
    );
    ensure!(grant.not_after > unix_now(), "the grant has already ended");
    http::save(&http::ApiRecord::new(
        grant.grant_id.clone(),
        api,
        grant.not_after,
    ))?;
    announce(&grant);
    Ok(())
}

fn announce(grant: &GrantView) {
    println!(
        "approved: grant {} until {}",
        grant.grant_id,
        local_time(grant.not_after)
    );
}

/// Create `req`, wait for the owner's decision and return the approved
/// grant. `subject` completes "a request …" in messages. Denied, expired,
/// revoked and failed requests end the process with their own exit codes.
async fn request_grant(
    config: &Config,
    client: &Client,
    req: &CreateRequest,
    subject: &str,
) -> Result<GrantView> {
    let created = client.create(req).await?;
    if created.fingerprint != fingerprint(&config.agent, req) {
        // The broker answered with another pending request of this agent for
        // the same target or secret, made with a different goal, window or
        // (for SSH) key: approving it would not grant what was asked here.
        bail!(
            "a request {subject} is already pending (fingerprint {}); wait for it to be decided or expire",
            created.fingerprint
        );
    }
    eprintln!(
        "fingerprint {} — waiting for approval…",
        created.fingerprint
    );

    let created_at = unix_now();
    let deadline = Instant::now() + DECISION_TIMEOUT;
    let poll = || client.status(&created.id, MAX_WAIT_SECS);
    let status = match wait_for_decision(poll, deadline, FIRST_RETRY_DELAY).await {
        Ok(status) => status,
        Err(reason) => bail!(
            "{reason}; request {} may still be pending on the broker, where it expires \
             unanswered at about {}",
            created.id,
            local_time(created_at.saturating_add(PENDING_EXPIRY_SECS))
        ),
    };
    match status {
        RequestStatus::Approved(grant) => Ok(grant),
        RequestStatus::Error { message } => {
            Err(Exit::new(EXIT_ERROR, format!("request failed: {message}")).into())
        }
        other => {
            let code = terminal_exit_code(&other).unwrap_or(EXIT_ERROR);
            let what = match other {
                RequestStatus::Denied => "denied",
                RequestStatus::Expired => "expired",
                _ => "revoked",
            };
            Err(Exit::new(code, format!("request {what}")).into())
        }
    }
}

/// Long-poll until the request reaches a terminal status. Transport errors
/// and 5xx answers are retried with exponential backoff (from `first_delay`,
/// doubling, at most [`MAX_RETRY_DELAY`]) until `deadline`, with one note on
/// stderr per failure. Returns why it gave up: a refusal (4xx) or the
/// deadline.
async fn wait_for_decision<F, Fut>(
    mut poll: F,
    deadline: Instant,
    first_delay: Duration,
) -> Result<RequestStatus, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<RequestStatus, CallError>>,
{
    let mut delay = first_delay;
    loop {
        let Some(left) = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        else {
            return Err(format!(
                "no decision within {} minutes",
                DECISION_TIMEOUT.as_secs() / 60
            ));
        };
        match poll().await {
            Ok(status) if terminal_exit_code(&status).is_some() => return Ok(status),
            Ok(_) => delay = first_delay,
            Err(CallError::Refused(message)) => return Err(message),
            Err(CallError::Unavailable(message)) => {
                let pause = delay.min(left);
                eprintln!("warden: {message}; retrying in {} ms", pause.as_millis());
                tokio::time::sleep(pause).await;
                delay = next_retry_delay(delay);
            }
        }
    }
}

/// The delay after `delay`: doubled, at most [`MAX_RETRY_DELAY`].
fn next_retry_delay(delay: Duration) -> Duration {
    delay.saturating_mul(2).min(MAX_RETRY_DELAY)
}

/// Start the grant's agent, load the key and certificate into it, pin the
/// host keys and record the grant. On failure nothing is left behind.
async fn install_grant(
    target: &TargetName,
    user: &UnixUser,
    key: &PrivateKey,
    grant: &GrantView,
) -> Result<()> {
    let ssh = match &grant.access {
        GrantAccess::Ssh(ssh) => ssh,
        GrantAccess::Relay(_) => {
            bail!("target {target} is a relay target, which this version of warden cannot use yet")
        }
        GrantAccess::Api(_) => bail!("the broker returned a non-ssh grant for an ssh request"),
    };
    let cert = Certificate::from_openssh(&ssh.certificate)
        .context("the grant's certificate is invalid")?;
    ensure!(
        &ssh.user == user,
        "the grant is for user {}, not {user}",
        ssh.user
    );
    ensure!(
        agent::is_safe_host(&ssh.host),
        "the grant's host {:?} is invalid",
        ssh.host
    );
    let remaining = grant.not_after.saturating_sub(unix_now());
    let lifetime = Duration::from_secs(
        u64::try_from(remaining)
            .ok()
            .filter(|s| *s > 0)
            .context("the grant has already ended")?,
    );

    let agent = agent::start(&grant.grant_id, lifetime)?;
    let setup = async {
        agent::record(
            &agent,
            &agent::GrantRecord {
                grant_id: grant.grant_id.clone(),
                target: target.clone(),
                host: ssh.host.clone(),
                port: ssh.port,
                user: user.clone(),
                not_after: grant.not_after,
                socket: agent.socket.clone(),
                pid: agent.pid,
            },
        )?;
        agent::add_cert(&agent, key, &cert, lifetime).await?;
        agent::write_known_hosts(&agent.dir, &ssh.host, ssh.port, &ssh.host_keys)?;
        Ok::<_, anyhow::Error>(())
    };
    if let Err(e) = setup.await {
        if let Err(cleanup) = agent::discard(&agent.dir, &agent.socket, agent.pid) {
            eprintln!("warden: warning: {cleanup:#}");
        }
        return Err(e);
    }
    Ok(())
}

fn run_ssh(target: &TargetName, command: &[String]) -> Result<()> {
    let grants = agent::grants_dir()?;
    let Some(grant) = ssh::active_grant(&grants, target, unix_now()) else {
        return Err(Exit::new(
            EXIT_NO_GRANT,
            format!("no active grant for {target}; run warden request ssh {target} --user <user> --for <window> --goal <text>"),
        )
        .into());
    };
    let args = ssh::ssh_args(&grant, command)?;
    Err(ssh::exec(&args)).context("cannot run ssh")
}

/// Everything `warden http` was asked to send.
struct HttpCall {
    secret: SecretName,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    data: Option<String>,
    data_file: Option<String>,
}

async fn run_http(call: HttpCall, include: bool, fail: bool) -> Result<()> {
    let Some(grant) = http::active(&call.secret, unix_now())? else {
        let secret = &call.secret;
        return Err(Exit::new(
            EXIT_NO_GRANT,
            format!("no active api grant for {secret}; run warden request api {secret} --for <window> --goal <text>"),
        )
        .into());
    };
    let body = http::read_body(call.data.as_deref(), call.data_file.as_deref())?;
    let proxy = http::proxy_request(&call.method, &call.url, call.headers, body.as_deref())?;
    let (_, client) = client()?;
    let resp = client.proxy(&grant.grant_id, &proxy).await?;
    let reply = http::decode(&resp)?;
    http::emit(
        &reply,
        include,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )?;
    if fail && reply.status >= 400 {
        return Err(Exit::new(
            EXIT_HTTP_FAIL,
            format!("the server answered with status {}", reply.status),
        )
        .into());
    }
    Ok(())
}

async fn status() -> Result<()> {
    let grants = agent::grants_dir()?;
    println!("local grants:");
    for (dir, record) in agent::load_grants(&grants) {
        match record {
            Ok(r) => println!(
                "  {}  {}@{}:{}  grant {}  until {}",
                r.target,
                r.user,
                r.host,
                r.port,
                r.grant_id,
                local_time(r.not_after)
            ),
            Err(e) => println!("  {}: {e:#}", dir.display()),
        }
    }
    println!("local api grants:");
    for (path, record) in http::load()? {
        match record {
            Ok(r) => println!(
                "  api:{}  {}  grant {}  until {}",
                r.secret,
                r.origin,
                r.grant_id,
                local_time(r.not_after)
            ),
            Err(e) => println!("  {}: {e:#}", path.display()),
        }
    }
    let (_, client) = client()?;
    println!("broker grants:");
    for g in client.grants().await? {
        let subject = match &g.access {
            GrantAccess::Ssh(ssh) => format!("{}@{}:{}", ssh.user, ssh.host, ssh.port),
            GrantAccess::Api(api) => format!("api:{}", api.secret),
            GrantAccess::Relay(relay) => format!("{}@{} via relay", relay.user, relay.target),
        };
        println!(
            "  {subject}  grant {}  until {}",
            g.grant_id,
            local_time(g.not_after)
        );
    }
    Ok(())
}

async fn revoke(grant: &Id) -> Result<()> {
    // Stop the local agent first: the grant is unusable here whatever the
    // broker answers.
    let local = agent::discard_grant(grant)? | http::discard(grant)?;
    let (_, client) = client()?;
    client.revoke(grant).await?;
    eprintln!(
        "revoked grant {grant}{}",
        if local {
            " and removed its local state"
        } else {
            ""
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use warden_broker_proto::{GrantAccess, GrantView, Id, RequestStatus, SshGrant};

    use std::time::{Duration, Instant};

    use super::{CallError, next_retry_delay, terminal_exit_code, wait_for_decision};

    #[test]
    fn retry_delay_doubles_up_to_15s() {
        let delays: Vec<u64> =
            std::iter::successors(Some(Duration::from_secs(1)), |d| Some(next_retry_delay(*d)))
                .take(7)
                .map(|d| d.as_secs())
                .collect();
        assert_eq!(delays, [1, 2, 4, 8, 15, 15, 15]);
    }

    /// A poll that answers with `script`, in order, then stays pending.
    fn scripted(
        script: Vec<Result<RequestStatus, CallError>>,
    ) -> (
        impl FnMut() -> std::future::Ready<Result<RequestStatus, CallError>>,
        std::rc::Rc<std::cell::Cell<usize>>,
    ) {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let seen = calls.clone();
        let mut script = script.into_iter();
        let poll = move || {
            seen.set(seen.get() + 1);
            std::future::ready(script.next().unwrap_or(Ok(RequestStatus::Pending)))
        };
        (poll, calls)
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[tokio::test]
    async fn unavailable_broker_is_retried_until_a_decision() {
        let down = || Err(CallError::Unavailable("connection refused".to_owned()));
        let (poll, calls) = scripted(vec![
            Ok(RequestStatus::Pending),
            down(),
            down(),
            Err(CallError::Unavailable("broker refused (500)".to_owned())),
            Ok(RequestStatus::Pending),
            Ok(RequestStatus::Denied),
        ]);
        let got = wait_for_decision(poll, soon(), Duration::from_millis(1)).await;
        assert_eq!(got, Ok(RequestStatus::Denied));
        assert_eq!(calls.get(), 6);
    }

    #[tokio::test]
    async fn refusal_ends_the_wait_at_once() {
        let (poll, calls) = scripted(vec![
            Ok(RequestStatus::Pending),
            Err(CallError::Refused(
                "broker refused (404 Not Found)".to_owned(),
            )),
            Ok(RequestStatus::Denied),
        ]);
        let got = wait_for_decision(poll, soon(), Duration::from_millis(1)).await;
        assert_eq!(got, Err("broker refused (404 Not Found)".to_owned()));
        assert_eq!(calls.get(), 2);
    }

    #[tokio::test]
    async fn deadline_ends_retries() {
        let (poll, _) = scripted(Vec::new());
        let deadline = Instant::now() + Duration::from_millis(30);
        let got = wait_for_decision(poll, deadline, Duration::from_millis(1)).await;
        assert_eq!(got, Err("no decision within 11 minutes".to_owned()));

        let always_down = || std::future::ready(Err(CallError::Unavailable("down".to_owned())));
        let started = Instant::now();
        let got = wait_for_decision(
            always_down,
            started + Duration::from_millis(50),
            Duration::from_secs(15),
        )
        .await;
        assert!(got.is_err());
        // The pause before a retry never runs past the deadline.
        assert!(started.elapsed() < Duration::from_secs(2));
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
