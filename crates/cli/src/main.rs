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
    Access, AgentName, ApiGrant, CreateRequest, Goal, GrantAccess, GrantView, Id, RequestStatus,
    SecretName, TargetName, UnixUser, Window, fingerprint, is_read_only, modifying_methods,
    under_prefix,
};
use zeroize::Zeroizing;

use crate::client::{CallError, Client, MAX_WAIT_SECS};
use crate::config::Config;

/// Exit code: any other failure.
const EXIT_ERROR: u8 = 1;
/// Exit code: a request was denied.
const EXIT_DENIED: u8 = 2;
/// Exit code: a request expired before a decision.
const EXIT_EXPIRED: u8 = 3;
/// Exit code: the grant was revoked.
const EXIT_REVOKED: u8 = 4;
/// Exit code: `warden ssh` found no active grant for the target.
const EXIT_NO_GRANT: u8 = 5;
/// Exit code: a request was cancelled (by the agent, from another terminal)
/// while this command waited for it.
const EXIT_CANCELLED: u8 = 6;
/// Exit code: `warden http --fail` got an upstream status of 400 or more
/// (curl's code for the same condition).
const EXIT_HTTP_FAIL: u8 = 22;
/// Exit code: interrupted with Ctrl-C (128 plus SIGINT, as shells report it).
const EXIT_INTERRUPTED: u8 = 130;

/// How long Ctrl-C waits for the broker to confirm the cancellation of the
/// request being waited for.
const CANCEL_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// Run ssh to a target through its active grant that stays valid longest.
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
    /// SSH access as a user on a target: a certificate, or for a relay
    /// target a session through the broker's relay.
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
        /// Methods to allow, comma separated (default: read-only, GET and
        /// HEAD); the broker refuses any the secret does not allow.
        #[arg(long, value_delimiter = ',')]
        methods: Option<Vec<String>>,
        /// Limit the grant to this path prefix (default: the secret's).
        #[arg(long)]
        path: Option<String>,
        /// Window length: 15m, 30m, 1h or 4h.
        #[arg(long = "for")]
        window: Window,
        /// What the access is for, shown to the owner.
        #[arg(long)]
        goal: Goal,
    },
    /// Withdraw one of this agent's pending requests, so its approval link
    /// stops working.
    Cancel {
        /// Request identifier, as printed while `warden request` waits.
        id: Id,
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
                    methods,
                    path,
                    window,
                    goal,
                },
        } => request_api(secret, methods, path, window, goal).await,
        Cmd::Request {
            kind: RequestKind::Cancel { id },
        } => cancel(&id).await,
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
        RequestStatus::Cancelled => Some(EXIT_CANCELLED),
        RequestStatus::Revoked => Some(EXIT_REVOKED),
        RequestStatus::Error { .. } => Some(EXIT_ERROR),
    }
}

async fn cancel(id: &Id) -> Result<()> {
    let (_, client) = client()?;
    client.cancel(id).await?;
    println!("cancelled: request {id}");
    Ok(())
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

async fn request_api(
    secret: SecretName,
    methods: Option<Vec<String>>,
    path: Option<String>,
    window: Window,
    goal: Goal,
) -> Result<()> {
    let (config, client) = client()?;
    let methods: Option<Vec<String>> = methods.map(|m| {
        m.iter()
            .map(|method| method.trim().to_ascii_uppercase())
            .collect()
    });
    let req = CreateRequest {
        goal,
        access: Access::Api {
            secret: secret.clone(),
            methods: methods.clone(),
            path_prefix: path.clone(),
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
    if let Err(problem) = check_scope_not_wider(api, methods.as_deref(), path.as_deref()) {
        bail!(
            "the broker granted a wider scope than requested ({problem}); upgrade the broker \
             to 0.4 or later. Grant {} was not recorded here; revoke it with `warden revoke {}`",
            grant.grant_id,
            grant.grant_id
        );
    }
    http::save(&http::ApiRecord::new(
        grant.grant_id.clone(),
        api,
        grant.not_after,
    ))?;
    announce(&grant);
    println!("{}", api_scope(api));
    Ok(())
}

/// Whether `api` is inside what was asked for. A broker older than 0.4
/// ignores `--methods` and `--path` and grants the whole item, so the CLI
/// must not record such a grant as if it were narrow. Without `methods` the
/// request means read-only; without `path` any prefix the broker picks is
/// its own to choose.
///
/// # Errors
/// What is wider, for the message.
fn check_scope_not_wider(
    api: &ApiGrant,
    methods: Option<&[String]>,
    path: Option<&str>,
) -> Result<(), String> {
    let extra: Vec<&str> = match methods {
        Some(requested) => api
            .methods
            .iter()
            .map(String::as_str)
            .filter(|m| !requested.iter().any(|r| r == m))
            .collect(),
        None if is_read_only(&api.methods) => Vec::new(),
        None => modifying_methods(&api.methods),
    };
    if !extra.is_empty() {
        return Err(format!("methods {}", extra.join(", ")));
    }
    if let Some(wanted) = path
        && !under_prefix(&api.path_prefix, wanted)
    {
        return Err(format!("path {} is not under {wanted}", api.path_prefix));
    }
    Ok(())
}

/// The scope of `api` for the owner-facing line after approval: whether it
/// can modify anything, the methods and where it applies.
fn api_scope(api: &ApiGrant) -> String {
    let access = if is_read_only(&api.methods) {
        "read-only".to_owned()
    } else {
        format!("can modify: {}", modifying_methods(&api.methods).join(", "))
    };
    format!(
        "scope: {access}; methods {}; {}{}",
        api.methods.join(", "),
        api.origin,
        api.path_prefix
    )
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
/// revoked, cancelled and failed requests end the process with their own exit
/// codes. Ctrl-C while waiting cancels the request (best effort, for at most
/// [`CANCEL_TIMEOUT`]) and exits 130.
async fn request_grant(
    config: &Config,
    client: &Client,
    req: &CreateRequest,
    subject: &str,
) -> Result<GrantView> {
    // Registered before anything is sent, so Ctrl-C is never lost.
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("cannot listen for Ctrl-C")?;
    let create = client.create(req);
    tokio::pin!(create);
    let created = tokio::select! {
        created = &mut create => created?,
        _ = interrupt.recv() => {
            // The request may be made already: give the broker's answer a
            // moment, then withdraw what it made.
            let exit = match tokio::time::timeout(CANCEL_TIMEOUT, &mut create).await {
                Ok(Ok(created)) => withdraw_after_interrupt(client, &created.id).await,
                Ok(Err(_)) | Err(_) => Exit::new(
                    EXIT_INTERRUPTED,
                    "interrupted; the request may have been made; it expires unanswered on the broker",
                ),
            };
            return Err(exit.into());
        }
    };
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
        "request {}, fingerprint {} — waiting for approval…",
        created.id, created.fingerprint
    );

    let created_at = unix_now();
    let deadline = Instant::now() + DECISION_TIMEOUT;
    let poll = || client.status(&created.id, MAX_WAIT_SECS);
    let waited = tokio::select! {
        waited = wait_for_decision(poll, deadline, FIRST_RETRY_DELAY) => waited,
        _ = interrupt.recv() => return Err(withdraw_after_interrupt(client, &created.id).await.into()),
    };
    let status = match waited {
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
            Err(Exit::new(code, format!("request {}", status_word(&other))).into())
        }
    }
}

/// Withdraw request `id` after Ctrl-C and say what came of it, within
/// [`CANCEL_TIMEOUT`]. The exit is the same either way; a request that could
/// not be cancelled is left to expire on its own, except one the owner
/// approved first, whose grant is revoked.
async fn withdraw_after_interrupt(client: &Client, id: &Id) -> Exit {
    let message = tokio::time::timeout(CANCEL_TIMEOUT, cancel_or_revoke(client, id))
        .await
        .unwrap_or_else(|_| {
            format!(
                "interrupted; cancelling request {id} timed out; it expires unanswered on the broker"
            )
        });
    Exit::new(EXIT_INTERRUPTED, message)
}

/// Cancel request `id`. If the broker refuses because it was decided in the
/// meantime, look at how: an approval has produced a grant nobody will use,
/// which is revoked.
async fn cancel_or_revoke(client: &Client, id: &Id) -> String {
    let refused = match client.cancel(id).await {
        Ok(()) => return format!("interrupted; request {id} cancelled"),
        Err(e @ CallError::Unavailable(_)) => {
            return format!(
                "interrupted; could not cancel request {id} ({e}); it expires unanswered on the broker"
            );
        }
        Err(e) => e,
    };
    match client.status(id, 0).await {
        Ok(RequestStatus::Approved(grant)) => match client.revoke(&grant.grant_id).await {
            Ok(()) => format!(
                "interrupted; request {id} was approved before it could be cancelled; grant {} revoked",
                grant.grant_id
            ),
            Err(e) => format!(
                "interrupted; request {id} was approved before it could be cancelled; could not revoke grant {} ({e})",
                grant.grant_id
            ),
        },
        Ok(other) => format!(
            "interrupted; request {id} was already {}; nothing to cancel",
            status_word(&other)
        ),
        Err(_) => format!(
            "interrupted; could not cancel request {id} ({refused}); it expires unanswered on the broker"
        ),
    }
}

/// The word for a terminal or pending `status` in messages.
const fn status_word(status: &RequestStatus) -> &'static str {
    match status {
        RequestStatus::Pending => "pending",
        RequestStatus::Approved(_) => "approved",
        RequestStatus::Denied => "denied",
        RequestStatus::Expired => "expired",
        RequestStatus::Cancelled => "cancelled",
        RequestStatus::Revoked => "revoked",
        RequestStatus::Error { .. } => "failed",
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

/// What to install locally for an approved SSH grant.
#[derive(Debug)]
struct SshSetup<'a> {
    /// Straight to the target, or through the relay.
    route: agent::Route,
    /// Where ssh connects: the target's or the relay's address.
    host: &'a str,
    port: u16,
    /// Host keys pinned for `host:port`.
    host_keys: &'a [String],
    /// The certificate loaded with the key (direct grants only: the relay
    /// authenticates the bound key itself).
    certificate: Option<Certificate>,
}

/// Check that `grant` is an SSH grant for `target` as `user` and say how
/// to install it.
///
/// # Errors
/// If the grant is for something else or carries an invalid host or
/// certificate.
fn ssh_setup<'a>(
    target: &TargetName,
    user: &UnixUser,
    grant: &'a GrantView,
) -> Result<SshSetup<'a>> {
    let (setup, granted_user) = match &grant.access {
        GrantAccess::Ssh(ssh) => (
            SshSetup {
                route: agent::Route::Direct,
                host: &ssh.host,
                port: ssh.port,
                host_keys: &ssh.host_keys,
                certificate: Some(
                    Certificate::from_openssh(&ssh.certificate)
                        .context("the grant's certificate is invalid")?,
                ),
            },
            &ssh.user,
        ),
        GrantAccess::Relay(relay) => {
            ensure!(
                &relay.target == target,
                "the grant is for target {}, not {target}",
                relay.target
            );
            (
                SshSetup {
                    route: agent::Route::Relay,
                    host: &relay.relay_host,
                    port: relay.relay_port,
                    host_keys: std::slice::from_ref(&relay.relay_host_key),
                    certificate: None,
                },
                &relay.user,
            )
        }
        GrantAccess::Api(_) => bail!("the broker returned a non-ssh grant for an ssh request"),
    };
    ensure!(
        granted_user == user,
        "the grant is for user {granted_user}, not {user}"
    );
    ensure!(
        agent::is_safe_host(setup.host),
        "the grant's host {:?} is invalid",
        setup.host
    );
    ensure!(setup.port != 0, "the grant's port is invalid");
    Ok(setup)
}

/// Start the grant's agent, load the key (and, for a direct grant, its
/// certificate) into it, pin the host keys of where ssh connects and record
/// the grant. On failure nothing is left behind.
async fn install_grant(
    target: &TargetName,
    user: &UnixUser,
    key: &PrivateKey,
    grant: &GrantView,
) -> Result<()> {
    let setup = ssh_setup(target, user, grant)?;
    let remaining = grant.not_after.saturating_sub(unix_now());
    let lifetime = Duration::from_secs(
        u64::try_from(remaining)
            .ok()
            .filter(|s| *s > 0)
            .context("the grant has already ended")?,
    );

    let agent = agent::start(&grant.grant_id, lifetime)?;
    let install = async {
        agent::record(
            &agent,
            &agent::GrantRecord {
                grant_id: grant.grant_id.clone(),
                target: target.clone(),
                route: setup.route,
                host: setup.host.to_owned(),
                port: setup.port,
                user: user.clone(),
                not_after: grant.not_after,
                socket: agent.socket.clone(),
                pid: agent.pid,
            },
        )?;
        match &setup.certificate {
            Some(cert) => agent::add_cert(&agent, key, cert, lifetime).await?,
            None => agent::add_key(&agent, key, lifetime).await?,
        }
        agent::write_known_hosts(&agent.dir, setup.host, setup.port, setup.host_keys)?;
        Ok::<_, anyhow::Error>(())
    };
    if let Err(e) = install.await {
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
    let secret = &call.secret;
    let active = http::active(secret, unix_now())?;
    if active.is_empty() {
        return Err(Exit::new(
            EXIT_NO_GRANT,
            format!("no active api grant for {secret}; run warden request api {secret} --for <window> --goal <text>"),
        )
        .into());
    }
    let body = http::read_body(call.data.as_deref(), call.data_file.as_deref())?;
    let proxy = http::proxy_request(&call.method, &call.url, call.headers, body.as_deref())?;
    let path = url::Url::parse(&proxy.url)
        .context("the broker request holds an invalid URL")?
        .path()
        .to_owned();
    let Some(grant) = http::covering(&active, &proxy.method, &path) else {
        return Err(Exit::new(
            EXIT_NO_GRANT,
            http::no_covering_message(secret, &proxy.method, &path),
        )
        .into());
    };
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
                "  {}  {}  grant {}  until {}",
                r.target,
                local_subject(&r),
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

/// How `status` shows where a local grant connects.
fn local_subject(record: &agent::GrantRecord) -> String {
    let (user, host, port) = (&record.user, &record.host, record.port);
    match record.route {
        agent::Route::Direct => format!("{user}@{host}:{port}"),
        agent::Route::Relay => format!("{user} via relay {host}:{port}"),
    }
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
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey, certificate};
    use warden_broker_proto::{
        ApiGrant, GrantAccess, GrantView, Id, RelayGrant, RequestStatus, SshGrant,
    };

    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use super::{
        CallError, check_scope_not_wider, local_subject, next_retry_delay, ssh_setup,
        terminal_exit_code, wait_for_decision,
    };
    use crate::agent::{GrantRecord, Route};

    fn relay_view(relay: RelayGrant) -> GrantView {
        GrantView {
            grant_id: Id::random(),
            not_before: 0,
            not_after: 1,
            access: GrantAccess::Relay(relay),
        }
    }

    fn nas_relay() -> RelayGrant {
        RelayGrant {
            target: "nas".parse().unwrap(),
            user: "backup".parse().unwrap(),
            relay_host: "relay.example.com".to_owned(),
            relay_port: 2222,
            relay_host_key: PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
                .unwrap()
                .public_key()
                .to_openssh()
                .unwrap(),
            digest: "ab".repeat(32),
        }
    }

    /// A direct grant for `alice@pi` reaching `pi.example.com:<port>`, with
    /// a certificate signed by a throwaway CA.
    fn pi_direct(port: u16) -> GrantView {
        let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut cert =
            certificate::Builder::new_with_random_nonce(&mut OsRng, key.public_key(), 0, 1)
                .unwrap();
        cert.cert_type(certificate::CertType::User).unwrap();
        cert.valid_principal("alice").unwrap();
        GrantView {
            grant_id: Id::random(),
            not_before: 0,
            not_after: 1,
            access: GrantAccess::Ssh(SshGrant {
                certificate: cert.sign(&ca).unwrap().to_openssh().unwrap(),
                host: "pi.example.com".to_owned(),
                port,
                user: "alice".parse().unwrap(),
                host_keys: Vec::new(),
            }),
        }
    }

    #[test]
    fn direct_grant_with_port_zero_is_refused() {
        let (target, user) = ("pi".parse().unwrap(), "alice".parse().unwrap());
        let ok = pi_direct(22);
        let setup = ssh_setup(&target, &user, &ok).unwrap();
        assert_eq!(setup.route, Route::Direct);
        assert_eq!((setup.host, setup.port), ("pi.example.com", 22));
        assert!(setup.certificate.is_some());

        let no_port = pi_direct(0);
        let refused = ssh_setup(&target, &user, &no_port).unwrap_err();
        assert!(refused.to_string().contains("port"), "{refused}");
    }

    /// A relay grant connects to the relay, pins only the relay's host key
    /// and loads no certificate.
    #[test]
    fn relay_grant_installs_relay_address_and_key_without_certificate() {
        let relay = nas_relay();
        let view = relay_view(relay.clone());
        let setup = ssh_setup(&relay.target, &relay.user, &view).unwrap();
        assert_eq!(setup.route, Route::Relay);
        assert_eq!(setup.host, "relay.example.com");
        assert_eq!(setup.port, 2222);
        assert_eq!(setup.host_keys, [relay.relay_host_key]);
        assert!(setup.certificate.is_none());
    }

    #[test]
    fn relay_grant_for_something_else_is_refused() {
        let relay = nas_relay();
        let user = relay.user.clone();
        let target = relay.target.clone();
        let refused = |view: GrantView| ssh_setup(&target, &user, &view).unwrap_err().to_string();

        let other_target = relay_view(RelayGrant {
            target: "pi".parse().unwrap(),
            ..relay.clone()
        });
        assert!(refused(other_target).contains("target pi"));
        let other_user = relay_view(RelayGrant {
            user: "root".parse().unwrap(),
            ..relay.clone()
        });
        assert!(refused(other_user).contains("user root"));
        for host in ["-oProxyCommand=x", "a b", ""] {
            let bad = relay_view(RelayGrant {
                relay_host: host.to_owned(),
                ..relay.clone()
            });
            assert!(refused(bad).contains("host"), "{host:?}");
        }
        let no_port = relay_view(RelayGrant {
            relay_port: 0,
            ..relay
        });
        assert!(refused(no_port).contains("port"));
    }

    #[test]
    fn status_says_when_a_grant_goes_through_the_relay() {
        let mut record = GrantRecord {
            grant_id: Id::random(),
            target: "nas".parse().unwrap(),
            route: Route::Relay,
            host: "relay.example.com".to_owned(),
            port: 2222,
            user: "backup".parse().unwrap(),
            not_after: 1,
            socket: PathBuf::from("/tmp/s.sock"),
            pid: 1,
        };
        assert_eq!(
            local_subject(&record),
            "backup via relay relay.example.com:2222"
        );
        record.route = Route::Direct;
        assert_eq!(local_subject(&record), "backup@relay.example.com:2222");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn interrupt_after_approval_revokes_the_grant() {
        use warden_broker::testkit::{CapturingNotifier, TestBroker};
        use warden_broker_proto::Window;
        use zeroize::Zeroizing;

        use crate::{Client, EXIT_INTERRUPTED, withdraw_after_interrupt};

        let broker = TestBroker::new().await;
        let key = broker.add_agent("bot").await;
        let urls = broker.spawn_behind_serve().await;
        let client = Client::new(&urls.api, Zeroizing::new(key)).unwrap();
        let req = TestBroker::pi_request("restart the backup job", Window::M30);
        let created = client.create(&req).await.unwrap();
        let token = CapturingNotifier::token(&broker.capture.next().await);
        let approved = broker.approve(&token, Window::M30).await;
        assert!(approved.status.is_success(), "{}", approved.body);

        // The owner approved before the cancel: the grant is revoked, not left.
        let exit = withdraw_after_interrupt(&client, &created.id).await;
        assert_eq!(exit.code, EXIT_INTERRUPTED);
        assert!(
            exit.message
                .contains("approved before it could be cancelled")
                && exit.message.contains("revoked"),
            "{}",
            exit.message
        );
        assert_eq!(
            client.status(&created.id, 0).await,
            Ok(RequestStatus::Revoked)
        );
        assert!(client.grants().await.unwrap().is_empty());

        // A request decided otherwise is just reported.
        let again = client.create(&req).await.unwrap();
        assert_eq!(client.cancel(&again.id).await, Ok(()));
        let exit = withdraw_after_interrupt(&client, &again.id).await;
        assert!(
            exit.message.contains("already cancelled"),
            "{}",
            exit.message
        );
    }

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

    fn api_grant(methods: &[&str], prefix: &str) -> ApiGrant {
        ApiGrant {
            secret: "github".parse().unwrap(),
            origin: "https://api.example.com".to_owned(),
            methods: methods.iter().map(|m| (*m).to_owned()).collect(),
            path_prefix: prefix.to_owned(),
            header: "authorization".to_owned(),
            digest: String::new(),
        }
    }

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn narrow_grants_pass_the_scope_check() {
        let get = api_grant(&["GET", "HEAD"], "/v1/");
        assert!(check_scope_not_wider(&get, None, None).is_ok());
        let post = api_grant(&["POST"], "/v1/repos");
        let asked = strings(&["POST", "GET"]);
        assert!(check_scope_not_wider(&post, Some(&asked), Some("/v1/")).is_ok());
    }

    #[test]
    fn older_broker_grant_wider_than_requested_is_refused() {
        // Default request, broker ignored the missing scope and granted write.
        let full = api_grant(&["GET", "POST", "DELETE"], "/");
        assert_eq!(
            check_scope_not_wider(&full, None, None).unwrap_err(),
            "methods POST, DELETE"
        );
        // An empty method list is not read-only either.
        assert!(check_scope_not_wider(&api_grant(&[], "/"), None, None).is_err());
        // Requested GET only, got more.
        let asked = strings(&["GET"]);
        assert_eq!(
            check_scope_not_wider(&full, Some(&asked), None).unwrap_err(),
            "methods POST, DELETE"
        );
        // Requested a path, got a wider one.
        let wide = api_grant(&["GET"], "/");
        assert_eq!(
            check_scope_not_wider(&wide, None, Some("/v1/")).unwrap_err(),
            "path / is not under /v1/"
        );
        assert!(check_scope_not_wider(&api_grant(&["GET"], "/v1x"), None, Some("/v1")).is_err());
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
