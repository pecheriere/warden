//! `warden-server` binary.

use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use sqlx::SqlitePool;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;
use url::Url;
use warden_broker::approval::passkeys::{self, Passkeys};
use warden_broker::audit::AuditLog;
use warden_broker::config::{
    BackendSettings, Config, DEFAULT_AUDIENCE_PATH, UrlTransport, parse_public_url,
};
use warden_broker::identity::TailscaleServeIdentity;
use warden_broker::notify::{ChannelSettings, Fallback, Notifier};
use warden_broker::policy::local::{ACCESS_NOTE, Unverified, seal_policy_file};
use warden_broker::policy::{LocalBackend, OnePasswordConnect, SecretBackend};
use warden_broker::private_files::{self, DirectoryState};
use warden_broker::relay::host_key::RelayHostKey;
use warden_broker::relay::{RelayEndpoint, RelayLimits, RelayServer, host_key};
use warden_broker::requests::{self, AuditOutcome, Clock, Requests, SystemClock};
use warden_broker::{AppState, agents, audience, audit, build_routers, enrollment, store};
use warden_broker::{doctor, health};
use warden_broker_proto::AgentName;

#[derive(Parser)]
#[command(version, about = "warden approval broker server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the agent API and approval UI.
    Serve,
    /// Manage agent API keys.
    #[command(subcommand)]
    Agent(AgentCommand),
    /// Inspect the audit log.
    #[command(subcommand)]
    Audit(AuditCommand),
    /// Check the configuration and say what to fix. Read-only unless
    /// --send-test-notification is given. Exits 1 when a check failed, otherwise
    /// 0, listing what could not be checked and how to check it by hand.
    Doctor {
        /// Send a test notification through every channel: it reaches the
        /// owner's phone.
        #[arg(long)]
        send_test_notification: bool,
        /// Exit 7 when nothing failed but some check could not run.
        #[arg(long)]
        strict: bool,
    },
    /// Print a one-time code (valid 10 minutes) for enrolling a passkey.
    Enroll,
    /// Probe the agent API's /healthz (for container health checks); exits 0
    /// when healthy, 1 otherwise.
    Healthcheck,
    /// Manage enrolled passkeys.
    #[command(subcommand)]
    Passkey(PasskeyCommand),
    /// With the local backend: end a finished policy file with its digest, and
    /// replace it in one step. Needs no other setting.
    SealPolicy {
        /// The policy file, which warden reads.
        file: PathBuf,
        /// Take the content from this draft, rather than from the file itself.
        #[arg(long, value_name = "DRAFT")]
        from: Option<PathBuf>,
        /// Seal the file itself although its digest does not match. It may be a mix
        /// of two versions: run without this first, and read what it would allow.
        #[arg(long, conflicts_with = "from")]
        accept_unverified: bool,
    },
}

#[derive(Subcommand)]
enum PasskeyCommand {
    /// List enrolled passkeys.
    List,
    /// Remove an enrolled passkey.
    Remove { id: String },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Verify the audit log's hash chain.
    Verify,
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Create an agent and print the command to run on its machine. With
    /// --public-key it signs its requests with that SSH key and no bearer
    /// key is made; without, its bearer key is printed once, on stdout.
    Add {
        name: AgentName,
        /// The agent API's URL, as agents reach it (not the approval UI's),
        /// to put in the printed command.
        #[arg(long, value_name = "URL", value_parser = enrollment::parse_agent_api_url)]
        server: Option<Url>,
        /// The agent's OpenSSH public key line (ssh-ed25519 or
        /// ecdsa-sha2-nistp256), as in its .pub file.
        #[arg(long)]
        public_key: Option<String>,
    },
    /// Switch an existing agent to signing requests with an SSH key; its
    /// bearer key stops working at once.
    SetKey {
        name: AgentName,
        /// The OpenSSH public key line, as in the .pub file.
        public_key: String,
    },
    /// List agents with their kind of authentication and key fingerprint.
    List,
    /// Revoke an agent's key.
    Revoke { name: AgentName },
}

fn db_path() -> Result<PathBuf> {
    match std::env::var_os("WARDEN_DB_PATH") {
        Some(path) if !path.is_empty() => Ok(path.into()),
        _ => bail!("missing required environment variable WARDEN_DB_PATH"),
    }
}

fn audit_path() -> Result<PathBuf> {
    match std::env::var_os("WARDEN_AUDIT_PATH") {
        Some(path) if !path.is_empty() => Ok(path.into()),
        _ => bail!("missing required environment variable WARDEN_AUDIT_PATH"),
    }
}

fn audience_path() -> PathBuf {
    std::env::var_os("WARDEN_AUDIENCE_PATH")
        .filter(|path| !path.is_empty())
        .map_or_else(|| DEFAULT_AUDIENCE_PATH.into(), PathBuf::from)
}

fn public_url() -> Result<Url> {
    match std::env::var("WARDEN_PUBLIC_URL") {
        Ok(value) if !value.trim().is_empty() => Ok(parse_public_url(&value)?),
        _ => bail!("missing required environment variable WARDEN_PUBLIC_URL"),
    }
}

/// Longest `agent revoke` waits to open the audit log, which verifies all of it.
const AUDIT_OPEN_WAIT: Duration = Duration::from_secs(30);

async fn open_audit() -> Result<AuditLog> {
    let path = audit_path()?;
    AuditLog::open(&path)
        .await
        .with_context(|| format!("opening audit log {}", path.display()))
}

#[tokio::main]
async fn main() -> Result<ExitCode> {
    match Cli::parse().command {
        Command::Agent(command) => agent(command).await?,
        Command::Audit(AuditCommand::Verify) => {
            let path = audit_path()?;
            let count =
                audit::verify(&path).with_context(|| format!("verifying {}", path.display()))?;
            println!("audit log ok: {count} entries");
            report_waiting_entries().await;
        }
        Command::Doctor {
            send_test_notification,
            strict,
        } => {
            let report = doctor::live::report(send_test_notification).await;
            print!("{}", report.render(strict));
            return Ok(ExitCode::from(report.exit_code(strict)));
        }
        Command::Healthcheck => {
            let listen = health::api_listen(|var| std::env::var(var).ok())?;
            health::probe(listen).await?;
        }
        Command::Serve => serve().await?,
        Command::Enroll => enroll().await?,
        Command::Passkey(command) => passkey(command).await?,
        Command::SealPolicy {
            file,
            from,
            accept_unverified,
        } => {
            let unverified = if accept_unverified {
                Unverified::Accept
            } else {
                Unverified::Refuse
            };
            let shown = file.display().to_string();
            let sealed = tokio::task::spawn_blocking(move || {
                seal_policy_file(&file, from.as_deref(), unverified)
            })
            .await
            .context("the seal task failed")?
            .with_context(|| format!("sealing {shown}"))?;
            println!(
                "{shown} sealed: {} target(s), {} API entry(ies). Entries and secrets are not \
                 checked here: run warden-server doctor.",
                sealed.targets, sealed.api_entries
            );
            for line in &sealed.access {
                println!("  {line}");
            }
            println!("{ACCESS_NOTE}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn agent(command: AgentCommand) -> Result<()> {
    let pool = store::open(&db_path()?).await?;
    match command {
        AgentCommand::Add {
            name,
            server,
            public_key: None,
        } => {
            let audit = open_audit().await?;
            let key = agents::add_audited(&pool, &audit, &name)
                .await
                .with_context(|| format!("adding agent {name}"))?;
            eprintln!("warning: this key is shown once and cannot be recovered; store it now.");
            println!("{}", key.expose());
            eprintln!("{}", enrollment::bearer_next_steps(&name, server.as_ref()));
        }
        AgentCommand::Add {
            name,
            server,
            public_key: Some(line),
        } => {
            let key = agents::AgentPublicKey::parse(&line).context("refusing the public key")?;
            let audit = open_audit().await?;
            agents::add_key_audited(&pool, &audit, &name, &key)
                .await
                .with_context(|| format!("adding agent {name}"))?;
            eprintln!(
                "agent {name} added; it signs requests with key {}",
                key.fingerprint()
            );
            // The agent exists by now: not reading the audience only leaves
            // the pin out of the command.
            let audience = audience::read_existing(audience_path())
                .await
                .inspect_err(|e| {
                    eprintln!(
                        "note: the command below does not pin the broker's audience ({e}); \
                         login pins what the broker reports"
                    );
                })
                .ok();
            eprintln!(
                "{}",
                enrollment::key_next_steps(&name, server.as_ref(), audience.as_ref())
            );
        }
        AgentCommand::SetKey { name, public_key } => {
            let key =
                agents::AgentPublicKey::parse(&public_key).context("refusing the public key")?;
            let audit = open_audit().await?;
            agents::set_key_audited(&pool, &audit, &name, &key)
                .await
                .with_context(|| format!("setting the key of agent {name}"))?;
            eprintln!(
                "agent {name} now signs requests with key {}; any bearer key it had no longer works",
                key.fingerprint()
            );
        }
        AgentCommand::List => {
            for agent in agents::list(&pool).await? {
                let state = agent
                    .revoked_at
                    .map_or_else(|| "active".to_owned(), |t| format!("revoked@{t}"));
                println!(
                    "{}\tcreated@{}\t{state}\t{}\t{}",
                    agent.name,
                    agent.created_at,
                    agent.auth.as_str(),
                    agent.fingerprint.as_deref().unwrap_or("-")
                );
            }
        }
        AgentCommand::Revoke { name } => {
            // Stop access first: nothing about the audit log can prevent this.
            let now = SystemClock.now();
            let affected = requests::revoke_agent(&pool, &name, now)
                .await
                .with_context(|| format!("revoking agent {name}"))?;
            eprintln!("agent {name} revoked; {} request(s) ended", affected.len());
            record_revocation(&pool, &name).await;
        }
    }
    Ok(())
}

/// Say if entries are waiting in the database to reach the log just verified, as
/// the log is then missing them. The database is optional here: the check above
/// needs only the log.
async fn report_waiting_entries() {
    let Some(db) = std::env::var_os("WARDEN_DB_PATH").filter(|path| !path.is_empty()) else {
        return;
    };
    match requests::revocation::count_waiting_read_only(PathBuf::from(db).as_path()).await {
        Ok(0) => {}
        Ok(n) => eprintln!(
            "warning: {n} entries are waiting in the database and are not in this log yet: a \
             running server writes them once the log works"
        ),
        Err(reason) => eprintln!("could not check for entries waiting in the database: {reason}"),
    }
}

/// Write the entries of a revocation that has taken effect to the audit log. If
/// that fails, print what is missing, as this command has no server log, and exit
/// with an error. A running server writes those entries once the log works.
async fn record_revocation(pool: &SqlitePool, name: &AgentName) {
    let cause = match tokio::time::timeout(AUDIT_OPEN_WAIT, open_audit()).await {
        Ok(Ok(audit)) => {
            let clock: Arc<dyn Clock> = Arc::new(SystemClock);
            let written = requests::write_entries(pool, &Arc::new(audit), &clock).await;
            if written.outcome == AuditOutcome::Recorded {
                return;
            }
            written
                .cause
                .unwrap_or_else(|| "entries are still waiting".to_owned())
        }
        Ok(Err(e)) => format!("{e:#}"),
        Err(_) => format!("opening it took over {} s", AUDIT_OPEN_WAIT.as_secs()),
    };
    eprintln!("error: agent {name} is revoked, but this is NOT in the audit log: {cause}");
    match requests::unwritten_entries(pool).await {
        Ok(entries) => {
            eprintln!("these entries are waiting in the database for the log to work:");
            for entry in entries {
                match serde_json::to_string(&entry) {
                    Ok(line) => eprintln!("{line}"),
                    Err(e) => eprintln!("(an entry cannot be shown: {e})"),
                }
            }
        }
        Err(e) => eprintln!("the waiting entries cannot be read: {e}"),
    }
    // Not by returning: the runtime waits for blocking work when it shuts down,
    // so an audit volume that has stalled would keep this process from ending.
    std::process::exit(1);
}

async fn enroll() -> Result<()> {
    let public_url = public_url()?;
    let pool = store::open(&db_path()?).await?;
    let audit = Arc::new(open_audit().await?);
    let service = Passkeys::new(pool, audit, &public_url, Arc::new(SystemClock))
        .context("configuring WebAuthn for WARDEN_PUBLIC_URL")?;
    let code = service
        .create_enrollment_code(SystemClock.now())
        .await
        .context("creating an enrollment code")?;
    let page = public_url
        .join("enroll")
        .context("building the enrollment URL")?;
    println!("enrollment code: {code}");
    println!("open {page} on your phone; the code works once, for 10 minutes");
    Ok(())
}

async fn passkey(command: PasskeyCommand) -> Result<()> {
    let pool = store::open(&db_path()?).await?;
    match command {
        PasskeyCommand::List => {
            for passkey in passkeys::list(&pool).await? {
                println!(
                    "{}\t{}\tcreated@{}",
                    passkey.id, passkey.label, passkey.created_at
                );
            }
        }
        PasskeyCommand::Remove { id } => {
            let audit = open_audit().await?;
            passkeys::remove(&pool, &audit, &id)
                .await
                .with_context(|| format!("removing passkey {id}"))?;
            eprintln!("passkey {id} removed");
        }
    }
    Ok(())
}

/// How often pending requests past their deadline are expired.
const SWEEP_EVERY: Duration = Duration::from_secs(15);

/// How long in-flight requests (long polls) may delay shutdown.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// The configured channels in priority order: the first that accepts the
/// notification wins and the rest are fallbacks.
fn build_notifier(config: &Config) -> Result<Arc<dyn Notifier>> {
    let build = |settings: &ChannelSettings| {
        settings
            .build()
            .with_context(|| format!("configuring the {} notifier", settings.kind().name()))
    };
    let primary = build(config.notify.primary())?;
    let fallbacks = config
        .notify
        .fallbacks()
        .iter()
        .map(build)
        .collect::<Result<Vec<_>>>()?;
    Ok(Arc::new(Fallback::new(primary, fallbacks)))
}

/// Say at startup which service URLs send tokens and secrets without TLS. Only
/// the variable, because a URL can hold a secret.
fn log_plain_http(config: &Config) {
    for (variable, transport) in config.plain_http_urls() {
        if transport == UrlTransport::PlainRemote {
            tracing::warn!(
                variable,
                "plain http to a host that is not clearly local or private: tokens and secrets \
                 cross that path in clear"
            );
        } else {
            tracing::info!(variable, "plain http to a local or private host");
        }
    }
}

/// Where agents reach the relay and the relay's host key (loaded, and
/// created on first use), or `None` when `WARDEN_RELAY_PUBLIC_ADDR` is unset.
async fn relay_endpoint(config: &Config) -> Result<Option<(RelayEndpoint, RelayHostKey)>> {
    let Some(addr) = &config.relay.public_addr else {
        tracing::info!("WARDEN_RELAY_PUBLIC_ADDR unset; relay targets cannot be requested");
        return Ok(None);
    };
    let path = &config.relay.host_key_path;
    let key = host_key::load_or_create(path.clone())
        .await
        .with_context(|| format!("loading the relay host key {}", path.display()))?;
    tracing::info!(
        public_addr = %format!("{}:{}", addr.host, addr.port),
        host_key = %key.fingerprint(),
        "relay host key loaded"
    );
    let endpoint = RelayEndpoint::new(addr, &key).context("encoding the relay host key")?;
    Ok(Some((endpoint, key)))
}

/// Bind the relay listener and start serving agents until `stop`.
async fn start_relay(
    config: &Config,
    requests: &Requests,
    backend: Arc<dyn SecretBackend>,
    audit: Arc<AuditLog>,
    key: &RelayHostKey,
    stop: watch::Receiver<bool>,
) -> Result<tokio::task::JoinHandle<()>> {
    let limits = RelayLimits {
        max_sessions: config.relay.max_sessions,
        ..RelayLimits::default()
    };
    let server = RelayServer::new(requests.clone(), backend, audit, key, limits)
        .context("starting the SSH relay")?;
    let listener = TcpListener::bind(config.relay.listen)
        .await
        .with_context(|| format!("binding the SSH relay on {}", config.relay.listen))?;
    tracing::info!(relay = %config.relay.listen, max_sessions = limits.max_sessions, "SSH relay listening");
    Ok(tokio::spawn(server.serve(listener, stop)))
}

/// Resolves on SIGTERM or Ctrl-C.
async fn termination() -> Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing the SIGTERM handler")?;
    tokio::select! {
        _ = term.recv() => {}
        result = tokio::signal::ctrl_c() => result.context("installing the Ctrl-C handler")?,
    }
    Ok(())
}

async fn stopped(mut rx: watch::Receiver<bool>) {
    // Any change, or the sender going away, means stop.
    let _ = rx.changed().await;
}

/// The broker's parts, ready to serve.
struct App {
    api: axum::Router,
    approval: axum::Router,
    requests: Requests,
    backend: Arc<dyn SecretBackend>,
    audit: Arc<AuditLog>,
    /// The relay's host key, when the relay is configured.
    relay_key: Option<RelayHostKey>,
}

/// The configured secret backend. The local one is checked whole first, and
/// an invalid one stops the server.
async fn secret_backend(config: &Config, audit: &Arc<AuditLog>) -> Result<Arc<dyn SecretBackend>> {
    match &config.backend {
        BackendSettings::OnePassword(connect) => Ok(Arc::new(OnePasswordConnect::new(
            connect.url.clone(),
            connect.token.clone(),
            connect.vault.clone(),
        ))),
        BackendSettings::Local(settings) => {
            tracing::warn!(
                "secrets come from files on this host: a compromised host gets them, and \
                 1Password stays the recommended backend (docs/local-backend.md)"
            );
            let backend = LocalBackend::open(settings, audit.clone())
                .await
                .context("the local secret backend is not usable")?;
            Ok(Arc::new(backend))
        }
    }
}

/// Make the data directory private if it is clearly warden's, and say what
/// happened if not. Refuses to go on if others can write to it.
async fn report_data_directory(config: &Config) -> Result<()> {
    let directory = private_files::data_directory(&config.db_path);
    let others = [
        config.audit_path.as_path(),
        config.audience_path.as_path(),
        config.relay.host_key_path.as_path(),
    ];
    let state = private_files::tighten_data_directory(&config.db_path, &others).await?;
    match state {
        DirectoryState::Tightened => {
            tracing::info!(path = %directory.display(), "data directory set to mode 0700");
        }
        DirectoryState::Readable { reason } => tracing::warn!(
            path = %directory.display(),
            %reason,
            "others can list the data directory, and warden did not change it: they can see \
             its files' names and sizes, not their contents. warden-server doctor fails it"
        ),
        DirectoryState::Unchecked { reason } => tracing::warn!(
            path = %directory.display(),
            %reason,
            "warden could not check the data directory's mode"
        ),
        _ => {}
    }
    Ok(())
}

async fn build_app(config: &Arc<Config>) -> Result<App> {
    report_data_directory(config).await?;
    let pool = store::open(&config.db_path).await?;
    let audit = Arc::new(
        AuditLog::open(&config.audit_path)
            .await
            .with_context(|| format!("opening audit log {}", config.audit_path.display()))?,
    );
    let backend = secret_backend(config, &audit).await?;
    let audience = audience::load_or_create(config.audience_path.clone())
        .await
        .with_context(|| format!("loading the audience {}", config.audience_path.display()))?;
    tracing::info!(%audience, "audience loaded");
    let (relay, relay_key) = relay_endpoint(config).await?.unzip();
    let clock = Arc::new(SystemClock);
    let requests = Requests::new(
        pool.clone(),
        audit.clone(),
        backend.clone(),
        build_notifier(config)?,
        config.public_url.clone(),
        clock.clone(),
        relay,
    )
    .with_limits(config.requests)
    .with_call_limits(config.proxy.max_calls_per_agent, config.proxy.max_calls);
    let passkeys = Passkeys::new(
        pool.clone(),
        audit.clone(),
        &config.public_url,
        clock.clone(),
    )
    .context("configuring WebAuthn for WARDEN_PUBLIC_URL")?;
    let state = AppState {
        pool,
        config: config.clone(),
        identity: Arc::new(TailscaleServeIdentity),
        audit: audit.clone(),
        backend: backend.clone(),
        clock,
        requests: requests.clone(),
        passkeys: Arc::new(passkeys),
        audience,
    };
    let (api, approval) = build_routers(state);
    Ok(App {
        api,
        approval,
        requests,
        backend,
        audit,
        relay_key,
    })
}

async fn serve() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        // Colour only for a person at a terminal: under Docker/systemd the
        // lines go to a log pipeline, where escape codes are noise.
        .with_ansi(std::io::stdout().is_terminal())
        .init();
    // This reads secret files, so it does not run on the async workers.
    let config = tokio::task::spawn_blocking(Config::from_env)
        .await
        .context("reading configuration")?
        .context("reading configuration")?;
    let config = Arc::new(config);
    let App {
        api,
        approval,
        requests,
        backend,
        audit,
        relay_key,
    } = build_app(&config).await?;

    let api_listener = TcpListener::bind(config.api_listen)
        .await
        .with_context(|| format!("binding the agent API on {}", config.api_listen))?;
    let approval_listener = TcpListener::bind(config.approval_listen)
        .await
        .with_context(|| format!("binding the approval UI on {}", config.approval_listen))?;
    log_plain_http(&config);
    match &config.backend {
        BackendSettings::OnePassword(connect) => tracing::info!(
            api = %config.api_listen,
            approval = %config.approval_listen,
            public_url = %config.public_url,
            vault = %connect.vault,
            "warden-server listening"
        ),
        BackendSettings::Local(_) => tracing::info!(
            api = %config.api_listen,
            approval = %config.approval_listen,
            public_url = %config.public_url,
            secret_backend = config.backend.name(),
            "warden-server listening"
        ),
    }

    let (stop, stop_rx) = watch::channel(false);
    let relay = match &relay_key {
        Some(key) => {
            Some(start_relay(&config, &requests, backend, audit, key, stop_rx.clone()).await?)
        }
        None => None,
    };
    // The private key now lives only in the relay's SSH configuration.
    drop(relay_key);
    let sweeper = tokio::spawn(requests::sweep_loop(requests, SWEEP_EVERY, stop_rx.clone()));
    let relay_done = async {
        if let Some(relay) = relay {
            // The relay returns once stopped and its sessions are recorded.
            relay.await.context("SSH relay task failed")?;
        }
        Ok::<(), anyhow::Error>(())
    };
    let servers = async {
        tokio::try_join!(
            async {
                axum::serve(api_listener, api)
                    .with_graceful_shutdown(stopped(stop_rx.clone()))
                    .await
                    .context("serving the agent API")
            },
            async {
                axum::serve(approval_listener, approval)
                    .with_graceful_shutdown(stopped(stop_rx.clone()))
                    .await
                    .context("serving the approval UI")
            },
            relay_done,
        )
    };
    let grace = async {
        stopped(stop_rx.clone()).await;
        tokio::time::sleep(SHUTDOWN_GRACE).await;
    };
    let signal = async {
        termination().await?;
        tracing::info!("shutdown requested");
        // A send error means every receiver is gone, which is shutdown anyway.
        let _ = stop.send(true);
        std::future::pending::<Result<()>>().await
    };
    tokio::select! {
        result = servers => { result?; }
        result = signal => result?,
        () = grace => tracing::warn!("in-flight requests did not finish in time; exiting"),
    }
    // The sender may already be gone if a listener failed first.
    let _ = stop.send(true);
    if let Err(e) = sweeper.await {
        tracing::error!(error = %e, "sweeper task failed");
    }
    Ok(())
}
