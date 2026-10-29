//! `warden-server` binary.

use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;
use url::Url;
use warden_broker::approval::passkeys::{self, Passkeys};
use warden_broker::audit::AuditLog;
use warden_broker::config::{Config, parse_public_url};
use warden_broker::health;
use warden_broker::identity::TailscaleServeIdentity;
use warden_broker::notify::{ChannelSettings, Fallback, Notifier};
use warden_broker::policy::OnePasswordConnect;
use warden_broker::proxy::CallSlots;
use warden_broker::relay::host_key::RelayHostKey;
use warden_broker::relay::{RelayEndpoint, RelayLimits, RelayServer, host_key};
use warden_broker::requests::{self, Clock as _, Requests, SystemClock};
use warden_broker::{AppState, agents, audit, build_routers, store};
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
    /// Print a one-time code (valid 10 minutes) for enrolling a passkey.
    Enroll,
    /// Probe the agent API's /healthz (for container health checks); exits 0
    /// when healthy, 1 otherwise.
    Healthcheck,
    /// Manage enrolled passkeys.
    #[command(subcommand)]
    Passkey(PasskeyCommand),
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
    /// Create an agent and print its key once.
    Add { name: AgentName },
    /// List agents.
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

fn public_url() -> Result<Url> {
    match std::env::var("WARDEN_PUBLIC_URL") {
        Ok(value) if !value.trim().is_empty() => Ok(parse_public_url(&value)?),
        _ => bail!("missing required environment variable WARDEN_PUBLIC_URL"),
    }
}

async fn open_audit() -> Result<AuditLog> {
    let path = audit_path()?;
    AuditLog::open(&path)
        .await
        .with_context(|| format!("opening audit log {}", path.display()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let command = match Cli::parse().command {
        Command::Agent(command) => command,
        Command::Audit(AuditCommand::Verify) => {
            let path = audit_path()?;
            let count =
                audit::verify(&path).with_context(|| format!("verifying {}", path.display()))?;
            println!("audit log ok: {count} entries");
            return Ok(());
        }
        Command::Healthcheck => {
            let listen = health::api_listen(|var| std::env::var(var).ok())?;
            return health::probe(listen).await;
        }
        Command::Serve => return serve().await,
        Command::Enroll => return enroll().await,
        Command::Passkey(command) => return passkey(command).await,
    };
    let pool = store::open(&db_path()?).await?;
    match command {
        AgentCommand::Add { name } => {
            let audit = open_audit().await?;
            let key = agents::add_audited(&pool, &audit, &name)
                .await
                .with_context(|| format!("adding agent {name}"))?;
            eprintln!("warning: this key is shown once and cannot be recovered; store it now.");
            println!("{}", key.expose());
        }
        AgentCommand::List => {
            for agent in agents::list(&pool).await? {
                let state = agent
                    .revoked_at
                    .map_or_else(|| "active".to_owned(), |t| format!("revoked@{t}"));
                println!("{}\tcreated@{}\t{state}", agent.name, agent.created_at);
            }
        }
        AgentCommand::Revoke { name } => {
            let audit = open_audit().await?;
            let affected = requests::revoke_agent(&pool, &audit, &name, SystemClock.now())
                .await
                .with_context(|| format!("revoking agent {name}"))?;
            eprintln!("agent {name} revoked; {} request(s) ended", affected.len());
        }
    }
    Ok(())
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
    backend: Arc<OnePasswordConnect>,
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
    backend: Arc<OnePasswordConnect>,
    audit: Arc<AuditLog>,
    /// The relay's host key, when the relay is configured.
    relay_key: Option<RelayHostKey>,
}

async fn build_app(config: &Arc<Config>) -> Result<App> {
    let pool = store::open(&config.db_path).await?;
    let audit = Arc::new(
        AuditLog::open(&config.audit_path)
            .await
            .with_context(|| format!("opening audit log {}", config.audit_path.display()))?,
    );
    let backend = Arc::new(OnePasswordConnect::new(
        config.connect_url.clone(),
        config.connect_token.clone(),
        config.vault.clone(),
    ));
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
    );
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
        proxy_calls: CallSlots::new(config.proxy.max_calls_per_agent, config.proxy.max_calls),
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
    let config = Arc::new(Config::from_env().context("reading configuration")?);
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
    tracing::info!(
        api = %config.api_listen,
        approval = %config.approval_listen,
        public_url = %config.public_url,
        vault = %config.vault,
        "warden-server listening"
    );

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
