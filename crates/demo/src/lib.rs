//! A throwaway warden on one machine, to see the approval flow before setting
//! up a real deployment. **Not secure for real use.**
//!
//! This crate is the only place the three things a deployment gets from its
//! environment are replaced:
//!
//! - the owner's identity, which comes from Tailscale Serve in production:
//!   [`parts::LoopbackOwner`];
//! - the vault, which is 1Password in production: [`parts::DemoBackend`];
//! - `WARDEN_PUBLIC_URL`, which must be https in production: [`Config`] is
//!   built with a placeholder that passes the real validation, then its public
//!   URL is set to `http://localhost:<port>/`, which browsers treat as a secure
//!   context for `WebAuthn`.
//!
//! Everything else is the broker's own code, unchanged: the routers, requests,
//! passkey ceremonies, the proxy with its redaction, and the audit log. No
//! setting of `warden-server` can reach this crate, and
//! `scripts/check-demo-not-shipped.sh` fails the build if the image or the
//! server starts to include it.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use axum::Router;
use sqlx::SqlitePool;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use url::Url;
use warden_broker::approval::passkeys::Passkeys;
use warden_broker::audit::{self, AuditLog};
use warden_broker::config::Config;
use warden_broker::notify::Doorbell;
use warden_broker::requests::{self, Clock as _, Requests, SystemClock};
use warden_broker::{AppState, agents, audience, build_routers, store};
use warden_broker_proto::AgentName;
use zeroize::Zeroizing;

pub mod parts;
mod upstream;

use parts::{DemoBackend, LoopbackOwner, TerminalNotifier};

/// Name of the one API secret the demo's vault holds.
pub const SECRET_NAME: &str = "demo-api";

/// Name of the one agent the demo enrolls.
pub const AGENT_NAME: &str = "demo-agent";

/// The owner's login. There is no one to authenticate: see
/// [`parts::LoopbackOwner`].
const OWNER_LOGIN: &str = "owner@demo.invalid";

/// How often pending requests past their deadline are expired.
const SWEEP_EVERY: Duration = Duration::from_secs(15);

/// Refuse anything but a loopback address. The demo identifies every caller
/// as the owner, so it must never be reachable from another machine.
///
/// # Errors
/// If `addr` is not a loopback address.
pub fn check_loopback(addr: SocketAddr) -> Result<()> {
    let ip: IpAddr = addr.ip();
    if ip.is_loopback() {
        Ok(())
    } else {
        bail!("the demo listens on loopback only, and refuses {addr}")
    }
}

/// A listener on a free port of `127.0.0.1`, the only address the demo uses.
async fn bind_loopback() -> Result<TcpListener> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .context("binding a loopback port")?;
    check_loopback(listener.local_addr()?)?;
    Ok(listener)
}

/// The broker's configuration, with nothing taken from the process
/// environment: a `WARDEN_*` variable meant for a real server cannot change
/// where the demo listens. The Connect and ntfy values are placeholders that
/// nothing reads, because the demo passes its own backend and notifier.
fn demo_config(
    dir: &Path,
    api_listen: SocketAddr,
    approval_listen: SocketAddr,
    public_url: Url,
) -> Result<Config> {
    let path = |file: &str| dir.join(file).display().to_string();
    let mut config = Config::from_lookup(|var| match var {
        "WARDEN_DB_PATH" => Some(path("warden.db")),
        "WARDEN_AUDIT_PATH" => Some(path("audit.jsonl")),
        "WARDEN_AUDIENCE_PATH" => Some(path("audience")),
        "WARDEN_RELAY_HOST_KEY_PATH" => Some(path("relay_host_ed25519")),
        "WARDEN_API_LISTEN" => Some(api_listen.to_string()),
        "WARDEN_APPROVAL_LISTEN" => Some(approval_listen.to_string()),
        "WARDEN_PUBLIC_URL" => Some("https://localhost".to_owned()),
        "WARDEN_OWNER_LOGIN" => Some(OWNER_LOGIN.to_owned()),
        "WARDEN_OP_CONNECT_URL" => Some("https://connect.invalid".to_owned()),
        "WARDEN_OP_CONNECT_TOKEN" => Some("unused-by-the-demo".to_owned()),
        "WARDEN_NOTIFY" => Some("ntfy".to_owned()),
        "WARDEN_NOTIFY_NTFY_URL" => Some("https://ntfy.invalid/warden".to_owned()),
        _ => None,
    })
    .context("building the demo configuration")?;
    // Past validation on purpose: this field is what the real server's
    // `parse_public_url` refuses, and it stays refused there.
    config.public_url = public_url;
    Ok(config)
}

/// A value quoted for a POSIX shell.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// How the banner should name the `warden` CLI: the one beside this binary when
/// there is one, as in `target/debug` or a directory holding both unpacked
/// archives, and otherwise whatever `warden` is on the `PATH`.
fn warden_command(demo_binary: Option<&Path>) -> String {
    demo_binary
        .and_then(Path::parent)
        .map(|dir| dir.join("warden"))
        .filter(|cli| cli.is_file())
        .map_or_else(
            || "warden".to_owned(),
            |cli| shell_quote(&cli.display().to_string()),
        )
}

/// Create `path` with its parents, readable only by this user.
async fn private_dir(path: &Path) -> Result<()> {
    tokio::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .await
        .with_context(|| format!("creating {}", path.display()))
}

/// Create `path`, readable only by this user.
async fn private_file(path: &Path, contents: &str) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .await
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents.as_bytes()).await?;
    file.flush().await?;
    Ok(())
}

/// Write what the `warden` CLI needs into the temporary directory, and return
/// the path of the file to source: it points the CLI there, so a real
/// configuration on this machine is neither used nor changed, and the
/// Keychain is not touched.
async fn write_agent_env(dir: &Path, api_url: &Url, agent_key: &str) -> Result<PathBuf> {
    let config_dir = dir.join("config");
    let state_dir = dir.join("state");
    private_dir(&config_dir.join("warden")).await?;
    private_dir(&state_dir).await?;
    private_file(
        &config_dir.join("warden/config.toml"),
        &format!("server = \"{api_url}\"\nagent = \"{AGENT_NAME}\"\n"),
    )
    .await?;
    let env_path = dir.join("agent.env");
    let contents = Zeroizing::new(format!(
        "# Throwaway settings for the warden demo, gone when it stops.\n\
         export WARDEN_DEMO_DIR={}\n\
         export XDG_CONFIG_HOME={}\n\
         export XDG_STATE_HOME={}\n\
         export WARDEN_AGENT_KEY={}\n",
        shell_quote(&dir.display().to_string()),
        shell_quote(&config_dir.display().to_string()),
        shell_quote(&state_dir.display().to_string()),
        shell_quote(agent_key),
    ));
    private_file(&env_path, &contents).await?;
    Ok(env_path)
}

/// The demo's listening sockets, every one on loopback.
struct Listeners {
    api: TcpListener,
    approval: TcpListener,
    target: TcpListener,
}

/// Start the broker's two listeners, the demo API and the sweeper of expired
/// requests. Dropping the set stops them.
fn serve_all(
    listeners: Listeners,
    api: Router,
    approval: Router,
    target: upstream::Target,
    requests: Requests,
) -> (JoinSet<Result<()>>, watch::Sender<bool>) {
    let (stop, stop_rx) = watch::channel(false);
    let mut servers = JoinSet::new();
    servers.spawn(async move {
        axum::serve(listeners.api, api)
            .await
            .context("serving the agent API")
    });
    servers.spawn(async move {
        axum::serve(listeners.approval, approval)
            .await
            .context("serving the approval UI")
    });
    servers.spawn(target.serve(listeners.target));
    servers.spawn(async move {
        requests::sweep_loop(requests, SWEEP_EVERY, stop_rx).await;
        Ok(())
    });
    (servers, stop)
}

/// Everything the demo sets up before the demo API has any keys: its directory,
/// its database, its listeners, what it tells the owner. The banner is printed
/// from this, so no key can reach the terminal.
pub struct Prepared {
    dir: TempDir,
    pool: SqlitePool,
    config: Arc<Config>,
    audit: Arc<AuditLog>,
    passkeys: Arc<Passkeys>,
    listeners: Listeners,
    approval_url: Url,
    api_url: Url,
    target_origin: Url,
    target_url: Url,
    enrollment_code: String,
    agent_env: PathBuf,
}

impl Prepared {
    /// Create the throwaway directory, database, agent and enrollment code,
    /// and bind the listeners. Nothing is served yet.
    ///
    /// # Errors
    /// If the temporary directory, the database or a listener cannot be set
    /// up.
    pub async fn new() -> Result<Self> {
        let dir = tokio::task::spawn_blocking(|| {
            tempfile::Builder::new().prefix("warden-demo-").tempdir()
        })
        .await?
        .context("creating the temporary directory")?;

        let listeners = Listeners {
            api: bind_loopback().await?,
            approval: bind_loopback().await?,
            target: bind_loopback().await?,
        };
        let (api_addr, approval_addr) = (
            listeners.api.local_addr()?,
            listeners.approval.local_addr()?,
        );
        // `localhost`, not 127.0.0.1: WebAuthn needs a domain as relying party.
        let approval_url = Url::parse(&format!("http://localhost:{}/", approval_addr.port()))?;
        let api_url = Url::parse(&format!("http://{api_addr}/"))?;
        let target_origin = Url::parse(&format!(
            "https://localhost:{}",
            listeners.target.local_addr()?.port()
        ))?;
        let target_url = target_origin.join("v1/hello")?;
        let config = Arc::new(demo_config(
            dir.path(),
            api_addr,
            approval_addr,
            approval_url.clone(),
        )?);

        let pool = store::open(&config.db_path).await?;
        let audit = Arc::new(AuditLog::open(&config.audit_path).await?);
        let clock = Arc::new(SystemClock);
        let passkeys = Arc::new(
            Passkeys::new(
                pool.clone(),
                audit.clone(),
                &config.public_url,
                clock.clone(),
            )
            .context("configuring WebAuthn for localhost")?,
        );
        let enrollment_code = passkeys
            .create_enrollment_code(clock.now())
            .await
            .context("creating the enrollment code")?;
        let agent_name = AgentName::try_from(AGENT_NAME.to_owned())?;
        let agent_key = agents::add_audited(&pool, &audit, &agent_name)
            .await
            .context("adding the demo agent")?;
        let agent_env = write_agent_env(dir.path(), &api_url, agent_key.expose()).await?;

        Ok(Self {
            dir,
            pool,
            config,
            audit,
            passkeys,
            listeners,
            approval_url,
            api_url,
            target_origin,
            target_url,
            enrollment_code,
            agent_env,
        })
    }

    /// What to print at startup: that this is a demo, and the exact steps.
    #[must_use]
    pub fn banner(&self) -> String {
        let enroll = self
            .approval_url
            .join("enroll")
            .map_or_else(|_| self.approval_url.to_string(), |url| url.to_string());
        format!(
            "\n\
             ================================================================\n\
             \x20 WARDEN DEMO. THIS IS NOT SECURE FOR REAL USE.\n\
             \x20 Everyone on this machine counts as the owner, and everything\n\
             \x20 below is throwaway. Do not put real secrets near it.\n\
             \x20 A real deployment works differently:\n\
             \x20 https://github.com/pecheriere/warden/blob/main/docs/deployment.md\n\
             ================================================================\n\
             \n\
             Listening on loopback only. Data in {dir} (deleted when this stops).\n\
             \n\
             1. Enroll a passkey in your browser. Use this exact address:\n\
             \x20    {enroll}\n\
             \x20  Enrollment code (works once, for 10 minutes): {code}\n\
             \n\
             2. In a second terminal, be the agent:\n\
             \x20    source {env}\n\
             \x20    {warden} request api {SECRET_NAME} --for 15m --goal \"try the warden demo\"\n\
             \x20  It waits for your decision. The approval link appears here.\n\
             \n\
             3. Approve with your passkey on that page. Then, as the agent:\n\
             \x20    {warden} http {SECRET_NAME} GET {target}\n\
             \x20  The demo API received the secret. The agent sees [REDACTED].\n\
             \n\
             4. Read what happened:\n\
             \x20    cat \"$WARDEN_DEMO_DIR/audit.jsonl\"\n\
             \x20  Or open {history}\n\
             \n\
             Press Ctrl-C here to stop and delete everything.\n",
            dir = self.dir.path().display(),
            code = self.enrollment_code,
            env = shell_quote(&self.agent_env.display().to_string()),
            warden = warden_command(std::env::current_exe().ok().as_deref()),
            target = self.target_url,
            history = self
                .approval_url
                .join("history")
                .map_or_else(|_| self.approval_url.to_string(), |url| url.to_string()),
        )
    }

    /// Generate the demo API's keys and token, and start serving.
    ///
    /// # Errors
    /// If a key cannot be generated or the broker cannot be set up.
    pub async fn serve(self) -> Result<Demo> {
        let Self {
            dir,
            pool,
            config,
            audit,
            passkeys,
            listeners,
            approval_url,
            api_url,
            target_origin,
            target_url,
            enrollment_code,
            agent_env,
        } = self;
        let (api_addr, approval_addr) = (config.api_listen, config.approval_listen);
        let clock = Arc::new(SystemClock);
        let (notifier, doorbells) = TerminalNotifier::new();

        let target = upstream::Target::generate(target_origin)?;
        let backend = Arc::new(DemoBackend::new(
            target.policy(SECRET_NAME)?,
            target.secret(),
        ));
        let requests = Requests::new(
            pool.clone(),
            audit.clone(),
            backend.clone(),
            Arc::new(notifier),
            config.public_url.clone(),
            clock.clone(),
            None,
        )
        .with_call_limits(config.proxy.max_calls_per_agent, config.proxy.max_calls);
        let audience = audience::load_or_create(config.audience_path.clone()).await?;
        let state = AppState {
            pool: pool.clone(),
            config: config.clone(),
            identity: Arc::new(LoopbackOwner::new(
                OWNER_LOGIN,
                [
                    format!("localhost:{}", approval_addr.port()),
                    format!("127.0.0.1:{}", api_addr.port()),
                ],
            )),
            audit,
            backend,
            clock,
            requests: requests.clone(),
            passkeys,
            audience,
        };
        let (api, approval) = build_routers(state);

        let (servers, stop) = serve_all(listeners, api, approval, target, requests);

        Ok(Demo {
            dir,
            pool,
            approval_url,
            api_url,
            target_url,
            enrollment_code,
            agent_env,
            doorbells,
            servers,
            _stop: stop,
        })
    }
}

/// A running demo: the broker's two listeners and the demo API, all on
/// loopback, with its data in a temporary directory removed by
/// [`Demo::finish`] (or on drop).
pub struct Demo {
    dir: TempDir,
    pool: SqlitePool,
    approval_url: Url,
    api_url: Url,
    target_url: Url,
    enrollment_code: String,
    agent_env: PathBuf,
    doorbells: mpsc::UnboundedReceiver<Doorbell>,
    servers: JoinSet<Result<()>>,
    _stop: watch::Sender<bool>,
}

impl Demo {
    /// [`Prepared::new`], then [`Prepared::serve`].
    ///
    /// # Errors
    /// As those.
    pub async fn start() -> Result<Self> {
        Prepared::new().await?.serve().await
    }

    /// The approval UI, as the browser must open it: `http://localhost:<port>/`.
    #[must_use]
    pub const fn approval_url(&self) -> &Url {
        &self.approval_url
    }

    /// The agent API, `http://127.0.0.1:<port>/`.
    #[must_use]
    pub const fn api_url(&self) -> &Url {
        &self.api_url
    }

    /// The demo API's URL the agent calls through the broker.
    #[must_use]
    pub const fn target_url(&self) -> &Url {
        &self.target_url
    }

    /// The one-time code that enrolls the owner's passkey (valid 10 minutes).
    #[must_use]
    pub fn enrollment_code(&self) -> &str {
        &self.enrollment_code
    }

    /// The file an agent's shell sources.
    #[must_use]
    pub fn agent_env(&self) -> &Path {
        &self.agent_env
    }

    /// The hash-chained audit log.
    #[must_use]
    pub fn audit_path(&self) -> PathBuf {
        self.dir.path().join("audit.jsonl")
    }

    /// The temporary directory holding everything.
    #[must_use]
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// The next notification, which on a real server would go to the owner's
    /// phone.
    ///
    /// # Errors
    /// If a server stops, which they only do on failure.
    pub async fn next_doorbell(&mut self) -> Result<Doorbell> {
        tokio::select! {
            bell = self.doorbells.recv() => bell.context("the broker is gone"),
            stopped = self.servers.join_next() => match stopped {
                Some(Ok(Err(e))) => Err(e),
                Some(Err(e)) => Err(e).context("a demo server crashed"),
                Some(Ok(Ok(()))) | None => bail!("a demo server stopped unexpectedly"),
            },
        }
    }

    /// Stop serving, verify the audit log's hash chain and delete the
    /// temporary directory. Returns the number of audit entries.
    ///
    /// # Errors
    /// If the audit log does not verify or the directory cannot be deleted.
    pub async fn finish(mut self) -> Result<u64> {
        self.servers.shutdown().await;
        self.pool.close().await;
        let audit_path = self.audit_path();
        let entries = tokio::task::spawn_blocking(move || audit::verify(&audit_path))
            .await?
            .context("verifying the audit log")?;
        let dir = self.dir;
        tokio::task::spawn_blocking(move || dir.close())
            .await?
            .context("deleting the temporary directory")?;
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use url::Url;
    use warden_broker::config::{Config, parse_public_url};

    use super::{check_loopback, demo_config, shell_quote, warden_command};

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn loopback_is_the_only_address_accepted() {
        check_loopback(addr("127.0.0.1:8080")).unwrap();
        check_loopback(addr("[::1]:8080")).unwrap();
        for other in [
            "0.0.0.0:8080",
            "[::]:8080",
            "192.0.2.10:8080",
            "198.51.100.1:8080",
            "[2001:db8::1]:8080",
        ] {
            let error = check_loopback(addr(other)).unwrap_err().to_string();
            assert!(error.contains("loopback"), "{error}");
        }
    }

    /// The demo must get its `http://localhost` past the configuration, not
    /// by relaxing it: what the demo runs on stays refused by the real server.
    #[test]
    fn the_real_server_still_refuses_what_the_demo_uses() {
        assert!(parse_public_url("http://localhost:8081/").is_err());
        let error = Config::from_lookup(|var| match var {
            "WARDEN_PUBLIC_URL" => Some("http://localhost:8081/".to_owned()),
            _ => None,
        })
        .unwrap_err();
        assert!(error.to_string().contains("https"), "{error}");
    }

    #[test]
    fn config_takes_nothing_from_the_environment() {
        let dir = tempfile::tempdir().unwrap();
        let public = Url::parse("http://localhost:1/").unwrap();
        let config = demo_config(
            dir.path(),
            addr("127.0.0.1:1"),
            addr("127.0.0.1:2"),
            public.clone(),
        )
        .unwrap();
        assert_eq!(config.public_url, public);
        assert_eq!(config.api_listen, addr("127.0.0.1:1"));
        assert_eq!(config.approval_listen, addr("127.0.0.1:2"));
        assert!(config.db_path.starts_with(dir.path()));
        assert!(config.audit_path.starts_with(dir.path()));
        assert!(config.audience_path.starts_with(dir.path()));
        assert!(config.relay.public_addr.is_none(), "the relay stays off");
    }

    #[test]
    fn shell_quote_survives_quotes_and_spaces() {
        assert_eq!(shell_quote("/tmp/a b"), "'/tmp/a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn names_the_cli_beside_the_demo_when_there_is_one() {
        let dir = tempfile::tempdir().unwrap();
        let cli = dir.path().join("warden");
        std::fs::write(&cli, "").unwrap();
        assert_eq!(
            warden_command(Some(&dir.path().join("warden-demo"))),
            shell_quote(&cli.display().to_string())
        );
    }

    #[test]
    fn falls_back_to_the_path_without_a_cli_beside_the_demo() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            warden_command(Some(&dir.path().join("warden-demo"))),
            "warden"
        );
        assert_eq!(warden_command(None), "warden");
    }
}
