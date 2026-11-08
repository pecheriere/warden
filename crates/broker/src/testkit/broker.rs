//! [`TestBroker`], an in-process broker: its state, construction and restart.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use serde_json::Value;
use tempfile::TempDir;
use tokio::task::AbortHandle;
use url::Url;
use warden_broker_proto::Window;

use super::{
    CapturingNotifier, FakeBackend, ManualClock, RELAY_PUBLIC_HOST, RELAY_PUBLIC_PORT,
    SoftAuthenticator, TEST_ORIGIN, TEST_OWNER, TEST_START,
};
use crate::approval::passkeys::Passkeys;
use crate::audit::AuditLog;
use crate::config::Config;
use crate::identity::TailscaleServeIdentity;
use crate::policy::SecretBackend;
use crate::proxy::ProxyLimits;
use crate::relay::{RelayEndpoint, RelayLimits, host_key};
use crate::requests::{LinkHosts, RequestLimits, Requests};
use crate::signed::BodyReadTimeout;
use crate::{AppState, store};

mod approval;
mod inspect;
mod requests;
mod serve;

pub use inspect::LiveHold;
pub use requests::request_signature;

/// A response read in full. Must be checked: a test that ignores it
/// silently passes when the call fails.
#[derive(Debug)]
#[must_use]
pub struct TestResponse {
    /// Status code.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// Body as text.
    pub body: String,
}

impl TestResponse {
    /// The body parsed as JSON.
    ///
    /// # Panics
    /// If the body is not JSON.
    #[must_use]
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("body is not JSON ({e}): {}", self.body))
    }

    /// A header's value as text.
    ///
    /// # Panics
    /// If the header is absent or not text.
    #[must_use]
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .unwrap_or_else(|| panic!("missing header {name}"))
            .to_str()
            .expect("header is text")
    }
}

/// Base URLs of a broker's two listeners, each ending in `/`.
#[derive(Debug, Clone)]
pub struct BaseUrls {
    /// The agent API.
    pub api: Url,
    /// The approval UI.
    pub approval: Url,
}

/// The limits a test may change from the broker's defaults; kept across
/// [`TestBroker::restart`].
#[derive(Debug, Clone)]
struct Limits {
    proxy: ProxyLimits,
    requests: RequestLimits,
    link_hosts: LinkHosts,
    body_read_timeout: BodyReadTimeout,
    commit_signing_max: Window,
    commit_signing_per_day: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            proxy: ProxyLimits::default(),
            requests: RequestLimits::default(),
            body_read_timeout: BodyReadTimeout::default(),
            commit_signing_max: Window::COMMIT_SIGNING_DEFAULT,
            commit_signing_per_day: crate::requests::SIGNATURES_PER_DAY,
            link_hosts: LinkHosts::default(),
        }
    }
}

/// A broker running in-process: real state, real routes driven with
/// `tower::ServiceExt::oneshot` (or on loopback ports after
/// [`TestBroker::spawn`]), a fake backend, a capturing notifier and a manual
/// clock, on a temporary database and audit log.
pub struct TestBroker {
    state: AppState,
    router: Router,
    api_router: Router,
    /// The broker's clock.
    pub clock: Arc<ManualClock>,
    /// Captures every doorbell.
    pub capture: Arc<CapturingNotifier>,
    /// The broker's policy source.
    pub backend: Arc<FakeBackend>,
    /// What the broker actually asks: [`Self::backend`], unless built with
    /// [`TestBroker::with_secret_backend`].
    policy_source: Arc<dyn SecretBackend>,
    db_path: PathBuf,
    audit_path: PathBuf,
    default_passkey: tokio::sync::Mutex<Option<SoftAuthenticator>>,
    servers: Mutex<Vec<AbortHandle>>,
    relays: Mutex<
        Vec<(
            tokio::sync::watch::Sender<bool>,
            tokio::task::JoinHandle<()>,
        )>,
    >,
    dir: Option<TempDir>,
    limits: Limits,
    /// `WARDEN_RELAY_PUBLIC_ADDR`, if the relay is configured.
    relay: Option<String>,
}

/// The fake backend a test can change, and the backend the broker asks: the
/// same one, unless built with [`TestBroker::with_secret_backend`].
struct PolicySources {
    fake: Arc<FakeBackend>,
    asked: Arc<dyn SecretBackend>,
}

impl PolicySources {
    fn fake() -> Self {
        let fake = Arc::new(FakeBackend::new());
        Self {
            asked: fake.clone(),
            fake,
        }
    }
}

impl Drop for TestBroker {
    fn drop(&mut self) {
        if let Ok(servers) = self.servers.get_mut() {
            for server in servers.drain(..) {
                server.abort();
            }
        }
        if let Ok(relays) = self.relays.get_mut() {
            for (_, relay) in relays.drain(..) {
                relay.abort();
            }
        }
    }
}

impl TestBroker {
    /// A fresh broker with no agents and no passkeys. Its relay is
    /// configured: public address [`RELAY_PUBLIC_HOST`]:[`RELAY_PUBLIC_PORT`],
    /// host key created in the temporary directory.
    ///
    /// # Panics
    /// If any part of the setup fails.
    pub async fn new() -> Self {
        Self::with_proxy_limits(ProxyLimits::default()).await
    }

    /// Like [`TestBroker::new`], reading its policy from `backend` instead of
    /// [`Self::backend`], and with a directory of its own for its files.
    ///
    /// # Panics
    /// If any part of the setup fails.
    pub async fn with_secret_backend(backend: Arc<dyn SecretBackend>) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("warden.db");
        let audit_path = dir.path().join("audit.jsonl");
        Self::build(
            Some(dir),
            db_path,
            audit_path,
            Arc::new(ManualClock::new(TEST_START)),
            PolicySources {
                fake: Arc::new(FakeBackend::new()),
                asked: backend,
            },
            Limits::default(),
            None,
        )
        .await
    }

    /// Like [`TestBroker::new`], without `WARDEN_RELAY_PUBLIC_ADDR`: the
    /// relay is off.
    ///
    /// # Panics
    /// If any part of the setup fails.
    pub async fn without_relay() -> Self {
        Self::fresh(Limits::default(), None).await
    }

    /// Like [`TestBroker::new`], with the relay already running on an
    /// ephemeral loopback port that is also its public address: relay
    /// grants name where it really listens, so a client following a grant
    /// (like the `warden` CLI) reaches it. Returns the relay's address too.
    ///
    /// # Panics
    /// If any part of the setup fails.
    pub async fn with_reachable_relay() -> (Self, std::net::SocketAddr) {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind relay listener");
        let addr = listener.local_addr().expect("relay listener address");
        let broker = Self::fresh(Limits::default(), Some(addr.to_string())).await;
        broker.serve_relay(listener, RelayLimits::default()).await;
        (broker, addr)
    }

    /// Like [`TestBroker::new`], with proxied calls held to `proxy` (for
    /// example a short timeout).
    ///
    /// # Panics
    /// If any part of the setup fails.
    pub async fn with_proxy_limits(proxy: ProxyLimits) -> Self {
        Self::fresh(
            Limits {
                proxy,
                ..Limits::default()
            },
            Some(format!("{RELAY_PUBLIC_HOST}:{RELAY_PUBLIC_PORT}")),
        )
        .await
    }

    /// Like [`TestBroker::new`], with `WARDEN_COMMIT_SIGNING_MAX_WINDOW` at this.
    ///
    /// # Panics
    /// If any part of the setup fails.
    pub async fn with_commit_signing_max(commit_signing_max: Window) -> Self {
        Self::fresh(
            Limits {
                commit_signing_max,
                ..Limits::default()
            },
            Some(format!("{RELAY_PUBLIC_HOST}:{RELAY_PUBLIC_PORT}")),
        )
        .await
    }

    /// Like [`TestBroker::new`], with `WARDEN_COMMIT_SIGNING_MAX_PER_DAY` at this.
    ///
    /// # Panics
    /// If any part of the setup fails.
    pub async fn with_commit_signing_per_day(commit_signing_per_day: u32) -> Self {
        Self::fresh(
            Limits {
                commit_signing_per_day,
                ..Limits::default()
            },
            Some(format!("{RELAY_PUBLIC_HOST}:{RELAY_PUBLIC_PORT}")),
        )
        .await
    }

    /// Like [`TestBroker::new`], accepting links to `hosts` (comma separated).
    ///
    /// # Panics
    /// If `hosts` is not a valid setting, or any part of the setup fails.
    pub async fn with_link_hosts(hosts: &str) -> Self {
        Self::fresh(
            Limits {
                link_hosts: LinkHosts::parse(hosts).expect("link hosts"),
                ..Limits::default()
            },
            Some(format!("{RELAY_PUBLIC_HOST}:{RELAY_PUBLIC_PORT}")),
        )
        .await
    }

    /// Like [`TestBroker::new`], with agents held to `requests`.
    ///
    /// # Panics
    /// If any part of the setup fails.
    pub async fn with_request_limits(requests: RequestLimits) -> Self {
        Self::fresh(
            Limits {
                requests,
                ..Limits::default()
            },
            Some(format!("{RELAY_PUBLIC_HOST}:{RELAY_PUBLIC_PORT}")),
        )
        .await
    }

    /// Like [`TestBroker::new`], with the body of a signed request given
    /// `timeout` to arrive instead of the broker's fixed default (to test
    /// it without waiting seconds).
    ///
    /// # Panics
    /// If any part of the setup fails.
    pub async fn with_body_read_timeout(timeout: BodyReadTimeout) -> Self {
        Self::fresh(
            Limits {
                body_read_timeout: timeout,
                ..Limits::default()
            },
            Some(format!("{RELAY_PUBLIC_HOST}:{RELAY_PUBLIC_PORT}")),
        )
        .await
    }

    async fn fresh(limits: Limits, relay: Option<String>) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("warden.db");
        let audit_path = dir.path().join("audit.jsonl");
        Self::build(
            Some(dir),
            db_path,
            audit_path,
            Arc::new(ManualClock::new(TEST_START)),
            PolicySources::fake(),
            limits,
            relay,
        )
        .await
    }

    /// Stop this broker and start another on the same database, audit log,
    /// clock, policy source and passkey. Everything held in memory is lost,
    /// as in a process restart: begun ceremonies, long polls, listeners and
    /// captured doorbells.
    ///
    /// # Panics
    /// If any part of the setup fails.
    pub async fn restart(self) -> Self {
        let relay = self.relay.clone();
        self.restart_with(relay).await
    }

    /// Like [`TestBroker::restart`], but the broker comes back without
    /// `WARDEN_RELAY_PUBLIC_ADDR`.
    ///
    /// # Panics
    /// If any part of the setup fails.
    pub async fn restart_without_relay(self) -> Self {
        self.restart_with(None).await
    }

    async fn restart_with(mut self, relay: Option<String>) -> Self {
        self.state.pool.close().await;
        let passkey = std::mem::take(self.default_passkey.get_mut());
        let next = Self::build(
            self.dir.take(),
            self.db_path.clone(),
            self.audit_path.clone(),
            self.clock.clone(),
            PolicySources {
                fake: self.backend.clone(),
                asked: self.policy_source.clone(),
            },
            self.limits.clone(),
            relay,
        )
        .await;
        *next.default_passkey.lock().await = passkey;
        next
    }

    async fn build(
        dir: Option<TempDir>,
        db_path: PathBuf,
        audit_path: PathBuf,
        clock: Arc<ManualClock>,
        sources: PolicySources,
        limits: Limits,
        relay: Option<String>,
    ) -> Self {
        let PolicySources {
            fake: backend,
            asked: policy_source,
        } = sources;
        let pool = store::open(&db_path).await.expect("open database");
        let audit = Arc::new(AuditLog::open(&audit_path).await.expect("open audit log"));
        let host_key_path = db_path.with_file_name("relay_host_ed25519");
        let audience_path = db_path.with_file_name("audience");
        let mut config = Config::from_lookup(|var| match var {
            "WARDEN_RELAY_PUBLIC_ADDR" => relay.clone(),
            "WARDEN_RELAY_HOST_KEY_PATH" => Some(host_key_path.display().to_string()),
            "WARDEN_AUDIENCE_PATH" => Some(audience_path.display().to_string()),
            other => test_env(other),
        })
        .expect("test configuration");
        config.proxy = limits.proxy;
        config.body_read_timeout = limits.body_read_timeout;
        let config = Arc::new(config);
        let relay_endpoint = match &config.relay.public_addr {
            Some(addr) => {
                let key = host_key::load_or_create(config.relay.host_key_path.clone())
                    .await
                    .expect("relay host key");
                Some(RelayEndpoint::new(addr, &key).expect("relay endpoint"))
            }
            None => None,
        };
        let audience = crate::audience::load_or_create(config.audience_path.clone())
            .await
            .expect("audience");
        let capture = Arc::new(CapturingNotifier::new());
        let requests = Requests::new(
            pool.clone(),
            audit.clone(),
            policy_source.clone(),
            capture.clone(),
            config.public_url.clone(),
            clock.clone(),
            relay_endpoint,
        )
        .with_limits(limits.requests)
        .with_commit_signing_max(limits.commit_signing_max)
        .with_commit_signing_per_day(limits.commit_signing_per_day)
        .with_link_hosts(limits.link_hosts.clone())
        .with_call_limits(config.proxy.max_calls_per_agent, config.proxy.max_calls);
        let passkeys = Passkeys::new(
            pool.clone(),
            audit.clone(),
            &config.public_url,
            clock.clone(),
        )
        .expect("passkey service");
        let state = AppState {
            pool,
            config: config.clone(),
            identity: Arc::new(TailscaleServeIdentity),
            audit,
            backend: policy_source.clone(),
            clock: clock.clone(),
            requests,
            passkeys: Arc::new(passkeys),
            audience,
        };
        let (api_router, router) = crate::build_routers(state.clone());
        Self {
            state,
            router,
            api_router,
            clock,
            capture,
            backend,
            policy_source,
            db_path,
            audit_path,
            default_passkey: tokio::sync::Mutex::new(None),
            servers: Mutex::new(Vec::new()),
            relays: Mutex::new(Vec::new()),
            dir,
            limits,
            relay,
        }
    }
}

fn test_env(var: &str) -> Option<String> {
    let value = match var {
        "WARDEN_DB_PATH" => "/nonexistent/warden.db",
        "WARDEN_AUDIT_PATH" => "/nonexistent/audit.jsonl",
        "WARDEN_PUBLIC_URL" => TEST_ORIGIN,
        "WARDEN_OWNER_LOGIN" => TEST_OWNER,
        "WARDEN_OP_CONNECT_URL" => "https://connect.invalid:8080",
        "WARDEN_OP_CONNECT_TOKEN" => "unused-test-token",
        "WARDEN_NOTIFY" => "ntfy",
        "WARDEN_NOTIFY_NTFY_URL" => "https://ntfy.invalid/warden",
        _ => return None,
    };
    Some(value.to_owned())
}
