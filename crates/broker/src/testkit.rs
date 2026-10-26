//! Test helpers: a settable clock, notifiers that capture or fail, a fake
//! policy backend and an in-process broker driven with soft passkeys.
//!
//! Compiled only with the `testkit` feature; never part of a release build.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tower::ServiceExt as _;
use url::Url;
use warden_broker_proto::{
    Access, AgentName, CreateRequest, CreatedResponse, Goal, SecretName, TargetName, UnixUser,
    Window,
};
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RequestChallengeResponse,
};
use zeroize::Zeroizing;

pub mod upstream;

pub use upstream::{HttpsUpstream, Received};

use crate::approval::passkeys::Passkeys;
use crate::audit::AuditLog;
use crate::config::Config;
use crate::identity::TailscaleServeIdentity;
use crate::notify::{Doorbell, Notifier, NotifyError};
use crate::policy::{
    ApiSecretPolicy, CaKey, PolicyError, RelayCredential, SecretBackend, SecretValue, SshMode,
    SshTarget, ValueFormat, not_a_relay_target,
};
use crate::proxy::ProxyLimits;
use crate::relay::{RelayEndpoint, host_key};
use crate::requests::{Clock, Requests};
use crate::{AppState, agents, store};

/// A clock that only moves when told to.
#[derive(Debug)]
pub struct ManualClock(AtomicI64);

impl ManualClock {
    /// A clock reading `now` (Unix seconds).
    #[must_use]
    pub const fn new(now: i64) -> Self {
        Self(AtomicI64::new(now))
    }

    /// Move the clock forward by `secs`.
    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }

    /// Set the clock to `now`.
    pub fn set(&self, now: i64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Records every doorbell and always succeeds.
pub struct CapturingNotifier {
    rung: Mutex<Vec<Doorbell>>,
    tx: mpsc::UnboundedSender<Doorbell>,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Doorbell>>,
}

impl CapturingNotifier {
    /// An empty recorder.
    #[must_use]
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            rung: Mutex::new(Vec::new()),
            tx,
            rx: tokio::sync::Mutex::new(rx),
        }
    }

    /// Every doorbell rung so far, oldest first.
    ///
    /// # Panics
    /// If another thread panicked while recording.
    #[must_use]
    pub fn rung(&self) -> Vec<Doorbell> {
        self.rung.lock().expect("capture lock poisoned").clone()
    }

    /// Wait for the next doorbell not yet returned by `next`.
    ///
    /// # Panics
    /// If none arrives within 5 s.
    pub async fn next(&self) -> Doorbell {
        let mut rx = self.rx.lock().await;
        tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("no doorbell within 5 s")
            .expect("capture channel closed")
    }

    /// The approval token at the end of a doorbell's link.
    ///
    /// # Panics
    /// If the link has no path segment.
    #[must_use]
    pub fn token(d: &Doorbell) -> String {
        d.url
            .path_segments()
            .and_then(|mut s| s.next_back())
            .expect("approval link has a token segment")
            .to_owned()
    }
}

impl Default for CapturingNotifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Notifier for CapturingNotifier {
    fn name(&self) -> &'static str {
        "capture"
    }

    async fn ring(&self, d: &Doorbell) -> Result<(), NotifyError> {
        self.rung
            .lock()
            .expect("capture lock poisoned")
            .push(d.clone());
        // The receiver lives as long as `self`, so sending cannot fail.
        let _ = self.tx.send(d.clone());
        Ok(())
    }
}

/// Fails every delivery with HTTP 503.
pub struct FailingNotifier;

#[async_trait]
impl Notifier for FailingNotifier {
    fn name(&self) -> &'static str {
        "failing"
    }

    async fn ring(&self, _d: &Doorbell) -> Result<(), NotifyError> {
        Err(NotifyError::Status {
            notifier: "failing",
            status: 503,
        })
    }
}

// --- in-process broker ------------------------------------------------------

/// Owner login the test broker accepts.
pub const TEST_OWNER: &str = "owner@example.com";

/// Public URL (and `WebAuthn` origin) of the test broker.
pub const TEST_ORIGIN: &str = "https://warden.test";

/// Time the test broker's clock starts at, Unix seconds.
pub const TEST_START: i64 = 1_800_000_000;

/// Host of the default `pi` target.
pub const PI_HOST: &str = "192.0.2.10";

/// Host of [`FakeBackend::relay_target`].
pub const NAS_HOST: &str = "192.0.2.20";

/// Host of the relay's public address in a [`TestBroker`] (unless built
/// without a relay).
pub const RELAY_PUBLIC_HOST: &str = "relay.warden.test";

/// Port of the relay's public address in a [`TestBroker`].
pub const RELAY_PUBLIC_PORT: u16 = 2222;

/// A software passkey that claims user verification, as Face ID would.
pub type SoftAuthenticator = WebauthnAuthenticator<SoftPasskey>;

/// An in-memory [`SecretBackend`]: targets (with relay credentials) and API
/// secrets can be changed at any time, the CA key is generated per backend,
/// and target or CA lookups can be made to fail as if the backend were down.
pub struct FakeBackend {
    targets: Mutex<HashMap<String, (SshTarget, Option<RelayCredential>)>>,
    api_secrets: Mutex<HashMap<String, (ApiSecretPolicy, Zeroizing<String>)>>,
    api_swap: Mutex<Option<(ApiSecretPolicy, Zeroizing<String>)>>,
    ca: PrivateKey,
    target_outage: Mutex<Option<String>>,
    ca_outage: Mutex<Option<String>>,
}

impl FakeBackend {
    /// A backend holding [`FakeBackend::pi_target`] and a fresh Ed25519 CA.
    ///
    /// # Panics
    /// If no key can be generated.
    #[must_use]
    pub fn new() -> Self {
        let pi = Self::pi_target();
        Self {
            targets: Mutex::new(HashMap::from([(pi.name.as_str().to_owned(), (pi, None))])),
            api_secrets: Mutex::new(HashMap::new()),
            api_swap: Mutex::new(None),
            ca: PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("CA key generation"),
            target_outage: Mutex::new(None),
            ca_outage: Mutex::new(None),
        }
    }

    /// Target `pi`: cert mode, users `alice` and `admin`, max window 1h,
    /// `192.0.2.10:22`, one random host key.
    ///
    /// # Panics
    /// If no key can be generated.
    #[must_use]
    pub fn pi_target() -> SshTarget {
        let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("host key generation")
            .public_key()
            .clone();
        SshTarget {
            name: TargetName::try_from("pi".to_owned()).expect("valid target name"),
            host: PI_HOST.to_owned(),
            port: 22,
            mode: SshMode::Cert,
            users: ["alice", "admin"]
                .into_iter()
                .map(|u| UnixUser::try_from(u.to_owned()).expect("valid user"))
                .collect(),
            max_window: Window::H1,
            host_keys: vec![host_key],
        }
    }

    /// Target `nas`: relay mode, user `backup`, max window 1h,
    /// `192.0.2.20:22`, one random host key. Not added to any backend by
    /// itself; see [`FakeBackend::set_relay_target`].
    ///
    /// # Panics
    /// If no key can be generated.
    #[must_use]
    pub fn relay_target() -> SshTarget {
        let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("host key generation")
            .public_key()
            .clone();
        SshTarget {
            name: TargetName::try_from("nas".to_owned()).expect("valid target name"),
            host: NAS_HOST.to_owned(),
            port: 22,
            mode: SshMode::Relay,
            users: vec![UnixUser::try_from("backup".to_owned()).expect("valid user")],
            max_window: Window::H1,
            host_keys: vec![host_key],
        }
    }

    /// Add or replace a target, without a relay credential.
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn set_target(&self, target: SshTarget) {
        self.targets
            .lock()
            .expect("targets lock poisoned")
            .insert(target.name.as_str().to_owned(), (target, None));
    }

    /// Add or replace a relay target together with its onward credential.
    ///
    /// # Panics
    /// If the target is not in relay mode or the lock is poisoned.
    pub fn set_relay_target(&self, target: SshTarget, credential: RelayCredential) {
        assert_eq!(target.mode, SshMode::Relay, "not a relay target");
        self.targets
            .lock()
            .expect("targets lock poisoned")
            .insert(target.name.as_str().to_owned(), (target, Some(credential)));
    }

    /// The current definition of target `name`.
    ///
    /// # Panics
    /// If there is no such target or the lock is poisoned.
    #[must_use]
    pub fn target(&self, name: &str) -> SshTarget {
        self.targets
            .lock()
            .expect("targets lock poisoned")
            .get(name)
            .map(|(target, _)| target.clone())
            .expect("no such fake target")
    }

    /// API secret `github`: origin `https://api.example.com`, header
    /// `Authorization: Bearer {{secret}}`, `GET` only, path prefix `/`, no
    /// pinned CA, max window 1h. Not added to any backend by itself.
    ///
    /// # Panics
    /// Never: every part is a valid constant.
    #[must_use]
    pub fn example_api_secret() -> ApiSecretPolicy {
        ApiSecretPolicy {
            name: SecretName::try_from("github".to_owned()).expect("valid secret name"),
            origin: Url::parse("https://api.example.com")
                .expect("valid origin")
                .origin(),
            header: http::header::AUTHORIZATION,
            format: ValueFormat::default(),
            methods: vec![http::Method::GET],
            path_prefix: "/".to_owned(),
            ca_pem: None,
            max_window: Window::H1,
        }
    }

    /// Add or replace an API secret and its value.
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn set_api_secret(&self, policy: ApiSecretPolicy, value: &str) {
        self.api_secrets
            .lock()
            .expect("api secrets lock poisoned")
            .insert(
                policy.name.as_str().to_owned(),
                (policy, Zeroizing::new(value.to_owned())),
            );
    }

    /// Add or replace an API secret and its value right after the next API
    /// secret read, as if the item were edited in 1Password between two
    /// reads.
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn set_api_secret_after_next_read(&self, policy: ApiSecretPolicy, value: &str) {
        *self.api_swap.lock().expect("api swap lock poisoned") =
            Some((policy, Zeroizing::new(value.to_owned())));
    }

    /// Read API secret `name` through `pick`, then apply any change queued
    /// by [`FakeBackend::set_api_secret_after_next_read`].
    fn api_entry<T>(
        &self,
        name: &SecretName,
        pick: impl FnOnce(&(ApiSecretPolicy, Zeroizing<String>)) -> T,
    ) -> Result<T, PolicyError> {
        let poisoned = || PolicyError::Unavailable("fake backend lock poisoned".to_owned());
        let mut secrets = self.api_secrets.lock().map_err(|_| poisoned())?;
        let picked = secrets
            .get(name.as_str())
            .map(pick)
            .ok_or_else(|| PolicyError::UnknownSecret(name.as_str().to_owned()));
        if let Some((policy, value)) = self.api_swap.lock().map_err(|_| poisoned())?.take() {
            secrets.insert(policy.name.as_str().to_owned(), (policy, value));
        }
        picked
    }

    /// The CA's public key.
    #[must_use]
    pub fn ca_public_key(&self) -> &PublicKey {
        self.ca.public_key()
    }

    /// Make target lookups fail with [`PolicyError::Unavailable`] carrying
    /// `detail` (`None` restores them).
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn set_target_outage(&self, detail: Option<&str>) {
        *self.target_outage.lock().expect("outage lock poisoned") = detail.map(str::to_owned);
    }

    /// Make CA lookups fail with [`PolicyError::Unavailable`] carrying
    /// `detail` (`None` restores them).
    ///
    /// # Panics
    /// If the lock is poisoned.
    pub fn set_ca_outage(&self, detail: Option<&str>) {
        *self.ca_outage.lock().expect("outage lock poisoned") = detail.map(str::to_owned);
    }

    fn outage(slot: &Mutex<Option<String>>) -> Result<(), PolicyError> {
        match slot
            .lock()
            .map_err(|_| PolicyError::Unavailable("fake backend lock poisoned".to_owned()))?
            .as_ref()
        {
            Some(detail) => Err(PolicyError::Unavailable(detail.clone())),
            None => Ok(()),
        }
    }
}

impl Default for FakeBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretBackend for FakeBackend {
    async fn ssh_target(&self, name: &TargetName) -> Result<SshTarget, PolicyError> {
        Self::outage(&self.target_outage)?;
        self.targets
            .lock()
            .map_err(|_| PolicyError::Unavailable("fake backend lock poisoned".to_owned()))?
            .get(name.as_str())
            .map(|(target, _)| target.clone())
            .ok_or_else(|| PolicyError::NotFound(name.as_str().to_owned()))
    }

    async fn relay_target_with_credential(
        &self,
        name: &TargetName,
    ) -> Result<(SshTarget, RelayCredential), PolicyError> {
        Self::outage(&self.target_outage)?;
        let targets = self
            .targets
            .lock()
            .map_err(|_| PolicyError::Unavailable("fake backend lock poisoned".to_owned()))?;
        let (target, credential) = targets
            .get(name.as_str())
            .ok_or_else(|| PolicyError::NotFound(name.as_str().to_owned()))?;
        if target.mode != SshMode::Relay {
            return Err(not_a_relay_target(name.as_str()));
        }
        let credential = match credential {
            Some(RelayCredential::Key(key)) => RelayCredential::Key(key.clone()),
            Some(RelayCredential::Password(password)) => {
                RelayCredential::Password(password.clone())
            }
            None => {
                return Err(PolicyError::Invalid {
                    item: name.as_str().to_owned(),
                    field: "password".to_owned(),
                    reason: "missing: a relay target needs a credential".to_owned(),
                });
            }
        };
        Ok((target.clone(), credential))
    }

    async fn ssh_ca(&self) -> Result<CaKey, PolicyError> {
        Self::outage(&self.ca_outage)?;
        CaKey::new(self.ca.clone())
    }

    async fn api_secret(&self, name: &SecretName) -> Result<ApiSecretPolicy, PolicyError> {
        self.api_entry(name, |(policy, _)| policy.clone())
    }

    async fn api_secret_with_value(
        &self,
        name: &SecretName,
    ) -> Result<(ApiSecretPolicy, SecretValue), PolicyError> {
        self.api_entry(name, |(policy, value)| {
            (policy.clone(), SecretValue::new(value.clone()))
        })
    }
}

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
    db_path: PathBuf,
    audit_path: PathBuf,
    default_passkey: tokio::sync::Mutex<Option<SoftAuthenticator>>,
    servers: Mutex<Vec<AbortHandle>>,
    dir: Option<TempDir>,
    proxy: ProxyLimits,
    relay: bool,
}

impl Drop for TestBroker {
    fn drop(&mut self) {
        if let Ok(servers) = self.servers.get_mut() {
            for server in servers.drain(..) {
                server.abort();
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

    /// Like [`TestBroker::new`], without `WARDEN_RELAY_PUBLIC_ADDR`: the
    /// relay is off.
    ///
    /// # Panics
    /// If any part of the setup fails.
    pub async fn without_relay() -> Self {
        Self::fresh(ProxyLimits::default(), false).await
    }

    /// Like [`TestBroker::new`], with proxied calls held to `proxy` (for
    /// example a short timeout).
    ///
    /// # Panics
    /// If any part of the setup fails.
    pub async fn with_proxy_limits(proxy: ProxyLimits) -> Self {
        Self::fresh(proxy, true).await
    }

    async fn fresh(proxy: ProxyLimits, relay: bool) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let db_path = dir.path().join("warden.db");
        let audit_path = dir.path().join("audit.jsonl");
        Self::build(
            Some(dir),
            db_path,
            audit_path,
            Arc::new(ManualClock::new(TEST_START)),
            Arc::new(FakeBackend::new()),
            proxy,
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
        let relay = self.relay;
        self.restart_with(relay).await
    }

    /// Like [`TestBroker::restart`], but the broker comes back without
    /// `WARDEN_RELAY_PUBLIC_ADDR`.
    ///
    /// # Panics
    /// If any part of the setup fails.
    pub async fn restart_without_relay(self) -> Self {
        self.restart_with(false).await
    }

    async fn restart_with(mut self, relay: bool) -> Self {
        self.state.pool.close().await;
        let passkey = std::mem::take(self.default_passkey.get_mut());
        let next = Self::build(
            self.dir.take(),
            self.db_path.clone(),
            self.audit_path.clone(),
            self.clock.clone(),
            self.backend.clone(),
            self.proxy,
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
        backend: Arc<FakeBackend>,
        proxy: ProxyLimits,
        relay: bool,
    ) -> Self {
        let pool = store::open(&db_path).await.expect("open database");
        let audit = Arc::new(AuditLog::open(&audit_path).await.expect("open audit log"));
        let host_key_path = db_path.with_file_name("relay_host_ed25519");
        let mut config = Config::from_lookup(|var| match var {
            "WARDEN_RELAY_PUBLIC_ADDR" if relay => {
                Some(format!("{RELAY_PUBLIC_HOST}:{RELAY_PUBLIC_PORT}"))
            }
            "WARDEN_RELAY_HOST_KEY_PATH" => Some(host_key_path.display().to_string()),
            other => test_env(other),
        })
        .expect("test configuration");
        config.proxy = proxy;
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
        let capture = Arc::new(CapturingNotifier::new());
        let requests = Requests::new(
            pool.clone(),
            audit.clone(),
            backend.clone(),
            capture.clone(),
            config.public_url.clone(),
            clock.clone(),
            relay_endpoint,
        );
        let passkeys = Passkeys::new(
            pool.clone(),
            audit.clone(),
            &config.public_url,
            clock.clone(),
        )
        .expect("passkey service");
        let state = AppState {
            pool,
            config,
            identity: Arc::new(TailscaleServeIdentity),
            audit,
            backend: backend.clone(),
            clock: clock.clone(),
            requests,
            passkeys: Arc::new(passkeys),
        };
        let (api_router, router) = crate::build_routers(state.clone());
        Self {
            state,
            router,
            api_router,
            clock,
            capture,
            backend,
            db_path,
            audit_path,
            default_passkey: tokio::sync::Mutex::new(None),
            servers: Mutex::new(Vec::new()),
            dir,
            proxy,
            relay,
        }
    }

    /// Serve both routers on ephemeral loopback ports until the broker is
    /// dropped. The in-process helpers keep working alongside.
    ///
    /// # Panics
    /// If a listener cannot be bound.
    pub async fn spawn(&self) -> BaseUrls {
        self.serve([self.api_router.clone(), self.router.clone()], None)
            .await
    }

    /// Like [`TestBroker::spawn`], but every request reaching either listener
    /// first passes through a stand-in for Tailscale Serve: any
    /// `Tailscale-User-Login` header the client sent is replaced with
    /// [`TEST_OWNER`], as Serve does for the authenticated tailnet peer. Use
    /// it to drive the broker with a client (such as the `warden` CLI) that,
    /// like in production, never sets the identity header itself.
    ///
    /// # Panics
    /// If a listener cannot be bound.
    pub async fn spawn_behind_serve(&self) -> BaseUrls {
        self.serve(self.serve_routers(), None).await
    }

    /// Like [`TestBroker::spawn_behind_serve`], on the ports of `urls`: for
    /// example those of this broker before [`TestBroker::restart`], so that
    /// clients see the same broker come back.
    ///
    /// # Panics
    /// If a listener cannot be bound, for instance because the port is in use.
    pub async fn spawn_behind_serve_at(&self, urls: &BaseUrls) -> BaseUrls {
        let port = |url: &Url| url.port().expect("loopback URL has a port");
        self.serve(
            self.serve_routers(),
            Some([port(&urls.api), port(&urls.approval)]),
        )
        .await
    }

    fn serve_routers(&self) -> [Router; 2] {
        [
            self.api_router
                .clone()
                .layer(axum::middleware::map_request(as_owner)),
            self.router
                .clone()
                .layer(axum::middleware::map_request(as_owner)),
        ]
    }

    /// Serve `routers` on loopback, on `ports` or ephemeral ones. Stopping a
    /// server (on drop or restart) also drops its open connections, in-flight
    /// requests included, as a process exit would.
    async fn serve(&self, routers: [Router; 2], ports: Option<[u16; 2]>) -> BaseUrls {
        let ports = ports.unwrap_or([0, 0]);
        let mut bound = Vec::new();
        for (router, port) in routers.into_iter().zip(ports) {
            let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .expect("bind loopback listener");
            let addr = listener.local_addr().expect("listener address");
            let task = tokio::spawn(serve_connections(listener, router));
            self.servers
                .lock()
                .expect("servers lock poisoned")
                .push(task.abort_handle());
            bound.push(Url::parse(&format!("http://{addr}/")).expect("loopback URL"));
        }
        let approval = bound.pop().expect("approval listener");
        let api = bound.pop().expect("api listener");
        BaseUrls { api, approval }
    }

    /// Shared state of the broker.
    #[must_use]
    pub const fn state(&self) -> &AppState {
        &self.state
    }

    /// Path of the audit log.
    #[must_use]
    pub fn audit_path(&self) -> &Path {
        &self.audit_path
    }

    /// The `type` of every audit entry, oldest first.
    ///
    /// # Panics
    /// If the log cannot be read.
    #[must_use]
    pub fn audit_types(&self) -> Vec<String> {
        std::fs::read_to_string(&self.audit_path)
            .expect("read audit log")
            .lines()
            .map(|line| {
                let v: Value = serde_json::from_str(line).expect("audit line is JSON");
                v["event"]["type"].as_str().expect("event type").to_owned()
            })
            .collect()
    }

    /// Add an agent and return its key.
    ///
    /// # Panics
    /// If the agent cannot be added.
    pub async fn add_agent(&self, name: &str) -> String {
        let name = AgentName::try_from(name.to_owned()).expect("valid agent name");
        agents::add(&self.state.pool, &name)
            .await
            .expect("add agent")
            .expose()
            .to_owned()
    }

    /// An SSH request for `alice@pi` with a fresh Ed25519 key.
    ///
    /// # Panics
    /// If no key can be generated.
    #[must_use]
    pub fn pi_request(goal: &str, window: Window) -> CreateRequest {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("subject key generation")
            .public_key()
            .to_openssh()
            .expect("encode public key");
        CreateRequest {
            goal: Goal::try_from(goal.to_owned()).expect("valid goal"),
            access: Access::Ssh {
                target: TargetName::try_from("pi".to_owned()).expect("valid target"),
                user: UnixUser::try_from("alice".to_owned()).expect("valid user"),
                public_key: key,
            },
            window,
        }
    }

    /// An SSH request for `backup@nas` (see [`FakeBackend::relay_target`])
    /// with a fresh Ed25519 key.
    ///
    /// # Panics
    /// If no key can be generated or `goal` is not valid.
    #[must_use]
    pub fn relay_request(goal: &str, window: Window) -> CreateRequest {
        let mut request = Self::pi_request(goal, window);
        if let Access::Ssh { target, user, .. } = &mut request.access {
            *target = TargetName::try_from("nas".to_owned()).expect("valid target");
            *user = UnixUser::try_from("backup".to_owned()).expect("valid user");
        }
        request
    }

    /// A request to use API secret `secret`.
    ///
    /// # Panics
    /// If `secret` or `goal` is not valid.
    #[must_use]
    pub fn api_request(secret: &str, goal: &str, window: Window) -> CreateRequest {
        CreateRequest {
            goal: Goal::try_from(goal.to_owned()).expect("valid goal"),
            access: Access::Api {
                secret: SecretName::try_from(secret.to_owned()).expect("valid secret name"),
            },
            window,
        }
    }

    /// Create a request as `agent` and return it with the approval token
    /// from its doorbell.
    ///
    /// # Panics
    /// If creation fails or no doorbell arrives.
    pub async fn create_request(
        &self,
        agent: &str,
        req: CreateRequest,
    ) -> (CreatedResponse, String) {
        let agent = AgentName::try_from(agent.to_owned()).expect("valid agent name");
        let created = self
            .state
            .requests
            .create(&agent, req)
            .await
            .expect("create request");
        let bell = self.capture.next().await;
        (created, CapturingNotifier::token(&bell))
    }

    /// Send a raw request to the approval router.
    ///
    /// # Panics
    /// If the router or body fails.
    pub async fn send(&self, req: Request<Body>) -> TestResponse {
        read(
            self.router
                .clone()
                .oneshot(req)
                .await
                .expect("router is infallible"),
        )
        .await
    }

    /// `GET path` as the owner.
    ///
    /// # Panics
    /// If the request cannot be built.
    pub async fn get(&self, path: &str) -> TestResponse {
        let req = Request::get(path)
            .header("Tailscale-User-Login", TEST_OWNER)
            .body(Body::empty())
            .expect("request");
        self.send(req).await
    }

    /// `POST path` with a JSON body as the owner, from the public origin.
    ///
    /// # Panics
    /// If the request cannot be built.
    pub async fn post_json(&self, path: &str, body: &Value) -> TestResponse {
        let req = Request::post(path)
            .header("Tailscale-User-Login", TEST_OWNER)
            .header("Origin", TEST_ORIGIN)
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        self.send(req).await
    }

    /// Send a raw request to the agent API router.
    ///
    /// # Panics
    /// If the router or body fails.
    pub async fn api_send(&self, req: Request<Body>) -> TestResponse {
        read(
            self.api_router
                .clone()
                .oneshot(req)
                .await
                .expect("router is infallible"),
        )
        .await
    }

    /// `GET path` on the agent API as the owner, authenticated as the agent
    /// holding `key`.
    ///
    /// # Panics
    /// If the request cannot be built.
    pub async fn api_get(&self, key: &str, path: &str) -> TestResponse {
        let req = Request::get(path)
            .header("Tailscale-User-Login", TEST_OWNER)
            .header("Authorization", format!("Bearer {key}"))
            .body(Body::empty())
            .expect("request");
        self.api_send(req).await
    }

    /// `POST path` with no body on the agent API, authenticated like
    /// [`TestBroker::api_get`].
    ///
    /// # Panics
    /// If the request cannot be built.
    pub async fn api_post(&self, key: &str, path: &str) -> TestResponse {
        let req = Request::post(path)
            .header("Tailscale-User-Login", TEST_OWNER)
            .header("Authorization", format!("Bearer {key}"))
            .body(Body::empty())
            .expect("request");
        self.api_send(req).await
    }

    /// `POST path` with a JSON body on the agent API, authenticated like
    /// [`TestBroker::api_get`].
    ///
    /// # Panics
    /// If the request cannot be built.
    pub async fn api_post_json(&self, key: &str, path: &str, body: &Value) -> TestResponse {
        let req = Request::post(path)
            .header("Tailscale-User-Login", TEST_OWNER)
            .header("Authorization", format!("Bearer {key}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        self.api_send(req).await
    }

    /// A fresh enrollment code.
    ///
    /// # Panics
    /// If the code cannot be created.
    pub async fn enrollment_code(&self) -> String {
        self.state
            .passkeys
            .create_enrollment_code(self.clock.now())
            .await
            .expect("create enrollment code")
    }

    /// Enroll a new software passkey through the enrollment routes.
    ///
    /// # Panics
    /// If any step fails.
    pub async fn enroll_soft_passkey(&self) -> SoftAuthenticator {
        let code = self.enrollment_code().await;
        let mut auth = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let begin = self
            .post_json("/enroll/begin", &json!({"code": code, "label": "soft"}))
            .await;
        assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
        let begin = begin.json();
        let options: CreationChallengeResponse =
            serde_json::from_value(begin["options"].clone()).expect("creation options");
        let credential = auth
            .do_registration(origin(), options)
            .expect("soft passkey registration");
        let finish = self
            .post_json(
                "/enroll/finish",
                &json!({"ceremony": begin["ceremony"], "credential": credential}),
            )
            .await;
        assert_eq!(finish.status, StatusCode::OK, "{}", finish.body);
        auth
    }

    /// The destination digest the approval page for `token` embeds (as the
    /// browser script reads it), or an empty string if the page has none.
    pub async fn page_target_digest(&self, token: &str) -> String {
        let page = self.get(&format!("/approve/{token}")).await;
        page.body
            .split_once(r#"data-target=""#)
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(digest, _)| digest.to_owned())
            .unwrap_or_default()
    }

    /// `POST /approve/<token>/begin` for `window`, as the page's script sends
    /// it: with the destination digest the page was rendered with.
    pub async fn begin_approval(&self, token: &str, window: Window) -> TestResponse {
        let target = self.page_target_digest(token).await;
        self.begin_approval_for(token, window, &target).await
    }

    /// `POST /approve/<token>/begin` for `window`, claiming the page showed
    /// the destination with digest `target`.
    pub async fn begin_approval_for(
        &self,
        token: &str,
        window: Window,
        target: &str,
    ) -> TestResponse {
        self.post_json(
            &format!("/approve/{token}/begin"),
            &json!({ "window": window, "target": target }),
        )
        .await
    }

    /// Sign the challenge in a successful `begin` response.
    ///
    /// # Panics
    /// If `begin` is not a challenge or the authenticator refuses.
    #[must_use]
    pub fn sign(
        auth: &mut SoftAuthenticator,
        begin: &TestResponse,
    ) -> (Value, PublicKeyCredential) {
        assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
        let begin = begin.json();
        let options: RequestChallengeResponse =
            serde_json::from_value(begin["options"].clone()).expect("request options");
        let credential = auth
            .do_authentication(origin(), options)
            .expect("soft passkey assertion");
        (begin["ceremony"].clone(), credential)
    }

    /// `POST /approve/<token>/finish`.
    pub async fn finish_approval(
        &self,
        token: &str,
        ceremony: &Value,
        credential: &PublicKeyCredential,
    ) -> TestResponse {
        self.post_json(
            &format!("/approve/{token}/finish"),
            &json!({"ceremony": ceremony, "credential": credential}),
        )
        .await
    }

    /// Approve with `auth`: begin, sign, finish.
    ///
    /// # Panics
    /// If `begin` fails.
    pub async fn approve_with(
        &self,
        auth: &mut SoftAuthenticator,
        token: &str,
        window: Window,
    ) -> TestResponse {
        let begin = self.begin_approval(token, window).await;
        let (ceremony, credential) = Self::sign(auth, &begin);
        self.finish_approval(token, &ceremony, &credential).await
    }

    /// Approve with this broker's own passkey, enrolling it on first use.
    ///
    /// # Panics
    /// If enrollment or `begin` fails.
    pub async fn approve(&self, token: &str, window: Window) -> TestResponse {
        let mut slot = self.default_passkey.lock().await;
        if slot.is_none() {
            *slot = Some(self.enroll_soft_passkey().await);
        }
        let auth = slot.as_mut().expect("default passkey enrolled");
        self.approve_with(auth, token, window).await
    }

    /// `POST /approve/<token>/deny`.
    pub async fn deny(&self, token: &str) -> TestResponse {
        self.post_json(&format!("/approve/{token}/deny"), &json!({}))
            .await
    }
}

async fn read(resp: axum::response::Response) -> TestResponse {
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    TestResponse {
        status,
        headers,
        body: String::from_utf8(bytes.to_vec()).expect("body is UTF-8"),
    }
}

/// Accept HTTP/1 connections for `router` until aborted. The connections are
/// owned by this task, so aborting it closes them all.
async fn serve_connections(listener: tokio::net::TcpListener, router: Router) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let service = hyper_util::service::TowerToHyperService::new(router.clone());
                connections.spawn(async move {
                    // A connection error only ends that connection.
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

/// Stand-in for Tailscale Serve: the caller is always the owner, whatever
/// identity header the client sent.
async fn as_owner(mut req: Request<Body>) -> Request<Body> {
    req.headers_mut().insert(
        "Tailscale-User-Login",
        axum::http::HeaderValue::from_static(TEST_OWNER),
    );
    req
}

fn origin() -> Url {
    Url::parse(TEST_ORIGIN).expect("test origin is a URL")
}

fn test_env(var: &str) -> Option<String> {
    let value = match var {
        "WARDEN_DB_PATH" => "/nonexistent/warden.db",
        "WARDEN_AUDIT_PATH" => "/nonexistent/audit.jsonl",
        "WARDEN_PUBLIC_URL" => TEST_ORIGIN,
        "WARDEN_OWNER_LOGIN" => TEST_OWNER,
        "WARDEN_OP_CONNECT_URL" => "http://connect.invalid:8080",
        "WARDEN_OP_CONNECT_TOKEN" => "unused-test-token",
        "WARDEN_NTFY_URL" => "https://ntfy.invalid/warden",
        _ => return None,
    };
    Some(value.to_owned())
}
