//! Request lifecycle against a wiremock 1Password Connect, a manual clock and
//! capturing notifiers.

use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sqlx::{Row as _, SqlitePool};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use url::Url;
use warden_broker::audit::AuditLog;
use warden_broker::notify::Notifier;
use warden_broker::policy::OnePasswordConnect;
use warden_broker::requests::{RequestError, Requests};
use warden_broker::testkit::{CapturingNotifier, FailingNotifier, ManualClock};
use warden_broker::{agents, audit, store};
use warden_broker_proto::{
    Access, AgentName, CreateRequest, CreatedResponse, Goal, GrantAccess, GrantView, Id,
    RequestStatus, SshGrant, TargetName, UnixUser, Window, fingerprint,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "eyJ-test-connect-token-do-not-leak";
const VAULT_ID: &str = "vault0000000000000000000a1";
const VAULTS: &str = include_str!("fixtures/vaults.json");
const ITEMS: &str = include_str!("fixtures/items.json");
const ITEM_PI: &str = include_str!("fixtures/item-pi.json");
const ITEM_NAS: &str = include_str!("fixtures/item-nas.json");
const ITEM_NOUSERS: &str = include_str!("fixtures/item-nousers.json");
/// Public half of the throwaway ECDSA test key in `fixtures/`.
const ECDSA_PUBLIC: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDOD9dGycs21HGdrl2rZ8guDbG8gRD9X9gkhhcLjxBo8CsX3wW+OGr207Ma9n0Jo4dWyU4vl9mabud9Fqf042qE=";
const START: i64 = 1_800_000_000;
const PUBLIC_URL: &str = "https://warden.test/";

struct Harness {
    requests: Requests,
    pool: SqlitePool,
    clock: Arc<ManualClock>,
    capture: Arc<CapturingNotifier>,
    audit_path: std::path::PathBuf,
    bot_key: String,
    _connect: MockServer,
    _dir: tempfile::TempDir,
}

fn agent(name: &str) -> AgentName {
    AgentName::try_from(name.to_owned()).unwrap()
}

fn ed25519_public() -> String {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap()
}

fn ssh_request(target: &str, user: &str, window: Window, public_key: &str) -> CreateRequest {
    CreateRequest {
        goal: Goal::try_from("restart the backup job".to_owned()).unwrap(),
        access: Access::Ssh {
            target: TargetName::try_from(target.to_owned()).unwrap(),
            user: UnixUser::try_from(user.to_owned()).unwrap(),
            public_key: public_key.to_owned(),
        },
        window,
    }
}

fn pi_request() -> CreateRequest {
    ssh_request("pi", "alice", Window::M30, &ed25519_public())
}

fn fill_host_key(template: &str) -> Value {
    let key = ed25519_public();
    serde_json::from_str(&template.replace("{{HOST_KEY}}", &key)).unwrap()
}

async fn healthy_connect() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/vaults"))
        .respond_with(ResponseTemplate::new(200).set_body_string(VAULTS))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/vaults/{VAULT_ID}/items")))
        .respond_with(ResponseTemplate::new(200).set_body_string(ITEMS))
        .mount(&server)
        .await;
    for (id, body) in [
        ("pi00000000000000000000000a", ITEM_PI),
        ("nas0000000000000000000000b", ITEM_NAS),
        ("nousers000000000000000000c", ITEM_NOUSERS),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/v1/vaults/{VAULT_ID}/items/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(fill_host_key(body)))
            .mount(&server)
            .await;
    }
    server
}

async fn broken_connect() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    server
}

async fn harness_with(connect: MockServer, notifier: Option<Arc<dyn Notifier>>) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let pool = store::open(&dir.path().join("warden.db")).await.unwrap();
    let bot_key = agents::add(&pool, &agent("bot"))
        .await
        .unwrap()
        .expose()
        .to_owned();
    agents::add(&pool, &agent("other")).await.unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditLog::open(&audit_path).await.unwrap());
    let backend = Arc::new(OnePasswordConnect::new(
        Url::parse(&connect.uri()).unwrap(),
        SecretString::from(TOKEN.to_owned()),
        "Warden".to_owned(),
    ));
    let clock = Arc::new(ManualClock::new(START));
    let capture = Arc::new(CapturingNotifier::new());
    let notifier = notifier.unwrap_or_else(|| capture.clone());
    let requests = Requests::new(
        pool.clone(),
        audit,
        backend,
        notifier,
        Url::parse(PUBLIC_URL).unwrap(),
        clock.clone(),
    );
    Harness {
        requests,
        pool,
        clock,
        capture,
        audit_path,
        bot_key,
        _connect: connect,
        _dir: dir,
    }
}

async fn harness() -> Harness {
    harness_with(healthy_connect().await, None).await
}

/// Create a request and wait until its notification has been handled.
async fn create_notified(h: &Harness, who: &str, req: CreateRequest) -> (CreatedResponse, String) {
    let mut rx = h.requests.bus().subscribe();
    let created = h.requests.create(&agent(who), req).await.unwrap();
    wait_for(&mut rx, &created.id).await;
    let bell = h.capture.next().await;
    (created, CapturingNotifier::token(&bell))
}

async fn wait_for(rx: &mut tokio::sync::broadcast::Receiver<Id>, id: &Id) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while rx.recv().await.unwrap() != *id {}
    })
    .await
    .expect("no bus message for request within 5 s");
}

/// Wait until some long-poll is subscribed to the bus.
async fn wait_for_waiter(h: &Harness) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while h.requests.bus().receiver_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("long-poll never subscribed");
}

async fn row_count(pool: &SqlitePool, table: &str) -> i64 {
    let sql = match table {
        "requests" => "SELECT COUNT(*) AS n FROM requests",
        "grants" => "SELECT COUNT(*) AS n FROM grants",
        other => panic!("no count query for {other}"),
    };
    sqlx::query(sql).fetch_one(pool).await.unwrap().get("n")
}

fn audit_types(h: &Harness) -> Vec<String> {
    std::fs::read_to_string(&h.audit_path)
        .unwrap()
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).unwrap();
            v["event"]["type"].as_str().unwrap().to_owned()
        })
        .collect()
}

fn grant_for(h: &Harness, window: Window) -> GrantView {
    let now = h.clock_now();
    GrantView {
        grant_id: Id::random(),
        not_before: now,
        not_after: now + i64::try_from(window.secs()).unwrap(),
        access: GrantAccess::Ssh(SshGrant {
            certificate: "ssh-ed25519-cert-v01@openssh.com AAAA".to_owned(),
            host: "192.0.2.10".to_owned(),
            port: 22,
            user: UnixUser::try_from("alice".to_owned()).unwrap(),
            host_keys: vec![],
        }),
    }
}

impl Harness {
    fn clock_now(&self) -> i64 {
        use warden_broker::requests::Clock as _;
        self.clock.now()
    }
}

fn message(err: &RequestError) -> String {
    err.to_string()
}

// --- create -----------------------------------------------------------------

#[tokio::test]
async fn api_access_is_refused_until_supported() {
    let h = harness().await;
    let req = CreateRequest {
        goal: Goal::try_from("call the api".to_owned()).unwrap(),
        access: Access::Api {
            secret: "github".parse().unwrap(),
        },
        window: Window::M15,
    };
    let err = h.requests.create(&agent("bot"), req).await.unwrap_err();
    assert!(matches!(err, RequestError::Rejected(_)), "{err:?}");
    assert_eq!(message(&err), "api access is not supported yet");
    assert_eq!(row_count(&h.pool, "requests").await, 0);
}

#[tokio::test]
async fn create_notifies_with_link_and_no_secret() {
    let h = harness().await;
    let req = pi_request();
    let Access::Ssh { public_key, .. } = &req.access else {
        panic!("pi_request is an ssh request");
    };
    let public_key = public_key.clone();
    let created = h.requests.create(&agent("bot"), req.clone()).await.unwrap();
    assert_eq!(created.fingerprint, fingerprint(&agent("bot"), &req));

    let bell = h.capture.next().await;
    let link = bell.url.as_str();
    assert!(link.starts_with("https://warden.test/approve/"), "{link}");
    let token = CapturingNotifier::token(&bell);
    assert_eq!(token.len(), 43, "32 bytes base64url without padding");
    assert!(bell.title.contains("bot") && bell.title.contains("alice@pi"));
    assert_eq!(bell.message, "restart the backup job");
    for text in [&bell.title, &bell.message, &link.to_owned()] {
        assert!(!text.contains(TOKEN), "Connect token leaked");
        assert!(!text.contains(&public_key), "public key in notification");
    }

    let stored: String = sqlx::query("SELECT approval_token_hash FROM requests WHERE id = ?")
        .bind(created.id.as_str())
        .fetch_one(&h.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored, hex::encode(Sha256::digest(token.as_bytes())));
    let dump: Vec<String> = sqlx::query("SELECT body || approval_token_hash FROM requests")
        .fetch_all(&h.pool)
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert!(
        dump.iter().all(|row| !row.contains(&token)),
        "raw token stored"
    );

    let status = h
        .requests
        .status(&agent("bot"), &created.id, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(status, RequestStatus::Pending);
    let view = h.requests.pending_for_token(&token).await.unwrap();
    assert_eq!(view.id, created.id);
    assert_eq!(view.agent, agent("bot"));
    assert_eq!(view.request, req);
    assert_eq!(view.target.name.as_str(), "pi");
    assert_eq!(view.expires_at, START + 600);
}

#[tokio::test]
async fn create_rejects_user_not_allowed() {
    let h = harness().await;
    let err = h
        .requests
        .create(
            &agent("bot"),
            ssh_request("pi", "root", Window::M30, &ed25519_public()),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::Rejected(_)), "{err:?}");
    assert_eq!(message(&err), "user root not allowed for target pi");
    assert_eq!(row_count(&h.pool, "requests").await, 0);
    assert!(h.capture.rung().is_empty());
}

#[tokio::test]
async fn create_rejects_window_over_max() {
    let h = harness().await;
    let err = h
        .requests
        .create(
            &agent("bot"),
            ssh_request("pi", "alice", Window::H4, &ed25519_public()),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::Rejected(_)), "{err:?}");
    assert_eq!(message(&err), "window 4h exceeds max 1h for target pi");
    assert_eq!(row_count(&h.pool, "requests").await, 0);
    assert!(h.capture.rung().is_empty());
}

#[tokio::test]
async fn create_rejects_non_ed25519_key() {
    let h = harness().await;
    for key in [ECDSA_PUBLIC, "not a key", ""] {
        let err = h
            .requests
            .create(&agent("bot"), ssh_request("pi", "alice", Window::M30, key))
            .await
            .unwrap_err();
        assert!(matches!(err, RequestError::Rejected(_)), "{err:?}");
        assert!(message(&err).contains("ssh-ed25519"), "{err}");
    }
    assert_eq!(row_count(&h.pool, "requests").await, 0);
    assert!(h.capture.rung().is_empty());
}

#[tokio::test]
async fn create_rejects_relay_mode() {
    let h = harness().await;
    let err = h
        .requests
        .create(
            &agent("bot"),
            ssh_request("nas", "backup", Window::M30, &ed25519_public()),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::Rejected(_)), "{err:?}");
    assert_eq!(message(&err), "target nas: relay mode not supported yet");
    assert_eq!(row_count(&h.pool, "requests").await, 0);
}

#[tokio::test]
async fn connect_down_fails_request_without_notifying() {
    let down = harness_with(broken_connect().await, None).await;
    let err = down
        .requests
        .create(&agent("bot"), pi_request())
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::Unavailable(_)), "{err:?}");
    assert!(message(&err).contains("HTTP 500"), "{err}");
    assert!(!message(&err).contains(TOKEN));
    assert_eq!(row_count(&down.pool, "requests").await, 0);
    assert!(down.capture.rung().is_empty());

    let h = harness().await;
    let err = h
        .requests
        .create(
            &agent("bot"),
            ssh_request("nousers", "alice", Window::M30, &ed25519_public()),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::TargetInvalid { .. }), "{err:?}");
    assert!(
        message(&err).starts_with("target nousers: field users invalid: "),
        "{err}"
    );

    let err = h
        .requests
        .create(
            &agent("bot"),
            ssh_request("nope", "alice", Window::M30, &ed25519_public()),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, RequestError::UnknownTarget(_)), "{err:?}");
    assert_eq!(message(&err), "unknown target nope");

    assert_eq!(row_count(&h.pool, "requests").await, 0);
    assert!(h.capture.rung().is_empty());
}

#[tokio::test]
async fn duplicate_pending_returns_same_id() {
    let h = harness().await;
    let (first, token) = create_notified(&h, "bot", pi_request()).await;

    let bot = agent("bot");
    let (a, b, c) = tokio::join!(
        h.requests.create(&bot, pi_request()),
        h.requests.create(&bot, pi_request()),
        h.requests.create(&bot, pi_request()),
    );
    for again in [a, b, c] {
        assert_eq!(again.unwrap(), first);
    }
    assert_eq!(row_count(&h.pool, "requests").await, 1);
    assert_eq!(h.capture.rung().len(), 1, "duplicates must not notify");

    // Another agent's request for the same target is separate.
    let (theirs, _) = create_notified(&h, "other", pi_request()).await;
    assert_ne!(theirs.id, first.id);

    // Once decided, a new request takes the slot.
    h.requests.deny(&token).await.unwrap();
    let (next, _) = create_notified(&h, "bot", pi_request()).await;
    assert_ne!(next.id, first.id);
}

#[tokio::test]
async fn duplicate_of_stale_pending_expires_it_first() {
    let h = harness().await;
    let (first, _) = create_notified(&h, "bot", pi_request()).await;
    h.clock.advance(600);
    let (second, _) = create_notified(&h, "bot", pi_request()).await;
    assert_ne!(second.id, first.id);
    let status = h
        .requests
        .status(&agent("bot"), &first.id, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(status, RequestStatus::Expired);
}

#[tokio::test]
async fn notify_failure_ends_in_error() {
    let h = harness_with(healthy_connect().await, Some(Arc::new(FailingNotifier))).await;
    let created = h
        .requests
        .create(&agent("bot"), pi_request())
        .await
        .unwrap();
    let status = h
        .requests
        .status(&agent("bot"), &created.id, Duration::from_secs(30))
        .await
        .unwrap();
    let RequestStatus::Error { message } = status else {
        panic!("expected error, got {status:?}");
    };
    assert!(message.contains("failing returned HTTP 503"), "{message}");
    assert!(audit_types(&h).contains(&"notify_failed".to_owned()));
    // The token was never delivered, but even so it is no longer usable.
    assert_eq!(row_count(&h.pool, "requests").await, 1);
}

#[tokio::test]
async fn dropped_deny_future_leaves_log_usable() {
    let h = harness().await;
    let (created, token) = create_notified(&h, "bot", pi_request()).await;

    // Poll deny once, then drop it mid-flight.
    let dropped = tokio::time::timeout(Duration::ZERO, h.requests.deny(&token)).await;
    assert!(dropped.is_err(), "deny finished before it could be dropped");

    // The transition still lands as a whole.
    assert_eq!(
        h.requests
            .status(&agent("bot"), &created.id, Duration::from_secs(5))
            .await
            .unwrap(),
        RequestStatus::Denied
    );
    // And the next transition works on an intact log.
    let (_, token) = create_notified(&h, "bot", pi_request()).await;
    h.requests.deny(&token).await.unwrap();
    assert_eq!(
        audit_types(&h),
        [
            "request_created",
            "notified",
            "denied",
            "request_created",
            "notified",
            "denied"
        ]
    );
    audit::verify(&h.audit_path).unwrap();
}

// --- status -----------------------------------------------------------------

#[tokio::test]
async fn status_long_poll_wakes_on_deny() {
    let h = Arc::new(harness().await);
    let (created, token) = create_notified(&h, "bot", pi_request()).await;

    let poller = {
        let h = h.clone();
        let id = created.id.clone();
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            let status = h
                .requests
                .status(&agent("bot"), &id, Duration::from_secs(30))
                .await;
            (status, started.elapsed())
        })
    };
    wait_for_waiter(&h).await;
    h.requests.deny(&token).await.unwrap();

    let (status, elapsed) = poller.await.unwrap();
    assert_eq!(status.unwrap(), RequestStatus::Denied);
    assert!(elapsed < Duration::from_secs(5), "woke after {elapsed:?}");
    assert!(matches!(
        h.requests.deny(&token).await,
        Err(RequestError::AlreadyDecided)
    ));
    assert!(matches!(
        h.requests.pending_for_token(&token).await,
        Err(RequestError::NotFound)
    ));
}

#[tokio::test]
async fn status_long_poll_times_out_pending() {
    let h = harness().await;
    let (created, _) = create_notified(&h, "bot", pi_request()).await;
    let started = std::time::Instant::now();
    let status = h
        .requests
        .status(&agent("bot"), &created.id, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(status, RequestStatus::Pending);
    assert!(started.elapsed() >= Duration::from_millis(200));
}

#[tokio::test]
async fn status_of_other_agents_request_is_not_found() {
    let h = harness().await;
    let (created, _) = create_notified(&h, "bot", pi_request()).await;
    assert!(matches!(
        h.requests
            .status(&agent("other"), &created.id, Duration::ZERO)
            .await,
        Err(RequestError::NotFound)
    ));
    assert!(matches!(
        h.requests
            .status(&agent("bot"), &Id::random(), Duration::ZERO)
            .await,
        Err(RequestError::NotFound)
    ));
}

// --- approval ---------------------------------------------------------------

#[tokio::test]
async fn mark_approved_is_single_use_and_returns_grant() {
    let h = harness().await;
    let (created, token) = create_notified(&h, "bot", pi_request()).await;
    let grant = grant_for(&h, Window::M15);
    let other = grant_for(&h, Window::M15);

    let (a, b) = tokio::join!(
        h.requests
            .mark_approved(&token, Window::M15, grant.clone(), "pk1"),
        h.requests
            .mark_approved(&token, Window::M15, other.clone(), "pk1"),
    );
    let oks = [&a, &b].iter().filter(|r| r.is_ok()).count();
    assert_eq!(oks, 1, "{a:?} {b:?}");
    assert!(
        [a, b]
            .into_iter()
            .any(|r| matches!(r, Err(RequestError::AlreadyDecided)))
    );
    assert_eq!(row_count(&h.pool, "grants").await, 1);

    let RequestStatus::Approved(view) = h
        .requests
        .status(&agent("bot"), &created.id, Duration::ZERO)
        .await
        .unwrap()
    else {
        panic!("expected approved");
    };
    assert!(view == grant || view == other);
    let window: i64 = sqlx::query("SELECT window_secs FROM grants")
        .fetch_one(&h.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(window, 900);
    assert!(matches!(
        h.requests
            .mark_approved(
                "unknown-token",
                Window::M15,
                grant_for(&h, Window::M15),
                "pk1"
            )
            .await,
        Err(RequestError::NotFound)
    ));
}

#[tokio::test]
async fn mark_approved_rejects_grant_not_spanning_the_window() {
    let h = harness().await;
    let (created, token) = create_notified(&h, "bot", pi_request()).await;
    let mut longer = grant_for(&h, Window::M15);
    longer.not_after += 1;
    let shifted = grant_for(&h, Window::H1);
    for grant in [longer, shifted] {
        assert!(matches!(
            h.requests
                .mark_approved(&token, Window::M15, grant, "pk1")
                .await,
            Err(RequestError::Internal(_))
        ));
    }
    assert_eq!(row_count(&h.pool, "grants").await, 0);
    assert_eq!(
        h.requests
            .status(&agent("bot"), &created.id, Duration::ZERO)
            .await
            .unwrap(),
        RequestStatus::Pending
    );
}

#[tokio::test]
async fn mark_approved_after_expiry_leaves_no_grant() {
    let h = harness().await;
    let (_, token) = create_notified(&h, "bot", pi_request()).await;
    h.clock.advance(600);
    assert!(matches!(
        h.requests
            .mark_approved(&token, Window::M30, grant_for(&h, Window::M30), "pk1")
            .await,
        Err(RequestError::AlreadyDecided)
    ));
    assert_eq!(row_count(&h.pool, "grants").await, 0);
}

#[tokio::test]
async fn revoke_grant_marks_request_revoked() {
    let h = harness().await;
    let (created, token) = create_notified(&h, "bot", pi_request()).await;
    let grant = grant_for(&h, Window::M30);
    h.requests
        .mark_approved(&token, Window::M30, grant.clone(), "pk1")
        .await
        .unwrap();
    h.requests
        .revoke_grant(&grant.grant_id, "owner")
        .await
        .unwrap();
    assert_eq!(
        h.requests
            .status(&agent("bot"), &created.id, Duration::ZERO)
            .await
            .unwrap(),
        RequestStatus::Revoked
    );
    // Idempotent; unknown grants are not found.
    h.requests
        .revoke_grant(&grant.grant_id, "owner")
        .await
        .unwrap();
    assert!(matches!(
        h.requests.revoke_grant(&Id::random(), "owner").await,
        Err(RequestError::NotFound)
    ));
}

// --- expiry and revocation ----------------------------------------------------

#[tokio::test]
async fn sweep_expires_after_600s() {
    let h = harness().await;
    let (created, token) = create_notified(&h, "bot", pi_request()).await;
    let mut rx = h.requests.bus().subscribe();

    h.clock.advance(599);
    assert_eq!(h.requests.sweep_expired().await.unwrap(), 0);
    assert_eq!(
        h.requests
            .status(&agent("bot"), &created.id, Duration::ZERO)
            .await
            .unwrap(),
        RequestStatus::Pending
    );

    h.clock.advance(1);
    assert_eq!(h.requests.sweep_expired().await.unwrap(), 1);
    wait_for(&mut rx, &created.id).await;
    assert_eq!(
        h.requests
            .status(&agent("bot"), &created.id, Duration::ZERO)
            .await
            .unwrap(),
        RequestStatus::Expired
    );
    assert_eq!(h.requests.sweep_expired().await.unwrap(), 0);
    assert!(matches!(
        h.requests.pending_for_token(&token).await,
        Err(RequestError::NotFound)
    ));
}

#[tokio::test]
async fn revoking_agent_cancels_pending_and_wakes_waiters() {
    let h = Arc::new(harness().await);
    // One approved request with an active grant, then a pending one.
    let (approved, token) = create_notified(&h, "bot", pi_request()).await;
    let grant = grant_for(&h, Window::M30);
    h.requests
        .mark_approved(&token, Window::M30, grant.clone(), "pk1")
        .await
        .unwrap();
    let (pending, pending_token) = create_notified(&h, "bot", pi_request()).await;
    let (theirs, _) = create_notified(&h, "other", pi_request()).await;

    let poller = {
        let h = h.clone();
        let id = pending.id.clone();
        tokio::spawn(async move {
            h.requests
                .status(&agent("bot"), &id, Duration::from_secs(30))
                .await
        })
    };
    wait_for_waiter(&h).await;
    h.requests.revoke_agent(&agent("bot")).await.unwrap();

    let woke = tokio::time::timeout(Duration::from_secs(5), poller)
        .await
        .expect("long-poll not woken")
        .unwrap();
    assert_eq!(woke.unwrap(), RequestStatus::Revoked);
    assert_eq!(
        h.requests
            .status(&agent("bot"), &approved.id, Duration::ZERO)
            .await
            .unwrap(),
        RequestStatus::Revoked
    );
    let revoked_at: Option<i64> = sqlx::query("SELECT revoked_at FROM grants WHERE id = ?")
        .bind(grant.grant_id.as_str())
        .fetch_one(&h.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(revoked_at, Some(START));
    assert!(matches!(
        agents::authenticate(&h.pool, &h.bot_key).await,
        Err(agents::AgentError::Revoked)
    ));
    // Other agents are untouched.
    assert_eq!(
        h.requests
            .status(&agent("other"), &theirs.id, Duration::ZERO)
            .await
            .unwrap(),
        RequestStatus::Pending
    );
    // The cancelled request cannot be approved, and no new one can be made.
    assert!(matches!(
        h.requests
            .mark_approved(
                &pending_token,
                Window::M30,
                grant_for(&h, Window::M30),
                "pk1"
            )
            .await,
        Err(RequestError::AlreadyDecided)
    ));
    assert!(matches!(
        h.requests.create(&agent("bot"), pi_request()).await,
        Err(RequestError::AgentRevoked)
    ));
    let types = audit_types(&h);
    assert!(types.contains(&"agent_revoked".to_owned()));
    assert!(types.contains(&"grant_revoked".to_owned()));
    assert!(matches!(
        h.requests.revoke_agent(&agent("nobody")).await,
        Err(RequestError::UnknownAgent(_))
    ));
}

#[tokio::test]
async fn every_transition_is_audited() {
    let h = harness().await;
    let (_, token) = create_notified(&h, "bot", pi_request()).await;
    h.requests.deny(&token).await.unwrap();

    let (_, token) = create_notified(&h, "bot", pi_request()).await;
    let grant = grant_for(&h, Window::M30);
    h.requests
        .mark_approved(&token, Window::M30, grant.clone(), "pk1")
        .await
        .unwrap();
    h.requests
        .revoke_grant(&grant.grant_id, "owner")
        .await
        .unwrap();

    create_notified(&h, "bot", pi_request()).await;
    h.clock.advance(600);
    h.requests.sweep_expired().await.unwrap();

    create_notified(&h, "bot", pi_request()).await;
    h.requests.revoke_agent(&agent("bot")).await.unwrap();

    assert_eq!(
        audit_types(&h),
        [
            "request_created",
            "notified",
            "denied",
            "request_created",
            "notified",
            "approved",
            "grant_revoked",
            "request_created",
            "notified",
            "expired",
            "request_created",
            "notified",
            "agent_revoked",
        ]
    );
    assert_eq!(audit::verify(&h.audit_path).unwrap(), 13);
}

#[tokio::test]
async fn dropped_create_still_rings() {
    let h = harness().await;
    // Hold the audit log's file lock so the insert blocks inside its
    // transaction, after the row is written but before it commits.
    let lock = std::fs::File::open(&h.audit_path).unwrap();
    lock.try_lock().unwrap();
    let create = tokio::spawn({
        let requests = h.requests.clone();
        async move { requests.create(&agent("bot"), pi_request()).await }
    });
    // Policy lookup against the local mock takes milliseconds; give the
    // create ample time to reach the blocked insert, then drop the caller.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!create.is_finished());
    create.abort();
    assert!(create.await.unwrap_err().is_cancelled());
    lock.unlock().unwrap();

    // The insert still commits, and the owner is still notified about it.
    let bell = h.capture.next().await;
    let token = CapturingNotifier::token(&bell);
    let pending: i64 = sqlx::query(
        "SELECT COUNT(*) AS n FROM requests WHERE status = 'pending' AND approval_token_hash = ?",
    )
    .bind(hex::encode(Sha256::digest(token.as_bytes())))
    .fetch_one(&h.pool)
    .await
    .unwrap()
    .get("n");
    assert_eq!(pending, 1);
}
