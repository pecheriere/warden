//! Request lifecycle against a wiremock 1Password Connect, a manual clock and
//! capturing notifiers.

use std::sync::Arc;
use std::time::Duration;

use secrecy::SecretString;
use serde_json::Value;
use sqlx::{Row as _, SqlitePool};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use url::Url;
use warden_broker::audit::AuditLog;
use warden_broker::notify::Notifier;
use warden_broker::policy::OnePasswordConnect;
use warden_broker::relay::RelayEndpoint;
use warden_broker::requests::{RequestError, Requests};
use warden_broker::testkit::{CapturingNotifier, ManualClock};
use warden_broker::{agents, store};
use warden_broker_proto::{
    Access, AgentName, CreateRequest, CreatedResponse, Goal, GrantAccess, GrantView, Id,
    SecretName, SshGrant, TargetName, UnixUser, Window,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "eyJ-test-connect-token-do-not-leak";
const VAULT_ID: &str = "vault0000000000000000000a1";
const VAULTS: &str = include_str!("../fixtures/vaults.json");
const ITEMS: &str = include_str!("../fixtures/items.json");
const ITEM_PI: &str = include_str!("../fixtures/item-pi.json");
const ITEM_NAS: &str = include_str!("../fixtures/item-nas.json");
const ITEM_NOUSERS: &str = include_str!("../fixtures/item-nousers.json");
const ITEM_API: &str = include_str!("../fixtures/item-api.json");
/// Credential of the `github` API secret item.
const CREDENTIAL: &str = "test-credential-0123456789abcdef";
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
        session: None,
        link: None,
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

fn api_request(secret: &str, window: Window) -> CreateRequest {
    CreateRequest {
        session: None,
        link: None,
        goal: Goal::try_from("list the open pull requests".to_owned()).unwrap(),
        access: Access::Api {
            secret: SecretName::try_from(secret.to_owned()).unwrap(),
            methods: None,
            path_prefix: None,
        },
        window,
    }
}

async fn healthy_connect() -> MockServer {
    connect_with_credential(CREDENTIAL).await
}

/// A Connect whose `github` API secret item holds `credential`.
async fn connect_with_credential(credential: &str) -> MockServer {
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
    let api: Value = serde_json::from_str(&ITEM_API.replace("{{CREDENTIAL}}", credential)).unwrap();
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/vaults/{VAULT_ID}/items/api00000000000000000000g00"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(api))
        .mount(&server)
        .await;
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

/// The relay endpoint the harness advertises, unless built without one.
fn test_relay() -> RelayEndpoint {
    RelayEndpoint {
        host: "relay.warden.test".to_owned(),
        port: 2222,
        host_key: ed25519_public(),
    }
}

async fn harness_with(connect: MockServer, notifier: Option<Arc<dyn Notifier>>) -> Harness {
    harness_with_relay(connect, notifier, Some(test_relay())).await
}

async fn harness_with_relay(
    connect: MockServer,
    notifier: Option<Arc<dyn Notifier>>,
    relay: Option<RelayEndpoint>,
) -> Harness {
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
        relay,
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

mod create;
mod decisions;
mod lifecycle;
