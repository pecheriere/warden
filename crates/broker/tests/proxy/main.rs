//! The HTTP proxy route end to end: an agent with an approved api grant asks
//! the broker to call a local HTTPS upstream, which sees the secret; the
//! agent never does.

use std::time::Duration;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};
use warden_broker::policy::ApiSecretPolicy;
use warden_broker::proxy::ProxyLimits;
use warden_broker::testkit::{HttpsUpstream, TestBroker, TestResponse};
use warden_broker_proto::{Access, AgentName, Id, ProxyResponse, RequestStatus, Window};

mod audit_log;
mod forwarding;
mod grants;
mod limits;
mod policy;
mod upstream;

/// Has `/`, `+`, `=`, `&` and `~`, which every encoding spells differently.
const SECRET: &str = "pr0xy-Cred/+=en&tial~42";

/// The credential after rotation in 1Password.
const ROTATED: &str = "r0tated-Cred/+=second~99";

struct Setup {
    broker: TestBroker,
    upstream: HttpsUpstream,
    key: String,
    grant: Id,
}

async fn setup() -> Setup {
    setup_with(ProxyLimits::default(), |_| {}).await
}

/// A broker with secret `svc` for a fresh upstream (adjusted by `edit`
/// before approval) and agent `bot` holding an approved 30m grant for it.
async fn setup_with(limits: ProxyLimits, edit: impl FnOnce(&mut ApiSecretPolicy)) -> Setup {
    let broker = TestBroker::with_proxy_limits(limits).await;
    let upstream = HttpsUpstream::start().await;
    let mut policy = upstream.policy("svc");
    edit(&mut policy);
    broker.backend.set_api_secret(policy, SECRET);
    let key = broker.add_agent("bot").await;
    let grant = approve_api(&broker, "bot", "svc").await;
    Setup {
        broker,
        upstream,
        key,
        grant,
    }
}

/// Have `agent` request api access to `secret` and approve it.
async fn approve_api(broker: &TestBroker, agent: &str, secret: &str) -> Id {
    let req = TestBroker::api_request(secret, "call the test api", Window::M30);
    approve(broker, agent, req).await
}

/// Have `agent` request `methods` (and `path_prefix`) of `secret` and
/// approve it.
async fn approve_scoped(
    broker: &TestBroker,
    agent: &str,
    secret: &str,
    methods: &[&str],
    path_prefix: Option<&str>,
) -> Id {
    let mut req = TestBroker::api_request(secret, "call the test api", Window::M30);
    if let Access::Api {
        methods: wanted,
        path_prefix: prefix,
        ..
    } = &mut req.access
    {
        *wanted = Some(methods.iter().map(|m| (*m).to_owned()).collect());
        *prefix = path_prefix.map(str::to_owned);
    }
    approve(broker, agent, req).await
}

async fn approve(broker: &TestBroker, agent: &str, req: warden_broker_proto::CreateRequest) -> Id {
    let (created, token) = broker.create_request(agent, req).await;
    let done = broker.approve(&token, Window::M30).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    let agent = AgentName::try_from(agent.to_owned()).unwrap();
    match broker
        .state()
        .requests
        .status(&agent, &created.id, Duration::ZERO)
        .await
        .unwrap()
    {
        RequestStatus::Approved(view) => view.grant_id,
        other => panic!("expected approved, got {other:?}"),
    }
}

async fn call_as(
    broker: &TestBroker,
    key: &str,
    grant: &Id,
    method: &str,
    url: &str,
    body: Option<&[u8]>,
) -> TestResponse {
    broker
        .api_post_json(
            key,
            &format!("/v1/grants/{grant}/http"),
            &json!({
                "method": method,
                "url": url,
                "headers": [["X-Trace", "1"]],
                "body_b64": body.map(|b| STANDARD.encode(b)),
            }),
        )
        .await
}

async fn get(s: &Setup, path: &str) -> TestResponse {
    call_as(
        &s.broker,
        &s.key,
        &s.grant,
        "GET",
        &s.upstream.url(path),
        None,
    )
    .await
}

/// The proxied response in a 200 from the broker, and its decoded body.
fn proxied(resp: &TestResponse) -> (ProxyResponse, Vec<u8>) {
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let proxied: ProxyResponse = serde_json::from_str(&resp.body).unwrap();
    let body = STANDARD.decode(&proxied.body_b64).unwrap();
    (proxied, body)
}

fn header<'a>(resp: &'a ProxyResponse, name: &str) -> Option<&'a str> {
    resp.headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// Every form of `value` a leak could take, computed independently of the
/// broker's redaction code.
fn encodings(value: &str) -> Vec<String> {
    let pct = utf8_percent_encode(value, NON_ALPHANUMERIC).to_string();
    let form: String = url::form_urlencoded::byte_serialize(value.as_bytes()).collect();
    vec![
        value.to_owned(),
        STANDARD.encode(value),
        STANDARD_NO_PAD.encode(value),
        URL_SAFE.encode(value),
        URL_SAFE_NO_PAD.encode(value),
        pct.to_ascii_lowercase(),
        pct,
        form,
        serde_json::to_string(value).unwrap().replace('/', "\\/"),
    ]
}

fn leaks(secret: &str) -> Vec<String> {
    let mut all = encodings(secret);
    all.extend(encodings(&format!("Bearer {secret}")));
    all
}

/// `text` holds no form of `secret`.
fn assert_clean(text: &str, secret: &str, what: &str) {
    for leak in leaks(secret) {
        assert!(!text.contains(&leak), "{what} leaks {leak:?}:\n{text}");
    }
}

/// Neither the broker's response (status line aside: headers and the JSON
/// as sent) nor anything decoded from it holds the secret.
fn assert_response_clean(resp: &TestResponse, secret: &str) {
    assert_clean(&resp.body, secret, "wire body");
    for (name, value) in &resp.headers {
        assert_clean(
            &format!("{name}: {}", String::from_utf8_lossy(value.as_bytes())),
            secret,
            "broker header",
        );
    }
    if let Ok(proxied) = serde_json::from_str::<ProxyResponse>(&resp.body) {
        let body = STANDARD.decode(&proxied.body_b64).unwrap();
        assert_clean(&String::from_utf8_lossy(&body), secret, "decoded body");
        for (name, value) in &proxied.headers {
            assert_clean(&format!("{name}: {value}"), secret, "proxied header");
        }
    }
}

/// Audit events of the given types, oldest first.
fn audit_events(broker: &TestBroker, types: &[&str]) -> Vec<Value> {
    std::fs::read_to_string(broker.audit_path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["event"].clone())
        .filter(|event| types.iter().any(|t| event["type"] == *t))
        .collect()
}

fn proxy_calls(broker: &TestBroker) -> Vec<Value> {
    audit_events(broker, &["proxy_call"])
}
