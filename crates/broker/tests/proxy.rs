//! The HTTP proxy route end to end: an agent with an approved api grant asks
//! the broker to call a local HTTPS upstream, which sees the secret; the
//! agent never does.

use std::time::{Duration, Instant};

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};
use warden_broker::audit;
use warden_broker::policy::{ApiSecretPolicy, ValueFormat};
use warden_broker::proxy::ProxyLimits;
use warden_broker::testkit::upstream::{HUGE_BYTES, SLOW_PREFIX};
use warden_broker::testkit::{HttpsUpstream, TestBroker, TestResponse};
use warden_broker_proto::{Access, AgentName, Id, ProxyResponse, RequestStatus, Window};

/// Has `/`, `+`, `=`, `&` and `~`, which every encoding spells differently.
const SECRET: &str = "pr0xy-Cred/+=en&tial~42";

/// The credential after rotation in 1Password.
const ROTATED: &str = "r0tated-Cred/+=second~99";

const METHOD_REFUSED: &str = r#"{"error":"method is not allowed for this secret"}"#;

const POLICY_CHANGED: &str = r#"{"error":"policy changed; request access again"}"#;

/// A named change to a policy.
type Change<'a> = (&'static str, Box<dyn Fn(&mut ApiSecretPolicy) + 'a>);

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

#[tokio::test]
async fn proxied_get_injects_header_and_returns_body() {
    let s = setup().await;
    let resp = get(&s, "/v1/hello?page=2").await;
    let (proxied, body) = proxied(&resp);
    assert_eq!(proxied.status, 200);
    assert_eq!(body, b"hello from upstream");
    assert_eq!(header(&proxied, "content-type"), Some("text/plain"));
    assert_eq!(header(&proxied, "content-length"), None);
    assert_eq!(proxied.redactions, 0);

    let received = s.upstream.received();
    assert_eq!(received.len(), 1);
    let sent = &received[0];
    assert_eq!(sent.method, "GET");
    assert_eq!(sent.path_and_query, "/v1/hello?page=2");
    assert_eq!(sent.headers["authorization"], format!("Bearer {SECRET}"));
    assert_eq!(sent.headers["accept-encoding"], "identity");
    assert_eq!(sent.headers["x-trace"], "1");
    assert_eq!(sent.headers.get_all("authorization").iter().count(), 1);
}

#[tokio::test]
async fn request_body_up_to_the_limit_is_forwarded() {
    let mut s = setup().await;
    s.grant = approve_scoped(&s.broker, "bot", "svc", &["POST"], None).await;
    // 1 MiB decoded is about 1.4 MB of base64 JSON: above the API's
    // ordinary body limit, within this route's.
    let payload = vec![b'p'; 1024 * 1024];
    let resp = call_as(
        &s.broker,
        &s.key,
        &s.grant,
        "POST",
        &s.upstream.url("/v1/items"),
        Some(&payload),
    )
    .await;
    let (proxied, _) = proxied(&resp);
    assert_eq!(proxied.status, 200);
    assert_eq!(s.upstream.received()[0].body, payload);

    let mut over = payload;
    over.push(b'p');
    let resp = call_as(
        &s.broker,
        &s.key,
        &s.grant,
        "POST",
        &s.upstream.url("/v1/items"),
        Some(&over),
    )
    .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    assert_eq!(
        resp.body,
        r#"{"error":"body refused: exceeds 1048576 bytes"}"#
    );
    assert_eq!(s.upstream.received().len(), 1);
}

#[tokio::test]
async fn agent_never_sees_secret_in_any_response_part() {
    let s = setup().await;
    for (path, status) in [
        ("/echo", StatusCode::OK),
        ("/redirect", StatusCode::OK),
        ("/v1/hello", StatusCode::OK),
        ("/huge", StatusCode::BAD_GATEWAY),
        ("/gzip", StatusCode::BAD_GATEWAY),
    ] {
        let resp = get(&s, path).await;
        assert_eq!(resp.status, status, "{path}: {}", resp.body);
        assert_response_clean(&resp, SECRET);
    }
    // The grant listing and request status carry no secret either.
    let grants = s.broker.api_get(&s.key, "/v1/grants").await;
    assert_eq!(grants.status, StatusCode::OK);
    assert_clean(&grants.body, SECRET, "grant list");
}

#[tokio::test]
async fn echoed_secret_is_redacted_in_every_encoding() {
    let s = setup().await;
    let resp = get(&s, "/echo").await;
    assert_response_clean(&resp, SECRET);
    let (proxied, body) = proxied(&resp);
    let text = String::from_utf8(body).unwrap();
    for label in [
        "raw",
        "b64",
        "b64url",
        "b64blob",
        "pct",
        "pct-lower",
        "json",
    ] {
        let line = text
            .lines()
            .find(|l| l.starts_with(&format!("{label} authorization: ")))
            .unwrap_or_else(|| panic!("no {label} line in:\n{text}"));
        assert!(line.contains("[REDACTED]"), "{line}");
    }
    assert_eq!(header(&proxied, "x-echo-authorization"), Some("[REDACTED]"));
    assert_eq!(
        header(&proxied, "x-echo-b64-authorization"),
        Some("[REDACTED]")
    );
    // Other headers come back untouched.
    assert_eq!(header(&proxied, "x-echo-x-trace"), Some("1"));
    assert!(proxied.redactions >= 9, "{}", proxied.redactions);
}

#[tokio::test]
async fn secret_echoed_into_a_header_name_is_dropped_whatever_its_case() {
    // Header-name safe, with upper case the HTTP stack lowercases.
    let secret = "MiXeD-Case-Cred42";
    let s = setup().await;
    s.broker
        .backend
        .set_api_secret(s.upstream.policy("svc"), secret);
    let resp = get(&s, "/name-echo").await;
    assert_response_clean(&resp, secret);
    assert!(
        !resp
            .body
            .to_ascii_lowercase()
            .contains(&secret.to_ascii_lowercase()),
        "lowercased leak: {}",
        resp.body
    );
    let (proxied, _) = proxied(&resp);
    assert_eq!(header(&proxied, "x-plain"), Some("fine"));
    assert_eq!(proxied.redactions, 1);
}

#[tokio::test]
async fn redirect_is_returned_not_followed() {
    let s = setup().await;
    let resp = get(&s, "/redirect").await;
    assert_response_clean(&resp, SECRET);
    let (proxied, body) = proxied(&resp);
    assert_eq!(proxied.status, 302);
    assert_eq!(body, b"moved");
    let location = header(&proxied, "location").unwrap();
    assert_eq!(
        location,
        "https://elsewhere.example/collect?auth=[REDACTED]"
    );
    assert_eq!(proxied.redactions, 1);
    assert_eq!(s.upstream.received().len(), 1);
}

#[tokio::test]
async fn policy_change_after_approval_is_refused() {
    let s = setup().await;
    let other = HttpsUpstream::start().await;
    let original = s.upstream.policy("svc");
    let edits: Vec<Change<'_>> = vec![
        (
            "origin",
            Box::new(|p| p.origin = other.policy("svc").origin),
        ),
        (
            "path prefix",
            Box::new(|p| p.path_prefix = "/v1".to_owned()),
        ),
        ("methods", Box::new(|p| p.methods.truncate(1))),
        (
            "extra method",
            Box::new(|p| p.methods.push(http::Method::DELETE)),
        ),
        (
            "header",
            Box::new(|p| p.header = http::HeaderName::from_static("x-api-key")),
        ),
        (
            "format",
            Box::new(|p| p.format = ValueFormat::parse("token {{secret}}").unwrap()),
        ),
        (
            "pinned CA",
            Box::new(|p| p.ca_pem = Some(other.ca_pem().to_owned())),
        ),
        ("CA unpinned", Box::new(|p| p.ca_pem = None)),
    ];
    for (what, change) in &edits {
        let mut changed = original.clone();
        change(&mut changed);
        s.broker.backend.set_api_secret(changed, SECRET);
        let resp = get(&s, "/v1/hello").await;
        assert_eq!(resp.status, StatusCode::CONFLICT, "{what}: {}", resp.body);
        assert_eq!(resp.body, POLICY_CHANGED, "{what}");
    }
    assert!(s.upstream.received().is_empty());
    assert!(other.received().is_empty());

    // Method order and the window are not part of the destination.
    let mut reordered = original.clone();
    reordered.methods.reverse();
    reordered.max_window = Window::H4;
    s.broker.backend.set_api_secret(reordered, SECRET);
    let (proxied, _) = proxied(&get(&s, "/v1/hello").await);
    assert_eq!(proxied.status, 200);
    assert_eq!(s.upstream.received().len(), 1);
}

/// An item edited between two reads must not mix the old policy with the
/// new credential: the policy that is checked and the value that is sent
/// come from one read.
#[tokio::test]
async fn policy_and_value_come_from_one_read() {
    let s = setup().await;
    let elsewhere = HttpsUpstream::start().await;
    s.broker
        .backend
        .set_api_secret_after_next_read(elsewhere.policy("svc"), ROTATED);
    let (proxied, _) = proxied(&get(&s, "/v1/hello").await);
    assert_eq!(proxied.status, 200);
    let received = s.upstream.received();
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].headers["authorization"],
        format!("Bearer {SECRET}")
    );

    // The edit is seen whole by the next call: the origin moved, so the
    // grant no longer holds and nothing is sent anywhere.
    let resp = get(&s, "/v1/hello").await;
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert_eq!(resp.body, POLICY_CHANGED);
    assert_eq!(s.upstream.received().len(), 1);
    assert!(elsewhere.received().is_empty());
}

#[tokio::test]
async fn rotated_credential_is_used() {
    let s = setup().await;
    let (first, _) = proxied(&get(&s, "/v1/hello").await);
    assert_eq!(first.status, 200);
    s.broker
        .backend
        .set_api_secret(s.upstream.policy("svc"), ROTATED);
    let resp = get(&s, "/echo").await;
    assert_response_clean(&resp, ROTATED);
    let received = s.upstream.received();
    assert_eq!(
        received[0].headers["authorization"],
        format!("Bearer {SECRET}")
    );
    assert_eq!(
        received[1].headers["authorization"],
        format!("Bearer {ROTATED}")
    );
}

#[tokio::test]
async fn oversized_response_is_refused_whole() {
    let s = setup().await;
    for path in ["/huge", "/huge-chunked"] {
        let resp = get(&s, path).await;
        assert_eq!(
            resp.status,
            StatusCode::BAD_GATEWAY,
            "{path}: {}",
            resp.body
        );
        assert_eq!(resp.body, r#"{"error":"response exceeds 1048576 bytes"}"#);
    }
    let calls = proxy_calls(&s.broker);
    assert_eq!(calls.len(), 2);
    for call in &calls {
        assert_eq!(call["outcome"], "response exceeds 1048576 bytes");
        assert_eq!(call["status"], Value::Null);
    }

    // A larger configured limit lets the same body through.
    let roomy = ProxyLimits {
        max_response_bytes: HUGE_BYTES,
        ..ProxyLimits::default()
    };
    let s = setup_with(roomy, |_| {}).await;
    let (proxied, body) = proxied(&get(&s, "/huge-chunked").await);
    assert_eq!(proxied.status, 200);
    assert_eq!(body.len(), HUGE_BYTES);
}

#[tokio::test]
async fn compressed_response_is_refused() {
    let s = setup().await;
    let resp = get(&s, "/gzip").await;
    assert_eq!(resp.status, StatusCode::BAD_GATEWAY, "{}", resp.body);
    assert_eq!(
        resp.body,
        r#"{"error":"compressed responses are not supported"}"#
    );
    assert_eq!(
        proxy_calls(&s.broker)[0]["outcome"],
        "compressed responses are not supported"
    );
}

#[tokio::test]
async fn slow_upstream_times_out() {
    let limits = ProxyLimits {
        timeout: Duration::from_secs(1),
        ..ProxyLimits::default()
    };
    let s = setup_with(limits, |_| {}).await;
    let started = Instant::now();
    let resp = get(&s, "/slow").await;
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(resp.status, StatusCode::GATEWAY_TIMEOUT, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"upstream timed out"}"#);
    assert!(
        !resp
            .body
            .contains(std::str::from_utf8(SLOW_PREFIX).unwrap())
    );
    let calls = proxy_calls(&s.broker);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["outcome"], "upstream timed out");
}

/// An item deleted in 1Password after approval is refused as a changed
/// policy, whatever the backend said, and the upstream is never contacted.
#[tokio::test]
async fn item_deleted_after_approval_is_refused() {
    let s = setup().await;
    s.broker.backend.remove_api_secret("svc");
    let resp = get(&s, "/v1/hello").await;
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert_eq!(resp.body, POLICY_CHANGED);
    assert!(s.upstream.received().is_empty());
    let calls = proxy_calls(&s.broker);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["status"], Value::Null);
    assert_eq!(calls[0]["outcome"], "policy changed; request access again");
    assert!(audit_events(&s.broker, &["proxy_call_started"]).is_empty());
    audit::verify(s.broker.audit_path()).unwrap();

    // Nothing is left half done: with the item back, the grant works.
    s.broker
        .backend
        .set_api_secret(s.upstream.policy("svc"), SECRET);
    let (proxied, _) = proxied(&get(&s, "/v1/hello").await);
    assert_eq!(proxied.status, 200);
}

/// A secret backend that is down at call time gives a fixed 503 that does
/// not carry the backend's own words; the call is audited and never sent.
#[tokio::test]
async fn backend_unavailable_at_call_time_is_a_fixed_503() {
    const DETAIL: &str = "connect to http://10.9.8.7:8080 refused for item \"svc\"";
    let s = setup().await;
    s.broker.backend.set_api_outage(Some(DETAIL));
    let resp = get(&s, "/v1/hello").await;
    assert_eq!(
        resp.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        resp.body
    );
    assert_eq!(resp.body, r#"{"error":"secret backend unavailable"}"#);
    assert!(!resp.body.contains("10.9.8.7"));
    assert!(s.upstream.received().is_empty());
    let calls = proxy_calls(&s.broker);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["outcome"], "secret backend unavailable");
    let log = std::fs::read_to_string(s.broker.audit_path()).unwrap();
    assert!(!log.contains("10.9.8.7"));
    assert!(audit_events(&s.broker, &["proxy_call_started"]).is_empty());
    audit::verify(s.broker.audit_path()).unwrap();

    // The outage leaves no state behind: the next call succeeds.
    s.broker.backend.set_api_outage(None);
    let (proxied, _) = proxied(&get(&s, "/v1/hello").await);
    assert_eq!(proxied.status, 200);
}

/// An origin that accepts the TCP connection but never answers the TLS
/// handshake hits the connect timeout (which covers TCP and TLS), well
/// before the call's overall limit.
#[tokio::test]
async fn upstream_connect_timeout_is_a_fixed_504() {
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = silent.local_addr().unwrap().port();
    let held = tokio::spawn(async move {
        let mut open = Vec::new();
        while let Ok((stream, _)) = silent.accept().await {
            open.push(stream);
        }
    });
    let limits = ProxyLimits {
        connect_timeout: Duration::from_millis(500),
        timeout: Duration::from_secs(60),
        ..ProxyLimits::default()
    };
    let s = setup_with(limits, |p| {
        p.origin = url::Url::parse(&format!("https://127.0.0.1:{port}"))
            .unwrap()
            .origin();
    })
    .await;
    let url = format!("https://127.0.0.1:{port}/v1/hello");
    let started = Instant::now();
    let resp = call_as(&s.broker, &s.key, &s.grant, "GET", &url, None).await;
    assert!(started.elapsed() < Duration::from_secs(10));
    held.abort();
    assert_eq!(resp.status, StatusCode::GATEWAY_TIMEOUT, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"upstream timed out"}"#);
    let calls = proxy_calls(&s.broker);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["status"], Value::Null);
    assert_eq!(calls[0]["outcome"], "upstream timed out");
    assert_eq!(audit_events(&s.broker, &["proxy_call_started"]).len(), 1);
    audit::verify(s.broker.audit_path()).unwrap();
    assert_clean(&resp.body, SECRET, "timeout response");
}

#[tokio::test]
async fn revoked_or_expired_grant_refused() {
    let s = setup().await;
    let revoked = s
        .broker
        .api_post(&s.key, &format!("/v1/grants/{}/revoke", s.grant))
        .await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT, "{}", revoked.body);
    let resp = get(&s, "/v1/hello").await;
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"grant revoked"}"#);

    let fresh = approve_api(&s.broker, "bot", "svc").await;
    let url = s.upstream.url("/v1/hello");
    let resp = call_as(&s.broker, &s.key, &fresh, "GET", &url, None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    s.broker.clock.advance(30 * 60);
    let resp = call_as(&s.broker, &s.key, &fresh, "GET", &url, None).await;
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"grant expired"}"#);
    assert_eq!(s.upstream.received().len(), 1);
}

#[tokio::test]
async fn other_agents_grant_not_found() {
    let s = setup().await;
    let eve = s.broker.add_agent("eve").await;
    let url = s.upstream.url("/v1/hello");
    let resp = call_as(&s.broker, &eve, &s.grant, "GET", &url, None).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"not found"}"#);

    let resp = call_as(&s.broker, &s.key, &Id::random(), "GET", &url, None).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);

    let resp = s
        .broker
        .api_post_json(&s.key, "/v1/grants/not-an-id/http", &json!({}))
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);

    let resp = s
        .broker
        .api_post_json(&s.key, "/v1/grants/x/http", &json!({}))
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    assert!(s.upstream.received().is_empty());
    assert!(proxy_calls(&s.broker).is_empty());
}

#[tokio::test]
async fn ssh_grant_cannot_proxy() {
    let s = setup().await;
    let ssh = approve(
        &s.broker,
        "bot",
        TestBroker::pi_request("restart the backup job", Window::M30),
    )
    .await;
    let url = s.upstream.url("/v1/hello");
    let resp = call_as(&s.broker, &s.key, &ssh, "GET", &url, None).await;
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"grant is not for API access"}"#);
    assert!(s.upstream.received().is_empty());
}

#[tokio::test]
async fn untrusted_cert_refused_without_ca_pem() {
    // System roots only: the test CA is not among them.
    let s = setup_with(ProxyLimits::default(), |p| p.ca_pem = None).await;
    let resp = get(&s, "/v1/hello").await;
    assert_eq!(resp.status, StatusCode::BAD_GATEWAY, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"upstream unreachable"}"#);
    assert!(s.upstream.received().is_empty());

    // The right CA, but a name the certificate does not cover: the host
    // name is always verified.
    let s = setup_with(ProxyLimits::default(), |p| {
        let ip = p
            .origin
            .ascii_serialization()
            .replace("localhost", "127.0.0.1");
        p.origin = url::Url::parse(&ip).unwrap().origin();
    })
    .await;
    let ip_url = s
        .upstream
        .url("/v1/hello")
        .replace("localhost", "127.0.0.1");
    let resp = call_as(&s.broker, &s.key, &s.grant, "GET", &ip_url, None).await;
    assert_eq!(resp.status, StatusCode::BAD_GATEWAY, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"upstream unreachable"}"#);
    assert!(s.upstream.received().is_empty());

    // Another CA pinned is no better.
    let other = HttpsUpstream::start().await;
    let pem = other.ca_pem().to_owned();
    let s = setup_with(ProxyLimits::default(), move |p| p.ca_pem = Some(pem)).await;
    let resp = get(&s, "/v1/hello").await;
    assert_eq!(resp.status, StatusCode::BAD_GATEWAY, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"upstream unreachable"}"#);
    assert!(s.upstream.received().is_empty());
}

#[tokio::test]
async fn every_call_audited_without_secret() {
    let s = setup().await;
    let (ok, _) = proxied(&get(&s, "/v1/hello?token=agent-query-value").await);
    assert_eq!(ok.status, 200);
    let (echo, _) = proxied(&get(&s, "/echo").await);
    let (moved, _) = proxied(&get(&s, "/redirect").await);
    let url = s.upstream.url("/v1/hello");
    let refused = call_as(&s.broker, &s.key, &s.grant, "DELETE", &url, None).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert_eq!(
        refused.body,
        r#"{"error":"method is not allowed for this secret"}"#
    );
    s.broker
        .backend
        .set_api_secret(s.upstream.policy("svc"), ROTATED);
    let (rotated, _) = proxied(&get(&s, "/echo").await);
    let mut moved_policy = s.upstream.policy("svc");
    moved_policy.path_prefix = "/v1".to_owned();
    s.broker.backend.set_api_secret(moved_policy, ROTATED);
    let changed = get(&s, "/v1/hello").await;
    assert_eq!(changed.status, StatusCode::CONFLICT);

    let calls = proxy_calls(&s.broker);
    let origin = s.upstream.origin();
    let grant = s.grant.as_str();
    let expected = [
        json!({"type": "proxy_call", "grant_id": grant, "method": "GET",
               "url": format!("{origin}/v1/hello"), "status": 200,
               "response_bytes": 19, "redactions": 0, "outcome": "ok"}),
        json!({"type": "proxy_call", "grant_id": grant, "method": "GET",
               "url": format!("{origin}/echo"), "status": 200,
               "response_bytes": calls[1]["response_bytes"], "redactions": echo.redactions,
               "outcome": "ok"}),
        json!({"type": "proxy_call", "grant_id": grant, "method": "GET",
               "url": format!("{origin}/redirect"), "status": 302,
               "response_bytes": 5, "redactions": moved.redactions, "outcome": "ok"}),
        json!({"type": "proxy_call", "grant_id": grant, "method": "DELETE",
               "url": format!("{origin}/v1/hello"), "status": null,
               "response_bytes": 0, "redactions": 0,
               "outcome": "method is not allowed for this secret"}),
        json!({"type": "proxy_call", "grant_id": grant, "method": "GET",
               "url": format!("{origin}/echo"), "status": 200,
               "response_bytes": calls[4]["response_bytes"], "redactions": rotated.redactions,
               "outcome": "ok"}),
        json!({"type": "proxy_call", "grant_id": grant, "method": "GET",
               "url": format!("{origin}/v1/hello"), "status": null,
               "response_bytes": 0, "redactions": 0,
               "outcome": "policy changed; request access again"}),
    ];
    assert_eq!(calls, expected);
    assert!(echo.redactions > 0);

    // Each call that went out was recorded as started before it was sent;
    // refused calls never started.
    let events = audit_events(&s.broker, &["proxy_call_started", "proxy_call"]);
    let types: Vec<&str> = events.iter().map(|e| e["type"].as_str().unwrap()).collect();
    assert_eq!(
        types,
        [
            "proxy_call_started",
            "proxy_call",
            "proxy_call_started",
            "proxy_call",
            "proxy_call_started",
            "proxy_call",
            "proxy_call",
            "proxy_call_started",
            "proxy_call",
            "proxy_call",
        ]
    );
    assert_eq!(
        events[0],
        json!({"type": "proxy_call_started", "grant_id": grant, "method": "GET",
               "url": format!("{origin}/v1/hello")})
    );

    let log = std::fs::read_to_string(s.broker.audit_path()).unwrap();
    assert!(!log.contains("agent-query-value"));
    assert_clean(&log, SECRET, "audit log");
    assert_clean(&log, ROTATED, "audit log");
    audit::verify(s.broker.audit_path()).unwrap();
}

#[tokio::test]
async fn proxy_refused_when_audit_unwritable() {
    let s = setup().await;
    // Another writer holds the audit log's lock: the pre-flight entry
    // cannot be written, so nothing may be sent.
    let holder = std::fs::File::open(s.broker.audit_path()).unwrap();
    holder.lock().unwrap();
    let resp = get(&s, "/v1/hello").await;
    holder.unlock().unwrap();
    assert_eq!(
        resp.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        resp.body
    );
    assert_eq!(resp.body, r#"{"error":"internal error"}"#);
    assert!(s.upstream.received().is_empty());
    assert!(audit_events(&s.broker, &["proxy_call_started", "proxy_call"]).is_empty());

    // Once the log is writable again, calls go through.
    let (proxied, _) = proxied(&get(&s, "/v1/hello").await);
    assert_eq!(proxied.status, 200);
}

#[tokio::test]
async fn revoked_during_call_withholds_response() {
    let s = setup().await;
    let call = get(&s, "/delayed");
    let revoke = async {
        while s.upstream.received().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        s.broker
            .api_post(&s.key, &format!("/v1/grants/{}/revoke", s.grant))
            .await
    };
    let (resp, revoked) = tokio::join!(call, revoke);
    assert_eq!(revoked.status, StatusCode::NO_CONTENT, "{}", revoked.body);
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"grant revoked during the call"}"#);
    let calls = proxy_calls(&s.broker);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["outcome"], "grant revoked during the call");
    assert_eq!(calls[0]["status"], 200);
}

#[tokio::test]
async fn expired_during_call_withholds_response() {
    let s = setup().await;
    let call = get(&s, "/delayed");
    let expire = async {
        while s.upstream.received().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        s.broker.clock.advance(30 * 60);
    };
    let (resp, ()) = tokio::join!(call, expire);
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"grant expired during the call"}"#);
    let calls = proxy_calls(&s.broker);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["outcome"], "grant expired during the call");
    assert_eq!(calls[0]["status"], 200);
}

/// A request that names no methods is approved read-only: `GET` and `HEAD`
/// work, a write the item would allow is refused.
#[tokio::test]
async fn read_only_grant_by_default() {
    let s = setup_with(ProxyLimits::default(), |p| {
        p.methods.push(http::Method::HEAD);
    })
    .await;
    let resp = get(&s, "/v1/hello").await;
    assert_eq!(proxied(&resp).0.status, 200);
    let url = s.upstream.url("/v1/items");
    let head = call_as(&s.broker, &s.key, &s.grant, "HEAD", &url, None).await;
    assert_eq!(proxied(&head).0.status, 200);
    let post = call_as(&s.broker, &s.key, &s.grant, "POST", &url, Some(b"x")).await;
    assert_eq!(post.status, StatusCode::BAD_REQUEST, "{}", post.body);
    assert_eq!(post.body, METHOD_REFUSED);
    assert_eq!(s.upstream.received().len(), 2);
}

/// Methods the request named are what the grant allows, no more.
#[tokio::test]
async fn write_grant_allows_requested_methods() {
    let s = setup().await;
    let grant = approve_scoped(&s.broker, "bot", "svc", &["POST"], None).await;
    let url = s.upstream.url("/v1/items");
    let post = call_as(&s.broker, &s.key, &grant, "POST", &url, Some(b"x")).await;
    assert_eq!(proxied(&post).0.status, 200);
    let get = call_as(&s.broker, &s.key, &grant, "GET", &url, None).await;
    assert_eq!(get.status, StatusCode::BAD_REQUEST, "{}", get.body);
    assert_eq!(get.body, METHOD_REFUSED);
    let both = approve_scoped(&s.broker, "bot", "svc", &["POST", "GET"], None).await;
    let get = call_as(&s.broker, &s.key, &both, "GET", &url, None).await;
    assert_eq!(proxied(&get).0.status, 200);
    let delete = call_as(&s.broker, &s.key, &both, "DELETE", &url, None).await;
    assert_eq!(delete.status, StatusCode::BAD_REQUEST, "{}", delete.body);
    assert_eq!(s.upstream.received().len(), 2);
}

/// A call the item would allow but the grant does not (a method or a path
/// outside what was approved) is refused like an item violation, audited,
/// and never reaches the upstream.
#[tokio::test]
async fn call_outside_narrowed_scope_refused() {
    let s = setup().await;
    let grant = approve_scoped(&s.broker, "bot", "svc", &["GET"], Some("/v1/")).await;
    let post = call_as(
        &s.broker,
        &s.key,
        &grant,
        "POST",
        &s.upstream.url("/v1/items"),
        Some(b"x"),
    )
    .await;
    assert_eq!(post.status, StatusCode::BAD_REQUEST, "{}", post.body);
    assert_eq!(post.body, METHOD_REFUSED);
    let outside = call_as(
        &s.broker,
        &s.key,
        &grant,
        "GET",
        &s.upstream.url("/v2/items"),
        None,
    )
    .await;
    assert_eq!(outside.status, StatusCode::BAD_REQUEST, "{}", outside.body);
    assert!(
        outside.body.contains("URL path is not allowed"),
        "{}",
        outside.body
    );
    assert!(s.upstream.received().is_empty());

    let calls = proxy_calls(&s.broker);
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert_eq!(calls[0]["method"], "POST");
    assert_eq!(calls[0]["status"], Value::Null);
    assert_eq!(calls[0]["outcome"], "method is not allowed for this secret");
    assert_eq!(calls[1]["method"], "GET");
    assert_eq!(calls[1]["status"], Value::Null);
    assert!(
        calls[1]["outcome"]
            .as_str()
            .unwrap()
            .starts_with("URL path is not allowed"),
        "{calls:?}"
    );

    let inside = call_as(
        &s.broker,
        &s.key,
        &grant,
        "GET",
        &s.upstream.url("/v1/items"),
        None,
    )
    .await;
    assert_eq!(proxied(&inside).0.status, 200);
}

/// A grant holding the item's whole scope, as 0.3 approvals stored, keeps
/// allowing every item method: the stored scope is honoured, not
/// re-defaulted to read-only.
#[tokio::test]
async fn full_scope_grant_still_allows_item_write_methods() {
    let s = setup().await;
    let grant = approve_scoped(&s.broker, "bot", "svc", &["GET", "POST"], Some("/")).await;
    let post = call_as(
        &s.broker,
        &s.key,
        &grant,
        "POST",
        &s.upstream.url("/v1/items"),
        Some(b"x"),
    )
    .await;
    assert_eq!(proxied(&post).0.status, 200);
    assert_eq!(s.upstream.received()[0].method, "POST");
}

const TOO_MANY: &str = r#"{"error":"too many concurrent calls"}"#;

fn limited(max_calls_per_agent: usize, max_calls: usize) -> ProxyLimits {
    ProxyLimits {
        max_calls_per_agent,
        max_calls,
        ..ProxyLimits::default()
    }
}

/// Assert that exactly `refused` of `responses` were refused for too many
/// calls and the rest succeeded, and that each refusal was audited without
/// reaching the upstream.
fn assert_refusals(s: &Setup, responses: &[TestResponse], refused: usize) {
    let (slow, others): (Vec<_>, Vec<_>) =
        responses.iter().partition(|r| r.status == StatusCode::OK);
    assert_eq!(others.len(), refused, "{responses:?}");
    for r in &others {
        assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.body);
        assert_eq!(r.body, TOO_MANY);
    }
    assert_eq!(s.upstream.received().len(), slow.len());
    let calls = proxy_calls(&s.broker);
    let audited = calls
        .iter()
        .filter(|c| c["outcome"] == "too many concurrent calls")
        .collect::<Vec<_>>();
    assert_eq!(audited.len(), refused);
    for c in audited {
        assert_eq!(c["status"], Value::Null);
        assert_eq!(c["response_bytes"], 0);
    }
}

#[tokio::test]
async fn per_agent_limit_refuses_excess() {
    let s = setup_with(limited(1, 16), |_| {}).await;
    let (a, b) = tokio::join!(get(&s, "/delayed"), get(&s, "/delayed"));
    assert_refusals(&s, &[a, b], 1);

    // Another agent is not held up by the first one's calls.
    let other_key = s.broker.add_agent("other").await;
    let other_grant = approve_api(&s.broker, "other", "svc").await;
    let url = s.upstream.url("/delayed");
    let (mine, theirs) = tokio::join!(
        get(&s, "/delayed"),
        call_as(&s.broker, &other_key, &other_grant, "GET", &url, None)
    );
    assert_eq!(mine.status, StatusCode::OK, "{}", mine.body);
    assert_eq!(theirs.status, StatusCode::OK, "{}", theirs.body);
}

#[tokio::test]
async fn overall_limit_refuses_excess() {
    let s = setup_with(limited(1, 2), |_| {}).await;
    let url = s.upstream.url("/delayed");
    let mut agents = vec![(s.key.clone(), s.grant.clone())];
    for name in ["second", "third"] {
        let key = s.broker.add_agent(name).await;
        let grant = approve_api(&s.broker, name, "svc").await;
        agents.push((key, grant));
    }
    let call = |i: usize| call_as(&s.broker, &agents[i].0, &agents[i].1, "GET", &url, None);
    let (a, b, c) = tokio::join!(call(0), call(1), call(2));
    assert_refusals(&s, &[a, b, c], 1);
}

#[tokio::test]
async fn slot_released_after_error_and_disconnect() {
    let s = setup_with(limited(1, 1), |_| {}).await;

    // A refused call and an upstream failure each give the slot back.
    let url = s.upstream.url("/v1/hello");
    let refused = call_as(&s.broker, &s.key, &s.grant, "DELETE", &url, None).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    let failed = get(&s, "/gzip").await;
    assert_eq!(failed.status, StatusCode::BAD_GATEWAY, "{}", failed.body);
    let (ok, _) = proxied(&get(&s, "/v1/hello").await);
    assert_eq!(ok.status, 200);

    // An agent that hangs up leaves its call running, still holding the
    // slot, and the slot is free again once that call is over.
    let gone = tokio::time::timeout(Duration::from_millis(100), get(&s, "/delayed")).await;
    assert!(gone.is_err(), "the call should still be running");
    let busy = get(&s, "/v1/hello").await;
    assert_eq!(busy.status, StatusCode::TOO_MANY_REQUESTS, "{}", busy.body);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let resp = get(&s, "/v1/hello").await;
        if resp.status == StatusCode::OK {
            break;
        }
        assert_eq!(resp.status, StatusCode::TOO_MANY_REQUESTS, "{}", resp.body);
        assert!(Instant::now() < deadline, "slot never released");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
