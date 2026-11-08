//! The item at call time: a changed, rotated or deleted policy, and a backend
//! that is down.

use axum::http::StatusCode;
use serde_json::Value;
use warden_broker::audit;
use warden_broker::policy::{ApiSecretPolicy, ValueFormat};
use warden_broker::testkit::HttpsUpstream;
use warden_broker_proto::Window;

use super::{
    ROTATED, SECRET, assert_response_clean, audit_events, get, proxied, proxy_calls, setup,
};

const POLICY_CHANGED: &str = r#"{"error":"policy changed; request access again"}"#;

/// A named change to a policy.
type Change<'a> = (&'static str, Box<dyn Fn(&mut ApiSecretPolicy) + 'a>);

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
    assert_eq!(
        audit_events(&s.broker, &["proxy_call_started"]),
        [] as [serde_json::Value; 0]
    );
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
    assert_eq!(
        audit_events(&s.broker, &["proxy_call_started"]),
        [] as [serde_json::Value; 0]
    );
    audit::verify(s.broker.audit_path()).unwrap();

    // The outage leaves no state behind: the next call succeeds.
    s.broker.backend.set_api_outage(None);
    let (proxied, _) = proxied(&get(&s, "/v1/hello").await);
    assert_eq!(proxied.status, 200);
}
