//! Which grant may call what: revoked, expired, foreign and ssh grants, and the
//! methods and path a grant was approved for.

use axum::http::StatusCode;
use serde_json::{Value, json};
use warden_broker::proxy::ProxyLimits;
use warden_broker::testkit::TestBroker;
use warden_broker_proto::{Id, Window};

use super::{
    approve, approve_api, approve_scoped, call_as, get, proxied, proxy_calls, setup, setup_with,
};

const METHOD_REFUSED: &str = r#"{"error":"method is not allowed for this secret"}"#;

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
    assert_eq!(proxy_calls(&s.broker), [] as [serde_json::Value; 0]);
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
