//! Upstreams that misbehave: oversized, compressed or slow responses, a stalled
//! handshake, and an untrusted certificate.

use std::time::Duration;

use axum::http::StatusCode;
use serde_json::Value;
use warden_broker::audit;
use warden_broker::proxy::ProxyLimits;
use warden_broker::testkit::HttpsUpstream;
use warden_broker::testkit::upstream::{HUGE_BYTES, SLOW_PREFIX};

use super::{
    SECRET, assert_clean, audit_events, call_as, get, proxied, proxy_calls, setup, setup_with,
};

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
    // Short of the minute `/slow` takes to end by itself.
    let resp = tokio::time::timeout(Duration::from_secs(30), get(&s, "/slow"))
        .await
        .expect("the upstream timeout never fired");
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
        timeout: Duration::from_secs(600),
        ..ProxyLimits::default()
    };
    let s = setup_with(limits, |p| {
        p.origin = url::Url::parse(&format!("https://127.0.0.1:{port}"))
            .unwrap()
            .origin();
    })
    .await;
    let url = format!("https://127.0.0.1:{port}/v1/hello");
    // Far short of the overall timeout, which would answer the same.
    let resp = tokio::time::timeout(
        Duration::from_secs(60),
        call_as(&s.broker, &s.key, &s.grant, "GET", &url, None),
    )
    .await
    .expect("the connect timeout never fired");
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
