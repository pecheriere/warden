//! What a call forwards and returns: the injected header, request bodies,
//! redaction of an echoed secret, and redirects.

use axum::http::StatusCode;

use super::{
    SECRET, approve_scoped, assert_clean, assert_response_clean, call_as, get, header, proxied,
    setup,
};

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
