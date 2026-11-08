//! Valid signed requests: accepted on the agent routes and for proxied calls.

use std::time::Duration;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;
use ssh_key::Algorithm;
use warden_broker::test_keys::P256;
use warden_broker::testkit::{HttpsUpstream, TestBroker};
use warden_broker_proto::{Id, RequestStatus, Window};

use super::{BODY_LIMIT, create_body, name, nonce_rows};

#[tokio::test]
async fn signed_request_accepted() {
    for algorithm in [Algorithm::Ed25519, P256] {
        let broker = TestBroker::new().await;
        let key = broker.add_signing_agent("bot", algorithm.clone()).await;

        let created = broker
            .api_signed(&key, "bot", "POST", "/v1/requests", &create_body("deploy"))
            .await;
        assert_eq!(
            created.status,
            StatusCode::CREATED,
            "{algorithm}: {}",
            created.body
        );
        let id = created.json()["id"].as_str().unwrap().to_owned();

        // A long poll signs its query and the empty body.
        let polled = broker
            .api_signed(
                &key,
                "bot",
                "GET",
                &format!("/v1/requests/{id}?wait=1"),
                b"",
            )
            .await;
        assert_eq!(polled.status, StatusCode::OK, "{}", polled.body);
        assert_eq!(polled.json()["status"], "pending");

        let grants = broker
            .api_signed(&key, "bot", "GET", "/v1/grants", b"")
            .await;
        assert_eq!(grants.status, StatusCode::OK, "{}", grants.body);
        assert_eq!(grants.body, "[]");

        let cancelled = broker
            .api_signed(
                &key,
                "bot",
                "POST",
                &format!("/v1/requests/{id}/cancel"),
                b"",
            )
            .await;
        assert_eq!(
            cancelled.status,
            StatusCode::NO_CONTENT,
            "{}",
            cancelled.body
        );

        // Authenticated: the grant lookup itself answers.
        let revoke = broker
            .api_signed(
                &key,
                "bot",
                "POST",
                &format!("/v1/grants/{}/revoke", Id::random()),
                b"",
            )
            .await;
        assert_eq!(revoke.status, StatusCode::NOT_FOUND, "{}", revoke.body);

        assert_eq!(nonce_rows(&broker).await, 5);
    }
}

#[tokio::test]
async fn signed_proxy_call_and_grant_revocation() {
    let broker = TestBroker::new().await;
    let upstream = HttpsUpstream::start().await;
    broker
        .backend
        .set_api_secret(upstream.policy("svc"), "s3cret-value-for-tests");
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let mut request = TestBroker::api_request("svc", "call the test api", Window::M30);
    if let warden_broker_proto::Access::Api { methods, .. } = &mut request.access {
        *methods = Some(vec!["POST".to_owned()]);
    }
    let (created, token) = broker.create_request("bot", request).await;
    let done = broker.approve(&token, Window::M30).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    let RequestStatus::Approved(view) = broker
        .state()
        .requests
        .status(&name("bot"), &created.id, Duration::ZERO)
        .await
        .unwrap()
    else {
        panic!("expected approved")
    };
    let grant = view.grant_id;

    // Well above the ordinary 16 KiB limit, within the proxy route's.
    let payload = vec![b'p'; 512 * 1024];
    let body = serde_json::to_vec(&json!({
        "method": "POST",
        "url": upstream.url("/v1/items"),
        "headers": [],
        "body_b64": STANDARD.encode(&payload),
    }))
    .unwrap();
    assert!(body.len() > BODY_LIMIT);
    let resp = broker
        .api_signed(
            &key,
            "bot",
            "POST",
            &format!("/v1/grants/{grant}/http"),
            &body,
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(resp.json()["status"], 200);
    assert_eq!(upstream.received()[0].body, payload);

    let revoked = broker
        .api_signed(
            &key,
            "bot",
            "POST",
            &format!("/v1/grants/{grant}/revoke"),
            b"",
        )
        .await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT, "{}", revoked.body);
}
