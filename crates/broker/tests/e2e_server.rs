//! The agent API end to end: requests, approval, long-polling, grants,
//! restart behaviour and the real listeners, against the in-process broker.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use ssh_key::Certificate;
use warden_broker::requests;
use warden_broker::testkit::{TEST_OWNER, TestBroker};
use warden_broker_proto::{CreatedResponse, GrantView, Id, RequestStatus, Window};

fn body(goal: &str, window: Window) -> Value {
    serde_json::to_value(TestBroker::pi_request(goal, window)).unwrap()
}

async fn create(broker: &TestBroker, key: &str, goal: &str) -> CreatedResponse {
    let resp = broker
        .api_post_json(key, "/v1/requests", &body(goal, Window::M30))
        .await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.body);
    serde_json::from_str(&resp.body).unwrap()
}

async fn poll(broker: &TestBroker, key: &str, id: &Id, wait: u32) -> RequestStatus {
    let resp = broker
        .api_get(key, &format!("/v1/requests/{id}?wait={wait}"))
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    serde_json::from_str(&resp.body).unwrap()
}

/// Create and approve a 30m request, returning the grant.
async fn granted(broker: &TestBroker, key: &str) -> GrantView {
    let created = create(broker, key, "restart the backup job").await;
    let token = warden_broker::testkit::CapturingNotifier::token(&broker.capture.next().await);
    let done = broker.approve(&token, Window::M30).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    match poll(broker, key, &created.id, 0).await {
        RequestStatus::Approved(view) => view,
        other => panic!("expected approved, got {other:?}"),
    }
}

#[tokio::test]
async fn full_flow_request_approve_returns_cert() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;

    let created = create(&broker, &key, "restart the backup job").await;
    let bell = broker.capture.next().await;
    assert!(bell.message.contains("restart the backup job"));
    let token = warden_broker::testkit::CapturingNotifier::token(&bell);

    let (status, approved) = tokio::join!(poll(&broker, &key, &created.id, 30), async {
        broker.approve(&token, Window::M30).await
    });
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);

    let RequestStatus::Approved(view) = status else {
        panic!("long poll should return the approval, got {status:?}");
    };
    let cert = Certificate::from_openssh(&view.ssh.certificate).unwrap();
    assert_eq!(
        cert.key_id(),
        format!("warden:bot:{}", view.grant_id.as_str())
    );
    assert_eq!(cert.valid_principals(), ["warden:pi:alice"]);
    assert_eq!(view.not_after - view.not_before, 1800);

    let listed = broker.api_get(&key, "/v1/grants").await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    let listed: Vec<GrantView> = serde_json::from_str(&listed.body).unwrap();
    assert_eq!(listed, [view]);
}

#[tokio::test]
async fn agent_cannot_read_other_agents_request() {
    let broker = TestBroker::new().await;
    let alice = broker.add_agent("alice").await;
    let bob = broker.add_agent("bob").await;
    let created = create(&broker, &alice, "alice's job").await;

    let theirs = broker
        .api_get(&bob, &format!("/v1/requests/{}", created.id))
        .await;
    assert_eq!(theirs.status, StatusCode::NOT_FOUND, "{}", theirs.body);
    assert_eq!(theirs.json(), json!({"error": "not found"}));
    assert_eq!(
        poll(&broker, &alice, &created.id, 0).await,
        RequestStatus::Pending
    );
}

#[tokio::test]
async fn revoke_grant_via_api_then_listed_inactive() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let other = broker.add_agent("other").await;
    let view = granted(&broker, &key).await;
    let path = format!("/v1/grants/{}/revoke", view.grant_id);

    let foreign = broker.api_post(&other, &path).await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND, "{}", foreign.body);
    assert_eq!(
        broker
            .api_get(&key, "/v1/grants")
            .await
            .json()
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let revoked = broker.api_post(&key, &path).await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT, "{}", revoked.body);
    assert!(revoked.body.is_empty());

    let listed = broker.api_get(&key, "/v1/grants").await;
    assert_eq!(listed.json(), json!([]));
    let again = broker.api_post(&key, &path).await;
    assert_eq!(again.status, StatusCode::NO_CONTENT, "{}", again.body);
    assert!(broker.audit_types().contains(&"grant_revoked".to_owned()));
}

#[tokio::test]
async fn restart_preserves_pending_and_grants() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let mut passkey = broker.enroll_soft_passkey().await;

    let first = create(&broker, &key, "first").await;
    let first_token =
        warden_broker::testkit::CapturingNotifier::token(&broker.capture.next().await);
    let done = broker
        .approve_with(&mut passkey, &first_token, Window::M30)
        .await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    let RequestStatus::Approved(grant) = poll(&broker, &key, &first.id, 0).await else {
        panic!("first request should be approved");
    };

    let second = create(&broker, &key, "second").await;
    let token = warden_broker::testkit::CapturingNotifier::token(&broker.capture.next().await);
    let begin = broker.begin_approval(&token, Window::M30).await;
    let (ceremony, credential) = TestBroker::sign(&mut passkey, &begin);

    let broker = broker.restart().await;

    assert_eq!(
        poll(&broker, &key, &second.id, 0).await,
        RequestStatus::Pending
    );
    let listed: Vec<GrantView> =
        serde_json::from_str(&broker.api_get(&key, "/v1/grants").await.body).unwrap();
    assert_eq!(
        listed.iter().map(|g| &g.grant_id).collect::<Vec<_>>(),
        [&grant.grant_id]
    );

    let lost = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(lost.status, StatusCode::GONE, "{}", lost.body);
    assert_eq!(
        poll(&broker, &key, &second.id, 0).await,
        RequestStatus::Pending
    );

    let retried = broker.approve_with(&mut passkey, &token, Window::M30).await;
    assert_eq!(retried.status, StatusCode::OK, "{}", retried.body);
    assert!(matches!(
        poll(&broker, &key, &second.id, 0).await,
        RequestStatus::Approved(_)
    ));
}

#[tokio::test]
async fn healthz_unauthenticated() {
    let broker = TestBroker::new().await;
    let resp = broker
        .api_send(Request::get("/healthz").body(Body::empty()).unwrap())
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body, "ok");
}

#[tokio::test]
async fn every_other_route_requires_the_owner_and_an_agent_key() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let id = Id::random();
    let routes = [
        ("POST", "/v1/requests".to_owned()),
        ("GET", format!("/v1/requests/{id}")),
        ("GET", "/v1/grants".to_owned()),
        ("POST", format!("/v1/grants/{id}/revoke")),
    ];
    for (method, path) in routes {
        let build = |login: Option<&str>, bearer: Option<&str>| {
            let mut req = Request::builder().method(method).uri(&path);
            if let Some(login) = login {
                req = req.header("Tailscale-User-Login", login);
            }
            if let Some(bearer) = bearer {
                req = req.header("Authorization", format!("Bearer {bearer}"));
            }
            req.body(Body::empty()).unwrap()
        };
        let anonymous = broker.api_send(build(None, None)).await;
        assert_eq!(anonymous.status, StatusCode::FORBIDDEN, "{method} {path}");
        let no_key = broker.api_send(build(Some(TEST_OWNER), None)).await;
        assert_eq!(no_key.status, StatusCode::UNAUTHORIZED, "{method} {path}");
        let bad_key = broker
            .api_send(build(Some(TEST_OWNER), Some("wdn_nope")))
            .await;
        assert_eq!(bad_key.status, StatusCode::UNAUTHORIZED, "{method} {path}");
        let stranger = broker
            .api_send(build(Some("evil@example.com"), Some(&key)))
            .await;
        assert_eq!(stranger.status, StatusCode::FORBIDDEN, "{method} {path}");
    }
}

#[tokio::test]
async fn bodies_over_16_kib_are_rejected() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let mut huge = body("x", Window::M30);
    huge["padding"] = Value::String("a".repeat(17 * 1024));
    let resp = broker.api_post_json(&key, "/v1/requests", &huge).await;
    assert_eq!(resp.status, StatusCode::PAYLOAD_TOO_LARGE, "{}", resp.body);
    assert!(resp.json()["error"].is_string());
}

#[tokio::test]
async fn errors_map_to_statuses_without_leaking_internals() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;

    let mut unknown = body("job", Window::M30);
    unknown["access"]["target"] = json!("nope");
    let resp = broker.api_post_json(&key, "/v1/requests", &unknown).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);
    assert!(resp.json()["error"].as_str().unwrap().contains("nope"));

    let too_long = broker
        .api_post_json(&key, "/v1/requests", &body("job", Window::H4))
        .await;
    assert_eq!(
        too_long.status,
        StatusCode::BAD_REQUEST,
        "{}",
        too_long.body
    );

    let mut bad_goal = body("job", Window::M30);
    bad_goal["goal"] = json!("");
    let resp = broker.api_post_json(&key, "/v1/requests", &bad_goal).await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);

    let id = Id::random();
    for wait in ["31", "abc", "-1"] {
        let resp = broker
            .api_get(&key, &format!("/v1/requests/{id}?wait={wait}"))
            .await;
        assert_eq!(
            resp.status,
            StatusCode::BAD_REQUEST,
            "wait={wait}: {}",
            resp.body
        );
    }
    let resp = broker.api_get(&key, "/v1/requests/not-an-id").await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);

    sqlx::query("DROP TABLE requests")
        .execute(&broker.state().pool)
        .await
        .unwrap();
    let failed = broker
        .api_post_json(&key, "/v1/requests", &body("job", Window::M30))
        .await;
    assert_eq!(failed.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(failed.json(), json!({"error": "internal error"}));
}

#[tokio::test]
async fn spawn_serves_both_routers_on_real_ports() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let urls = broker.spawn().await;
    let client = reqwest::Client::new();

    let health = client
        .get(urls.api.join("healthz").unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let created = client
        .post(urls.api.join("v1/requests").unwrap())
        .header("Tailscale-User-Login", TEST_OWNER)
        .bearer_auth(&key)
        .json(&body("over the wire", Window::M30))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: CreatedResponse = created.json().await.unwrap();
    let token = warden_broker::testkit::CapturingNotifier::token(&broker.capture.next().await);

    let page = client
        .get(urls.approval.join(&format!("approve/{token}")).unwrap())
        .header("Tailscale-User-Login", TEST_OWNER)
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert!(page.text().await.unwrap().contains("over the wire"));

    let denied = client
        .get(urls.approval.join("history").unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        poll(&broker, &key, &created.id, 0).await,
        RequestStatus::Pending
    );
}

#[tokio::test]
async fn sweep_loop_expires_pending_requests_and_stops_on_shutdown() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let created = create(&broker, &key, "will lapse").await;
    broker.clock.advance(601);

    let (stop, stopped) = tokio::sync::watch::channel(false);
    let sweeper = tokio::spawn(requests::sweep_loop(
        broker.state().requests.clone(),
        Duration::from_millis(10),
        stopped,
    ));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let row: (String,) = sqlx::query_as("SELECT status FROM requests WHERE id = ?")
                .bind(created.id.as_str())
                .fetch_one(&broker.state().pool)
                .await
                .unwrap();
            if row.0 == "expired" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("sweeper expires the request");

    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), sweeper)
        .await
        .expect("sweeper stops")
        .unwrap();
}

#[tokio::test]
async fn backend_outage_is_503_without_detail() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    broker
        .backend
        .set_target_outage(Some("connect at http://10.9.8.7:8080 refused"));
    let resp = broker
        .api_post_json(
            &key,
            "/v1/requests",
            &body("restart the backup job", Window::M30),
        )
        .await;
    assert_eq!(
        resp.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        resp.body
    );
    assert_eq!(resp.body, r#"{"error":"secret backend unavailable"}"#);
}
