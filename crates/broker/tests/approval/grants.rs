//! Denying a request, the active grants page with its live activity, and
//! the history page.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use warden_broker::testkit::{TEST_START, TestBroker};
use warden_broker_proto::{Id, RequestStatus, Window};

use super::{CSP, bot, grant_count, pending, status};

#[tokio::test]
async fn deny_marks_denied_and_wakes_cli() {
    let (broker, created, token) = pending().await;
    let broker = Arc::new(broker);
    let poller = {
        let broker = broker.clone();
        let id = created.id.clone();
        tokio::spawn(async move {
            broker
                .state()
                .requests
                .status(&bot(), &id, Duration::from_secs(30))
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        while broker.state().requests.bus().receiver_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("long-poll never subscribed");

    let denied = broker.deny(&token).await;
    assert_eq!(denied.status, StatusCode::OK, "{}", denied.body);
    let woke = tokio::time::timeout(Duration::from_secs(5), poller)
        .await
        .expect("long-poll not woken")
        .unwrap();
    assert_eq!(woke.unwrap(), RequestStatus::Denied);
    assert!(broker.audit_types().contains(&"denied".to_owned()));

    let again = broker.deny(&token).await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{}", again.body);
    let unknown = broker.deny("no-such-token").await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND, "{}", unknown.body);
}

#[tokio::test]
async fn cancelled_request_cannot_be_approved() {
    let (broker, created, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    // The ceremony starts while the request is still pending.
    let begin = broker.begin_approval(&token, Window::M15).await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);

    broker
        .state()
        .requests
        .cancel(&bot(), &created.id)
        .await
        .unwrap();
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Cancelled);

    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::NOT_FOUND);
    assert!(
        page.body.contains("Cancelled by the agent."),
        "{}",
        page.body
    );
    let again = broker.begin_approval(&token, Window::M15).await;
    assert_eq!(again.status, StatusCode::NOT_FOUND, "{}", again.body);
    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(finish.status, StatusCode::CONFLICT, "{}", finish.body);
    assert_eq!(grant_count(&broker).await, 0);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Cancelled);
    let denied = broker.deny(&token).await;
    assert_eq!(denied.status, StatusCode::CONFLICT, "{}", denied.body);

    let history = broker.get("/history").await;
    assert!(history.body.contains("cancelled"), "{}", history.body);
}

#[tokio::test]
async fn grants_page_lists_and_revokes() {
    let (broker, created, token) = pending().await;
    let approved = broker.approve(&token, Window::M30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let RequestStatus::Approved(view) = status(&broker, &created.id).await else {
        panic!("expected approved");
    };

    let page = broker.get("/grants").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains(view.grant_id.as_str()), "{}", page.body);
    assert!(page.body.contains("<bdi>bot</bdi>"), "{}", page.body);
    assert!(page.body.contains(created.fingerprint.as_str()));

    let revoke = broker
        .post_json(
            &format!("/grants/{}/revoke", view.grant_id.as_str()),
            &json!({}),
        )
        .await;
    assert_eq!(revoke.status, StatusCode::OK, "{}", revoke.body);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Revoked);
    let page = broker.get("/grants").await;
    assert!(!page.body.contains(view.grant_id.as_str()), "{}", page.body);
    assert!(broker.audit_types().contains(&"grant_revoked".to_owned()));

    let unknown = broker
        .post_json(
            &format!("/grants/{}/revoke", Id::random().as_str()),
            &json!({}),
        )
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
}

/// A broker with one approved grant for `bot`.
async fn approved_grant() -> (TestBroker, Id) {
    let (broker, created, token) = pending().await;
    let approved = broker.approve(&token, Window::M30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let RequestStatus::Approved(view) = status(&broker, &created.id).await else {
        panic!("expected approved");
    };
    (broker, view.grant_id)
}

#[tokio::test]
async fn live_lists_session_and_call_under_their_grant() {
    let (broker, grant) = approved_grant().await;
    let quiet = broker.get("/grants/live").await;
    assert_eq!(quiet.status, StatusCode::OK, "{}", quiet.body);
    assert_eq!(
        quiet.json(),
        json!({"grants": [{"grant_id": grant.as_str(), "relay_sessions": [], "proxy_calls": []}]})
    );

    let _session = broker.hold_live_session(&grant, "bot");
    let _call = broker.hold_live_call(&grant, "bot", "POST", "/v1/jobs");
    // Entries of a grant that is not active are not listed.
    let _other = broker.hold_live_call(&Id::random(), "bot", "GET", "/elsewhere");

    let live = broker.get("/grants/live").await;
    assert_eq!(live.status, StatusCode::OK, "{}", live.body);
    assert_eq!(live.header("content-type"), "application/json");
    assert_eq!(live.header("cache-control"), "no-store");
    assert_eq!(live.header("content-security-policy"), CSP);
    assert_eq!(
        live.json(),
        json!({"grants": [{
            "grant_id": grant.as_str(),
            "relay_sessions": [{
                "started_at": TEST_START,
                "bytes_to_target": 0,
                "bytes_from_target": 0,
                "idle_secs": 0,
            }],
            "proxy_calls": [{
                "method": "POST",
                "path": "/v1/jobs",
                "started_at": TEST_START,
            }],
        }]})
    );
}

/// Idle time follows the broker's clock.
#[tokio::test]
async fn live_session_idle_time_follows_the_clock() {
    let (broker, grant) = approved_grant().await;
    let _session = broker.hold_live_session(&grant, "bot");
    broker.clock.advance(125);

    let live = broker.get("/grants/live").await;
    assert_eq!(live.status, StatusCode::OK, "{}", live.body);
    assert_eq!(
        live.json()["grants"][0]["relay_sessions"][0]["idle_secs"],
        125
    );
}

#[tokio::test]
async fn live_omits_query_string() {
    let (broker, grant) = approved_grant().await;
    let _call = broker.hold_live_call(&grant, "bot", "GET", "/v1/jobs?token=secret#frag");
    let live = broker.get("/grants/live").await;
    assert_eq!(live.status, StatusCode::OK, "{}", live.body);
    assert!(!live.body.contains("secret"), "{}", live.body);
    assert!(!live.body.contains("frag"), "{}", live.body);
    assert!(live.body.contains("/v1/jobs"), "{}", live.body);
}

#[tokio::test]
async fn live_drops_revoked_grant() {
    let (broker, grant) = approved_grant().await;
    let _session = broker.hold_live_session(&grant, "bot");
    let _call = broker.hold_live_call(&grant, "bot", "GET", "/v1/jobs");
    let revoke = broker
        .post_json(&format!("/grants/{}/revoke", grant.as_str()), &json!({}))
        .await;
    assert_eq!(revoke.status, StatusCode::OK, "{}", revoke.body);

    let live = broker.get("/grants/live").await;
    assert_eq!(live.status, StatusCode::OK, "{}", live.body);
    assert_eq!(live.json(), json!({"grants": []}));
    assert!(!live.body.contains(grant.as_str()), "{}", live.body);
}

#[tokio::test]
async fn live_drops_expired_grant() {
    let (broker, grant) = approved_grant().await;
    let _session = broker.hold_live_session(&grant, "bot");
    let _call = broker.hold_live_call(&grant, "bot", "GET", "/v1/jobs");
    broker.clock.advance(30 * 60);

    let live = broker.get("/grants/live").await;
    assert_eq!(live.status, StatusCode::OK, "{}", live.body);
    assert_eq!(live.json(), json!({"grants": []}));
    assert!(!live.body.contains(grant.as_str()), "{}", live.body);
}

#[tokio::test]
async fn live_requires_owner() {
    let (broker, _grant) = approved_grant().await;
    for login in [None, Some("mallory@example.com"), Some("OWNER@example.com")] {
        let mut refusals = Vec::new();
        for path in ["/grants", "/grants/live"] {
            let mut req = Request::get(path);
            if let Some(login) = login {
                req = req.header("Tailscale-User-Login", login);
            }
            let resp = broker.send(req.body(Body::empty()).unwrap()).await;
            assert_eq!(resp.status, StatusCode::FORBIDDEN, "{path} as {login:?}");
            let csp = resp.header("content-security-policy").to_owned();
            refusals.push((resp.body, csp));
        }
        assert_eq!(refusals[0], refusals[1], "as {login:?}");
    }
}

#[tokio::test]
async fn history_lists_decided_requests_newest_first() {
    let (broker, denied, token) = pending().await;
    let deny = broker.deny(&token).await;
    assert_eq!(deny.status, StatusCode::OK, "{}", deny.body);
    broker.clock.advance(10);
    let (approved, token) = broker
        .create_request("bot", TestBroker::pi_request("second", Window::M30))
        .await;
    assert_eq!(
        broker.approve(&token, Window::M15).await.status,
        StatusCode::OK
    );
    broker.clock.advance(10);
    let (expired, _) = broker
        .create_request("bot", TestBroker::pi_request("third", Window::H1))
        .await;
    broker.clock.advance(600);
    broker.state().requests.sweep_expired().await.unwrap();

    let page = broker.get("/history").await;
    assert_eq!(page.status, StatusCode::OK);
    let html = &page.body;
    let at = |needle: &str| {
        html.find(needle)
            .unwrap_or_else(|| panic!("{needle} missing from {html}"))
    };
    let (e, a, d) = (
        at(expired.fingerprint.as_str()),
        at(approved.fingerprint.as_str()),
        at(denied.fingerprint.as_str()),
    );
    assert!(e < a && a < d, "not newest first: {html}");
    for needle in [
        "expired",
        "approved",
        "denied",
        "<bdi>second</bdi>",
        "alice@pi",
        "15m",
        // Date and time in separate spans, so a narrow column breaks only
        // between them.
        r#"<span class="nowrap">2027-01-15</span> <span class="nowrap">08:00:00 UTC</span>"#,
    ] {
        at(needle);
    }
}
