//! The passkey ceremony table: however often the pending screen opens a request and
//! its approval begins, it cannot crowd out other requests or enrollment.

use std::time::Duration;

use axum::http::StatusCode;
use serde_json::json;
use sqlx::Row as _;
use warden_broker::approval::passkeys::{ApprovalBinding, PasskeyError};
use warden_broker::requests::Clock as _;
use warden_broker::testkit::{TEST_ORIGIN, TestBroker};
use warden_broker_proto::{AgentName, CreatedResponse, Fingerprint, Id, RequestStatus, Window};

fn bot() -> AgentName {
    AgentName::try_from("bot".to_owned()).unwrap()
}

/// A broker with agent `bot` and one pending 30m request for `pi`.
async fn pending() -> (TestBroker, CreatedResponse, String) {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let (created, token) = broker
        .create_request(
            "bot",
            TestBroker::pi_request("restart the backup job", Window::M30),
        )
        .await;
    (broker, created, token)
}

async fn status(broker: &TestBroker, id: &Id) -> RequestStatus {
    broker
        .state()
        .requests
        .status(&bot(), id, Duration::ZERO)
        .await
        .unwrap()
}

async fn grant_count(broker: &TestBroker) -> i64 {
    sqlx::query("SELECT COUNT(*) FROM grants")
        .fetch_one(&broker.state().pool)
        .await
        .unwrap()
        .get(0)
}

/// Open request `id` from the screen, and return the token of its new link.
async fn opened_token(broker: &TestBroker, id: &Id) -> String {
    let opened = broker
        .post_json(&format!("/pending/{id}/open"), &json!({}))
        .await;
    assert_eq!(opened.status, StatusCode::OK, "{}", opened.body);
    let link = opened.json()["link"].as_str().unwrap().to_owned();
    let (origin, token) = link.rsplit_once("/approve/").unwrap();
    assert_eq!(origin, TEST_ORIGIN.trim_end_matches('/'), "{link}");
    token.to_owned()
}

#[tokio::test]
async fn one_request_cannot_crowd_out_other_approvals_or_enrollment() {
    let (broker, created, _) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    broker.add_agent("bot-2").await;
    let (_, other_token) = broker
        .create_request("bot-2", TestBroker::pi_request("other", Window::M15))
        .await;
    let other_begin = broker.begin_approval(&other_token, Window::M15).await;
    let (other_ceremony, other_credential) = TestBroker::sign(&mut auth, &other_begin);

    // Far more than the table once held, on one request, opened again each time.
    let mut token = String::new();
    for _ in 0..40 {
        token = opened_token(&broker, &created.id).await;
        for _ in 0..3 {
            let begin = broker.begin_approval(&token, Window::M15).await;
            assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
        }
    }

    // The other request's prompt is untouched, and new ones and enrollment can begin.
    let code = broker.enrollment_code().await;
    let enroll = broker
        .post_json("/enroll/begin", &json!({"code": code, "label": "laptop"}))
        .await;
    assert_eq!(enroll.status, StatusCode::OK, "{}", enroll.body);
    let finish = broker
        .finish_approval(&other_token, &other_ceremony, &other_credential)
        .await;
    assert_eq!(finish.status, StatusCode::OK, "{}", finish.body);
    assert_eq!(grant_count(&broker).await, 1);

    // The same request itself is never locked out: its newest prompt works.
    let approved = broker.approve_with(&mut auth, &token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
}

#[tokio::test]
async fn a_request_keeps_only_its_newest_ceremonies() {
    let (broker, created, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    let first = broker.begin_approval(&token, Window::M15).await;
    let (first_ceremony, first_credential) = TestBroker::sign(&mut auth, &first);
    // Three more fit next to it, whichever link they began on.
    let mut last = None;
    for _ in 0..3 {
        last = Some(broker.begin_approval(&token, Window::M15).await);
    }
    let (held_ceremony, held_credential) = TestBroker::sign(&mut auth, &last.unwrap());
    // One more drops the oldest, and only that one.
    let newest = broker.begin_approval(&token, Window::M15).await;
    assert_eq!(newest.status, StatusCode::OK, "{}", newest.body);
    let dropped = broker
        .finish_approval(&token, &first_ceremony, &first_credential)
        .await;
    assert_eq!(dropped.status, StatusCode::GONE, "{}", dropped.body);
    let finish = broker
        .finish_approval(&token, &held_ceremony, &held_credential)
        .await;
    assert_eq!(finish.status, StatusCode::OK, "{}", finish.body);
    assert!(matches!(
        status(&broker, &created.id).await,
        RequestStatus::Approved(_)
    ));
}

#[tokio::test]
async fn many_enrollments_cannot_crowd_out_approvals() {
    let (broker, created, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    // Begun and never finished, until the table refuses another.
    let mut refused = None;
    for _ in 0..20 {
        let code = broker.enrollment_code().await;
        let begin = broker
            .post_json("/enroll/begin", &json!({"code": code, "label": "laptop"}))
            .await;
        if begin.status != StatusCode::OK {
            refused = Some((begin, code));
            break;
        }
    }
    let (begin, code) = refused.expect("enrollment ceremonies are limited");
    assert_eq!(
        begin.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        begin.body
    );

    let approved = broker.approve_with(&mut auth, &token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert!(matches!(
        status(&broker, &created.id).await,
        RequestStatus::Approved(_)
    ));

    // The refusal did not spend the code: it works when a slot is free again.
    broker.clock.advance(121);
    let again = broker
        .post_json("/enroll/begin", &json!({"code": code, "label": "laptop"}))
        .await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.body);
}

#[tokio::test]
async fn approval_ceremonies_as_a_whole_are_bounded_without_touching_enrollment() {
    let broker = TestBroker::new().await;
    broker.enroll_soft_passkey().await;
    let binding = || ApprovalBinding {
        request_id: Id::random(),
        token_hash: "not a real hash".to_owned(),
        window: Window::M15,
        fingerprint: Fingerprint::try_from("abcd-ef01-2345".to_owned()).unwrap(),
        destination_digest: "not a real digest".to_owned(),
        request_expires_at: broker.clock.now() + 600,
    };
    let passkeys = &broker.state().passkeys;
    for _ in 0..1024 {
        passkeys.begin_approval(binding()).await.unwrap();
    }
    let refused = passkeys.begin_approval(binding()).await;
    assert!(matches!(refused, Err(PasskeyError::Busy)), "{refused:?}");

    let code = broker.enrollment_code().await;
    let enroll = broker
        .post_json("/enroll/begin", &json!({"code": code, "label": "laptop"}))
        .await;
    assert_eq!(enroll.status, StatusCode::OK, "{}", enroll.body);

    // They expire, and then there is room again.
    broker.clock.advance(121);
    passkeys.begin_approval(binding()).await.unwrap();
}
