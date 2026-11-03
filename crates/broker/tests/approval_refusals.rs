//! Approval refusals that need something to change under a ceremony: the request,
//! the policy or the database. Each must leave the request undecided, with no
//! grant, and say nothing about the failure beyond what the page already shows.

use std::time::Duration;

use axum::http::StatusCode;
use serde_json::json;
use warden_broker::testkit::{
    FakeBackend, SoftAuthenticator, TEST_ORIGIN, TestBroker, TestResponse,
};
use warden_broker_proto::{AgentName, CreatedResponse, Id, RequestStatus, Window};
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

/// A broker with agent `bot` and one pending request for `pi`.
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
    let bot = AgentName::try_from("bot".to_owned()).unwrap();
    broker
        .state()
        .requests
        .status(&bot, id, Duration::ZERO)
        .await
        .unwrap()
}

async fn rows(broker: &TestBroker, query: &'static str) -> i64 {
    sqlx::query_scalar(query)
        .fetch_one(&broker.state().pool)
        .await
        .unwrap()
}

/// The owner signed for the request as it was; a request that differs by the
/// time the ceremony finishes is not what was approved.
#[tokio::test]
async fn a_request_changed_during_the_ceremony_is_not_approved() {
    let (broker, created, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    let begin = broker.begin_approval(&token, Window::M15).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    let another = if created.fingerprint.as_str() == "0000-0000-0000" {
        "1111-1111-1111"
    } else {
        "0000-0000-0000"
    };
    sqlx::query("UPDATE requests SET fingerprint = ? WHERE id = ?")
        .bind(another)
        .bind(created.id.as_str())
        .execute(&broker.state().pool)
        .await
        .unwrap();

    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(finish.status, StatusCode::CONFLICT, "{}", finish.body);
    assert!(finish.body.contains("reload the page"), "{}", finish.body);
    assert_eq!(rows(&broker, "SELECT COUNT(*) FROM grants").await, 0);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);
}

/// Begin an enrollment, returning its ceremony and the authenticator's answer.
async fn begun_enrollment(
    broker: &TestBroker,
) -> (serde_json::Value, serde_json::Value, SoftAuthenticator) {
    let code = broker.enrollment_code().await;
    let mut auth: SoftAuthenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let begin = broker
        .post_json("/enroll/begin", &json!({"code": code, "label": "laptop"}))
        .await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
    let begin = begin.json();
    let credential = auth
        .do_registration(
            url::Url::parse(TEST_ORIGIN).unwrap(),
            serde_json::from_value(begin["options"].clone()).unwrap(),
        )
        .unwrap();
    (
        begin["ceremony"].clone(),
        serde_json::to_value(credential).unwrap(),
        auth,
    )
}

fn assert_wrong_ceremony(resp: &TestResponse) {
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    assert!(resp.body.contains("ceremony"), "{}", resp.body);
}

/// A ceremony proves one thing only: an approval's id does not finish an
/// enrollment, so no passkey comes of it, and an enrollment's id does not finish
/// an approval, so no grant does.
#[tokio::test]
async fn a_ceremony_of_the_other_kind_finishes_nothing() {
    let (broker, created, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    let enrolled = rows(&broker, "SELECT COUNT(*) FROM passkeys").await;

    let (enrollment, registration, _) = begun_enrollment(&broker).await;
    let begin = broker.begin_approval(&token, Window::M15).await;
    let (approval, assertion) = TestBroker::sign(&mut auth, &begin);

    let finish = broker
        .post_json(
            "/enroll/finish",
            &json!({"ceremony": approval, "credential": registration}),
        )
        .await;
    assert_wrong_ceremony(&finish);
    assert_eq!(
        rows(&broker, "SELECT COUNT(*) FROM passkeys").await,
        enrolled
    );

    let finish = broker
        .finish_approval(&token, &enrollment, &assertion)
        .await;
    assert_wrong_ceremony(&finish);
    assert_eq!(rows(&broker, "SELECT COUNT(*) FROM grants").await, 0);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);
}

/// Once the policy no longer has the item a request asks for, the request can
/// be neither shown as approvable nor approved. The owner can still deny it.
#[tokio::test]
async fn a_request_whose_policy_item_is_gone_cannot_be_approved_but_can_be_denied() {
    let broker = TestBroker::new().await;
    broker
        .backend
        .set_api_secret(FakeBackend::example_api_secret(), "not-a-real-secret");
    broker.add_agent("bot").await;
    broker.enroll_soft_passkey().await;
    let (created, token) = broker
        .create_request(
            "bot",
            TestBroker::api_request("github", "list issues", Window::M15),
        )
        .await;
    let digest = broker.page_target_digest(&token).await;
    broker.backend.remove_api_secret("github");

    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(
        page.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        page.body
    );
    assert!(!page.body.contains("data-target"), "{}", page.body);
    let begin = broker
        .begin_approval_for(&token, Window::M15, &digest)
        .await;
    assert_eq!(
        begin.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        begin.body
    );
    assert_eq!(rows(&broker, "SELECT COUNT(*) FROM grants").await, 0);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);

    let denied = broker.deny(&token).await;
    assert_eq!(denied.status, StatusCode::OK, "{}", denied.body);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Denied);
}

/// With the database gone every owner page and action fails, and none of them
/// passes on what the database said.
#[tokio::test]
async fn a_failed_database_is_a_plain_error_on_every_owner_route() {
    let (broker, _, token) = pending().await;
    broker.state().pool.close().await;

    let revoke = format!("/grants/{}/revoke", Id::random().as_str());
    let answers = [
        (
            "approve page",
            broker.get(&format!("/approve/{token}")).await,
        ),
        ("grants page", broker.get("/grants").await),
        ("grants activity", broker.get("/grants/live").await),
        ("history page", broker.get("/history").await),
        ("revoke", broker.post_json(&revoke, &json!({})).await),
        ("deny", broker.deny(&token).await),
    ];
    for (name, answer) in answers {
        assert_eq!(
            answer.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{name}: {}",
            answer.body
        );
        for detail in ["pool", "sqlite", "sqlx", "closed"] {
            assert!(
                !answer.body.to_lowercase().contains(detail),
                "{name}: {}",
                answer.body
            );
        }
    }
}
