//! Passkey enrollment, and removing a passkey.

use axum::http::StatusCode;
use serde_json::json;
use sqlx::Row as _;
use warden_broker::approval::passkeys;
use warden_broker::testkit::{TEST_ORIGIN, TEST_START, TestBroker};
use warden_broker_proto::{CreatedResponse, RequestStatus, Window};
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

use super::{grant_count, pending, status};

#[tokio::test]
async fn stylesheet_served_and_csp_forbids_inline_styles() {
    let (broker, _, _) = pending().await;
    let css = broker.get("/static/warden.css").await;
    assert_eq!(css.status, StatusCode::OK, "{css:?}");
    assert!(css.header("content-type").starts_with("text/css"));
    assert!(css.body.contains("prefers-color-scheme:dark"));
    let page = broker.get("/grants").await;
    let csp = page.header("content-security-policy");
    assert!(csp.contains("style-src 'self'"), "{csp}");
    assert!(!csp.contains("unsafe-inline"), "{csp}");
    assert!(
        page.body
            .contains(r#"<link rel="stylesheet" href="/static/warden.css">"#)
    );
    assert!(!page.body.contains("<style"));
}

#[tokio::test]
async fn enroll_with_code_then_code_is_spent() {
    let broker = TestBroker::new().await;
    let code = broker.enrollment_code().await;
    assert_eq!(code.len(), 12, "{code}");
    assert!(
        code.chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)),
        "{code}"
    );
    // Only a hash of the code is stored.
    let stored: String = sqlx::query("SELECT code_hash FROM enrollment_codes")
        .fetch_one(&broker.state().pool)
        .await
        .unwrap()
        .get(0);
    assert_ne!(stored, code);
    assert!(!stored.contains(&code));

    let mut auth = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let begin = broker
        .post_json("/enroll/begin", &json!({"code": code, "label": "phone"}))
        .await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
    let begin = begin.json();
    let credential = auth
        .do_registration(
            url::Url::parse(TEST_ORIGIN).unwrap(),
            serde_json::from_value(begin["options"].clone()).unwrap(),
        )
        .unwrap();
    let finish = broker
        .post_json(
            "/enroll/finish",
            &json!({"ceremony": begin["ceremony"], "credential": credential}),
        )
        .await;
    assert_eq!(finish.status, StatusCode::OK, "{}", finish.body);
    let passkey_id = finish.json()["passkey_id"].as_str().unwrap().to_owned();

    let listed = passkeys::list(&broker.state().pool).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, passkey_id);
    assert_eq!(listed[0].label, "phone");
    assert_eq!(listed[0].created_at, TEST_START);
    // The counter column mirrors the one inside the credential from the start.
    let mirrored: i64 = sqlx::query(
        "SELECT COUNT(*) FROM passkeys WHERE counter = json_extract(credential, '$.cred.counter')",
    )
    .fetch_one(&broker.state().pool)
    .await
    .unwrap()
    .get(0);
    assert_eq!(mirrored, 1);
    assert!(
        broker
            .audit_types()
            .contains(&"passkey_enrolled".to_owned())
    );

    // The code is single use, even for a different authenticator.
    let again = broker
        .post_json("/enroll/begin", &json!({"code": code, "label": "laptop"}))
        .await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST, "{}", again.body);
    assert!(again.json()["error"].as_str().unwrap().contains("code"));

    // The enrolled passkey can approve.
    let (created, token) = broker_request(&broker).await;
    let approved = broker.approve_with(&mut auth, &token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert!(matches!(
        status(&broker, &created.id).await,
        RequestStatus::Approved(_)
    ));
}

async fn broker_request(broker: &TestBroker) -> (CreatedResponse, String) {
    broker.add_agent("bot").await;
    broker
        .create_request(
            "bot",
            TestBroker::pi_request("restart the backup job", Window::M30),
        )
        .await
}

#[tokio::test]
async fn enroll_code_expires_after_600s() {
    let broker = TestBroker::new().await;
    let early = broker.enrollment_code().await;
    broker.clock.advance(599);
    let ok = broker
        .post_json("/enroll/begin", &json!({"code": early, "label": "phone"}))
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);

    let late = broker.enrollment_code().await;
    broker.clock.advance(600);
    let expired = broker
        .post_json("/enroll/begin", &json!({"code": late, "label": "phone"}))
        .await;
    assert_eq!(expired.status, StatusCode::BAD_REQUEST, "{}", expired.body);
}

#[tokio::test]
async fn enroll_rejects_bad_label_and_unknown_code() {
    let broker = TestBroker::new().await;
    let code = broker.enrollment_code().await;
    for label in ["", "   ", "tab\there", &"x".repeat(65)] {
        let resp = broker
            .post_json("/enroll/begin", &json!({"code": code, "label": label}))
            .await;
        assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{label:?}");
    }
    let resp = broker
        .post_json(
            "/enroll/begin",
            &json!({"code": "AAAAAAAAAAAA", "label": "phone"}),
        )
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    // A rejected label does not spend the code; codes are case-insensitive.
    let resp = broker
        .post_json(
            "/enroll/begin",
            &json!({"code": code.to_lowercase(), "label": "phone"}),
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
}

#[tokio::test]
async fn removed_passkey_can_no_longer_approve() {
    let (broker, _, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    let id = passkeys::list(&broker.state().pool).await.unwrap()[0]
        .id
        .clone();
    let begin = broker.begin_approval(&token, Window::M15).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);

    passkeys::remove(&broker.state().pool, &broker.state().audit, &id)
        .await
        .unwrap();
    assert!(broker.audit_types().contains(&"passkey_removed".to_owned()));
    assert!(matches!(
        passkeys::remove(&broker.state().pool, &broker.state().audit, &id).await,
        Err(passkeys::PasskeyError::NotFound)
    ));

    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(finish.status, StatusCode::FORBIDDEN, "{}", finish.body);
    let begin = broker.begin_approval(&token, Window::M15).await;
    assert_eq!(begin.status, StatusCode::CONFLICT, "{}", begin.body);
    assert!(begin.body.contains("enroll"), "{}", begin.body);
    assert_eq!(grant_count(&broker).await, 0);
}
