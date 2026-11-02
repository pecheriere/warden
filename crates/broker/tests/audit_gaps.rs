//! An action that gives access does not happen without its audit entry.
//!
//! The audit log is made to fail by adding a line it cannot read: appends then
//! refuse at once, and removing the line makes them work again.

use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{Value, json};
use ssh_key::Certificate;
use warden_broker::approval::passkeys::PasskeyError;
use warden_broker::requests::{Clock as _, sha256_hex};
use warden_broker::testkit::{SoftAuthenticator, TestBroker, TestResponse};
use warden_broker_proto::{AgentName, CreatedResponse, GrantAccess, RequestStatus, Window};

/// Make every append to the audit log fail until the returned bytes are put
/// back.
fn break_audit_log(broker: &TestBroker) -> Vec<u8> {
    let good = std::fs::read(broker.audit_path()).unwrap();
    let mut corrupt = good.clone();
    corrupt.extend_from_slice(b"not an audit line\n");
    std::fs::write(broker.audit_path(), &corrupt).unwrap();
    good
}

fn repair_audit_log(broker: &TestBroker, good: &[u8]) {
    std::fs::write(broker.audit_path(), good).unwrap();
}

fn audit_events(broker: &TestBroker) -> Vec<Value> {
    std::fs::read_to_string(broker.audit_path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["event"].clone())
        .collect()
}

/// Wait until the request's notification is recorded, the last entry the broker
/// writes on its own, so that the log stays as a test saves it.
async fn notification_recorded(broker: &TestBroker) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !broker.audit_types().iter().any(|t| t == "notified") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("notification recorded within 5 s");
}

async fn pending(window: Window) -> (TestBroker, SoftAuthenticator, CreatedResponse, String) {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let auth = broker.enroll_soft_passkey().await;
    let (created, token) = broker
        .create_request("bot", TestBroker::pi_request("restart the job", window))
        .await;
    notification_recorded(&broker).await;
    (broker, auth, created, token)
}

async fn approve(broker: &TestBroker, auth: &mut SoftAuthenticator, token: &str) -> TestResponse {
    let begin = broker.begin_approval(token, Window::M15).await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
    let (ceremony, credential) = TestBroker::sign(auth, &begin);
    broker
        .post_json(
            &format!("/approve/{token}/finish"),
            &json!({"ceremony": ceremony, "credential": credential}),
        )
        .await
}

async fn status(broker: &TestBroker, created: &CreatedResponse) -> RequestStatus {
    let bot = AgentName::try_from("bot".to_owned()).unwrap();
    broker
        .state()
        .requests
        .status(&bot, &created.id, Duration::ZERO)
        .await
        .unwrap()
}

async fn row_count(broker: &TestBroker, table: &str) -> i64 {
    let sql = match table {
        "grants" => "SELECT COUNT(*) FROM grants",
        "enrollment_codes" => "SELECT COUNT(*) FROM enrollment_codes",
        other => panic!("no count query for {other}"),
    };
    sqlx::query_scalar(sql)
        .fetch_one(&broker.state().pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn no_certificate_leaves_the_broker_without_its_audit_entry() {
    let (broker, mut auth, created, token) = pending(Window::M30).await;
    let good = break_audit_log(&broker);

    let refused = approve(&broker, &mut auth, &token).await;
    assert_eq!(
        refused.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        refused.body
    );
    let message = refused.json()["error"].as_str().unwrap().to_owned();
    assert!(message.contains("no access was given"), "{message}");

    // Nothing is stored, and the agent still sees the truth: nothing decided.
    assert_eq!(row_count(&broker, "grants").await, 0);
    assert_eq!(status(&broker, &created).await, RequestStatus::Pending);

    // Once the log works, the owner approves again and all of it is recorded.
    repair_audit_log(&broker, &good);
    let approved = approve(&broker, &mut auth, &token).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let RequestStatus::Approved(view) = status(&broker, &created).await else {
        panic!("expected approved");
    };
    let GrantAccess::Ssh(ssh) = &view.access else {
        panic!("expected an ssh grant");
    };
    let events = audit_events(&broker);
    let approved_at = events
        .iter()
        .position(|e| e["type"] == "approved")
        .expect("approved entry");
    let issued = &events[approved_at + 1];
    assert_eq!(issued["type"], "cert_issued", "{events:?}");
    assert_eq!(issued["grant_id"], view.grant_id.as_str());
    assert_eq!(issued["not_after"], view.not_after);
    // What is recorded is what the certificate says.
    let cert = Certificate::from_openssh(&ssh.certificate).unwrap();
    assert_eq!(issued["key_id"], cert.key_id());
    warden_broker::audit::verify(broker.audit_path()).unwrap();
}

#[tokio::test]
async fn one_certificate_gets_one_entry() {
    let (broker, mut auth, created, token) = pending(Window::M15).await;
    let approved = approve(&broker, &mut auth, &token).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert_eq!(
        broker
            .audit_types()
            .iter()
            .filter(|t| *t == "cert_issued")
            .count(),
        1
    );
    assert!(matches!(
        status(&broker, &created).await,
        RequestStatus::Approved(_)
    ));
}

#[tokio::test]
async fn denying_says_so_when_the_log_cannot_be_written() {
    let (broker, _auth, created, token) = pending(Window::M15).await;
    let good = break_audit_log(&broker);
    let refused = broker.deny(&token).await;
    assert_eq!(
        refused.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        refused.body
    );
    assert_eq!(status(&broker, &created).await, RequestStatus::Pending);
    repair_audit_log(&broker, &good);
    assert_eq!(broker.deny(&token).await.status, StatusCode::OK);
}

#[tokio::test]
async fn making_an_enrollment_code_is_audited_without_the_code() {
    let broker = TestBroker::new().await;
    let code = broker.enrollment_code().await;
    let events = audit_events(&broker);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["type"], "enrollment_code_created");
    assert_eq!(events[0]["expires_at"], broker.clock.now() + 600);
    let log = std::fs::read_to_string(broker.audit_path()).unwrap();
    assert!(!log.contains(&code), "{log}");
    assert!(!log.contains(&sha256_hex(&code)), "{log}");
}

#[tokio::test]
async fn no_enrollment_code_exists_without_its_audit_entry() {
    let broker = TestBroker::new().await;
    let good = break_audit_log(&broker);
    let got = broker
        .state()
        .passkeys
        .create_enrollment_code(broker.clock.now())
        .await;
    assert!(matches!(got, Err(PasskeyError::Audit(_))), "{got:?}");
    assert_eq!(row_count(&broker, "enrollment_codes").await, 0);

    repair_audit_log(&broker, &good);
    broker.enrollment_code().await;
    assert_eq!(row_count(&broker, "enrollment_codes").await, 1);
}
