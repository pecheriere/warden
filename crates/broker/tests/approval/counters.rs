//! Passkey signature counters that go backwards.

use std::time::Duration;

use axum::http::StatusCode;
use warden_broker::testkit::TestBroker;
use warden_broker_proto::{AgentName, RequestStatus, Window};

use super::{grant_count, pending, status, stored_counters, stored_credentials};

#[tokio::test]
async fn counter_regression_refused() {
    let (broker, first, token_a) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    broker.add_agent("other").await;
    let (_second, token_b) = broker
        .create_request(
            "other",
            TestBroker::pi_request("rotate the logs", Window::M15),
        )
        .await;

    // Both ceremonies begin while the stored counter is 0; the authenticator
    // signs the first with counter 1 and the second with counter 2.
    let begin_a = broker.begin_approval(&token_a, Window::M15).await;
    let begin_b = broker.begin_approval(&token_b, Window::M15).await;
    let (ceremony_a, older) = TestBroker::sign(&mut auth, &begin_a);
    let (ceremony_b, newer) = TestBroker::sign(&mut auth, &begin_b);

    // The newer assertion arrives first and is stored.
    let done = broker.finish_approval(&token_b, &ceremony_b, &newer).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    let stored = stored_counters(&broker).await;
    assert_eq!(stored, [2]);
    let credential = stored_credentials(&broker).await;

    // The older one arrives late: refused as a possible cloned authenticator,
    // with a fixed message, no grant, and the stored counter untouched.
    let late = broker.finish_approval(&token_a, &ceremony_a, &older).await;
    assert_eq!(late.status, StatusCode::FORBIDDEN, "{}", late.body);
    assert_eq!(
        late.json()["error"],
        "passkey refused: its signature counter went backwards"
    );
    assert_eq!(grant_count(&broker).await, 1);
    assert_eq!(status(&broker, &first.id).await, RequestStatus::Pending);
    assert_eq!(stored_counters(&broker).await, [2]);
    assert_eq!(stored_credentials(&broker).await, credential);
    let types = broker.audit_types();
    assert!(
        types.contains(&"passkey_counter_regressed".to_owned()),
        "{types:?}"
    );
}

#[tokio::test]
async fn counter_regression_against_snapshot_refused() {
    let (broker, first, token_a) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    let begin_a = broker.begin_approval(&token_a, Window::M15).await;
    let (ceremony_a, signed) = TestBroker::sign(&mut auth, &begin_a);
    let done = broker.finish_approval(&token_a, &ceremony_a, &signed).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    assert_eq!(stored_counters(&broker).await, [1]);

    // A clone of the authenticator signed further meanwhile: the stored
    // counter is above anything this copy will produce next. (The software
    // authenticator cannot be cloned, so the clone's approvals are written
    // straight into the store.)
    sqlx::query(
        "UPDATE passkeys SET counter = 100, \
         credential = json_set(credential, '$.cred.counter', 100)",
    )
    .execute(&broker.state().pool)
    .await
    .unwrap();
    let credential = stored_credentials(&broker).await;

    // A fresh ceremony begins with the raised counter; this copy signs with
    // counter 2, which webauthn-rs itself refuses against that snapshot.
    broker.add_agent("other").await;
    let (second, token_b) = broker
        .create_request(
            "other",
            TestBroker::pi_request("rotate the logs", Window::M15),
        )
        .await;
    let begin_b = broker.begin_approval(&token_b, Window::M15).await;
    let (ceremony_b, lower) = TestBroker::sign(&mut auth, &begin_b);
    let late = broker.finish_approval(&token_b, &ceremony_b, &lower).await;
    assert_eq!(late.status, StatusCode::FORBIDDEN, "{}", late.body);
    assert_eq!(
        late.json()["error"],
        "passkey refused: its signature counter went backwards"
    );
    assert_eq!(grant_count(&broker).await, 1);
    assert_eq!(
        broker
            .state()
            .requests
            .status(
                &AgentName::try_from("other".to_owned()).unwrap(),
                &second.id,
                Duration::ZERO
            )
            .await
            .unwrap(),
        RequestStatus::Pending
    );
    assert_ne!(status(&broker, &first.id).await, RequestStatus::Pending);
    assert_eq!(stored_counters(&broker).await, [100]);
    assert_eq!(stored_credentials(&broker).await, credential);
    let types = broker.audit_types();
    assert!(
        types.contains(&"passkey_counter_regressed".to_owned()),
        "{types:?}"
    );
}
