//! `GET /v1/requests`: what an agent that lost track of its requests can learn,
//! and what it collects when the client that asked is gone. Time only moves
//! through the broker's manual clock.

use axum::http::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, Certificate, PrivateKey};
use warden_broker::requests::{Clock as _, RequestLimits};
use warden_broker::testkit::{CapturingNotifier, TestBroker};
use warden_broker_proto::{Access, CreateRequest, Window};

const GOAL: &str = "restart the web container";

async fn broker() -> TestBroker {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    broker
}

async fn list(broker: &TestBroker, key: &str) -> Vec<Value> {
    let resp = broker.api_get(key, "/v1/requests").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    resp.json().as_array().unwrap().clone()
}

fn pi_request() -> CreateRequest {
    TestBroker::pi_request(GOAL, Window::M15)
}

#[tokio::test]
async fn an_agent_sees_its_own_pending_request_and_no_link() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let before = broker.clock.now();
    let (created, token) = broker.create_request("bot", pi_request()).await;

    let resp = broker.api_get(&key, "/v1/requests").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let listed = resp.json();
    let entry = &listed.as_array().unwrap()[0];
    let keys: Vec<&str> = entry
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys.iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "access",
            "created_at",
            "expires_at",
            "fingerprint",
            "goal",
            "id",
            "window"
        ]
        .into_iter()
        .collect(),
        "{entry}"
    );
    assert_eq!(entry["id"], created.id.as_str());
    assert_eq!(entry["fingerprint"], created.fingerprint.as_str());
    assert_eq!(entry["goal"], GOAL);
    assert_eq!(entry["window"], "15m");
    assert_eq!(entry["access"]["kind"], "ssh");
    assert_eq!(entry["access"]["target"], "pi");
    assert_eq!(entry["created_at"], before);
    assert_eq!(entry["expires_at"], before + 600);

    // Neither the link, nor its token, nor the hash the broker keeps of it. The
    // exact keys above leave no field for them; this also covers their values.
    let hash = hex::encode(Sha256::digest(token.as_bytes()));
    for hidden in [token.as_str(), hash.as_str(), "/approve"] {
        assert!(!resp.body.contains(hidden), "{hidden} in {}", resp.body);
    }
}

/// The session label is part of the fingerprint, so an agent writing the same
/// request again needs it back.
#[tokio::test]
async fn a_session_label_comes_back_as_sent() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let mut request = pi_request();
    request.session = Some("build-work".to_owned().try_into().unwrap());
    broker.create_request("bot", request).await;
    assert_eq!(list(&broker, &key).await[0]["session"], "build-work");
}

/// A commit signing request is listed like any other: it, too, is the agent's own,
/// and the link in the answer is at most the page the agent named.
#[tokio::test]
async fn a_commit_signing_request_is_listed_with_no_approval_link() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let other = broker.add_agent("other").await;
    let request = CreateRequest {
        goal: GOAL.to_owned().try_into().unwrap(),
        access: Access::CommitSigning {},
        window: Window::D30,
        session: Some("build-work".to_owned().try_into().unwrap()),
        link: None,
    };
    let (created, token) = broker.create_request("bot", request).await;

    let resp = broker.api_get(&key, "/v1/requests").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let listed = resp.json();
    let entry = &listed[0];
    assert_eq!(entry["id"], created.id.as_str());
    assert_eq!(entry["fingerprint"], created.fingerprint.as_str());
    assert_eq!(entry["access"]["kind"], "commit_signing");
    assert_eq!(entry["window"], "30d");
    assert_eq!(entry["session"], "build-work");
    let hash = hex::encode(Sha256::digest(token.as_bytes()));
    for hidden in [token.as_str(), hash.as_str(), "/approve"] {
        assert!(!resp.body.contains(hidden), "{hidden} in {}", resp.body);
    }
    assert_eq!(list(&broker, &other).await, [] as [Value; 0]);
}

#[tokio::test]
async fn another_agent_sees_nothing_of_it() {
    let broker = broker().await;
    let other = broker.add_agent("other").await;
    let (created, _) = broker.create_request("bot", pi_request()).await;

    assert_eq!(list(&broker, &other).await, [] as [Value; 0]);
    // The same answer as asking for it by id: it does not exist for this agent.
    let by_id = broker
        .api_get(&other, &format!("/v1/requests/{}", created.id))
        .await;
    assert_eq!(by_id.status, StatusCode::NOT_FOUND, "{}", by_id.body);
}

#[tokio::test]
async fn an_unauthenticated_caller_gets_nothing() {
    let broker = broker().await;
    broker.create_request("bot", pi_request()).await;
    let resp = broker.api_get("wdn_not_a_real_key", "/v1/requests").await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED, "{}", resp.body);
    assert!(!resp.body.contains(GOAL), "{}", resp.body);
}

#[tokio::test]
async fn a_signed_agent_lists_its_own_and_a_signature_for_another_call_is_refused() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("signer", Algorithm::Ed25519).await;
    let (created, _) = broker.create_request("signer", pi_request()).await;

    let listed = broker
        .api_signed(&key, "signer", "GET", "/v1/requests", b"")
        .await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    assert_eq!(listed.json()[0]["id"], created.id.as_str());

    // The signature covers the method and the target: one made for another call
    // does not open this one.
    let mut request = broker.signed_request(&key, "signer", "GET", "/v1/grants", Vec::new());
    *request.uri_mut() = "/v1/requests".parse().unwrap();
    let refused = broker.api_send(request).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{}", refused.body);
    assert!(!refused.body.contains(GOAL), "{}", refused.body);
}

#[tokio::test]
async fn a_request_past_its_expiry_is_not_listed_even_before_any_sweep() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    broker.create_request("bot", pi_request()).await;
    assert_eq!(list(&broker, &key).await.len(), 1);
    broker.clock.advance(599);
    assert_eq!(list(&broker, &key).await.len(), 1);
    broker.clock.advance(1);
    assert_eq!(list(&broker, &key).await, [] as [Value; 0]);
}

#[tokio::test]
async fn decided_and_cancelled_requests_are_not_listed() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    broker.enroll_soft_passkey().await;

    let (_, denied) = broker.create_request("bot", pi_request()).await;
    assert_eq!(list(&broker, &key).await.len(), 1);
    assert!(broker.deny(&denied).await.status.is_success());
    assert_eq!(list(&broker, &key).await, [] as [Value; 0]);

    let (created, _) = broker.create_request("bot", pi_request()).await;
    assert_eq!(list(&broker, &key).await.len(), 1);
    let cancelled = broker
        .api_post(&key, &format!("/v1/requests/{}/cancel", created.id))
        .await;
    assert_eq!(
        cancelled.status,
        StatusCode::NO_CONTENT,
        "{}",
        cancelled.body
    );
    assert_eq!(list(&broker, &key).await, [] as [Value; 0]);

    let (_, approved) = broker.create_request("bot", pi_request()).await;
    assert_eq!(list(&broker, &key).await.len(), 1);
    let answer = broker.approve(&approved, Window::M15).await;
    assert!(answer.status.is_success(), "{}", answer.body);
    assert_eq!(list(&broker, &key).await, [] as [Value; 0]);
}

#[tokio::test]
async fn listing_notifies_nobody_records_nothing_and_uses_up_no_limit() {
    let broker = TestBroker::with_request_limits(RequestLimits {
        max_pending: 2,
        max_new: 2,
        window_secs: 300,
    })
    .await;
    let key = broker.add_agent("bot").await;
    let mut changes = broker.state().requests.bus().subscribe();
    let (created, _) = broker.create_request("bot", pi_request()).await;
    // The request's own `notified` entry follows the doorbell, and the bus says when
    // it is written: only then does the log stand still.
    while changes.recv().await.unwrap() != created.id {}
    let rung = broker.capture.rung().len();
    let audit = std::fs::read_to_string(broker.audit_path()).unwrap();

    for _ in 0..5 {
        assert_eq!(list(&broker, &key).await.len(), 1);
    }

    assert_eq!(broker.capture.rung().len(), rung);
    assert_eq!(std::fs::read_to_string(broker.audit_path()).unwrap(), audit);
    // Both limits are 2 and one is used: the second request still goes through.
    let body = serde_json::to_value(TestBroker::api_request("github", GOAL, Window::M15)).unwrap();
    broker.backend.set_api_secret(
        warden_broker::testkit::FakeBackend::example_api_secret(),
        "s3cr3t",
    );
    let second = broker.api_post_json(&key, "/v1/requests", &body).await;
    assert_eq!(second.status, StatusCode::CREATED, "{}", second.body);
    assert_eq!(list(&broker, &key).await.len(), 2);
}

/// Whoever kept the private key of an SSH request can complete it with no trace of
/// the client that asked: the certificate is for the key named, from the list of
/// grants as well as by the request's id.
#[tokio::test]
async fn an_approved_certificate_is_for_the_key_the_request_named() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    broker.enroll_soft_passkey().await;
    let named = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut request = pi_request();
    let Access::Ssh { public_key, .. } = &mut request.access else {
        panic!("expected an ssh request");
    };
    *public_key = named.public_key().to_openssh().unwrap();

    let body = serde_json::to_value(&request).unwrap();
    let created = broker.api_post_json(&key, "/v1/requests", &body).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let id = created.json()["id"].as_str().unwrap().to_owned();
    let token = CapturingNotifier::token(&broker.capture.next().await);
    let answer = broker.approve(&token, Window::M15).await;
    assert!(answer.status.is_success(), "{}", answer.body);

    let by_id = broker
        .api_get(&key, &format!("/v1/requests/{id}"))
        .await
        .json();
    assert_eq!(by_id["status"], "approved");
    let grants = broker.api_get(&key, "/v1/grants").await.json();
    assert_eq!(
        grants,
        json!([{
            "grant_id": by_id["grant_id"],
            "not_before": by_id["not_before"],
            "not_after": by_id["not_after"],
            "access": by_id["access"],
        }])
    );
    let certificate = by_id["access"]["certificate"].as_str().unwrap();
    let certificate = Certificate::from_openssh(certificate).unwrap();
    assert_eq!(certificate.public_key(), named.public_key().key_data());
}
