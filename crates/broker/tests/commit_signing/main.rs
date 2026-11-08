//! Commit signing through the agent API. Keys are generated for each test; time only
//! moves through the broker's manual clock.

use std::fs;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use warden_broker::testkit::{TestBroker, TestResponse};
use warden_broker_proto::Window;

mod key;
mod pages;
mod renewal;
mod signing;
mod windows;

const TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

const PARENT: &str = "1111111111111111111111111111111111111111";

const AUTHOR: &str = "build-agent <build-agent@example.com> 1800000000 +0000";

fn commit() -> String {
    format!("tree {TREE}\nparent {PARENT}\nauthor {AUTHOR}\ncommitter {AUTHOR}\n\nFix the thing\n")
}

fn body(namespace: &str, payload: &[u8]) -> Value {
    json!({"namespace": namespace, "payload_b64": STANDARD.encode(payload)})
}

async fn sign_as(broker: &TestBroker, key: &str, namespace: &str, payload: &[u8]) -> TestResponse {
    broker
        .api_post_json(key, "/v1/commit-signing/sign", &body(namespace, payload))
        .await
}

async fn sign(broker: &TestBroker, key: &str) -> TestResponse {
    sign_as(broker, key, "git", commit().as_bytes()).await
}

/// A broker and an agent with an active 30-day grant; returns the agent's key and
/// the grant.
async fn granted() -> (TestBroker, String, String) {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let grant = approve(&broker, "bot").await;
    (broker, key, grant)
}

/// Ask for and approve commit signing for `agent`, returning the grant.
async fn approve(broker: &TestBroker, agent: &str) -> String {
    let (created, token) = broker
        .create_request(
            agent,
            TestBroker::commit_signing_request("sign my commits", Window::D30),
        )
        .await;
    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let agent_name = agent.parse().unwrap();
    let status = broker
        .state()
        .requests
        .status(&agent_name, &created.id, std::time::Duration::ZERO)
        .await
        .unwrap();
    let warden_broker_proto::RequestStatus::Approved(view) = status else {
        panic!("not approved: {status:?}");
    };
    view.grant_id.to_string()
}

/// Every audit entry of type `kind`, oldest first.
fn entries(broker: &TestBroker, kind: &str) -> Vec<Value> {
    fs::read_to_string(broker.audit_path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["event"].clone())
        .filter(|event| event["type"] == kind)
        .collect()
}

/// Assert `resp` was refused with `status`, carries no signature, and was recorded
/// with its reason.
fn assert_refused(broker: &TestBroker, resp: &TestResponse, status: StatusCode, says: &str) {
    assert_eq!(resp.status, status, "{}", resp.body);
    assert!(resp.body.contains(says), "{}", resp.body);
    assert!(!resp.body.contains("SSH SIGNATURE"), "{}", resp.body);
    let refused = entries(broker, "commit_signing_refused");
    let last = refused.last().expect("a refusal entry");
    assert!(
        last["reason"].as_str().unwrap().contains(says),
        "{last}: {says}"
    );
}
