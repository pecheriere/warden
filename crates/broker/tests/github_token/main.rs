//! GitHub token grants: requests, windows and the approval pages. The App's key
//! is a throwaway one; time only moves through the broker's manual clock.

use std::fs;

use serde_json::Value;
use warden_broker::testkit::{TestBroker, github_app_key};
use warden_broker_proto::Window;

mod mint;
mod pages;
mod renewal;
mod windows;

/// A broker that holds a GitHub App, with an enrolled agent `bot` whose key is
/// returned.
async fn configured(broker: TestBroker) -> (TestBroker, String) {
    broker.backend.set_github_app(Some(github_app_key().0));
    let key = broker.add_agent("bot").await;
    (broker, key)
}

/// Ask for a GitHub token as `agent`, approve it for `window` and return the grant.
async fn approve(broker: &TestBroker, agent: &str, window: Window) -> String {
    let (created, token) = broker
        .create_request(
            agent,
            TestBroker::github_token_request(
                "push the fix",
                window,
                &["example-owner/example-repo"],
            ),
        )
        .await;
    let approved = broker.approve(&token, window).await;
    assert_eq!(
        approved.status,
        axum::http::StatusCode::OK,
        "{}",
        approved.body
    );
    let status = broker
        .state()
        .requests
        .status(
            &agent.parse().unwrap(),
            &created.id,
            std::time::Duration::ZERO,
        )
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
