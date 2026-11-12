//! GitHub token grants: requests, windows and the approval pages. The App's key
//! is a throwaway one; time only moves through the broker's manual clock.

use std::fs;

use serde_json::Value;
use warden_broker::github_app::GithubApi;
use warden_broker::requests::Clock as _;
use warden_broker::testkit::github_app::token_answer;
use warden_broker::testkit::upstream::HttpsUpstream;
use warden_broker::testkit::{TestBroker, github_app_key};
use warden_broker_proto::Window;

mod legacy;
mod mint;
mod pages;
mod renewal;
mod scope;
mod windows;

/// A broker that holds a GitHub App, with an enrolled agent `bot` whose key is
/// returned.
async fn configured(broker: TestBroker) -> (TestBroker, String) {
    broker.backend.set_github_app(Some(github_app_key().0));
    let key = broker.add_agent("bot").await;
    (broker, key)
}

/// The GitHub API that is `upstream`, a local server.
fn api_of(upstream: &HttpsUpstream) -> GithubApi {
    GithubApi::pinned(
        upstream.origin().parse().unwrap(),
        upstream.origin().parse().unwrap(),
        upstream.ca_pem().as_bytes().to_vec(),
    )
}

/// A broker that holds a GitHub App and talks to a local fake GitHub, with an
/// enrolled agent `bot` whose key is returned.
async fn configured_on_fake() -> (TestBroker, String, HttpsUpstream) {
    let upstream = HttpsUpstream::start().await;
    let (broker, key) = configured(TestBroker::with_github_api(api_of(&upstream)).await).await;
    (broker, key, upstream)
}

/// GitHub's answer when the App reaches `repositories` (`(id, full_name)`): the
/// token that resolves their names, which reads metadata only.
fn resolved(
    broker: &TestBroker,
    repositories: &[(u64, &str)],
) -> warden_broker::testkit::upstream::Scripted {
    token_answer(
        "ghs_resolve_0123456789",
        broker.clock.now() + 3600,
        repositories,
        &[("metadata", "read")],
        "selected",
    )
}

/// Ask for a GitHub token as `agent`, approve it for `window` and return the grant.
/// GitHub, which is `upstream`, resolves the repository as `example-owner/example-repo`.
async fn approve(
    broker: &TestBroker,
    upstream: &HttpsUpstream,
    agent: &str,
    window: Window,
) -> String {
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
    upstream.script_github_token(resolved(broker, &[(1001, "example-owner/example-repo")]));
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
