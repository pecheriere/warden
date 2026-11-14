//! GitHub token grants: requests, windows and the approval pages. The App's key
//! is a throwaway one; time only moves through the broker's manual clock.

use std::fs;

use serde_json::Value;
use warden_broker::github_app::GithubApi;
use warden_broker::requests::{ActiveGithubToken, Clock as _, GithubLookup};
use warden_broker::testkit::github_app::INSTALLATION_ID;
use warden_broker::testkit::github_app::token_answer;
use warden_broker::testkit::upstream::{HttpsUpstream, Received, installation_json};
use warden_broker::testkit::{TestBroker, github_app_key};
use warden_broker_proto::Window;

mod legacy;
mod mint;
mod overlap;
mod pages;
mod permissions;
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

/// The permissions the fake GitHub says the App's installation holds, unless a
/// test says otherwise: more than any request of these tests asks for.
const INSTALLATION: &[(&str, &str)] = &[
    ("actions", "read"),
    ("checks", "write"),
    ("contents", "write"),
    ("issues", "write"),
    ("metadata", "read"),
    ("pull_requests", "write"),
];

/// A broker that holds a GitHub App and talks to a local fake GitHub, with an
/// enrolled agent `bot` whose key is returned. GitHub answers every read of the
/// installation with [`INSTALLATION`].
async fn configured_on_fake() -> (TestBroker, String, HttpsUpstream) {
    let upstream = fake_github().await;
    let (broker, key) = configured(TestBroker::with_github_api(api_of(&upstream)).await).await;
    (broker, key, upstream)
}

/// A local fake GitHub that answers every read of the installation with
/// [`INSTALLATION`].
async fn fake_github() -> HttpsUpstream {
    let upstream = HttpsUpstream::start().await;
    upstream.answer_github_installation(Some(installation(INSTALLATION)));
    upstream
}

/// The calls `upstream` received, but for the reads of the installation, which the
/// broker makes at each render of an approval page.
fn github_calls(upstream: &HttpsUpstream) -> Vec<Received> {
    let read = format!("/app/installations/{INSTALLATION_ID}");
    upstream
        .received()
        .into_iter()
        .filter(|call| !(call.method == "GET" && call.path_and_query == read))
        .collect()
}

/// GitHub's answer to a read of an installation that holds `permissions`.
fn installation(permissions: &[(&str, &str)]) -> warden_broker::testkit::upstream::Scripted {
    warden_broker::testkit::upstream::Scripted::with_body(200, installation_json(permissions))
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
    approve_repositories(
        broker,
        upstream,
        agent,
        window,
        &[(1001, "example-owner/example-repo")],
    )
    .await
}

/// As [`approve`], for the repositories `(id, name)` that GitHub resolves.
async fn approve_repositories(
    broker: &TestBroker,
    upstream: &HttpsUpstream,
    agent: &str,
    window: Window,
    repositories: &[(u64, &str)],
) -> String {
    let names: Vec<&str> = repositories.iter().map(|(_, name)| *name).collect();
    let (created, token) = broker
        .create_request(
            agent,
            TestBroker::github_token_request("push the fix", window, &names),
        )
        .await;
    upstream.script_github_token(resolved(broker, repositories));
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

/// The grant `agent` would mint with now for `repository`, if any.
///
/// # Panics
/// If two grants cover it.
async fn active_for(
    broker: &TestBroker,
    agent: &str,
    repository: &str,
) -> Option<ActiveGithubToken> {
    let found = broker
        .state()
        .requests
        .active_github_token_for(
            &agent.parse().unwrap(),
            &repository.to_owned().try_into().unwrap(),
        )
        .await
        .unwrap();
    match found {
        GithubLookup::None => None,
        GithubLookup::One(active) => Some(active),
        GithubLookup::Ambiguous(_) => panic!("two grants cover {repository}"),
    }
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
