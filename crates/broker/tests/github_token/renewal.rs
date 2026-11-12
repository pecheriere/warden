//! Renewing a GitHub token grant, and the notice before one ends.

use axum::http::StatusCode;
use serde_json::json;
use warden_broker::requests::{Resolution, ScopedRepository};
use warden_broker::testkit::TestBroker;
use warden_broker::testkit::upstream::{HttpsUpstream, Scripted};
use warden_broker_proto::Window;
use warden_broker_proto::github_token::NOT_CONFIGURED;

use super::{approve, configured_on_fake, entries, resolved};

/// The approval token at the end of `link`.
fn token_of(link: &str) -> String {
    link.rsplit('/').next().unwrap().to_owned()
}

/// The grant `bot` would mint with now, if any.
async fn minting_with(broker: &TestBroker) -> Option<String> {
    broker
        .state()
        .requests
        .active_github_token(&"bot".parse().unwrap())
        .await
        .unwrap()
        .map(|active| active.grant_id.to_string())
}

/// Start renewing `grant` from the grants page, with GitHub answering `current`
/// (`(id, name)`) to the question what the grant's repositories are called now, and
/// return the approval token.
async fn renew_as(
    broker: &TestBroker,
    upstream: &HttpsUpstream,
    grant: &str,
    current: Scripted,
) -> String {
    upstream.script_github_token(current);
    renew_unscripted(broker, grant).await
}

/// As [`renew_as`], with GitHub unchanged: the repository is still called what it was.
async fn renew(broker: &TestBroker, upstream: &HttpsUpstream, grant: &str) -> String {
    let current = resolved(broker, &[(1001, "example-owner/example-repo")]);
    renew_as(broker, upstream, grant, current).await
}

async fn renew_unscripted(broker: &TestBroker, grant: &str) -> String {
    let renewed = broker
        .post_json(&format!("/grants/{grant}/renew"), &json!({}))
        .await;
    assert_eq!(renewed.status, StatusCode::OK, "{}", renewed.body);
    token_of(renewed.json()["link"].as_str().unwrap())
}

fn renewal_notices(broker: &TestBroker) -> Vec<warden_broker::notify::Doorbell> {
    broker
        .capture
        .rung()
        .into_iter()
        .filter(|bell| bell.title.contains("ends soon"))
        .collect()
}

#[tokio::test]
async fn renewing_takes_one_passkey_approval_and_replaces_the_grant() {
    let (broker, key, upstream) = configured_on_fake().await;
    let old = approve(&broker, &upstream, "bot", Window::D30).await;
    broker.clock.advance(28 * 86_400);
    let rung_before = broker.capture.rung().len();
    let token = renew(&broker, &upstream, &old).await;
    // The same length as the grant it renews.
    let page = broker.get(&format!("/approve/{token}")).await;
    assert!(
        page.body.contains(r#"value="30d" checked"#),
        "{}",
        page.body
    );
    assert!(page.body.contains("Renew GitHub token"), "{}", page.body);
    // Starting it rings nobody, grants nothing and leaves the old grant minting.
    assert_eq!(broker.capture.rung().len(), rung_before);
    assert_eq!(minting_with(&broker).await.as_deref(), Some(old.as_str()));

    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);

    let list = broker.api_get(&key, "/v1/grants").await.json();
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 1, "one grant at a time: {list:?}");
    let new = list[0]["grant_id"].as_str().unwrap().to_owned();
    assert_ne!(new, old);
    let ended = entries(&broker, "grant_revoked");
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0]["grant_id"], old.as_str());
    // Renewing replaces the grant that shares its repository, as any approval does.
    assert_eq!(ended[0]["by"], "replaced");
    let replaced = entries(&broker, "github_token_grant_replaced");
    assert_eq!(replaced.len(), 1, "{replaced:?}");
    assert_eq!(replaced[0]["grant_id"], old.as_str());
    assert_eq!(replaced[0]["by_grant"], new.as_str());

    // Past the end of the old window, minting goes on under the new one.
    broker.clock.advance(3 * 86_400);
    assert_eq!(minting_with(&broker).await.as_deref(), Some(new.as_str()));
}

#[tokio::test]
async fn renewing_asks_for_no_more_than_the_server_now_allows() {
    let (broker, _, upstream) = configured_on_fake().await;
    let old = approve(&broker, &upstream, "bot", Window::D30).await;
    let broker = broker.restart_with_github_token_max(Window::D7).await;
    let token = renew(&broker, &upstream, &old).await;
    let page = broker.get(&format!("/approve/{token}")).await;
    assert!(page.body.contains(r#"value="7d" checked"#), "{}", page.body);
    assert!(!page.body.contains(r#"value="30d""#), "{}", page.body);
}

#[tokio::test]
async fn a_request_already_waiting_is_what_renewing_opens() {
    let (broker, _, upstream) = configured_on_fake().await;
    let old = approve(&broker, &upstream, "bot", Window::D30).await;
    let (created, stale) = broker
        .create_request(
            "bot",
            TestBroker::github_token_request("again", Window::D7, &["example-owner/example-repo"]),
        )
        .await;
    let token = renew_unscripted(&broker, &old).await;
    // The same request, on a new link.
    assert_ne!(token, stale);
    let pending = broker.state().requests.pending_expiries().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0, created.id);
    // With the goal and window its agent gave, not the grant's. Its repositories
    // are resolved by the page, as for any request: renewing did not.
    upstream.script_github_token(resolved(&broker, &[(1001, "example-owner/example-repo")]));
    let page = broker.get(&format!("/approve/{token}")).await;
    assert!(page.body.contains("again"), "{}", page.body);
    assert!(page.body.contains(r#"value="7d" checked"#), "{}", page.body);
}

#[tokio::test]
async fn renewing_is_refused_once_the_app_is_gone() {
    let (broker, _, upstream) = configured_on_fake().await;
    let old = approve(&broker, &upstream, "bot", Window::D30).await;
    broker.backend.set_github_app(None);
    let resp = broker
        .post_json(&format!("/grants/{old}/renew"), &json!({}))
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    assert!(resp.body.contains(NOT_CONFIGURED), "{}", resp.body);
    assert_eq!(
        broker.state().requests.pending_expiries().await.unwrap(),
        []
    );
}

#[tokio::test]
async fn an_ended_github_token_grant_cannot_be_renewed() {
    let (broker, _, upstream) = configured_on_fake().await;
    let grant = approve(&broker, &upstream, "bot", Window::D1).await;
    broker.clock.advance(86_400);
    let resp = broker
        .post_json(&format!("/grants/{grant}/renew"), &json!({}))
        .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);
    assert!(resp.body.contains("cannot be renewed"), "{}", resp.body);
}

#[tokio::test]
async fn the_owner_hears_once_a_few_days_before_a_grant_ends() {
    let (broker, _, upstream) = configured_on_fake().await;
    let grant = approve(&broker, &upstream, "bot", Window::D30).await;
    let requests = broker.state().requests.clone();

    broker.clock.advance(27 * 86_400 - 1);
    requests.notify_ending_grants().await;
    assert_eq!(renewal_notices(&broker), []);

    broker.clock.advance(1);
    requests.notify_ending_grants().await;
    let notices = renewal_notices(&broker);
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].title, "warden: GitHub token for bot ends soon");
    for says in ["3 days", "next git or gh call", "asks you again"] {
        assert!(notices[0].message.contains(says), "{}", notices[0].message);
    }
    assert!(notices[0].url.path().ends_with("/grants"));
    let told = entries(&broker, "github_token_renewal_notified");
    assert_eq!(told.len(), 1);
    assert_eq!(told[0]["grant_id"], grant.as_str());
    assert_eq!(entries(&broker, "commit_signing_renewal_notified").len(), 0);

    broker.clock.advance(86_400);
    requests.notify_ending_grants().await;
    assert_eq!(renewal_notices(&broker).len(), 1, "told once");
}

#[tokio::test]
async fn a_short_grant_is_told_about_late_and_a_revoked_one_not_at_all() {
    let (broker, _, upstream) = configured_on_fake().await;
    approve(&broker, &upstream, "bot", Window::D1).await;
    let requests = broker.state().requests.clone();
    requests.notify_ending_grants().await;
    assert_eq!(
        renewal_notices(&broker),
        [],
        "not as soon as it is approved"
    );
    broker.clock.advance(18 * 3600 - 1);
    requests.notify_ending_grants().await;
    assert_eq!(renewal_notices(&broker), []);
    broker.clock.advance(1);
    requests.notify_ending_grants().await;
    let notices = renewal_notices(&broker);
    assert_eq!(notices.len(), 1);
    assert!(
        notices[0].message.contains("6 hours"),
        "{}",
        notices[0].message
    );

    let (other, _, upstream) = configured_on_fake().await;
    let grant = approve(&other, &upstream, "bot", Window::D30).await;
    other.clock.advance(28 * 86_400);
    let revoked = other
        .post_json(&format!("/grants/{grant}/revoke"), &json!({}))
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.body);
    other.state().requests.notify_ending_grants().await;
    assert_eq!(renewal_notices(&other), []);
}

/// The stored resolution of the one pending request.
async fn stored_resolution(broker: &TestBroker) -> Resolution {
    let pending = broker.state().requests.pending_expiries().await.unwrap();
    assert_eq!(pending.len(), 1);
    let text: String =
        sqlx::query_scalar("SELECT resolution FROM github_repositories WHERE request_id = ?")
            .bind(pending[0].0.as_str())
            .fetch_one(&broker.state().pool)
            .await
            .unwrap();
    serde_json::from_str(&text).unwrap()
}

fn scoped(id: u64, name: &str, renamed_from: Option<&str>) -> ScopedRepository {
    ScopedRepository {
        id,
        name: name.to_owned().try_into().unwrap(),
        renamed_from: renamed_from.map(|n| n.to_owned().try_into().unwrap()),
    }
}

#[tokio::test]
async fn renewal_copies_names_and_ids() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let old = approve(&broker, &upstream, "bot", Window::D30).await;
    let token = renew(&broker, &upstream, &old).await;
    let asked = upstream.received().len();

    // The request names the grant's repository and holds its resolution already.
    assert_eq!(
        stored_resolution(&broker).await,
        Resolution::Resolved(vec![scoped(1001, "example-owner/example-repo", None)])
    );
    let pending = broker.state().requests.pending_expiries().await.unwrap();
    let body: String = sqlx::query_scalar("SELECT body FROM requests WHERE id = ?")
        .bind(pending[0].0.as_str())
        .fetch_one(&broker.state().pool)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        body["access"]["repositories"],
        json!(["example-owner/example-repo"])
    );
    assert_eq!(
        body["goal"],
        "Renew GitHub token for example-owner/example-repo"
    );

    // Opening the page and approving ask GitHub nothing more.
    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert_eq!(upstream.received().len(), asked);
    assert_eq!(entries(&broker, "github_repositories_resolved").len(), 2);
}

#[tokio::test]
async fn renewal_shows_rename() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let old = approve(&broker, &upstream, "bot", Window::D30).await;
    let current = resolved(&broker, &[(1001, "example-owner/renamed-repo")]);
    let token = renew_as(&broker, &upstream, &old, current).await;
    assert_eq!(
        stored_resolution(&broker).await,
        Resolution::Resolved(vec![scoped(
            1001,
            "example-owner/renamed-repo",
            Some("example-owner/example-repo")
        )])
    );
    // Approving grants the id under the name GitHub gives it now.
    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let list = broker.state().requests.clone();
    let active = list
        .active_github_token(&"bot".parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(active.grant_id.to_string(), old);
    let name: warden_broker_proto::release::RepoName =
        "example-owner/renamed-repo".to_owned().try_into().unwrap();
    assert_eq!(active.grant.repositories.covering(&name).unwrap().id, 1001);
}

#[tokio::test]
async fn renewal_of_unreachable_repository_cannot_be_approved() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let old = approve(&broker, &upstream, "bot", Window::D30).await;
    let token = renew_as(
        &broker,
        &upstream,
        &old,
        Scripted::with_body(422, r#"{"message":"echoed"}"#),
    )
    .await;
    assert_eq!(stored_resolution(&broker).await, Resolution::NotAccessible);
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains("cannot be approved"), "{}", page.body);
    assert!(!page.body.contains("id=\"approve\""), "{}", page.body);
    assert!(!page.body.contains("echoed"), "{}", page.body);
    // The old grant keeps working.
    assert_eq!(minting_with(&broker).await.as_deref(), Some(old.as_str()));
}
