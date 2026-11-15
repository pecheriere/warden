//! Renewing a GitHub token grant, and the notice before one ends.

use axum::http::StatusCode;
use serde_json::json;
use warden_broker::requests::{Resolution, ScopedRepository};
use warden_broker::testkit::TestBroker;
use warden_broker::testkit::upstream::{HttpsUpstream, Scripted};
use warden_broker_proto::Window;
use warden_broker_proto::github_permissions::PermissionSet;
use warden_broker_proto::github_token::{
    EXTRA_NOT_ALLOWED, INSTALLATION_LACKS, NOT_CONFIGURED, SENSITIVE_WINDOW,
};

use super::extras::{LEGACY, REPO, allow, approve_with_extras};
use super::permissions::{WITH_CHECKS, set, set_default};
use super::{
    active_for, approve, configured_on_fake, entries, github_calls, installation, resolved,
};

/// The approval token at the end of `link`.
fn token_of(link: &str) -> String {
    link.rsplit('/').next().unwrap().to_owned()
}

/// The grant `bot` would mint with now, if any.
async fn minting_with(broker: &TestBroker) -> Option<String> {
    active_for(broker, "bot", "example-owner/example-repo")
        .await
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
    let current = resolved(&broker, &[(1001, "example-owner/example-repo")]);
    let token = renew_as(&broker, &upstream, &old, current).await;
    // The same request, on a new link.
    assert_ne!(token, stale);
    let pending = broker.state().requests.pending_expiries().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0, created.id);
    // With the goal and window its agent gave, not the grant's.
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
async fn ending_soon_notice_names_repositories() {
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
    assert!(
        notices[0]
            .message
            .starts_with("GitHub token for example-owner/example-repo ends in "),
        "{}",
        notices[0].message
    );
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
    let asked = github_calls(&upstream).len();

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

    // Opening the page and approving ask GitHub nothing more but what the installation
    // holds, which `github_calls` leaves out.
    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert_eq!(github_calls(&upstream).len(), asked);
    // One for the grant's own request, resolved when its owner opened the page, and
    // one for this renewal, recorded when it was started.
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
    let active = active_for(&broker, "bot", "example-owner/renamed-repo")
        .await
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

/// A request waiting in the slot holds no resolution until renewing stores the grant's
/// own ids, so a repository recreated under the name cannot be taken for the grant's.
#[tokio::test]
async fn renewing_pins_the_ids_of_a_request_already_waiting() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let old = approve(&broker, &upstream, "bot", Window::D30).await;
    broker
        .create_request(
            "bot",
            TestBroker::github_token_request("again", Window::D7, &["example-owner/example-repo"]),
        )
        .await;
    let before = entries(&broker, "github_repositories_resolved").len();
    let token = renew(&broker, &upstream, &old).await;
    assert_eq!(
        stored_resolution(&broker).await,
        Resolution::Resolved(vec![scoped(1001, "example-owner/example-repo", None)])
    );
    assert_eq!(
        entries(&broker, "github_repositories_resolved").len(),
        before + 1
    );

    // Renewing again asks nothing more and writes nothing more, and the page asks
    // GitHub nothing either but what the installation holds, which `github_calls`
    // leaves out.
    let asked = github_calls(&upstream).len();
    let again = renew_unscripted(&broker, &old).await;
    assert_ne!(again, token);
    let page = broker.get(&format!("/approve/{again}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert_eq!(github_calls(&upstream).len(), asked);
    assert_eq!(
        entries(&broker, "github_repositories_resolved").len(),
        before + 1
    );
}

/// The permissions of the grant `bot` holds for `REPO`.
async fn held_by_bot(
    broker: &TestBroker,
) -> warden_broker_proto::github_permissions::PermissionSet {
    active_for(broker, "bot", REPO)
        .await
        .expect("a grant for the repository")
        .grant
        .permissions
        .known()
        .expect("a set this broker knows")
}

#[tokio::test]
async fn renewal_uses_the_current_default() {
    let (broker, _key, upstream) = configured_on_fake().await;
    // Approved before the default had `checks:read`: a legacy grant.
    let old = approve(&broker, &upstream, "bot", Window::D30).await;
    assert_eq!(
        held_by_bot(&broker).await,
        warden_broker_proto::github_permissions::PermissionSet::legacy()
    );
    set_default(&broker, WITH_CHECKS);
    let token = renew(&broker, &upstream, &old).await;
    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert_eq!(held_by_bot(&broker).await, set(WITH_CHECKS));
}

#[tokio::test]
async fn renewal_of_legacy_grant_with_narrowed_default() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let old = approve(&broker, &upstream, "bot", Window::D30).await;
    set_default(&broker, "contents:read,metadata:read");
    let token = renew(&broker, &upstream, &old).await;
    let page = broker.get(&format!("/approve/{token}")).await;
    assert!(page.body.contains("id=\"approve\""), "{}", page.body);
    assert!(!page.body.contains("cannot be approved"), "{}", page.body);
    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert_eq!(
        held_by_bot(&broker).await,
        set("contents:read,metadata:read")
    );
}

#[tokio::test]
async fn renewal_page_shows_the_difference() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let old = approve(&broker, &upstream, "bot", Window::D30).await;
    set_default(&broker, WITH_CHECKS);
    let token = renew(&broker, &upstream, &old).await;
    let page = broker.get(&format!("/approve/{token}")).await;
    assert!(page.body.contains("checks: read"), "{}", page.body);
    assert!(
        page.body.contains(
            "was <code class=\"perm\">contents: write</code>, <code class=\"perm\">issues: write</code>"
        ),
        "{}",
        page.body
    );
}

#[tokio::test]
async fn renewal_page_says_nothing_was_when_nothing_differs() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let old = approve(&broker, &upstream, "bot", Window::D30).await;
    let token = renew(&broker, &upstream, &old).await;
    let page = broker.get(&format!("/approve/{token}")).await;
    assert!(page.body.contains("contents: write"), "{}", page.body);
    assert!(!page.body.contains("was <code"), "{}", page.body);
}

#[tokio::test]
async fn renewal_is_not_approvable_when_the_installation_lacks_a_permission() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let old = approve(&broker, &upstream, "bot", Window::D30).await;
    set_default(&broker, WITH_CHECKS);
    upstream.answer_github_installation(Some(installation(&[
        ("contents", "write"),
        ("issues", "write"),
        ("metadata", "read"),
        ("pull_requests", "write"),
    ])));
    let token = renew(&broker, &upstream, &old).await;
    let page = broker.get(&format!("/approve/{token}")).await;
    assert!(page.body.contains("cannot be approved"), "{}", page.body);
    assert!(page.body.contains("checks: read"), "{}", page.body);
    assert!(!page.body.contains("id=\"approve\""), "{}", page.body);
    broker.enroll_soft_passkey().await;
    let refused = broker.begin_approval(&token, Window::D30).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert!(
        refused.body.contains(INSTALLATION_LACKS),
        "{}",
        refused.body
    );
    // The old grant keeps minting, with what it holds.
    assert_eq!(minting_with(&broker).await.as_deref(), Some(old.as_str()));
}

#[tokio::test]
async fn grants_page_shows_a_renewed_grants_own_set() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let old = approve(&broker, &upstream, "bot", Window::D30).await;
    set_default(&broker, WITH_CHECKS);
    let token = renew(&broker, &upstream, &old).await;
    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let grants = broker.get("/grants").await;
    assert!(grants.body.contains("checks: read"), "{}", grants.body);
}

/// The extras of the grant `bot` holds for `REPO`.
async fn extras_of_bot(broker: &TestBroker) -> Option<PermissionSet> {
    active_for(broker, "bot", REPO)
        .await
        .expect("a grant for the repository")
        .grant
        .extra_permissions
        .map(|extras| extras.known().expect("a set this broker knows"))
}

#[tokio::test]
async fn renewal_keeps_extras() {
    let (broker, _key, upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "checks:read");
    let old = approve_with_extras(
        &broker,
        &upstream,
        Window::D7,
        "checks:read",
        &[("checks", "read")],
    )
    .await;
    let token = renew(&broker, &upstream, &old).await;
    let page = broker.get(&format!("/approve/{token}")).await;
    assert!(page.body.contains("checks: read"), "{}", page.body);
    assert!(page.body.contains("id=\"approve\""), "{}", page.body);
    let approved = broker.approve(&token, Window::D7).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert_eq!(extras_of_bot(&broker).await, Some(set("checks:read")));
    assert_eq!(held_by_bot(&broker).await, set(WITH_CHECKS));
}

#[tokio::test]
async fn renewal_with_disallowed_extra_is_unapprovable_and_says_which() {
    let (broker, _key, upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "checks:read");
    let old = approve_with_extras(
        &broker,
        &upstream,
        Window::D7,
        "checks:read",
        &[("checks", "read")],
    )
    .await;
    // The owner narrows the allowlist after approving.
    allow(&broker, LEGACY, "metadata:read");
    let token = renew(&broker, &upstream, &old).await;
    let page = broker.get(&format!("/approve/{token}")).await;
    assert!(page.body.contains("cannot be approved"), "{}", page.body);
    assert!(
        page.body
            .contains(&format!("{EXTRA_NOT_ALLOWED}<code>checks:read</code>")),
        "{}",
        page.body
    );
    assert!(!page.body.contains("id=\"approve\""), "{}", page.body);
    broker.enroll_soft_passkey().await;
    let refused = broker.begin_approval(&token, Window::D7).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert!(refused.body.contains(EXTRA_NOT_ALLOWED), "{}", refused.body);
    // The old grant keeps minting, with what it holds.
    assert_eq!(minting_with(&broker).await.as_deref(), Some(old.as_str()));
}

#[tokio::test]
async fn renewal_of_sensitive_grant_keeps_a_short_window() {
    let (broker, _key, upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "workflows:write");
    let old = approve_with_extras(
        &broker,
        &upstream,
        Window::H1,
        "workflows:write",
        &[("workflows", "write")],
    )
    .await;
    let token = renew(&broker, &upstream, &old).await;
    // Whatever the owner chooses, the renewal is never a long grant holding it.
    for window in [Window::D1, Window::D30] {
        let begin = broker.begin_approval(&token, window).await;
        assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
        assert!(begin.body.contains(SENSITIVE_WINDOW), "{}", begin.body);
    }
    let approved = broker.approve(&token, Window::H1).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert_eq!(extras_of_bot(&broker).await, Some(set("workflows:write")));
    assert_ne!(minting_with(&broker).await.as_deref(), Some(old.as_str()));
}

#[tokio::test]
async fn renewal_refuses_a_grant_whose_stored_extra_no_longer_parses() {
    let (broker, _key, upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "checks:read");
    let old = approve_with_extras(
        &broker,
        &upstream,
        Window::D7,
        "checks:read",
        &[("checks", "read")],
    )
    .await;
    sqlx::query(
        "UPDATE grants SET view = json_set(view, '$.access.extra_permissions', \
         'future_thing:read,metadata:read') WHERE id = ?",
    )
    .bind(&old)
    .execute(&broker.state().pool)
    .await
    .unwrap();
    let pending = broker
        .state()
        .requests
        .pending_requests()
        .await
        .unwrap()
        .len();
    let renewed = broker
        .post_json(&format!("/grants/{old}/renew"), &json!({}))
        .await;
    assert_eq!(
        renewed.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        renewed.body
    );
    assert!(!renewed.body.contains("future_thing"), "{}", renewed.body);
    // Nothing was opened, and the old grant is untouched.
    assert_eq!(
        broker
            .state()
            .requests
            .pending_requests()
            .await
            .unwrap()
            .len(),
        pending
    );
    assert_eq!(minting_with(&broker).await.as_deref(), Some(old.as_str()));
}

/// A request already waiting keeps the set it was created with, whatever the owner
/// does to the default afterwards, when renewing finds it.
#[tokio::test]
async fn a_renewal_finding_a_pending_request_keeps_that_requests_set_across_a_change_of_default() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let old = approve(&broker, &upstream, "bot", Window::D30).await;
    broker
        .create_request(
            "bot",
            TestBroker::github_token_request("again", Window::D7, &[REPO]),
        )
        .await;
    set_default(&broker, WITH_CHECKS);
    let token = renew(&broker, &upstream, &old).await;
    let approved = broker.approve(&token, Window::D7).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert_eq!(
        held_by_bot(&broker).await,
        warden_broker_proto::github_permissions::PermissionSet::legacy()
    );
}
