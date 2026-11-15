//! The permission set of a GitHub token request is fixed when it is created, bound
//! into the approval and held by the grant; the installation must hold it.

use axum::http::StatusCode;
use serde_json::json;
use warden_broker::policy::GithubPermissionPolicy;
use warden_broker::requests::RequestError;
use warden_broker::testkit::TestBroker;
use warden_broker_proto::Window;
use warden_broker_proto::github_permissions::PermissionSet;
use warden_broker_proto::github_token::{
    EXTRA_NOT_ALLOWED, INSTALLATION_LACKS, INSTALLATION_UNREADABLE,
};

use super::extras::{LEGACY, allow, installation_with, with_extras};
use super::{active_for, configured_on_fake, entries, installation, resolved};

const REPO: &str = "example-owner/example-repo";

/// A default wider than the legacy set by `checks:read`.
pub(super) const WITH_CHECKS: &str =
    "checks:read,contents:write,issues:write,metadata:read,pull_requests:write";

pub(super) fn set(text: &str) -> PermissionSet {
    PermissionSet::parse(text).unwrap()
}

/// Make `default` the owner's default, with no extras allowed.
pub(super) fn set_default(broker: &TestBroker, default: &str) {
    broker
        .backend
        .set_github_permissions(Some(GithubPermissionPolicy {
            default: set(default),
            allowed_extras: PermissionSet::metadata_only(),
        }));
}

fn request() -> warden_broker_proto::CreateRequest {
    TestBroker::github_token_request("push the fix", Window::D7, &[REPO])
}

/// Approve the request behind `token`, GitHub resolving it as `REPO`, and return the
/// permissions of the grant `bot` then holds for it.
async fn approve_and_read(
    broker: &TestBroker,
    upstream: &warden_broker::testkit::upstream::HttpsUpstream,
    token: &str,
) -> PermissionSet {
    upstream.script_github_token(resolved(broker, &[(1001, REPO)]));
    let approved = broker.approve(token, Window::D7).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    active_for(broker, "bot", REPO)
        .await
        .expect("a grant for the repository")
        .grant
        .permissions
        .known()
        .expect("a set this broker knows")
}

#[tokio::test]
async fn changed_default_does_not_touch_a_pending_request() {
    let (broker, _key, upstream) = configured_on_fake().await;
    set_default(&broker, WITH_CHECKS);
    let (_, token) = broker.create_request("bot", request()).await;
    set_default(&broker, &format!("actions:read,{WITH_CHECKS}"));
    assert_eq!(
        approve_and_read(&broker, &upstream, &token).await,
        set(WITH_CHECKS)
    );
}

#[tokio::test]
async fn request_without_row_means_legacy() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let (created, token) = broker.create_request("bot", request()).await;
    // What 0.14 stored: the request, and no permissions for it.
    sqlx::query("DELETE FROM github_permissions WHERE request_id = ?")
        .bind(created.id.as_str())
        .execute(&broker.state().pool)
        .await
        .unwrap();
    set_default(&broker, WITH_CHECKS);
    assert_eq!(
        approve_and_read(&broker, &upstream, &token).await,
        PermissionSet::legacy()
    );
}

#[tokio::test]
async fn unreadable_stored_permissions_refuse_the_page() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let (created, token) = broker.create_request("bot", request()).await;
    sqlx::query(
        "UPDATE github_permissions SET permissions = 'contents:admin' WHERE request_id = ?",
    )
    .bind(created.id.as_str())
    .execute(&broker.state().pool)
    .await
    .unwrap();
    upstream.script_github_token(resolved(&broker, &[(1001, REPO)]));
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(
        page.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        page.body
    );
    assert!(!page.body.contains("contents:admin"), "{}", page.body);
    let begin = broker.begin_approval(&token, Window::D7).await;
    assert_eq!(
        begin.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        begin.body
    );
    assert!(!begin.body.contains("contents:admin"), "{}", begin.body);
    assert!(active_for(&broker, "bot", REPO).await.is_none());
}

#[tokio::test]
async fn approval_refused_when_installation_lacks_a_permission() {
    let (broker, _key, upstream) = configured_on_fake().await;
    set_default(&broker, WITH_CHECKS);
    let (_, token) = broker.create_request("bot", request()).await;
    upstream.answer_github_installation(Some(installation(&[
        ("contents", "write"),
        ("issues", "write"),
        ("metadata", "read"),
        ("pull_requests", "write"),
    ])));
    upstream.script_github_token(resolved(&broker, &[(1001, REPO)]));
    let begin = broker.begin_approval(&token, Window::D7).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
    assert!(
        begin
            .body
            .contains(&format!("{INSTALLATION_LACKS}checks:read")),
        "{}",
        begin.body
    );
}

#[tokio::test]
async fn approval_refused_when_installation_unreadable() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let (_, token) = broker.create_request("bot", request()).await;
    upstream.answer_github_installation(None);
    upstream.script_github_token(resolved(&broker, &[(1001, REPO)]));
    let begin = broker.begin_approval(&token, Window::D7).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
    assert!(
        begin.body.contains(INSTALLATION_UNREADABLE),
        "{}",
        begin.body
    );
}

#[tokio::test]
async fn approval_refused_when_installation_narrows_after_begin() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let (_, token) = broker.create_request("bot", request()).await;
    upstream.script_github_token(resolved(&broker, &[(1001, REPO)]));
    let mut auth = broker.enroll_soft_passkey().await;
    let begin = broker.begin_approval(&token, Window::D7).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    upstream.answer_github_installation(Some(installation(&[("metadata", "read")])));
    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(finish.status, StatusCode::CONFLICT, "{}", finish.body);
    assert!(finish.body.contains(INSTALLATION_LACKS), "{}", finish.body);
    assert!(active_for(&broker, "bot", REPO).await.is_none());
}

#[tokio::test]
async fn approval_binds_the_set() {
    let (broker, _key, upstream) = configured_on_fake().await;
    set_default(&broker, WITH_CHECKS);
    let (_, token) = broker.create_request("bot", request()).await;
    upstream.script_github_token(resolved(&broker, &[(1001, REPO)]));
    let view = broker
        .state()
        .requests
        .pending_for_token(&token)
        .await
        .unwrap();
    assert_eq!(
        view.github.as_ref().unwrap().permissions.full,
        set(WITH_CHECKS)
    );
    broker.enroll_soft_passkey().await;
    let mut other = view.clone();
    other.github.as_mut().unwrap().permissions.full = PermissionSet::legacy();
    assert_ne!(other.destination_digest(), view.destination_digest());

    let refused = broker
        .begin_approval_for(&token, Window::D7, &other.destination_digest())
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
    let accepted = broker
        .begin_approval_for(&token, Window::D7, &view.destination_digest())
        .await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.body);
}

#[tokio::test]
async fn creation_refused_when_the_permission_fields_cannot_be_read() {
    let (broker, _key, _upstream) = configured_on_fake().await;
    broker
        .backend
        .set_github_app_outage(Some("1Password is down"));
    let refused = broker
        .state()
        .requests
        .create(&"bot".parse().unwrap(), request())
        .await;
    assert!(
        matches!(refused, Err(RequestError::Unavailable(_))),
        "{refused:?}"
    );
    let pool = &broker.state().pool;
    for (table, count) in [
        ("requests", "SELECT COUNT(*) FROM requests"),
        (
            "github_permissions",
            "SELECT COUNT(*) FROM github_permissions",
        ),
    ] {
        let rows: i64 = sqlx::query_scalar(count).fetch_one(pool).await.unwrap();
        assert_eq!(rows, 0, "nothing is written to {table}");
    }
}

/// A stored grant whose set this version cannot act on, as a newer broker could
/// leave after a downgrade, is refused, not read leniently: no token is minted
/// and the grants page refuses.
#[tokio::test]
async fn a_stored_grant_with_an_unknown_permission_refuses() {
    let (broker, key, upstream) = configured_on_fake().await;
    let grant = broker
        .insert_scoped_github_grant("bot", &[(REPO, 1001)])
        .await;
    let pool = &broker.state().pool;
    let view: String = sqlx::query_scalar("SELECT view FROM grants WHERE id = ?")
        .bind(grant.as_str())
        .fetch_one(pool)
        .await
        .unwrap();
    let newer = view.replace("contents:write", "contents:write,new_thing:write");
    assert_ne!(newer, view);
    sqlx::query("UPDATE grants SET view = ? WHERE id = ?")
        .bind(newer)
        .bind(grant.as_str())
        .execute(pool)
        .await
        .unwrap();

    let before = upstream.received().len();
    let resp = broker
        .api_post_json(&key, "/v1/github-token", &json!({"repository": REPO}))
        .await;
    assert_eq!(
        resp.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        resp.body
    );
    assert!(!resp.body.contains("new_thing"), "{}", resp.body);
    assert_eq!(upstream.received().len(), before, "GitHub was not asked");
    let page = broker.get("/grants").await;
    assert_eq!(
        page.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        page.body
    );
}

#[tokio::test]
async fn approved_entry_records_permissions() {
    let (broker, _key, upstream) = configured_on_fake().await;
    set_default(&broker, WITH_CHECKS);
    let (_, token) = broker.create_request("bot", request()).await;
    approve_and_read(&broker, &upstream, &token).await;
    let approved = entries(&broker, "approved");
    assert_eq!(approved.last().unwrap()["permissions"], WITH_CHECKS);
}

#[tokio::test]
async fn pending_request_unapprovable_after_allowlist_narrowed() {
    let (broker, _key, upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "checks:read");
    let (_, token) = broker
        .create_request("bot", with_extras(Window::D7, "checks:read"))
        .await;
    allow(&broker, LEGACY, "metadata:read");
    upstream.answer_github_installation(Some(installation_with(&[("checks", "read")])));
    upstream.script_github_token(resolved(&broker, &[(1001, REPO)]));
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains("cannot be approved"), "{}", page.body);
    assert!(
        page.body
            .contains(&format!("{EXTRA_NOT_ALLOWED}<code>checks:read</code>")),
        "{}",
        page.body
    );
    assert!(!page.body.contains("id=\"approve\""), "{}", page.body);
    broker.enroll_soft_passkey().await;
    let begin = broker.begin_approval(&token, Window::D7).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
    assert!(begin.body.contains(EXTRA_NOT_ALLOWED), "{}", begin.body);
    assert!(active_for(&broker, "bot", REPO).await.is_none());
    // Widened again, the same request approves.
    allow(&broker, LEGACY, "checks:read");
    let approved = broker.approve(&token, Window::D7).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
}
