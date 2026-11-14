//! The permission set of a GitHub token request is fixed when it is created, bound
//! into the approval and held by the grant; the installation must hold it.

use axum::http::StatusCode;
use warden_broker::policy::GithubPermissionPolicy;
use warden_broker::testkit::TestBroker;
use warden_broker_proto::Window;
use warden_broker_proto::github_permissions::PermissionSet;
use warden_broker_proto::github_token::{INSTALLATION_LACKS, INSTALLATION_UNREADABLE};

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
}

#[tokio::test]
async fn request_stores_the_default_at_creation() {
    let (broker, _key, upstream) = configured_on_fake().await;
    set_default(&broker, WITH_CHECKS);
    let (_, token) = broker.create_request("bot", request()).await;
    assert_eq!(
        approve_and_read(&broker, &upstream, &token).await,
        set(WITH_CHECKS)
    );
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
    let begin = broker.begin_approval(&token, Window::D7).await;
    assert_ne!(begin.status, StatusCode::OK, "{}", begin.body);
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
async fn creation_never_reads_the_key() {
    let (broker, _key, _upstream) = configured_on_fake().await;
    let before = broker.backend.github_app_reads();
    let _ = broker.create_request("bot", request()).await;
    assert_eq!(broker.backend.github_app_reads(), before);
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
    assert!(refused.is_err(), "{refused:?}");
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
