//! The publish step: `POST /v1/release/publish`.

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use warden_broker::testkit::upstream::Scripted;
use warden_broker_proto::Id;
use warden_broker_proto::release::{
    NO_ACTIVE_GRANT, PublishResponse, STEP_DONE, STEP_NOT_IN_GRANT,
};

use super::{Harness, NOW, REPO, Shape, TAG, approved, harness, repo};

const PATH: &str = "/v1/release/publish";
const NAME: &str = "warden-1.2.3-SHA256SUMS";
const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn target() -> Value {
    json!({"repository": REPO, "tag": TAG})
}

async fn call(h: &Harness) -> warden_broker::testkit::TestResponse {
    h.broker.api_post_json(&h.agent_key, PATH, &target()).await
}

/// Run the manifest step with a valid manifest.
async fn sign_manifest(h: &Harness) {
    let content = format!("{DIGEST}  warden-1.2.3.tar.gz\n");
    let body = json!({
        "repository": REPO,
        "tag": TAG,
        "name": NAME,
        "content_b64": STANDARD.encode(content.as_bytes()),
    });
    let response = h
        .broker
        .api_post_json(&h.agent_key, "/v1/release/manifest", &body)
        .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
}

fn error(response: &warden_broker::testkit::TestResponse) -> String {
    response.json()["error"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

async fn claimed(h: &Harness, grant: &Id) -> bool {
    let row = sqlx::query("SELECT publish_claimed_at FROM release_steps WHERE grant_id = ?")
        .bind(grant.as_str())
        .fetch_one(&h.broker.state().pool)
        .await
        .unwrap();
    row.get::<Option<i64>, _>("publish_claimed_at").is_some()
}

fn patches(h: &Harness) -> usize {
    h.upstream
        .github_release()
        .record()
        .iter()
        .filter(|call| call.method == "PATCH")
        .count()
}

fn is_draft(h: &Harness, id: u64) -> bool {
    h.upstream
        .github_release()
        .release(&repo(REPO), id)
        .unwrap()
        .draft
}

fn types(h: &Harness) -> Vec<String> {
    h.broker.audit_types()
}

#[tokio::test]
async fn publish_step_publishes() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    sign_manifest(&h).await;
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    let done: PublishResponse = serde_json::from_value(response.json()).unwrap();
    assert_eq!(done.grant_id, *release.grant_id());
    assert_eq!(done.tag.as_str(), TAG);
    assert!(!is_draft(&h, id));
    assert!(claimed(&h, release.grant_id()).await);
    assert!(types(&h).contains(&"release_published".to_owned()));
}

#[tokio::test]
async fn publish_step_publishes_without_a_manifest_step() {
    let h = harness(Shape::PublishOnly).await;
    let release = approved(&h).await;
    let id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert!(!is_draft(&h, id));
    assert!(claimed(&h, release.grant_id()).await);
}

#[tokio::test]
async fn publish_refuses_without_draft_and_keeps_step() {
    let h = harness(Shape::PublishOnly).await;
    let release = approved(&h).await;
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    assert_eq!(error(&response), "the tag has no draft release");
    assert!(!claimed(&h, release.grant_id()).await);
    assert_eq!(patches(&h), 0);
    assert!(types(&h).contains(&"release_refused".to_owned()));
}

#[tokio::test]
async fn publish_refuses_before_manifest() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    assert_eq!(error(&response), "the manifest has not been signed");
    assert!(!claimed(&h, release.grant_id()).await);
    assert_eq!(patches(&h), 0);
    assert!(is_draft(&h, id));
    // Once the manifest is signed, the same call goes through.
    sign_manifest(&h).await;
    assert_eq!(call(&h).await.status, StatusCode::OK);
}

#[tokio::test]
async fn publish_refuses_replaced_manifest() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let github = h.upstream.github_release();
    let id = github.add_release(&repo(REPO), TAG, true);
    sign_manifest(&h).await;
    // The draft's files are not the ones the broker signed: what it recorded
    // differs from what GitHub holds.
    sqlx::query("UPDATE release_steps SET manifest_sha256 = ? WHERE grant_id = ?")
        .bind(hex::encode(Sha256::digest(b"another manifest")))
        .bind(release.grant_id().as_str())
        .execute(&h.broker.state().pool)
        .await
        .unwrap();
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    assert_eq!(
        error(&response),
        "the draft's files are not the ones signed"
    );
    assert!(!claimed(&h, release.grant_id()).await);
    assert_eq!(patches(&h), 0);
    assert!(is_draft(&h, id));
}

#[tokio::test]
async fn publish_refuses_a_missing_signature_file() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let github = h.upstream.github_release();
    let id = github.add_release(&repo(REPO), TAG, true);
    sign_manifest(&h).await;
    // Both files are listed under their names; hide the signature.
    let listed = format!(
        "[{{\"id\":{id},\"tag_name\":\"{TAG}\",\"draft\":true,\"assets\":[\
         {{\"id\":1,\"name\":\"{NAME}\",\"digest\":\"sha256:{}\"}}]}}]",
        hex::encode(Sha256::digest(
            format!("{DIGEST}  warden-1.2.3.tar.gz\n").as_bytes()
        ))
    );
    github.answer_path_with("/releases", Scripted::with_body(200, listed));
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    assert_eq!(
        error(&response),
        "the draft's files are not the ones signed"
    );
    assert!(!claimed(&h, release.grant_id()).await);
}

#[tokio::test]
async fn publish_refuses_missing_digest() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let github = h.upstream.github_release();
    let id = github.add_release(&repo(REPO), TAG, true);
    sign_manifest(&h).await;
    let listed = format!(
        "[{{\"id\":{id},\"tag_name\":\"{TAG}\",\"draft\":true,\"assets\":[\
         {{\"id\":1,\"name\":\"{NAME}\",\"digest\":null}},\
         {{\"id\":2,\"name\":\"{NAME}.sig\",\"digest\":null}}]}}]"
    );
    github.answer_path_with("/releases", Scripted::with_body(200, listed));
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    assert_eq!(error(&response), "GitHub did not report the files' digests");
    assert!(!claimed(&h, release.grant_id()).await);
    assert_eq!(patches(&h), 0);
}

#[tokio::test]
async fn publish_refuses_already_published() {
    let h = harness(Shape::PublishOnly).await;
    let release = approved(&h).await;
    let _id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, false);
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    assert_eq!(error(&response), "the release is already published");
    assert!(!claimed(&h, release.grant_id()).await);
    assert_eq!(patches(&h), 0);
}

#[tokio::test]
async fn publish_step_runs_once() {
    let h = harness(Shape::PublishOnly).await;
    approved(&h).await;
    let _id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    assert_eq!(call(&h).await.status, StatusCode::OK);
    let sent = patches(&h);
    let again = call(&h).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(error(&again), STEP_DONE);
    assert_eq!(patches(&h), sent, "nothing more was sent");
}

#[tokio::test]
async fn publish_not_in_grant_when_publish_false() {
    let h = harness(Shape::TagOnly).await;
    let release = approved(&h).await;
    let id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(error(&response), STEP_NOT_IN_GRANT);
    assert!(!claimed(&h, release.grant_id()).await);
    assert!(is_draft(&h, id));
}

#[tokio::test]
async fn publish_refuses_without_grant() {
    let h = harness(Shape::Everything).await;
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(error(&response), NO_ACTIVE_GRANT);
    assert!(types(&h).contains(&"release_refused".to_owned()));
}

#[tokio::test]
async fn publish_refuses_after_revocation() {
    let h = harness(Shape::PublishOnly).await;
    let release = approved(&h).await;
    let id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    sqlx::query("UPDATE grants SET revoked_at = ? WHERE id = ?")
        .bind(NOW)
        .bind(release.grant_id().as_str())
        .execute(&h.broker.state().pool)
        .await
        .unwrap();
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(!claimed(&h, release.grant_id()).await);
    assert!(is_draft(&h, id));
}

#[tokio::test]
async fn publish_that_fails_at_github_after_the_claim_stays_used() {
    let h = harness(Shape::PublishOnly).await;
    let release = approved(&h).await;
    let github = h.upstream.github_release();
    let id = github.add_release(&repo(REPO), TAG, true);
    github.answer_path_with(
        &format!("/releases/{id}"),
        Scripted::with_body(500, "{}".to_owned()),
    );
    let response = call(&h).await;
    assert_eq!(
        response.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        response.body
    );
    assert!(claimed(&h, release.grant_id()).await);
    assert!(types(&h).contains(&"release_refused".to_owned()));
    github.answer_normally();
    let again = call(&h).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(error(&again), STEP_DONE);
    assert!(is_draft(&h, id));
}

#[tokio::test]
async fn grant_ends_after_publish() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let github = h.upstream.github_release();
    let _id = github.add_release(&repo(REPO), TAG, true);
    let tag = h
        .broker
        .api_post_json(&h.agent_key, "/v1/release/tag", &target())
        .await;
    assert_eq!(tag.status, StatusCode::OK, "{}", tag.body);
    sign_manifest(&h).await;
    let agent = "build-agent".parse().unwrap();
    let tag_name = TAG.to_owned().try_into().unwrap();
    let still_active = || async {
        h.broker
            .state()
            .requests
            .active_release(&agent, &repo(REPO), &tag_name)
            .await
            .unwrap()
            .is_some()
    };
    assert!(still_active().await, "the publish step is still open");
    let page = h.broker.get("/grants").await;
    assert!(page.body.contains(TAG), "the grants page lists the release");

    assert_eq!(call(&h).await.status, StatusCode::OK);
    assert!(!still_active().await, "the last step ended the grant");
    let page = h.broker.get("/grants").await;
    assert!(
        !page.body.contains(TAG),
        "the grants page no longer lists it: {}",
        page.body
    );
    let after = call(&h).await;
    assert_eq!(after.status, StatusCode::FORBIDDEN);
    assert_eq!(error(&after), NO_ACTIVE_GRANT);
    assert!(claimed(&h, release.grant_id()).await);
}
