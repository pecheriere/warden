//! The publish step: `POST /v1/release/publish`.

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use warden_broker::testkit::github_release::{signed_tag_object, unsigned_tag_object};
use warden_broker::testkit::upstream::Scripted;
use warden_broker_proto::Id;
use warden_broker_proto::release::{
    NO_ACTIVE_GRANT, PublishResponse, STEP_DONE, STEP_NOT_IN_GRANT,
};

use super::{HEAD, Harness, NOW, PARENT, REPO, Shape, TAG, approved, harness, repo};

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

/// Put the release key's signed tag on `commit` in place, as the tag step would
/// have, or as it already was when the release was requested.
fn put_tag_on(h: &Harness, commit: &str) {
    h.annotate(
        TAG,
        &signed_tag_object(&h.key, "git", TAG, commit, 1_794_000_000),
    );
}

/// A signed tag on the approved commit, in place before the release is requested,
/// so that the grant has no tag step.
fn put_tag(h: &Harness) {
    put_tag_on(h, HEAD);
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
    put_tag(&h);
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
    put_tag(&h);
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
    put_tag(&h);
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
    put_tag(&h);
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

/// The digests the manifest step recorded: manifest, then signature.
async fn recorded(h: &Harness, grant: &Id) -> (String, String) {
    let row = sqlx::query(
        "SELECT manifest_sha256, signature_sha256 FROM release_steps WHERE grant_id = ?",
    )
    .bind(grant.as_str())
    .fetch_one(&h.broker.state().pool)
    .await
    .unwrap();
    (row.get("manifest_sha256"), row.get("signature_sha256"))
}

/// Make GitHub list the draft `id` with both files, under the given digests.
fn serve_files(h: &Harness, id: u64, manifest: &str, signature: &str) {
    let listed = format!(
        "[{{\"id\":{id},\"tag_name\":\"{TAG}\",\"draft\":true,\"assets\":[\
         {{\"id\":1,\"name\":\"{NAME}\",\"digest\":\"sha256:{manifest}\"}},\
         {{\"id\":2,\"name\":\"{NAME}.sig\",\"digest\":\"sha256:{signature}\"}}]}}]"
    );
    h.upstream
        .github_release()
        .answer_path_with("/releases", Scripted::with_body(200, listed));
}

async fn assert_files_refused(h: &Harness, grant: &Id, id: u64) {
    let response = call(h).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    assert_eq!(
        error(&response),
        "the draft's files are not the ones signed"
    );
    assert!(!claimed(h, grant).await);
    assert_eq!(patches(h), 0);
    assert!(is_draft(h, id));
}

#[tokio::test]
async fn publish_refuses_a_replaced_manifest() {
    let h = harness(Shape::Everything).await;
    put_tag(&h);
    let release = approved(&h).await;
    let id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    sign_manifest(&h).await;
    // GitHub holds another manifest than the one the broker signed.
    let (_, signature) = recorded(&h, release.grant_id()).await;
    let other = hex::encode(Sha256::digest(b"another manifest"));
    serve_files(&h, id, &other, &signature);
    assert_files_refused(&h, release.grant_id(), id).await;
}

#[tokio::test]
async fn publish_refuses_a_replaced_signature() {
    let h = harness(Shape::Everything).await;
    put_tag(&h);
    let release = approved(&h).await;
    let id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    sign_manifest(&h).await;
    // Only the signature file differs.
    let (manifest, _) = recorded(&h, release.grant_id()).await;
    let other = hex::encode(Sha256::digest(b"another signature"));
    serve_files(&h, id, &manifest, &other);
    assert_files_refused(&h, release.grant_id(), id).await;
}

#[tokio::test]
async fn publish_refuses_a_missing_signature_file() {
    let h = harness(Shape::Everything).await;
    put_tag(&h);
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
    put_tag(&h);
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
    put_tag(&h);
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
    put_tag(&h);
    approved(&h).await;
    let _id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    assert_eq!(call(&h).await.status, StatusCode::OK);
    let sent = patches(&h);
    // The only step is done, so the grant has ended.
    let again = call(&h).await;
    assert_eq!(again.status, StatusCode::FORBIDDEN);
    assert_eq!(error(&again), NO_ACTIVE_GRANT);
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
    put_tag(&h);
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
    put_tag(&h);
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

const TAG_NOT_IN_PLACE: &str = "the tag is not in place on the approved commit";

/// Assert that publishing was refused for the tag, with the step still open.
async fn assert_tag_refused(h: &Harness, grant: &Id, id: u64) {
    let response = call(h).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    assert_eq!(error(&response), TAG_NOT_IN_PLACE);
    assert!(!claimed(h, grant).await);
    assert_eq!(patches(h), 0);
    assert!(is_draft(h, id));
    assert!(types(h).contains(&"release_refused".to_owned()));
}

#[tokio::test]
async fn publish_refuses_when_no_tag_exists() {
    let h = harness(Shape::PublishOnly).await;
    let release = approved(&h).await;
    let id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    assert_tag_refused(&h, release.grant_id(), id).await;
}

#[tokio::test]
async fn publish_refuses_when_the_tag_step_was_not_run() {
    let h = harness(Shape::PublishOnly).await;
    // The grant creates the tag; someone else's tag appears before the step runs.
    let release = approved(&h).await;
    assert!(release.grant().steps.tag);
    put_tag(&h);
    let id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    assert_tag_refused(&h, release.grant_id(), id).await;
}

#[tokio::test]
async fn publish_refuses_a_tag_on_another_commit() {
    let h = harness(Shape::PublishOnly).await;
    put_tag(&h);
    let release = approved(&h).await;
    // The tag moves after the owner approved.
    put_tag_on(&h, PARENT);
    let id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    assert_tag_refused(&h, release.grant_id(), id).await;
}

#[tokio::test]
async fn publish_refuses_a_tag_not_signed_by_the_release_key() {
    let h = harness(Shape::PublishOnly).await;
    let other =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
    put_tag(&h);
    let release = approved(&h).await;
    h.annotate(
        TAG,
        &signed_tag_object(&other, "git", TAG, HEAD, 1_794_000_000),
    );
    let id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    assert_tag_refused(&h, release.grant_id(), id).await;
}

#[tokio::test]
async fn publish_refuses_an_unsigned_tag() {
    let h = harness(Shape::PublishOnly).await;
    put_tag(&h);
    let release = approved(&h).await;
    h.annotate(TAG, &unsigned_tag_object(TAG, HEAD, 1_794_000_000));
    let id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    assert_tag_refused(&h, release.grant_id(), id).await;
}

#[tokio::test]
async fn publish_refuses_a_lightweight_tag() {
    let h = harness(Shape::PublishOnly).await;
    put_tag(&h);
    let release = approved(&h).await;
    h.upstream
        .github_release()
        .add_lightweight_tag(&repo(REPO), TAG, HEAD);
    let id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    assert_tag_refused(&h, release.grant_id(), id).await;
}
