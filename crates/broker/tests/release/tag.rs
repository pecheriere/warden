//! The tag step: `POST /v1/release/tag`.

use axum::http::StatusCode;
use serde_json::{Value, json};
use sqlx::Row as _;
use warden_broker::policy::{ReleaseAppKey, ReleaseSigningKey};
use warden_broker::testkit::github_app::RSA2048_PKCS8;
use warden_broker::testkit::github_release::signed_tag_object;
use warden_broker::testkit::upstream::Scripted;
use warden_broker_proto::Id;
use warden_broker_proto::release::{NO_ACTIVE_GRANT, STEP_DONE, STEP_NOT_IN_GRANT, TagResponse};

use super::{HEAD, Harness, NOW, PARENT, REPO, Shape, TAG, approved, harness, repo};

const PATH: &str = "/v1/release/tag";

fn body() -> Value {
    json!({"repository": REPO, "tag": TAG})
}

async fn call(h: &Harness) -> warden_broker::testkit::TestResponse {
    h.broker.api_post_json(&h.agent_key, PATH, &body()).await
}

fn error(response: &warden_broker::testkit::TestResponse) -> String {
    response.json()["error"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

async fn claimed(h: &Harness, grant: &Id) -> bool {
    let row = sqlx::query("SELECT tag_claimed_at FROM release_steps WHERE grant_id = ?")
        .bind(grant.as_str())
        .fetch_one(&h.broker.state().pool)
        .await
        .unwrap();
    row.get::<Option<i64>, _>("tag_claimed_at").is_some()
}

fn posts(h: &Harness, suffix: &str) -> usize {
    h.upstream
        .github_release()
        .record()
        .iter()
        .filter(|call| call.method == "POST" && call.path_and_query.ends_with(suffix))
        .count()
}

fn types(h: &Harness) -> Vec<String> {
    h.broker.audit_types()
}

#[tokio::test]
async fn tag_step_creates_signed_tag() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    let done: TagResponse = serde_json::from_value(response.json()).unwrap();
    assert_eq!(done.grant_id, *release.grant_id());
    assert_eq!(done.commit.as_str(), HEAD);
    let github = h.upstream.github_release();
    let repository = repo(REPO);
    assert_eq!(
        github.ref_target(&repository, TAG),
        Some(done.object.clone())
    );
    let raw = github.tag_object(&repository, &done.object).unwrap();
    let key = ReleaseSigningKey::for_tests(REPO, h.key.clone(), None, false);
    assert!(key.verifies_tag(&raw));
    let text = String::from_utf8(raw).unwrap();
    assert!(text.starts_with(&format!(
        "object {HEAD}\ntype commit\ntag {TAG}\ntagger Release Bot <release@example.com> {NOW} +0000\n\nexample-repo 1.2.3\n"
    )));
    assert!(types(&h).contains(&"release_tag_created".to_owned()));
    // The manifest and publish steps are still to do, so the grant stays.
    assert!(claimed(&h, release.grant_id()).await);
    assert!(
        h.broker
            .state()
            .requests
            .active_release(
                &"build-agent".parse().unwrap(),
                &repository,
                &release.grant().tag
            )
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn tag_step_ends_a_grant_that_was_only_the_tag() {
    let h = harness(Shape::TagOnly).await;
    let release = approved(&h).await;
    assert_eq!(call(&h).await.status, StatusCode::OK);
    assert!(
        h.broker
            .state()
            .requests
            .active_release(
                &"build-agent".parse().unwrap(),
                &repo(REPO),
                &release.grant().tag
            )
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn tag_step_refuses_on_id_mismatch() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let github = h.upstream.github_release();
    github.answer_path_with(
        "/git/tags",
        Scripted::with_body(201, json!({"sha": "f".repeat(40)}).to_string()),
    );
    let response = call(&h).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_GATEWAY,
        "{}",
        response.body
    );
    assert_eq!(posts(&h, "/git/refs"), 0, "no ref was created");
    assert!(claimed(&h, release.grant_id()).await, "the step is used");
    assert!(types(&h).contains(&"release_refused".to_owned()));
    github.answer_normally();
    let again = call(&h).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(error(&again), STEP_DONE);
}

#[tokio::test]
async fn tag_step_runs_once() {
    let h = harness(Shape::Everything).await;
    approved(&h).await;
    assert_eq!(call(&h).await.status, StatusCode::OK);
    let again = call(&h).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(error(&again), STEP_DONE);
    assert_eq!(posts(&h, "/git/tags"), 1);
}

#[tokio::test]
async fn tag_step_not_in_grant() {
    let h = harness(Shape::Everything).await;
    let raw = signed_tag_object(&h.key, "git", TAG, HEAD, 1_794_000_000);
    h.annotate(TAG, &raw);
    let release = approved(&h).await;
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(error(&response), STEP_NOT_IN_GRANT);
    assert!(!claimed(&h, release.grant_id()).await);
    assert_eq!(posts(&h, "/git/tags"), 0);
}

#[tokio::test]
async fn tag_step_refuses_without_grant() {
    let h = harness(Shape::Everything).await;
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(error(&response), NO_ACTIVE_GRANT);
    assert!(types(&h).contains(&"release_refused".to_owned()));
    assert_eq!(posts(&h, "/git/tags"), 0);
}

#[tokio::test]
async fn tag_step_refuses_when_key_changed() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let other =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
    h.broker
        .backend
        .replace_release_keys(ReleaseSigningKey::for_tests(REPO, other, None, false));
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    assert!(error(&response).starts_with("policy changed"));
    assert!(!claimed(&h, release.grant_id()).await);
    assert_eq!(posts(&h, "/git/tags"), 0);
}

#[tokio::test]
async fn tag_step_refuses_after_revocation() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    sqlx::query("UPDATE grants SET revoked_at = ? WHERE id = ?")
        .bind(NOW)
        .bind(release.grant_id().as_str())
        .execute(&h.broker.state().pool)
        .await
        .unwrap();
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(error(&response), NO_ACTIVE_GRANT);
    assert!(!claimed(&h, release.grant_id()).await);
    assert_eq!(posts(&h, "/git/tags"), 0);
}

#[tokio::test]
async fn tag_step_refuses_a_tag_that_appeared_meanwhile() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    h.upstream
        .github_release()
        .add_lightweight_tag(&repo(REPO), TAG, HEAD);
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    assert_eq!(error(&response), "the tag already exists");
    assert!(!claimed(&h, release.grant_id()).await);
    assert_eq!(posts(&h, "/git/tags"), 0);
}

#[tokio::test]
async fn tag_step_refuses_a_bad_body() {
    let h = harness(Shape::Everything).await;
    approved(&h).await;
    let response = h
        .broker
        .api_post_json(&h.agent_key, PATH, &json!({"repository": REPO}))
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(error(&response), "the request body is not valid");
    assert_eq!(posts(&h, "/git/tags"), 0);
}

#[tokio::test]
async fn tag_step_refuses_a_commit_that_left_the_default_branch() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    h.upstream
        .github_release()
        .set_default_branch(&repo(REPO), "main", PARENT);
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    assert_eq!(
        error(&response),
        "the approved commit is not on the repository's default branch"
    );
    assert!(!claimed(&h, release.grant_id()).await);
    assert_eq!(posts(&h, "/git/tags"), 0);
}

#[tokio::test]
async fn tag_step_refuses_when_the_app_changed() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    h.broker.backend.set_release_app(Some(
        ReleaseAppKey::new(
            "987655".to_owned(),
            std::str::from_utf8(RSA2048_PKCS8).unwrap(),
        )
        .unwrap(),
    ));
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    assert!(error(&response).starts_with("policy changed"));
    assert!(!claimed(&h, release.grant_id()).await);
    assert_eq!(posts(&h, "/git/tags"), 0);
}

#[tokio::test]
async fn tag_step_that_fails_at_github_after_the_claim_stays_used() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let github = h.upstream.github_release();
    github.answer_path_with("/git/tags", Scripted::with_body(500, "{}".to_owned()));
    let response = call(&h).await;
    assert_eq!(
        response.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        response.body
    );
    assert!(claimed(&h, release.grant_id()).await, "the step is used");
    assert!(types(&h).contains(&"release_refused".to_owned()));
    github.answer_normally();
    let again = call(&h).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(error(&again), STEP_DONE);
}
