//! The manifest step: `POST /v1/release/manifest`.

use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, Stdio};

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use warden_broker::release_signing::ManifestError;
use warden_broker::testkit::upstream::Scripted;
use warden_broker_proto::Id;
use warden_broker_proto::release::{
    ManifestResponse, NO_ACTIVE_GRANT, STEP_DONE, STEP_NOT_IN_GRANT,
};

use super::{Harness, NOW, REPO, Shape, TAG, approved, harness, repo};

const PATH: &str = "/v1/release/manifest";
const NAME: &str = "warden-1.2.3-SHA256SUMS";
const SIGNATURE_NAME: &str = "warden-1.2.3-SHA256SUMS.sig";
const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn manifest() -> String {
    format!(
        "{DIGEST}  warden-1.2.3-x86_64-unknown-linux-gnu.tar.gz\n{DIGEST}  ghcr.io/example-owner/example-repo:1.2.3\n"
    )
}

/// As many unique lines as fit in 64 KiB.
fn largest_manifest() -> String {
    let mut text = String::new();
    let mut i = 0_u32;
    while text.len() + 80 <= 65_536 {
        writeln!(text, "{DIGEST}  f{i}").unwrap();
        i += 1;
    }
    text
}

fn body_with(name: &str, content: &[u8]) -> Value {
    json!({
        "repository": REPO,
        "tag": TAG,
        "name": name,
        "content_b64": STANDARD.encode(content),
    })
}

async fn call_with(h: &Harness, body: &Value) -> warden_broker::testkit::TestResponse {
    h.broker.api_post_json(&h.agent_key, PATH, body).await
}

async fn call(h: &Harness) -> warden_broker::testkit::TestResponse {
    call_with(h, &body_with(NAME, manifest().as_bytes())).await
}

fn error(response: &warden_broker::testkit::TestResponse) -> String {
    response.json()["error"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

async fn claimed(h: &Harness, grant: &Id) -> bool {
    let row = sqlx::query("SELECT manifest_claimed_at FROM release_steps WHERE grant_id = ?")
        .bind(grant.as_str())
        .fetch_one(&h.broker.state().pool)
        .await
        .unwrap();
    row.get::<Option<i64>, _>("manifest_claimed_at").is_some()
}

fn writes(h: &Harness) -> usize {
    h.upstream
        .github_release()
        .record()
        .iter()
        .filter(|call| {
            (call.method == "POST" && call.path_and_query.contains("/assets"))
                || call.method == "DELETE"
        })
        .count()
}

fn types(h: &Harness) -> Vec<String> {
    h.broker.audit_types()
}

fn verifies(h: &Harness, signature: &[u8], namespace: &str, data: &[u8]) -> bool {
    let dir = tempfile::tempdir().unwrap();
    let signers = dir.path().join("allowed-signers");
    let public = h.key.public_key().to_openssh().unwrap();
    std::fs::write(
        &signers,
        format!("release@example.com namespaces=\"warden-release\" {public}\n"),
    )
    .unwrap();
    let sig = dir.path().join("manifest.sig");
    std::fs::write(&sig, signature).unwrap();
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&signers)
        .args(["-I", "release@example.com", "-n", namespace, "-s"])
        .arg(&sig)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(data).unwrap();
    child.wait().unwrap().success()
}

#[tokio::test]
async fn manifest_step_uploads_manifest_and_signature() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let github = h.upstream.github_release();
    let id = github.add_release(&repo(REPO), TAG, true);
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    let done: ManifestResponse = serde_json::from_value(response.json()).unwrap();
    assert_eq!(done.grant_id, *release.grant_id());
    assert_eq!(done.name, NAME);
    assert_eq!(done.signature_name, SIGNATURE_NAME);
    let digest = hex::encode(Sha256::digest(manifest().as_bytes()));
    assert_eq!(done.sha256, digest);

    let view = github.release(&repo(REPO), id).unwrap();
    assert!(view.draft, "the step does not publish");
    let asset = |name: &str| {
        view.assets
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, bytes)| bytes.clone())
            .unwrap()
    };
    assert_eq!(asset(NAME), manifest().as_bytes());
    let signature = asset(SIGNATURE_NAME);
    assert!(verifies(
        &h,
        &signature,
        "warden-release",
        manifest().as_bytes()
    ));
    assert!(!verifies(&h, &signature, "git", manifest().as_bytes()));

    let row = sqlx::query(
        "SELECT manifest_sha256, signature_sha256 FROM release_steps WHERE grant_id = ?",
    )
    .bind(release.grant_id().as_str())
    .fetch_one(&h.broker.state().pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("manifest_sha256"), digest);
    assert_eq!(
        row.get::<String, _>("signature_sha256"),
        hex::encode(Sha256::digest(&signature))
    );
    assert!(types(&h).contains(&"release_manifest_signed".to_owned()));
    assert!(claimed(&h, release.grant_id()).await);
}

#[tokio::test]
async fn manifest_step_replaces_existing_assets() {
    let h = harness(Shape::Everything).await;
    approved(&h).await;
    let github = h.upstream.github_release();
    let id = github.add_release(&repo(REPO), TAG, true);
    github.add_asset(&repo(REPO), id, NAME, b"stale manifest");
    github.add_asset(&repo(REPO), id, SIGNATURE_NAME, b"stale signature");
    github.add_asset(&repo(REPO), id, "keep-me.tar.gz", b"archive");
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    let view = github.release(&repo(REPO), id).unwrap();
    let mut names: Vec<&str> = view.assets.iter().map(|(n, _)| n.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["keep-me.tar.gz", NAME, SIGNATURE_NAME]);
    let manifest_asset = view.assets.iter().find(|(n, _)| n == NAME).unwrap();
    assert_eq!(manifest_asset.1, manifest().as_bytes());
}

#[tokio::test]
async fn manifest_step_refuses_without_draft_and_keeps_step() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    assert_eq!(error(&response), "the tag has no draft release");
    assert!(!claimed(&h, release.grant_id()).await);
    assert_eq!(writes(&h), 0);
    assert!(types(&h).contains(&"release_refused".to_owned()));
    let _id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    let retry = call(&h).await;
    assert_eq!(retry.status, StatusCode::OK, "{}", retry.body);
    assert!(claimed(&h, release.grant_id()).await);
}

#[tokio::test]
async fn manifest_step_refuses_published_release() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let _id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, false);
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::CONFLICT, "{}", response.body);
    assert_eq!(error(&response), "the release is already published");
    assert!(!claimed(&h, release.grant_id()).await);
    assert_eq!(writes(&h), 0);
}

#[tokio::test]
async fn manifest_step_runs_once() {
    let h = harness(Shape::Everything).await;
    approved(&h).await;
    let _id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    assert_eq!(call(&h).await.status, StatusCode::OK);
    let uploads = writes(&h);
    let again = call(&h).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(error(&again), STEP_DONE);
    assert_eq!(writes(&h), uploads, "nothing more was written");
}

#[tokio::test]
async fn manifest_step_not_in_tag_only_repository() {
    let h = harness(Shape::TagOnly).await;
    let release = approved(&h).await;
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(error(&response), STEP_NOT_IN_GRANT);
    assert!(!claimed(&h, release.grant_id()).await);
}

#[tokio::test]
async fn manifest_step_refuses_without_grant() {
    let h = harness(Shape::Everything).await;
    let response = call(&h).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(error(&response), NO_ACTIVE_GRANT);
    assert!(types(&h).contains(&"release_refused".to_owned()));
}

#[tokio::test]
async fn manifest_step_refuses_a_manifest_that_fails_the_check_and_keeps_step() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let _id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    let secret = "SECRET-CONTENT";
    let bad = format!("{DIGEST}  {secret}/x\n");
    let response = call_with(&h, &body_with(NAME, bad.as_bytes())).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.body
    );
    assert_eq!(
        error(&response),
        ManifestError::BadName { line: 1 }.to_string()
    );
    assert!(!response.body.contains(secret));
    assert!(!claimed(&h, release.grant_id()).await);
    assert_eq!(writes(&h), 0);
    // An image at another version is refused too.
    let other = format!("{DIGEST}  ghcr.io/example-owner/example-repo:1.2.4\n");
    let response = call_with(&h, &body_with(NAME, other.as_bytes())).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        error(&response),
        ManifestError::BadName { line: 1 }.to_string()
    );
    assert!(!claimed(&h, release.grant_id()).await);
}

#[tokio::test]
async fn manifest_step_refuses_another_name() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let _id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    let response = call_with(&h, &body_with("other-SHA256SUMS", manifest().as_bytes())).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.body
    );
    assert_eq!(error(&response), ManifestError::WrongName.to_string());
    assert!(!claimed(&h, release.grant_id()).await);
    assert_eq!(writes(&h), 0);
}

#[tokio::test]
async fn manifest_step_refuses_bad_base64_and_bad_body() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let mut body = body_with(NAME, b"x");
    body["content_b64"] = json!("not base64 !!");
    let response = call_with(&h, &body).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(error(&response), "the request body is not valid");
    let response = call_with(&h, &json!({"repository": REPO, "tag": TAG})).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(error(&response), "the request body is not valid");
    assert!(!claimed(&h, release.grant_id()).await);
}

#[tokio::test]
async fn manifest_step_accepts_the_largest_manifest() {
    let h = harness(Shape::Everything).await;
    approved(&h).await;
    let _id = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    let text = largest_manifest();
    let response = call_with(&h, &body_with(NAME, text.as_bytes())).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
}

#[tokio::test]
async fn manifest_step_refuses_a_manifest_over_the_limit() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let line = format!("{DIGEST}  a\n");
    let big = line.repeat(65_536 / line.len() + 1);
    let response = call_with(&h, &body_with(NAME, big.as_bytes())).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.body
    );
    assert_eq!(error(&response), ManifestError::TooLarge.to_string());
    assert!(!claimed(&h, release.grant_id()).await);
}

#[tokio::test]
async fn manifest_step_that_fails_at_github_after_the_claim_stays_used() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let github = h.upstream.github_release();
    let _id = github.add_release(&repo(REPO), TAG, true);
    github.answer_path_with("/assets", Scripted::with_body(500, "{}".to_owned()));
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
}

#[tokio::test]
async fn manifest_step_refuses_after_revocation() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let _id = h
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
    assert_eq!(writes(&h), 0);
}
