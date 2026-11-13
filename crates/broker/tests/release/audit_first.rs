//! Every step writes `release_step_started` before anything signed leaves the broker
//! and before GitHub is changed, and goes no further when it cannot.

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use warden_broker::audit::{self, AuditEvent};
use warden_broker::testkit::TestResponse;
use warden_broker::testkit::github_release::signed_tag_object;

use super::{HEAD, Harness, REPO, Shape, TAG, approved, harness, repo};

const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn target() -> Value {
    json!({"repository": REPO, "tag": TAG})
}

fn manifest() -> String {
    format!("{DIGEST}  warden-1.2.3-x86_64-unknown-linux-gnu.tar.gz\n")
}

async fn tag(h: &Harness) -> TestResponse {
    h.broker
        .api_post_json(&h.agent_key, "/v1/release/tag", &target())
        .await
}

async fn sign_manifest(h: &Harness) -> TestResponse {
    let body = json!({
        "repository": REPO,
        "tag": TAG,
        "name": "warden-1.2.3-SHA256SUMS",
        "content_b64": STANDARD.encode(manifest().as_bytes()),
    });
    h.broker
        .api_post_json(&h.agent_key, "/v1/release/manifest", &body)
        .await
}

async fn publish(h: &Harness) -> TestResponse {
    h.broker
        .api_post_json(&h.agent_key, "/v1/release/publish", &target())
        .await
}

/// The calls that change the repository, as `METHOD path`: token mints are not.
fn github_writes(h: &Harness) -> Vec<String> {
    h.upstream
        .github_release()
        .record()
        .iter()
        .filter(|call| call.method != "GET" && !call.path_and_query.starts_with("/app/"))
        .map(|call| format!("{} {}", call.method, call.path_and_query))
        .collect()
}

/// The audit entries, oldest first.
fn events(h: &Harness) -> Vec<Value> {
    std::fs::read_to_string(h.broker.audit_path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["event"].clone())
        .collect()
}

/// Make every append to the audit log fail until the returned bytes are put back.
fn break_audit_log(h: &Harness) -> Vec<u8> {
    let good = std::fs::read(h.broker.audit_path()).unwrap();
    let mut corrupt = good.clone();
    corrupt.extend_from_slice(b"not an audit line\n");
    std::fs::write(h.broker.audit_path(), &corrupt).unwrap();
    good
}

fn repair_audit_log(h: &Harness, good: &[u8]) {
    std::fs::write(h.broker.audit_path(), good).unwrap();
}

/// The `release_step_started` entry of `step`, followed later by an entry of type
/// `done`.
fn started_before(h: &Harness, step: &str, done: &str) -> Value {
    let events = events(h);
    let started = events
        .iter()
        .position(|e| e["type"] == "release_step_started" && e["step"] == step)
        .unwrap_or_else(|| panic!("no start entry for {step}: {events:?}"));
    let finished = events.iter().position(|e| e["type"] == done).unwrap();
    assert!(started < finished, "{events:?}");
    events[started].clone()
}

#[tokio::test]
async fn every_step_records_its_start_with_what_was_signed() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let tagged = tag(&h).await;
    assert_eq!(tagged.status, StatusCode::OK, "{}", tagged.body);
    let _draft = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    let signed = sign_manifest(&h).await;
    assert_eq!(signed.status, StatusCode::OK, "{}", signed.body);
    let published = publish(&h).await;
    assert_eq!(published.status, StatusCode::OK, "{}", published.body);

    let start = started_before(&h, "tag", "release_tag_created");
    assert_eq!(start["grant_id"], release.grant_id().as_str());
    assert_eq!(start["repository"], REPO);
    assert_eq!(start["tag"], TAG);
    assert_eq!(start["signed"], tagged.json()["object"]);
    let start = started_before(&h, "manifest", "release_manifest_signed");
    assert_eq!(
        start["signed"],
        hex::encode(Sha256::digest(manifest().as_bytes()))
    );
    let start = started_before(&h, "publish", "release_published");
    assert!(start.get("signed").is_none(), "{start}");
    audit::verify(h.broker.audit_path()).unwrap();
}

#[tokio::test]
async fn the_tag_is_not_created_when_its_start_cannot_be_recorded() {
    let h = harness(Shape::Everything).await;
    let _release = approved(&h).await;
    let good = break_audit_log(&h);
    let response = tag(&h).await;
    repair_audit_log(&h, &good);
    assert_eq!(
        response.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        response.body
    );
    assert_eq!(github_writes(&h), [] as [String; 0]);
    assert!(
        h.upstream
            .github_release()
            .ref_target(&repo(REPO), TAG)
            .is_none()
    );
    // The step was claimed before, and stays used.
    let again = tag(&h).await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{}", again.body);
    assert_eq!(github_writes(&h), [] as [String; 0]);
}

#[tokio::test]
async fn the_manifest_is_not_attached_when_its_start_cannot_be_recorded() {
    let h = harness(Shape::Everything).await;
    let _release = approved(&h).await;
    let _draft = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    let good = break_audit_log(&h);
    let response = sign_manifest(&h).await;
    repair_audit_log(&h, &good);
    assert_eq!(
        response.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        response.body
    );
    assert_eq!(github_writes(&h), [] as [String; 0]);
}

#[tokio::test]
async fn the_draft_is_not_published_when_its_start_cannot_be_recorded() {
    let h = harness(Shape::PublishOnly).await;
    h.annotate(
        TAG,
        &signed_tag_object(&h.key, "git", TAG, HEAD, 1_794_000_000),
    );
    let _release = approved(&h).await;
    let _draft = h
        .upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true);
    let good = break_audit_log(&h);
    let response = publish(&h).await;
    repair_audit_log(&h, &good);
    assert_eq!(
        response.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        response.body
    );
    assert_eq!(github_writes(&h), [] as [String; 0]);
}

/// A revocation while the start entry is being written stops the step: the tag
/// signed for it never reaches GitHub.
#[tokio::test]
async fn revoked_while_the_start_is_recorded_changes_nothing() {
    let h = harness(Shape::Everything).await;
    let release = approved(&h).await;
    let stall = h
        .broker
        .state()
        .audit
        .stall_appends(|event| matches!(event, AuditEvent::ReleaseStepStarted { .. }));
    let call = tag(&h);
    let revoke = async {
        stall.until_holding(1).await;
        h.broker
            .state()
            .requests
            .revoke_grant(release.grant_id(), "owner")
            .await
            .unwrap();
        drop(stall);
    };
    let (response, ()) = tokio::join!(call, revoke);
    assert_eq!(response.status, StatusCode::FORBIDDEN, "{}", response.body);
    assert_eq!(github_writes(&h), [] as [String; 0]);
}
