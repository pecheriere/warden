//! The publish step compares the release as published with what it checked, as
//! GitHub has no conditional publish.

use axum::http::StatusCode;
use warden_broker::testkit::TestResponse;
use warden_broker::testkit::github_release::signed_tag_object;

use super::{HEAD, Harness, PARENT, REPO, Shape, TAG, approved, harness, repo};

async fn publish(h: &Harness) -> TestResponse {
    h.broker
        .api_post_json(
            &h.agent_key,
            "/v1/release/publish",
            &serde_json::json!({"repository": REPO, "tag": TAG}),
        )
        .await
}

fn reasons(h: &Harness) -> Vec<String> {
    std::fs::read_to_string(h.broker.audit_path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["event"].clone())
        .filter(|e| e["type"] == "release_published_changed")
        .map(|e| e["reason"].as_str().unwrap().to_owned())
        .collect()
}

/// A publish-only release of a tag already in place, with its draft.
async fn ready(h: &Harness) -> u64 {
    h.annotate(
        TAG,
        &signed_tag_object(&h.key, "git", TAG, HEAD, 1_794_000_000),
    );
    let _release = approved(h).await;
    h.upstream
        .github_release()
        .add_release(&repo(REPO), TAG, true)
}

#[tokio::test]
async fn a_publish_as_checked_records_no_change() {
    let h = harness(Shape::PublishOnly).await;
    let _draft = ready(&h).await;
    let response = publish(&h).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert_eq!(reasons(&h), [] as [String; 0]);
}

#[tokio::test]
async fn a_tag_moved_before_the_publish_is_recorded_and_refused() {
    let h = harness(Shape::PublishOnly).await;
    let draft = ready(&h).await;
    h.upstream
        .github_release()
        .move_tag_before_publish(&repo(REPO), TAG, PARENT);
    let response = publish(&h).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_GATEWAY,
        "{}",
        response.body
    );
    // It is published all the same, and recorded as such.
    let fake = h.upstream.github_release();
    assert!(!fake.release(&repo(REPO), draft).unwrap().draft);
    assert!(
        h.broker
            .audit_types()
            .contains(&"release_published".to_owned())
    );
    assert_eq!(reasons(&h), ["its tag is not the one checked"]);
}

#[tokio::test]
async fn a_manifest_replaced_before_the_publish_is_recorded_and_refused() {
    use base64::Engine as _;
    let h = harness(Shape::Everything).await;
    let _draft = ready(&h).await;
    let content = format!("{}  warden-1.2.3.tar.gz\n", "0".repeat(64));
    let body = serde_json::json!({
        "repository": REPO,
        "tag": TAG,
        "name": "warden-1.2.3-SHA256SUMS",
        "content_b64": base64::engine::general_purpose::STANDARD.encode(content.as_bytes()),
    });
    let signed = h
        .broker
        .api_post_json(&h.agent_key, "/v1/release/manifest", &body)
        .await;
    assert_eq!(signed.status, StatusCode::OK, "{}", signed.body);
    h.upstream.github_release().replace_asset_before_publish(
        &repo(REPO),
        "warden-1.2.3-SHA256SUMS",
        b"something else\n",
    );
    let response = publish(&h).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_GATEWAY,
        "{}",
        response.body
    );
    assert_eq!(
        reasons(&h),
        ["its manifest or signature is not the one signed"]
    );
}
