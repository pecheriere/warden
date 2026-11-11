//! Creating a release request: what is checked against GitHub, and what is stored.

use sqlx::Row as _;
use warden_broker::requests::{Destination, ReleaseFacts, RequestError};
use warden_broker::testkit::github_release::{signed_tag_object, unsigned_tag_object};
use warden_broker::testkit::upstream::Scripted;
use warden_broker_proto::release::{NOT_CONFIGURED, ReleaseSteps, ReleaseTag};
use warden_broker_proto::{AgentName, CreateRequest, Window};

use super::{HEAD, PARENT, REPO, SIDE, Shape, harness, repo};

const OTHER_KEY_OR_COMMIT: &str = "the tag exists on another commit or under another key";
const TAG: &str = "v1.2.3";

fn agent() -> AgentName {
    AgentName::try_from("build-agent".to_owned()).unwrap()
}

fn request(repository: &str, tag: &str, commit: &str, window: Window) -> CreateRequest {
    warden_broker::testkit::TestBroker::release_request(
        "release the new version",
        repository,
        tag,
        commit,
        window,
    )
}

fn release(commit: &str) -> CreateRequest {
    request(REPO, TAG, commit, Window::D1)
}

fn rejected(result: Result<warden_broker_proto::CreatedResponse, RequestError>) -> String {
    match result {
        Err(RequestError::Rejected(message)) => message,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

async fn count(h: &super::Harness, table: &str) -> i64 {
    let sql = match table {
        "requests" => "SELECT COUNT(*) AS n FROM requests",
        "release_facts" => "SELECT COUNT(*) AS n FROM release_facts",
        "grants" => "SELECT COUNT(*) AS n FROM grants",
        other => panic!("no count for {other}"),
    };
    sqlx::query(sql)
        .fetch_one(&h.broker.state().pool)
        .await
        .unwrap()
        .get("n")
}

#[tokio::test]
async fn creates_a_pending_release_request() {
    let h = super::harness(Shape::Everything).await;
    let github = h.upstream.github_release();
    let repository = repo(REPO);
    github.add_file(
        &repository,
        HEAD,
        "CHANGELOG.md",
        b"# Changelog\n\n## [Unreleased]\n\n## [1.2.3] - 2026-11-07\n\n- Added a thing.\n\n## [1.2.2]\n\n- Older.\n",
    );
    github.add_lightweight_tag(&repository, "v1.2.2", PARENT);
    github.add_lightweight_tag(&repository, "v1.0.0", PARENT);
    github.add_lightweight_tag(&repository, "v1.3.0", PARENT);
    github.add_lightweight_tag(&repository, "not-a-release", PARENT);

    let (created, token) = h.broker.create_request("build-agent", release(HEAD)).await;
    assert_eq!(created.created, Some(true));

    let view = h
        .broker
        .state()
        .requests
        .pending_for_token(&token)
        .await
        .unwrap();
    let Destination::Release(policy) = &view.destination else {
        panic!("expected a release destination, got {:?}", view.destination);
    };
    assert_eq!(policy.repository.as_str(), REPO);
    assert_eq!(
        policy.key_fingerprint,
        h.key
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string()
    );
    assert_eq!(
        policy.steps(false),
        ReleaseSteps {
            tag: true,
            manifest: Some("warden-1.2.3-SHA256SUMS".to_owned()),
            publish: true,
        }
    );
    assert!(!policy.steps(true).tag);
    assert_eq!(view.destination.digest(), policy.digest());

    let stored: String = sqlx::query("SELECT facts FROM release_facts WHERE request_id = ?")
        .bind(created.id.as_str())
        .fetch_one(&h.broker.state().pool)
        .await
        .unwrap()
        .get("facts");
    let facts: ReleaseFacts = serde_json::from_str(&stored).unwrap();
    assert_eq!(facts.commit_title, "Add the release workflow");
    assert_eq!(facts.commit_date, "2026-11-07T10:30:00Z");
    assert!(facts.on_default_branch);
    assert!(!facts.tag_in_place);
    assert_eq!(
        facts.changelog.as_deref().map(str::trim),
        Some("- Added a thing.")
    );
    assert_eq!(
        facts.previous_tag,
        Some(ReleaseTag::try_from("v1.2.2".to_owned()).unwrap())
    );

    let (key, subject): (String, String) = {
        let row = sqlx::query("SELECT dedupe_key, body FROM requests WHERE id = ?")
            .bind(created.id.as_str())
            .fetch_one(&h.broker.state().pool)
            .await
            .unwrap();
        (row.get("dedupe_key"), row.get("body"))
    };
    assert_eq!(key, format!("build-agent|release|{REPO}|{TAG}"));
    assert!(subject.contains(r#""kind":"release""#));
    let summaries = h.broker.audit_summaries();
    assert!(
        summaries
            .iter()
            .any(|s| s.starts_with(&format!("release {REPO} {TAG} for 1d: "))),
        "{summaries:?}"
    );
}

#[tokio::test]
async fn refuses_unconfigured_repository() {
    let h = harness(Shape::Everything).await;
    let other = request("example-owner/other-repo", TAG, HEAD, Window::D1);
    let message = rejected(h.broker.state().requests.create(&agent(), other).await);
    assert_eq!(message, NOT_CONFIGURED);
    assert_eq!(count(&h, "requests").await, 0);

    h.broker.backend.set_release_app(None);
    let message = rejected(
        h.broker
            .state()
            .requests
            .create(&agent(), release(HEAD))
            .await,
    );
    assert_eq!(message, NOT_CONFIGURED);
    assert_eq!(count(&h, "requests").await, 0);
}

#[tokio::test]
async fn refuses_commit_off_default_branch() {
    let h = harness(Shape::Everything).await;
    let message = rejected(
        h.broker
            .state()
            .requests
            .create(&agent(), release(SIDE))
            .await,
    );
    assert_eq!(
        message,
        "the commit is not on the repository's default branch"
    );
    assert_eq!(count(&h, "requests").await, 0);
    assert_eq!(count(&h, "release_facts").await, 0);
}

#[tokio::test]
async fn refuses_tag_on_other_commit() {
    let h = harness(Shape::Everything).await;
    let raw = signed_tag_object(&h.key, "git", TAG, PARENT, 1_794_000_000);
    h.annotate(TAG, &raw);
    let message = rejected(
        h.broker
            .state()
            .requests
            .create(&agent(), release(HEAD))
            .await,
    );
    assert_eq!(message, OTHER_KEY_OR_COMMIT);
    assert_eq!(count(&h, "requests").await, 0);
}

#[tokio::test]
async fn refuses_tag_signed_by_other_key() {
    let h = harness(Shape::Everything).await;
    let other =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
    for (key, namespace) in [(&other, "git"), (&h.key, "file")] {
        let tag = if namespace == "git" {
            "v1.2.3"
        } else {
            "v1.2.4"
        };
        let raw = signed_tag_object(key, namespace, tag, HEAD, 1_794_000_000);
        h.annotate(tag, &raw);
        let message = rejected(
            h.broker
                .state()
                .requests
                .create(&agent(), request(REPO, tag, HEAD, Window::D1))
                .await,
        );
        assert_eq!(message, OTHER_KEY_OR_COMMIT, "{namespace}");
    }
    let raw = unsigned_tag_object("v1.2.5", HEAD, 1_794_000_000);
    h.annotate("v1.2.5", &raw);
    let message = rejected(
        h.broker
            .state()
            .requests
            .create(&agent(), request(REPO, "v1.2.5", HEAD, Window::D1))
            .await,
    );
    assert_eq!(message, OTHER_KEY_OR_COMMIT);
    assert_eq!(count(&h, "requests").await, 0);
}

#[tokio::test]
async fn refuses_lightweight_tag() {
    let h = harness(Shape::Everything).await;
    h.upstream
        .github_release()
        .add_lightweight_tag(&repo(REPO), TAG, HEAD);
    let message = rejected(
        h.broker
            .state()
            .requests
            .create(&agent(), release(HEAD))
            .await,
    );
    assert_eq!(message, OTHER_KEY_OR_COMMIT);
    assert_eq!(count(&h, "requests").await, 0);
}

#[tokio::test]
async fn accepts_tag_in_place_and_drops_tag_step() {
    let h = harness(Shape::Everything).await;
    let raw = signed_tag_object(&h.key, "git", TAG, HEAD, 1_794_000_000);
    h.annotate(TAG, &raw);
    let (created, token) = h.broker.create_request("build-agent", release(HEAD)).await;
    let view = h
        .broker
        .state()
        .requests
        .pending_for_token(&token)
        .await
        .unwrap();
    let Destination::Release(policy) = &view.destination else {
        panic!("expected a release destination");
    };
    assert!(policy.steps(true).manifest.is_some());
    let stored: String = sqlx::query("SELECT facts FROM release_facts WHERE request_id = ?")
        .bind(created.id.as_str())
        .fetch_one(&h.broker.state().pool)
        .await
        .unwrap()
        .get("facts");
    let facts: ReleaseFacts = serde_json::from_str(&stored).unwrap();
    assert!(facts.tag_in_place);
}

#[tokio::test]
async fn refuses_when_nothing_left() {
    let h = harness(Shape::TagOnly).await;
    let raw = signed_tag_object(&h.key, "git", TAG, HEAD, 1_794_000_000);
    h.annotate(TAG, &raw);
    let message = rejected(
        h.broker
            .state()
            .requests
            .create(&agent(), release(HEAD))
            .await,
    );
    assert_eq!(
        message,
        "nothing left to do: the tag exists and this repository signs no manifest and publishes nothing"
    );
    assert_eq!(count(&h, "requests").await, 0);
}

#[tokio::test]
async fn refuses_when_github_unreachable() {
    let h = harness(Shape::Everything).await;
    for answer in [
        Scripted::with_body(500, r#"{"message":"marker-github-said-this"}"#),
        Scripted::with_body(200, "marker-github-said-this, not JSON"),
    ] {
        h.upstream.github_release().answer_everything_with(answer);
        let message = rejected(
            h.broker
                .state()
                .requests
                .create(&agent(), release(HEAD))
                .await,
        );
        assert_eq!(
            message,
            "GitHub could not be asked about this release; try again"
        );
        assert!(!message.contains("marker"));
    }
    assert_eq!(count(&h, "requests").await, 0);
    assert_eq!(count(&h, "release_facts").await, 0);
    h.upstream.github_release().answer_normally();
    h.broker.create_request("build-agent", release(HEAD)).await;
}

#[tokio::test]
async fn second_request_for_same_release_is_deduplicated() {
    let h = harness(Shape::Everything).await;
    let (first, _) = h.broker.create_request("build-agent", release(HEAD)).await;
    let second = h
        .broker
        .state()
        .requests
        .create(&agent(), release(HEAD))
        .await
        .unwrap();
    assert_eq!(second.id, first.id);
    assert_eq!(second.created, Some(false));
    assert_eq!(count(&h, "requests").await, 1);
    assert_eq!(count(&h, "release_facts").await, 1);
}

#[tokio::test]
async fn refuses_window_other_than_one_day() {
    let h = harness(Shape::Everything).await;
    for window in [Window::H4, Window::D7, Window::D30] {
        let message = rejected(
            h.broker
                .state()
                .requests
                .create(&agent(), request(REPO, TAG, HEAD, window))
                .await,
        );
        assert_eq!(message, "a release grant lasts 1d");
    }
    assert_eq!(count(&h, "requests").await, 0);
}

/// The approval side is not built yet: a release request must not be approvable.
#[tokio::test]
async fn approving_a_release_request_still_refuses() {
    let h = harness(Shape::Everything).await;
    let (_, token) = h.broker.create_request("build-agent", release(HEAD)).await;
    h.broker.enroll_soft_passkey().await;
    let begun = h.broker.begin_approval(&token, Window::D1).await;
    assert_ne!(begun.status, axum::http::StatusCode::OK, "{}", begun.body);
    assert_eq!(count(&h, "grants").await, 0);
}
