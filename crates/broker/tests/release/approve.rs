//! Approving a release request: what is checked again, and what is stored.

use axum::http::StatusCode;
use sqlx::Row as _;
use warden_broker::policy::{ReleaseAppKey, ReleaseSigningKey};
use warden_broker::testkit::github_app::RSA2048_PKCS8;
use warden_broker::testkit::github_release::signed_tag_object;
use warden_broker::testkit::upstream::Scripted;
use warden_broker_proto::release::{ReleaseSteps, ReleaseTag};
use warden_broker_proto::{GrantAccess, GrantView, Window};

use super::{HEAD, Harness, MANIFEST, REPO, Shape, harness, repo};

const TAG: &str = "v1.2.3";
const DESTINATION_CHANGED: &str = "policy changed; reload and review";

fn release() -> warden_broker_proto::CreateRequest {
    warden_broker_proto::CreateRequest {
        goal: "Release 1.2.3".to_owned().try_into().unwrap(),
        access: warden_broker_proto::Access::Release {
            repository: repo(REPO),
            tag: ReleaseTag::try_from(TAG.to_owned()).unwrap(),
            commit: HEAD.to_owned().try_into().unwrap(),
        },
        window: Window::D1,
        session: None,
        link: None,
    }
}

async fn count(h: &Harness, table: &str) -> i64 {
    let sql = match table {
        "grants" => "SELECT COUNT(*) AS n FROM grants",
        "release_steps" => "SELECT COUNT(*) AS n FROM release_steps",
        other => panic!("no count for {other}"),
    };
    sqlx::query(sql)
        .fetch_one(&h.broker.state().pool)
        .await
        .unwrap()
        .get("n")
}

async fn grant_view(h: &Harness) -> GrantView {
    let view: String = sqlx::query("SELECT view FROM grants")
        .fetch_one(&h.broker.state().pool)
        .await
        .unwrap()
        .get("view");
    serde_json::from_str(&view).unwrap()
}

#[tokio::test]
async fn approve_creates_grant_and_steps_row() {
    let h = harness(Shape::Everything).await;
    let (_, token) = h.broker.create_request("build-agent", release()).await;
    let page = h.broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    let done = h.broker.approve(&token, Window::D1).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    assert!(done.body.contains("Approved for 1d"), "{}", done.body);

    let grant = grant_view(&h).await;
    assert_eq!(grant.not_after - grant.not_before, 86_400);
    let GrantAccess::Release(release) = grant.access else {
        panic!("expected a release grant");
    };
    assert_eq!(release.repository.as_str(), REPO);
    assert_eq!(release.tag.as_str(), TAG);
    assert_eq!(release.commit.as_str(), HEAD);
    assert_eq!(
        release.key_fingerprint,
        h.key
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string()
    );
    assert_eq!(
        release.steps,
        ReleaseSteps {
            tag: true,
            manifest: Some("warden-1.2.3-SHA256SUMS".to_owned()),
            publish: true,
        }
    );
    assert_eq!(release.digest.len(), 64);

    let row = sqlx::query("SELECT * FROM release_steps")
        .fetch_one(&h.broker.state().pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("grant_id"), grant_id(&h).await);
    for column in [
        "tag_claimed_at",
        "manifest_claimed_at",
        "publish_claimed_at",
    ] {
        assert_eq!(row.get::<Option<i64>, _>(column), None, "{column}");
    }
    assert_eq!(count(&h, "release_steps").await, 1);
}

async fn grant_id(h: &Harness) -> String {
    sqlx::query("SELECT id FROM grants")
        .fetch_one(&h.broker.state().pool)
        .await
        .unwrap()
        .get("id")
}

#[tokio::test]
async fn approve_drops_the_tag_step_when_the_tag_is_in_place() {
    let h = harness(Shape::Everything).await;
    h.annotate(
        TAG,
        &signed_tag_object(&h.key, "git", TAG, HEAD, 1_794_000_000),
    );
    let (_, token) = h.broker.create_request("build-agent", release()).await;
    let done = h.broker.approve(&token, Window::D1).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    let GrantAccess::Release(release) = grant_view(&h).await.access else {
        panic!("expected a release grant");
    };
    assert!(!release.steps.tag);
    assert!(release.steps.publish);
}

#[tokio::test]
async fn approve_refuses_when_key_changed() {
    let h = harness(Shape::Everything).await;
    let (_, token) = h.broker.create_request("build-agent", release()).await;
    let mut auth = h.broker.enroll_soft_passkey().await;
    let begin = h.broker.begin_approval(&token, Window::D1).await;
    let (ceremony, credential) = warden_broker::testkit::TestBroker::sign(&mut auth, &begin);

    // The owner rotates the repository's key while the passkey prompt is open.
    let other =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap();
    h.broker
        .backend
        .replace_release_keys(ReleaseSigningKey::for_tests(
            REPO,
            other,
            Some(MANIFEST),
            true,
        ));
    let done = h
        .broker
        .finish_approval(&token, &ceremony, &credential)
        .await;
    assert_eq!(done.status, StatusCode::CONFLICT, "{}", done.body);
    assert!(done.body.contains(DESTINATION_CHANGED), "{}", done.body);
    assert_eq!(count(&h, "grants").await, 0);
    assert_eq!(count(&h, "release_steps").await, 0);

    // The page shown before the change no longer begins an approval either.
    let stale = h
        .broker
        .begin_approval_for(&token, Window::D1, &"0".repeat(64))
        .await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{}", stale.body);
}

#[tokio::test]
async fn approve_refuses_when_the_app_changed() {
    let h = harness(Shape::Everything).await;
    let (_, token) = h.broker.create_request("build-agent", release()).await;
    let mut auth = h.broker.enroll_soft_passkey().await;
    let begin = h.broker.begin_approval(&token, Window::D1).await;
    let (ceremony, credential) = warden_broker::testkit::TestBroker::sign(&mut auth, &begin);
    h.broker.backend.set_release_app(Some(
        ReleaseAppKey::new(
            "111111".to_owned(),
            std::str::from_utf8(RSA2048_PKCS8).unwrap(),
        )
        .unwrap(),
    ));
    let done = h
        .broker
        .finish_approval(&token, &ceremony, &credential)
        .await;
    assert_eq!(done.status, StatusCode::CONFLICT, "{}", done.body);
    assert!(done.body.contains(DESTINATION_CHANGED), "{}", done.body);
    assert_eq!(count(&h, "grants").await, 0);
}

#[tokio::test]
async fn approve_refuses_when_tag_appeared() {
    let h = harness(Shape::Everything).await;
    let (_, token) = h.broker.create_request("build-agent", release()).await;
    let mut auth = h.broker.enroll_soft_passkey().await;
    let begin = h.broker.begin_approval(&token, Window::D1).await;
    let (ceremony, credential) = warden_broker::testkit::TestBroker::sign(&mut auth, &begin);

    // Someone tags the commit while the passkey prompt is open: the grant would
    // describe steps that are no longer the ones left.
    h.annotate(
        TAG,
        &signed_tag_object(&h.key, "git", TAG, HEAD, 1_794_000_000),
    );
    let done = h
        .broker
        .finish_approval(&token, &ceremony, &credential)
        .await;
    assert_eq!(done.status, StatusCode::CONFLICT, "{}", done.body);
    assert!(
        done.body.contains("the release changed on GitHub"),
        "{}",
        done.body
    );
    assert_eq!(count(&h, "grants").await, 0);
    assert_eq!(count(&h, "release_steps").await, 0);
    // Still pending: the owner can read the new page and decide again.
    let page = h.broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
}

#[tokio::test]
async fn approve_refuses_when_github_cannot_be_asked() {
    let h = harness(Shape::Everything).await;
    let (_, token) = h.broker.create_request("build-agent", release()).await;
    let mut auth = h.broker.enroll_soft_passkey().await;
    let begin = h.broker.begin_approval(&token, Window::D1).await;
    let (ceremony, credential) = warden_broker::testkit::TestBroker::sign(&mut auth, &begin);
    h.upstream
        .github_release()
        .answer_everything_with(Scripted::with_body(
            500,
            r#"{"message":"marker-github-said-this"}"#,
        ));
    let done = h
        .broker
        .finish_approval(&token, &ceremony, &credential)
        .await;
    assert_eq!(done.status, StatusCode::CONFLICT, "{}", done.body);
    assert!(
        done.body.contains("GitHub could not be asked"),
        "{}",
        done.body
    );
    assert!(!done.body.contains("marker"), "{}", done.body);
    assert_eq!(count(&h, "grants").await, 0);
}
