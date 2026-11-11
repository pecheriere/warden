//! Claiming the steps of a release grant, and ending the grant when the last one is
//! done. Steps are not reachable over HTTP yet, so these call the store directly.

use sqlx::Row as _;
use warden_broker::requests::ReleaseStep;
use warden_broker_proto::release::{ReleaseTag, RepoName};
use warden_broker_proto::{AgentName, Id, Window};

use super::{HEAD, Harness, NOW, REPO, Shape, harness, repo};

const TAG: &str = "v1.2.3";

fn agent() -> AgentName {
    "build-agent".parse().unwrap()
}

fn tag() -> ReleaseTag {
    ReleaseTag::try_from(TAG.to_owned()).unwrap()
}

/// Request and approve a release of [`TAG`] in [`REPO`]; the id of its grant.
async fn approved(h: &Harness) -> Id {
    let request = warden_broker_proto::CreateRequest {
        goal: "Release 1.2.3".to_owned().try_into().unwrap(),
        access: warden_broker_proto::Access::Release {
            repository: repo(REPO),
            tag: tag(),
            commit: HEAD.to_owned().try_into().unwrap(),
        },
        window: Window::D1,
        session: None,
        link: None,
    };
    let (_, token) = h.broker.create_request("build-agent", request).await;
    let done = h.broker.approve(&token, Window::D1).await;
    assert_eq!(done.status, axum::http::StatusCode::OK, "{}", done.body);
    h.broker
        .state()
        .requests
        .active_release(&agent(), &repo(REPO), &tag())
        .await
        .unwrap()
        .expect("the grant is active")
        .grant_id
}

async fn not_after(h: &Harness, grant: &Id) -> i64 {
    sqlx::query("SELECT not_after FROM grants WHERE id = ?")
        .bind(grant.as_str())
        .fetch_one(&h.broker.state().pool)
        .await
        .unwrap()
        .get("not_after")
}

#[tokio::test]
async fn claim_step_once() {
    let h = harness(Shape::Everything).await;
    let grant = approved(&h).await;
    let requests = &h.broker.state().requests;
    let (first, second) = tokio::join!(
        requests.claim_step(&grant, ReleaseStep::Tag, NOW),
        requests.claim_step(&grant, ReleaseStep::Tag, NOW),
    );
    let (first, second) = (first.unwrap(), second.unwrap());
    assert!(first ^ second, "exactly one claims: {first} {second}");
    assert!(
        !requests
            .claim_step(&grant, ReleaseStep::Tag, NOW)
            .await
            .unwrap(),
        "a retry after the claim is refused, whatever became of the step"
    );
    assert!(
        requests
            .claim_step(&grant, ReleaseStep::Publish, NOW)
            .await
            .unwrap(),
        "another step is claimed on its own"
    );
}

#[tokio::test]
async fn claim_step_survives_restart() {
    let h = harness(Shape::Everything).await;
    let grant = approved(&h).await;
    assert!(
        h.broker
            .state()
            .requests
            .claim_step(&grant, ReleaseStep::Manifest, NOW)
            .await
            .unwrap()
    );
    let Harness {
        broker,
        upstream,
        key,
    } = h;
    let broker = broker.restart().await;
    let h = Harness {
        broker,
        upstream,
        key,
    };
    assert!(
        !h.broker
            .state()
            .requests
            .claim_step(&grant, ReleaseStep::Manifest, NOW)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn claim_step_refuses_an_unknown_grant() {
    let h = harness(Shape::Everything).await;
    let unknown = Id::random();
    assert!(
        !h.broker
            .state()
            .requests
            .claim_step(&unknown, ReleaseStep::Tag, NOW)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn record_manifest_keeps_the_digests_once() {
    let h = harness(Shape::Everything).await;
    let grant = approved(&h).await;
    let requests = &h.broker.state().requests;
    let (manifest, signature) = ("a".repeat(64), "b".repeat(64));
    requests
        .record_manifest(&grant, &manifest, &signature)
        .await
        .expect_err("a manifest that was not claimed has no digests to keep");
    assert!(
        requests
            .claim_step(&grant, ReleaseStep::Manifest, NOW)
            .await
            .unwrap()
    );
    requests
        .record_manifest(&grant, &manifest, &signature)
        .await
        .unwrap();
    requests
        .record_manifest(&grant, &"c".repeat(64), &signature)
        .await
        .expect_err("the digests are kept once");
    let row = sqlx::query("SELECT manifest_sha256, signature_sha256 FROM release_steps")
        .fetch_one(&h.broker.state().pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("manifest_sha256"), manifest);
    assert_eq!(row.get::<String, _>("signature_sha256"), signature);
}

#[tokio::test]
async fn end_if_done_ends_grant_after_last_step() {
    let h = harness(Shape::Everything).await;
    let grant = approved(&h).await;
    let requests = &h.broker.state().requests;
    let window_end = not_after(&h, &grant).await;
    for step in [
        ReleaseStep::Tag,
        ReleaseStep::Manifest,
        ReleaseStep::Publish,
    ] {
        assert_eq!(not_after(&h, &grant).await, window_end);
        assert!(requests.claim_step(&grant, step, NOW).await.unwrap());
        requests.end_if_done(&grant, NOW + 5).await.unwrap();
    }
    assert_eq!(not_after(&h, &grant).await, NOW + 5);
    h.broker.clock.set(NOW + 5);
    assert!(
        requests
            .active_release(&agent(), &repo(REPO), &tag())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn end_if_done_counts_only_the_approved_steps() {
    let h = harness(Shape::TagOnly).await;
    let grant = approved(&h).await;
    let requests = &h.broker.state().requests;
    requests.end_if_done(&grant, NOW + 1).await.unwrap();
    assert!(not_after(&h, &grant).await > NOW + 1, "nothing is done yet");
    assert!(
        requests
            .claim_step(&grant, ReleaseStep::Tag, NOW)
            .await
            .unwrap()
    );
    requests.end_if_done(&grant, NOW + 2).await.unwrap();
    assert_eq!(not_after(&h, &grant).await, NOW + 2);
}

#[tokio::test]
async fn end_if_done_waits_for_all_steps() {
    let h = harness(Shape::Everything).await;
    let grant = approved(&h).await;
    let requests = &h.broker.state().requests;
    let window_end = not_after(&h, &grant).await;
    for step in [ReleaseStep::Tag, ReleaseStep::Publish] {
        assert!(requests.claim_step(&grant, step, NOW).await.unwrap());
    }
    requests.end_if_done(&grant, NOW + 1).await.unwrap();
    assert_eq!(
        not_after(&h, &grant).await,
        window_end,
        "the manifest is still to do"
    );
    assert!(
        requests
            .active_release(&agent(), &repo(REPO), &tag())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn active_release_matches_case_insensitively() {
    let h = harness(Shape::Everything).await;
    let grant = approved(&h).await;
    let requests = &h.broker.state().requests;
    let upper: RepoName = REPO.to_uppercase().try_into().unwrap();
    let active = requests
        .active_release(&agent(), &upper, &tag())
        .await
        .unwrap()
        .expect("the same repository in other case");
    assert_eq!(active.grant_id, grant);
    assert_eq!(active.grant.repository.as_str(), REPO);

    let other_tag = ReleaseTag::try_from("v1.2.4".to_owned()).unwrap();
    assert!(
        requests
            .active_release(&agent(), &repo(REPO), &other_tag)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        requests
            .active_release(&"other".parse().unwrap(), &repo(REPO), &tag())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn active_release_refuses_two_active_grants() {
    let h = harness(Shape::Everything).await;
    let grant = approved(&h).await;
    // A second row for the same release; only the foreign key stands in the way of
    // writing it, and no code path makes one, so it is written around the checks.
    let mut conn = h.broker.state().pool.acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO grants (id, request_id, agent, window_secs, not_before, not_after, view) \
         SELECT 'duplicate', 'duplicate-request', agent, window_secs, not_before, not_after, view \
         FROM grants WHERE id = ?",
    )
    .bind(grant.as_str())
    .execute(&mut *conn)
    .await
    .unwrap();
    drop(conn);
    h.broker
        .state()
        .requests
        .active_release(&agent(), &repo(REPO), &tag())
        .await
        .expect_err("two active grants for one release is a storage error");
}
