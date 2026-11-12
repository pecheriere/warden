//! Approving a GitHub token grant ends only the agent's grants that share a
//! repository with it, and two approvals at once leave one.

use axum::http::StatusCode;
use serde_json::Value;
use warden_broker::testkit::TestBroker;
use warden_broker_proto::Window;

use super::{approve_repositories, configured_on_fake, entries, resolved};

const A: (u64, &str) = (1001, "example-owner/example-repo");
const B: (u64, &str) = (1002, "example-owner/homebrew-tap");

/// How many active grants of any agent cover repository `id`.
async fn active_covering(broker: &TestBroker, id: u64) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM grants g, json_each(g.view, '$.access.repositories') j \
         WHERE g.revoked_at IS NULL AND json_extract(j.value, '$.id') = ?",
    )
    .bind(i64::try_from(id).unwrap())
    .fetch_one(&broker.state().pool)
    .await
    .unwrap()
}

async fn revoked(broker: &TestBroker, grant: &str) -> bool {
    sqlx::query_scalar::<_, Option<i64>>("SELECT revoked_at FROM grants WHERE id = ?")
        .bind(grant)
        .fetch_one(&broker.state().pool)
        .await
        .unwrap()
        .is_some()
}

#[tokio::test]
async fn grants_for_other_repositories_stay() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let first = approve_repositories(&broker, &upstream, "bot", Window::D7, &[A]).await;
    let second = approve_repositories(&broker, &upstream, "bot", Window::D7, &[B]).await;
    assert!(!revoked(&broker, &first).await);
    assert!(!revoked(&broker, &second).await);
    assert_eq!(active_covering(&broker, 1001).await, 1);
    assert_eq!(active_covering(&broker, 1002).await, 1);
    assert_eq!(entries(&broker, "grant_revoked"), [] as [Value; 0]);
}

#[tokio::test]
async fn overlapping_grant_is_replaced() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let first = approve_repositories(&broker, &upstream, "bot", Window::D7, &[A, B]).await;
    let second = approve_repositories(&broker, &upstream, "bot", Window::D7, &[B]).await;
    assert!(revoked(&broker, &first).await);
    assert!(!revoked(&broker, &second).await);

    let ended = entries(&broker, "grant_revoked");
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert_eq!(ended[0]["grant_id"], first.as_str());
    assert_eq!(ended[0]["by"], "replaced");
    let replaced = entries(&broker, "github_token_grant_replaced");
    assert_eq!(replaced.len(), 1, "{replaced:?}");
    assert_eq!(replaced[0]["grant_id"], first.as_str());
    assert_eq!(replaced[0]["by_grant"], second.as_str());
    assert_eq!(replaced[0]["repository_ids"], serde_json::json!([1002]));
    // The request behind the ended grant says so too.
    let status: String = sqlx::query_scalar(
        "SELECT r.status FROM requests r JOIN grants g ON g.request_id = r.id WHERE g.id = ?",
    )
    .bind(&first)
    .fetch_one(&broker.state().pool)
    .await
    .unwrap();
    assert_eq!(status, "revoked");
}

#[tokio::test]
async fn legacy_grant_is_replaced_by_any() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let legacy = broker.insert_legacy_github_grant("bot").await.to_string();
    let grant = approve_repositories(&broker, &upstream, "bot", Window::D7, &[A]).await;
    assert!(revoked(&broker, &legacy).await);
    assert!(!revoked(&broker, &grant).await);
    let replaced = entries(&broker, "github_token_grant_replaced");
    assert_eq!(replaced.len(), 1, "{replaced:?}");
    assert_eq!(replaced[0]["grant_id"], legacy.as_str());
    assert_eq!(replaced[0]["repository_ids"], serde_json::json!([]));
}

#[tokio::test]
async fn another_agents_grants_stay() {
    let (broker, _key, upstream) = configured_on_fake().await;
    broker.add_agent("other").await;
    let theirs = approve_repositories(&broker, &upstream, "other", Window::D7, &[A]).await;
    approve_repositories(&broker, &upstream, "bot", Window::D7, &[A]).await;
    assert!(!revoked(&broker, &theirs).await);
}

/// Two requests for overlapping repositories, both pages rendered and both
/// approvals begun before either finishes, then both finished at once. Whatever
/// order they run in, the later one is refused (the owner did not see the first)
/// or replaces the first: never both active.
#[tokio::test]
async fn concurrent_overlapping_approvals_leave_one() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let (_, first) = broker
        .create_request(
            "bot",
            TestBroker::github_token_request("one", Window::D7, &[A.1]),
        )
        .await;
    let (_, second) = broker
        .create_request(
            "bot",
            TestBroker::github_token_request("two", Window::D7, &[A.1, B.1]),
        )
        .await;
    upstream.script_github_token(resolved(&broker, &[A]));
    assert_eq!(
        broker.get(&format!("/approve/{first}")).await.status,
        StatusCode::OK
    );
    upstream.script_github_token(resolved(&broker, &[A, B]));
    assert_eq!(
        broker.get(&format!("/approve/{second}")).await.status,
        StatusCode::OK
    );

    // One passkey each: a passkey's signature counter must rise in the order its
    // assertions finish, which two approvals running at once do not fix.
    let mut auth_first = broker.enroll_soft_passkey().await;
    let mut auth_second = broker.enroll_soft_passkey().await;
    let begin_first = broker.begin_approval(&first, Window::D7).await;
    let (ceremony_first, credential_first) = TestBroker::sign(&mut auth_first, &begin_first);
    let begin_second = broker.begin_approval(&second, Window::D7).await;
    let (ceremony_second, credential_second) = TestBroker::sign(&mut auth_second, &begin_second);

    let (one, two) = tokio::join!(
        broker.finish_approval(&first, &ceremony_first, &credential_first),
        broker.finish_approval(&second, &ceremony_second, &credential_second),
    );
    let statuses = [one.status, two.status];
    assert!(statuses.contains(&StatusCode::OK), "{one:?} {two:?}");
    for status in statuses {
        assert!(
            status == StatusCode::OK || status == StatusCode::CONFLICT,
            "{one:?} {two:?}"
        );
    }
    assert_eq!(active_covering(&broker, 1001).await, 1);
}
