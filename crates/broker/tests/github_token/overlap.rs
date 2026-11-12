//! Approving a GitHub token grant ends only the agent's grants that share a
//! repository with it, and two approvals at once leave one.

use axum::http::StatusCode;
use serde_json::Value;
use warden_broker::requests::Clock as _;
use warden_broker::testkit::TestBroker;
use warden_broker::testkit::github_app::minted_answer;
use warden_broker::testkit::upstream::HttpsUpstream;
use warden_broker_proto::Window;
use warden_broker_proto::github_token::AMBIGUOUS_GRANT;

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
/// approvals begun before either finishes, then both finished at once. Both pages
/// showed no grant being replaced, so whichever commits second would end a grant its
/// owner never saw: it is refused with 409 whichever order they run in, and stores
/// nothing, so one grant covers the repository.
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
    let mut statuses = [one.status, two.status];
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        [StatusCode::OK, StatusCode::CONFLICT],
        "{one:?} {two:?}"
    );
    let refused = if one.status == StatusCode::CONFLICT {
        &one
    } else {
        &two
    };
    assert!(
        refused.body.contains("policy changed; reload and review"),
        "{refused:?}"
    );
    assert_eq!(active_covering(&broker, 1001).await, 1);
}

/// The repository `A` was deleted and created again under its name, which gave it
/// id 1003.
const RECREATED: (u64, &str) = (1003, A.1);

async fn mint_a(broker: &TestBroker, key: &str) -> warden_broker::testkit::TestResponse {
    broker
        .api_post_json(
            key,
            "/v1/github-token",
            &serde_json::json!({"repository": A.1}),
        )
        .await
}

/// Calls that asked GitHub for a token to mint.
fn mint_calls(upstream: &HttpsUpstream) -> usize {
    upstream
        .received()
        .iter()
        .filter(|call| {
            let body: Value = serde_json::from_slice(&call.body).unwrap();
            body["permissions"]["contents"] == "write"
        })
        .count()
}

#[tokio::test]
async fn grant_for_a_recreated_repository_replaces_the_stale_one() {
    let (broker, key, upstream) = configured_on_fake().await;
    let old = approve_repositories(&broker, &upstream, "bot", Window::D7, &[A]).await;

    // The name now answers with another id. Approving ends the old grant: the
    // page's `replaces`, the digest and the audit entries all follow the same overlap.
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::github_token_request("push the fix", Window::D7, &[A.1]),
        )
        .await;
    upstream.script_github_token(resolved(&broker, &[RECREATED]));
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    let approved = broker.approve(&token, Window::D7).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);

    assert!(revoked(&broker, &old).await);
    let ended = entries(&broker, "grant_revoked");
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert_eq!(ended[0]["grant_id"], old.as_str());
    assert_eq!(ended[0]["by"], "replaced");
    let replaced = entries(&broker, "github_token_grant_replaced");
    assert_eq!(replaced.len(), 1, "{replaced:?}");
    assert_eq!(replaced[0]["grant_id"], old.as_str());
    assert_eq!(active_covering(&broker, 1001).await, 0);
    assert_eq!(active_covering(&broker, 1003).await, 1);

    // Minting for the name now goes to the recreated repository.
    upstream.script_github_token(minted_answer(
        "ghs_test_0123456789",
        broker.clock.now() + 3600,
        &[RECREATED],
    ));
    let resp = mint_a(&broker, &key).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(resp.json()["repository_id"], 1003);
}

#[tokio::test]
async fn two_grants_for_one_name_under_different_ids_are_ambiguous() {
    let (broker, key, upstream) = configured_on_fake().await;
    approve_repositories(&broker, &upstream, "bot", Window::D7, &[A]).await;
    // Approving never leaves two, so this one is written straight into the database.
    let second = broker
        .insert_scoped_github_grant("bot", &[(RECREATED.1, RECREATED.0)])
        .await;
    let resp = mint_a(&broker, &key).await;
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert!(resp.body.contains(AMBIGUOUS_GRANT), "{}", resp.body);
    assert_eq!(mint_calls(&upstream), 0, "nothing went to GitHub");
    let refused = entries(&broker, "github_token_refused");
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert!(
        refused[0]["reason"]
            .as_str()
            .unwrap()
            .contains(AMBIGUOUS_GRANT)
    );
    assert!(
        refused[0]["grant_id"].is_string(),
        "names a conflicting grant: {refused:?} {second}"
    );
    assert_eq!(entries(&broker, "github_token_minted"), [] as [Value; 0]);
}
