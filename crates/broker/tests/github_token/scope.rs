//! A GitHub token request names repositories: they are checked at creation without
//! GitHub, resolved by GitHub when the owner opens the page, and approving grants
//! exactly the repositories and ids the page resolved.

use axum::http::StatusCode;
use serde_json::{Value, json};
use sha2::Digest as _;
use warden_broker::requests::{Resolution, ScopedRepository};
use warden_broker::testkit::TestBroker;
use warden_broker::testkit::upstream::Scripted;
use warden_broker_proto::Window;
use warden_broker_proto::github_token::OLD_CLIENT;
use warden_broker_proto::release::RepoName;

use super::{approve, configured_on_fake, entries, resolved};

const REPO: &str = "example-owner/example-repo";

fn request(repositories: &[&str]) -> warden_broker_proto::CreateRequest {
    TestBroker::github_token_request("push the fix", Window::D7, repositories)
}

async fn create_error(broker: &TestBroker, req: warden_broker_proto::CreateRequest) -> String {
    broker
        .state()
        .requests
        .create(&"bot".parse().unwrap(), req)
        .await
        .expect_err("refused")
        .to_string()
}

#[tokio::test]
async fn creates_request_for_one_repository() {
    let (broker, _key, _upstream) = configured_on_fake().await;
    let (created, _token) = broker.create_request("bot", request(&[REPO])).await;
    assert_eq!(created.created, Some(true));
}

#[tokio::test]
async fn creation_reads_no_key() {
    let (broker, _key, _upstream) = configured_on_fake().await;
    let before = broker.backend.github_app_reads();
    let (created, _token) = broker.create_request("bot", request(&[REPO])).await;
    assert_eq!(created.created, Some(true));
    assert_eq!(broker.backend.github_app_reads(), before);
}

#[tokio::test]
async fn refuses_legacy_body_with_upgrade_message() {
    let (broker, _key, _upstream) = configured_on_fake().await;
    let said = create_error(&broker, request(&[])).await;
    assert!(said.contains(OLD_CLIENT), "{said}");
}

#[tokio::test]
async fn refuses_two_owners() {
    let (broker, _key, _upstream) = configured_on_fake().await;
    let said = create_error(&broker, request(&[REPO, "other-owner/example-repo"])).await;
    assert!(said.contains("must belong to one account"), "{said}");
}

#[tokio::test]
async fn same_set_any_case_is_one_slot() {
    let (broker, _key, _upstream) = configured_on_fake().await;
    let (first, _token) = broker
        .create_request("bot", request(&["Example-Owner/Example-Repo"]))
        .await;
    let again = broker
        .state()
        .requests
        .create(&"bot".parse().unwrap(), request(&[REPO]))
        .await
        .unwrap();
    assert_eq!(again.created, Some(false));
    assert_eq!(again.id, first.id);
}

#[tokio::test]
async fn different_repositories_are_two_slots() {
    let (broker, _key, _upstream) = configured_on_fake().await;
    let (first, _token) = broker.create_request("bot", request(&[REPO])).await;
    let (second, _token) = broker
        .create_request("bot", request(&["example-owner/homebrew-tap"]))
        .await;
    assert_eq!(second.created, Some(true));
    assert_ne!(first.id, second.id);
}

#[tokio::test]
async fn page_resolves_once() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let (_, token) = broker.create_request("bot", request(&[REPO])).await;
    // Only one answer is scripted: a second call to GitHub would get a 500.
    upstream.script_github_token(resolved(&broker, &[(1001, REPO)]));
    for _ in 0..2 {
        let page = broker.get(&format!("/approve/{token}")).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        assert!(page.body.contains("id=\"approve\""), "{}", page.body);
    }
    let resolved = entries(&broker, "github_repositories_resolved");
    assert_eq!(resolved.len(), 1, "{resolved:?}");
    assert_eq!(resolved[0]["repository_ids"], json!([1001]));
    assert_eq!(resolved[0]["accessible"], json!(true));
}

#[tokio::test]
async fn page_shows_not_installed_and_no_approve() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let (_, token) = broker.create_request("bot", request(&[REPO])).await;
    upstream.script_github_token(Scripted::with_body(422, r#"{"message":"echoed"}"#));
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body.contains(&format!(
            "This request cannot be approved: the App is not installed on <code><bdi>{REPO}</bdi></code>, or one of them does not exist."
        )),
        "{}",
        page.body
    );
    assert!(!page.body.contains("id=\"approve\""), "{}", page.body);
    assert!(!page.body.contains("echoed"), "{}", page.body);
    assert_eq!(
        entries(&broker, "github_repositories_resolved")[0]["accessible"],
        json!(false)
    );
}

#[tokio::test]
async fn page_cannot_be_approved_when_github_answers_another_owner() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let (_, token) = broker.create_request("bot", request(&[REPO])).await;
    // The name resolves to a repository of another owner: a mismatch, stored as such,
    // and not an outage to be asked again on every open.
    upstream.script_github_token(resolved(&broker, &[(1001, "other-owner/example-repo")]));
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body.contains("This request cannot be approved"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("id=\"approve\""), "{}", page.body);
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM github_repositories")
        .fetch_one(&broker.state().pool)
        .await
        .unwrap();
    assert_eq!(stored, 1);
    // Opened again, it is not asked of GitHub again.
    let again = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.body);
    assert_eq!(entries(&broker, "github_repositories_resolved").len(), 1);
}

#[tokio::test]
async fn page_unavailable_when_github_down_and_stores_nothing() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let (_, token) = broker.create_request("bot", request(&[REPO])).await;
    upstream.script_github_token(Scripted::with_body(500, "ghs_echoed"));
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(
        page.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        page.body
    );
    assert!(!page.body.contains("ghs_echoed"), "{}", page.body);
    // GitHub's outage has its own words: the secret backend is not the problem.
    assert!(
        page.body
            .contains("GitHub could not be asked about the repositories"),
        "{}",
        page.body
    );
    assert!(
        !page.body.contains("secret backend unavailable"),
        "{}",
        page.body
    );
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM github_repositories")
        .fetch_one(&broker.state().pool)
        .await
        .unwrap();
    assert_eq!(stored, 0);
    assert_eq!(
        entries(&broker, "github_repositories_resolved"),
        [] as [Value; 0]
    );

    upstream.script_github_token(resolved(&broker, &[(1001, REPO)]));
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains("id=\"approve\""), "{}", page.body);
}

#[tokio::test]
async fn approve_builds_scoped_grant() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let grant = approve(&broker, &upstream, "bot", Window::D7).await;
    let view: String = sqlx::query_scalar("SELECT view FROM grants WHERE id = ?")
        .bind(&grant)
        .fetch_one(&broker.state().pool)
        .await
        .unwrap();
    let view: Value = serde_json::from_str(&view).unwrap();
    assert_eq!(
        view["access"]["repositories"],
        json!([{"name": REPO, "id": 1001}])
    );
}

#[tokio::test]
async fn approve_refuses_not_accessible() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let (_, token) = broker.create_request("bot", request(&[REPO])).await;
    upstream.script_github_token(Scripted::with_body(422, "{}"));
    let begin = broker.begin_approval(&token, Window::D7).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
    assert!(begin.body.contains("cannot be approved"), "{}", begin.body);
}

#[tokio::test]
async fn approve_refuses_when_resolution_changed() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let (created, token) = broker.create_request("bot", request(&[REPO])).await;
    upstream.script_github_token(resolved(&broker, &[(1001, REPO)]));
    let mut auth = broker.enroll_soft_passkey().await;
    let begin = broker.begin_approval(&token, Window::D7).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);

    let swapped = Resolution::Resolved(vec![ScopedRepository {
        id: 2002,
        name: RepoName::try_from(REPO.to_owned()).unwrap(),
        renamed_from: None,
    }]);
    sqlx::query("UPDATE github_repositories SET resolution = ? WHERE request_id = ?")
        .bind(serde_json::to_string(&swapped).unwrap())
        .bind(created.id.as_str())
        .execute(&broker.state().pool)
        .await
        .unwrap();
    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(finish.status, StatusCode::CONFLICT, "{}", finish.body);
    assert!(
        finish.body.contains("policy changed; reload and review"),
        "{}",
        finish.body
    );
}

#[tokio::test]
async fn owners_differing_in_case_are_one_account() {
    let (broker, _key, _upstream) = configured_on_fake().await;
    let (created, _token) = broker
        .create_request(
            "bot",
            request(&["Example-Owner/example-repo", "example-owner/homebrew-tap"]),
        )
        .await;
    assert_eq!(created.created, Some(true));
}

#[tokio::test]
async fn page_of_a_legacy_request_offers_no_approve() {
    let (broker, _key, _upstream) = configured_on_fake().await;
    let id = broker.insert_legacy_github_request("bot").await;
    let token = "legacy-approval-token";
    sqlx::query("UPDATE requests SET approval_token_hash = ? WHERE id = ?")
        .bind(hex::encode(sha2::Sha256::digest(token.as_bytes())))
        .bind(id.as_str())
        .execute(&broker.state().pool)
        .await
        .unwrap();
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body
            .contains("This request cannot be approved: it names no repository"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("id=\"approve\""), "{}", page.body);
    // And it is refused when begun.
    let begin = broker.begin_approval(token, Window::D7).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
}
