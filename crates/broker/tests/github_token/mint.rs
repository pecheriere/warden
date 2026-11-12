//! Minting under a grant: what is returned, what is refused and what the audit log
//! holds. GitHub is a local HTTPS server that answers as each test scripts.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{Value, json};
use warden_broker::github_app::GithubApi;
use warden_broker::policy::GithubAppKey;
use warden_broker::requests::Clock as _;
use warden_broker::testkit::github_app::{APP_ID, INSTALLATION_ID, RSA2048_PKCS8, minted_answer};
use warden_broker::testkit::upstream::{Gate, HttpsUpstream, Received, Scripted};
use warden_broker::testkit::{TestBroker, TestResponse};
use warden_broker_proto::Window;
use warden_broker_proto::github_token::{
    AMBIGUOUS_GRANT, HOURLY_LIMIT, NO_ACTIVE_GRANT, OLD_CLIENT, REPOSITORY_UNREACHABLE,
};

use super::{approve, approve_repositories, configured, entries};

const TOKEN: &str = "ghs_test_0123456789";
/// Repository 1001, which the grant of [`granted`] covers.
const REPO_A: &str = "example-owner/example-repo";
/// Repository 1002.
const REPO_B: &str = "example-owner/homebrew-tap";

/// A broker whose GitHub is `upstream`, with an agent `bot` holding a 30-day grant.
/// Returns the agent's key and the grant.
async fn granted() -> (Arc<TestBroker>, HttpsUpstream, String, String) {
    let upstream = HttpsUpstream::start().await;
    let api = GithubApi::pinned(
        upstream.origin().parse().unwrap(),
        upstream.origin().parse().unwrap(),
        upstream.ca_pem().as_bytes().to_vec(),
    );
    let (broker, key) = configured(TestBroker::with_github_api(api).await).await;
    let grant = approve(&broker, &upstream, "bot", Window::D30).await;
    (Arc::new(broker), upstream, key, grant)
}

/// What GitHub answers when it creates a token for repository 1001 that ends an hour
/// after the broker's clock.
fn created(broker: &TestBroker, token: &str) -> Scripted {
    created_for(broker, token, 1001, REPO_A)
}

/// As [`created`], for the repository `(id, name)`.
fn created_for(broker: &TestBroker, token: &str, id: u64, name: &str) -> Scripted {
    minted_answer(token, broker.clock.now() + 3600, &[(id, name)])
}

async fn mint(broker: &TestBroker, key: &str) -> TestResponse {
    mint_for(broker, key, REPO_A).await
}

async fn mint_for(broker: &TestBroker, key: &str, repository: &str) -> TestResponse {
    broker
        .api_post_json(key, "/v1/github-token", &json!({"repository": repository}))
        .await
}

/// The requests that asked GitHub for a token to mint (the approval's own look at
/// a repository is not one of them), oldest first.
fn mint_calls(upstream: &HttpsUpstream) -> Vec<Received> {
    upstream
        .received()
        .into_iter()
        .filter(|call| {
            let body: Value = serde_json::from_slice(&call.body).unwrap();
            body["permissions"]["contents"] == "write"
        })
        .collect()
}

/// The repository ids a mint call asked for.
fn asked_ids(call: &Received) -> Value {
    serde_json::from_slice::<Value>(&call.body).unwrap()["repository_ids"].clone()
}

fn assert_refused(broker: &TestBroker, resp: &TestResponse, status: StatusCode, says: &str) {
    assert_eq!(resp.status, status, "{}", resp.body);
    assert!(resp.body.contains(says), "{}", resp.body);
    assert!(!resp.body.contains("ghs_"), "{}", resp.body);
    let refused = entries(broker, "github_token_refused");
    let last = refused.last().expect("a refusal entry");
    assert!(
        last["reason"].as_str().unwrap().contains(says),
        "{last}: {says}"
    );
}

/// Start a mint that GitHub holds, and wait until GitHub has it.
async fn held_mint(
    broker: &Arc<TestBroker>,
    upstream: &HttpsUpstream,
    key: &str,
) -> (Gate, tokio::task::JoinHandle<TestResponse>) {
    let gate = Gate::new();
    upstream.script_github_token(created(broker, TOKEN).held_by(&gate));
    let expected = upstream.received().len() as u64 + 1;
    let call = tokio::spawn({
        let broker = broker.clone();
        let key = key.to_owned();
        async move { mint(&broker, &key).await }
    });
    upstream.wait_for_github_token_calls(expected).await;
    (gate, call)
}

#[tokio::test]
async fn mints_are_capped_per_agent_per_hour() {
    let upstream = HttpsUpstream::start().await;
    let api = GithubApi::pinned(
        upstream.origin().parse().unwrap(),
        upstream.origin().parse().unwrap(),
        upstream.ca_pem().as_bytes().to_vec(),
    );
    let (broker, key) = configured(TestBroker::with_github(api, Window::D30, 2).await).await;
    approve(&broker, &upstream, "bot", Window::D30).await;
    for _ in 0..2 {
        upstream.script_github_token(created(&broker, TOKEN));
        let resp = mint(&broker, &key).await;
        assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    }
    let resp = mint(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::TOO_MANY_REQUESTS, HOURLY_LIMIT);
    assert_eq!(
        mint_calls(&upstream).len(),
        2,
        "a refused mint costs GitHub nothing"
    );
    assert_eq!(entries(&broker, "github_token_minted").len(), 2);

    // The next hour starts afresh.
    let now = broker.clock.now();
    broker.clock.advance(3600 - now.rem_euclid(3600));
    upstream.script_github_token(created(&broker, TOKEN));
    let resp = mint(&broker, &key).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
}

async fn revoke(broker: &TestBroker, grant: &str) {
    let revoked = broker
        .post_json(&format!("/grants/{grant}/revoke"), &json!({}))
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.body);
}

#[tokio::test]
async fn mint_returns_token_under_grant() {
    let (broker, upstream, key, grant) = granted().await;
    upstream.script_github_token(created(&broker, TOKEN));
    let resp = mint(&broker, &key).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let token = resp.json();
    assert_eq!(token["token"], TOKEN);
    assert_eq!(token["grant_id"], grant);
    assert_eq!(token["expires_at"], broker.clock.now() + 3600);
    assert_eq!(token["repository"], REPO_A);
    assert_eq!(token["repository_id"], 1001);

    let received = mint_calls(&upstream);
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].path_and_query,
        format!("/app/installations/{INSTALLATION_ID}/access_tokens")
    );

    let minted = entries(&broker, "github_token_minted");
    assert_eq!(minted.len(), 1);
    assert_eq!(minted[0]["grant_id"], grant);
    assert_eq!(minted[0]["agent"], "bot");
    assert_eq!(minted[0]["installation_id"], INSTALLATION_ID);
    assert_eq!(
        minted[0]["permissions"],
        json!([
            "contents:write",
            "pull_requests:write",
            "issues:write",
            "metadata:read"
        ])
    );
    assert_eq!(minted[0]["expires_at"], token["expires_at"]);
    assert_eq!(entries(&broker, "github_token_refused"), [] as [Value; 0]);
}

#[tokio::test]
async fn mint_without_grant_is_403_and_audited() {
    let (broker, key) = configured(TestBroker::new().await).await;
    let resp = mint(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::FORBIDDEN, NO_ACTIVE_GRANT);
    let refused = entries(&broker, "github_token_refused");
    assert_eq!(refused[0]["agent"], "bot");
    assert_eq!(refused[0]["grant_id"], Value::Null);
    assert_eq!(entries(&broker, "github_token_minted"), [] as [Value; 0]);
}

#[tokio::test]
async fn mint_after_revoke_is_403() {
    let (broker, upstream, key, grant) = granted().await;
    revoke(&broker, &grant).await;
    let resp = mint(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::FORBIDDEN, NO_ACTIVE_GRANT);
    assert!(mint_calls(&upstream).is_empty(), "GitHub was never asked");
}

#[tokio::test]
async fn mint_after_the_window_is_403() {
    let (broker, upstream, key, _) = granted().await;
    broker.clock.advance(30 * 86_400);
    let resp = mint(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::FORBIDDEN, NO_ACTIVE_GRANT);
    assert!(mint_calls(&upstream).is_empty());
}

#[tokio::test]
async fn a_body_that_does_not_name_a_repository_is_refused_and_audited() {
    let (broker, upstream, key, _) = granted().await;
    for body in [
        json!({"repositories": ["x"]}),
        json!({"repository": "example-owner/example-repo", "extra": 1}),
        json!({"repository": "not a repository"}),
        json!({"repository": 7}),
        json!([]),
        json!("{}"),
        json!(null),
    ] {
        let resp = broker.api_post_json(&key, "/v1/github-token", &body).await;
        assert_refused(
            &broker,
            &resp,
            StatusCode::BAD_REQUEST,
            "the request body is not valid",
        );
        assert!(!resp.body.contains("repositories"), "{}", resp.body);
        assert!(!resp.body.contains("extra"), "{}", resp.body);
    }
    assert!(mint_calls(&upstream).is_empty());
}

#[tokio::test]
async fn revoked_during_mint_not_returned() {
    let (broker, upstream, key, grant) = granted().await;
    let (gate, call) = held_mint(&broker, &upstream, &key).await;
    revoke(&broker, &grant).await;
    gate.open();
    let resp = call.await.unwrap();
    assert_refused(
        &broker,
        &resp,
        StatusCode::CONFLICT,
        "grant revoked during the call",
    );
    // The token existed, so it is on record, and so is that it was not given out.
    assert_eq!(entries(&broker, "github_token_minted").len(), 1);
    let refused = entries(&broker, "github_token_refused");
    assert_eq!(refused[0]["grant_id"], grant);
}

#[tokio::test]
async fn expired_during_mint_not_returned() {
    let (broker, upstream, key, _) = granted().await;
    let (gate, call) = held_mint(&broker, &upstream, &key).await;
    broker.clock.advance(30 * 86_400);
    gate.open();
    let resp = call.await.unwrap();
    assert_refused(
        &broker,
        &resp,
        StatusCode::CONFLICT,
        "grant expired during the call",
    );
    assert_eq!(entries(&broker, "github_token_minted").len(), 1);
}

#[tokio::test]
async fn replaced_during_mint_not_returned() {
    let (broker, upstream, key, old) = granted().await;
    let (gate, call) = held_mint(&broker, &upstream, &key).await;
    let new = approve(&broker, &upstream, "bot", Window::D7).await;
    assert_ne!(new, old);
    gate.open();
    let resp = call.await.unwrap();
    assert_refused(
        &broker,
        &resp,
        StatusCode::CONFLICT,
        "grant revoked during the call",
    );
    assert_eq!(entries(&broker, "github_token_refused")[0]["grant_id"], old);
}

#[tokio::test]
async fn app_changed_since_approval_is_409() {
    let (broker, upstream, key, _) = granted().await;
    let other = GithubAppKey::new(APP_ID.to_owned(), INSTALLATION_ID + 1, RSA2048_PKCS8).unwrap();
    broker.backend.set_github_app(Some(other));
    let resp = mint(&broker, &key).await;
    assert_refused(
        &broker,
        &resp,
        StatusCode::CONFLICT,
        "the GitHub App changed; request a new grant",
    );
    assert!(mint_calls(&upstream).is_empty(), "no token for another App");
}

#[tokio::test]
async fn upstream_failure_is_503_without_echo_and_audited() {
    let (broker, upstream, key, grant) = granted().await;
    upstream.script_github_token(Scripted::with_body(
        401,
        r#"{"message":"bad credentials ghs_test_echoed eyJecho"}"#,
    ));
    let resp = mint(&broker, &key).await;
    assert_refused(
        &broker,
        &resp,
        StatusCode::SERVICE_UNAVAILABLE,
        "GitHub could not issue a token",
    );
    assert!(!resp.body.contains("echoed"), "{}", resp.body);
    assert!(!resp.body.contains("bad credentials"), "{}", resp.body);
    assert_eq!(
        entries(&broker, "github_token_refused")[0]["grant_id"],
        grant
    );
    assert_eq!(entries(&broker, "github_token_minted"), [] as [Value; 0]);
}

#[tokio::test]
async fn backend_failure_is_503_with_a_fixed_message() {
    let (broker, upstream, key, _) = granted().await;
    broker
        .backend
        .set_github_app_outage(Some("vault host vault.internal.example refused"));
    let resp = mint(&broker, &key).await;
    assert_refused(
        &broker,
        &resp,
        StatusCode::SERVICE_UNAVAILABLE,
        "secret backend unavailable",
    );
    assert!(!resp.body.contains("vault"), "{}", resp.body);
    let log = std::fs::read_to_string(broker.audit_path()).unwrap();
    assert!(!log.contains("vault.internal"), "{log}");
    assert!(mint_calls(&upstream).is_empty());
}

#[tokio::test]
async fn audit_never_contains_token_or_jwt() {
    let (broker, upstream, key, _) = granted().await;
    upstream.script_github_token(created(&broker, TOKEN));
    assert_eq!(mint(&broker, &key).await.status, StatusCode::OK);
    upstream.script_github_token(Scripted::with_body(
        401,
        r#"{"message":"ghs_test_echoed eyJecho"}"#,
    ));
    assert_eq!(
        mint(&broker, &key).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    // The JWT really was sent, so the scan below could have caught it.
    let sent = mint_calls(&upstream);
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|call| {
        call.headers["authorization"]
            .to_str()
            .unwrap()
            .contains("eyJ")
    }));
    let log = std::fs::read_to_string(broker.audit_path()).unwrap();
    assert!(!log.contains("ghs_test"), "{log}");
    assert!(!log.contains("eyJ"), "{log}");
}

#[tokio::test]
async fn client_disconnect_still_audits() {
    let (broker, upstream, key, _) = granted().await;
    let (gate, call) = held_mint(&broker, &upstream, &key).await;
    // The agent goes away while GitHub still holds the call.
    call.abort();
    assert!(call.await.unwrap_err().is_cancelled());
    gate.open();
    tokio::time::timeout(Duration::from_secs(30), async {
        while entries(&broker, "github_token_minted").is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the mint is recorded although nobody is waiting for it");
}

#[tokio::test]
async fn refusals_past_the_limit_are_counted_instead_of_listed() {
    let (broker, key) = configured(TestBroker::new().await).await;
    for _ in 0..33 {
        assert_eq!(mint(&broker, &key).await.status, StatusCode::FORBIDDEN);
    }
    assert_eq!(entries(&broker, "github_token_refused").len(), 30);
    broker.state().requests.flush_refusals(true).await;
    let held = entries(&broker, "github_token_refusals_held");
    assert_eq!(held.len(), 1);
    assert_eq!(held[0]["agent"], "bot");
    assert_eq!(held[0]["count"], 3);
}

#[tokio::test]
async fn hourly_limit_survives_restart() {
    let upstream = HttpsUpstream::start().await;
    let api = GithubApi::pinned(
        upstream.origin().parse().unwrap(),
        upstream.origin().parse().unwrap(),
        upstream.ca_pem().as_bytes().to_vec(),
    );
    let (broker, key) = configured(TestBroker::with_github(api, Window::D30, 2).await).await;
    broker
        .insert_scoped_github_grant("bot", &[("example-owner/example-repo", 1001)])
        .await;
    for _ in 0..2 {
        upstream.script_github_token(created(&broker, TOKEN));
        let resp = mint(&broker, &key).await;
        assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    }
    let broker = broker.restart().await;
    let resp = mint(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::TOO_MANY_REQUESTS, HOURLY_LIMIT);
    assert_eq!(mint_calls(&upstream).len(), 2);
    let minted = entries(&broker, "github_token_minted");
    assert_eq!(minted.len(), 2);
    assert_eq!(minted[0]["repository"], "example-owner/example-repo");
    assert_eq!(minted[0]["repository_id"], 1001);
}

#[tokio::test]
async fn info_says_scoped_github_tokens() {
    let broker = TestBroker::new().await;
    let resp = broker
        .api_send(
            axum::http::Request::get("/v1/info")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(resp.json()["scoped_github_tokens"], true);
}

#[tokio::test]
async fn mints_for_the_named_repository() {
    let (broker, upstream, key, grant) = granted().await;
    upstream.script_github_token(created(&broker, TOKEN));
    let resp = mint(&broker, &key).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let token = resp.json();
    assert_eq!(token["repository"], REPO_A);
    assert_eq!(token["repository_id"], 1001);
    assert_eq!(token["grant_id"], grant);

    let calls = mint_calls(&upstream);
    assert_eq!(calls.len(), 1);
    assert_eq!(asked_ids(&calls[0]), json!([1001]));
    let minted = entries(&broker, "github_token_minted");
    assert_eq!(minted[0]["repository"], REPO_A);
    assert_eq!(minted[0]["repository_id"], 1001);
}

#[tokio::test]
async fn mint_finds_grant_in_any_case() {
    let (broker, upstream, key, grant) = granted().await;
    upstream.script_github_token(created(&broker, TOKEN));
    let resp = mint_for(&broker, &key, "Example-Owner/Example-Repo").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let token = resp.json();
    // The answer names the repository as the grant stores it.
    assert_eq!(token["repository"], REPO_A);
    assert_eq!(token["grant_id"], grant);
    assert_eq!(asked_ids(&mint_calls(&upstream)[0]), json!([1001]));
}

#[tokio::test]
async fn mint_refuses_repository_without_grant() {
    let (broker, upstream, key, _) = granted().await;
    let resp = mint_for(&broker, &key, REPO_B).await;
    assert_refused(&broker, &resp, StatusCode::FORBIDDEN, NO_ACTIVE_GRANT);
    assert!(mint_calls(&upstream).is_empty(), "nothing went to GitHub");
}

#[tokio::test]
async fn mint_uses_the_right_grant_of_two() {
    let (broker, upstream, key, grant_a) = granted().await;
    let grant_b =
        approve_repositories(&broker, &upstream, "bot", Window::D30, &[(1002, REPO_B)]).await;
    assert_ne!(grant_a, grant_b, "the two do not overlap, so both stay");

    upstream.script_github_token(created_for(&broker, TOKEN, 1002, REPO_B));
    let resp = mint_for(&broker, &key, REPO_B).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(resp.json()["grant_id"], grant_b);
    assert_eq!(resp.json()["repository_id"], 1002);

    upstream.script_github_token(created(&broker, TOKEN));
    let resp = mint_for(&broker, &key, REPO_A).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(resp.json()["grant_id"], grant_a);

    let calls = mint_calls(&upstream);
    assert_eq!(asked_ids(&calls[0]), json!([1002]));
    assert_eq!(asked_ids(&calls[1]), json!([1001]));
    let minted = entries(&broker, "github_token_minted");
    assert_eq!(minted[0]["grant_id"], grant_b);
    assert_eq!(minted[1]["grant_id"], grant_a);
}

#[tokio::test]
async fn mint_refuses_two_grants_covering_one_id() {
    let (broker, upstream, key, _) = granted().await;
    // Approving never leaves two, so this one is written straight into the database.
    broker
        .insert_scoped_github_grant("bot", &[(REPO_A, 1001)])
        .await;
    let resp = mint(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::CONFLICT, AMBIGUOUS_GRANT);
    assert!(mint_calls(&upstream).is_empty(), "nothing went to GitHub");
    assert_eq!(entries(&broker, "github_token_minted"), [] as [Value; 0]);
}

#[tokio::test]
async fn mint_refuses_github_answer_for_other_id() {
    let (broker, upstream, key, grant) = granted().await;
    // The repository was deleted and recreated, or renamed and replaced: GitHub
    // answers for another one. The token is discarded and not retried.
    upstream.script_github_token(created_for(&broker, TOKEN, 1002, REPO_B));
    let resp = mint(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::CONFLICT, REPOSITORY_UNREACHABLE);
    assert_eq!(mint_calls(&upstream).len(), 1, "no retry");
    assert_eq!(entries(&broker, "github_token_minted"), [] as [Value; 0]);
    assert_eq!(
        entries(&broker, "github_token_refused")[0]["grant_id"],
        grant
    );
    let log = std::fs::read_to_string(broker.audit_path()).unwrap();
    assert!(!log.contains("ghs_"), "{log}");
}

#[tokio::test]
async fn mint_reports_unreachable_repository() {
    let (broker, upstream, key, grant) = granted().await;
    upstream.script_github_token(Scripted::with_body(
        422,
        r#"{"message":"repository ghs_test_echoed is gone"}"#,
    ));
    let resp = mint(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::CONFLICT, REPOSITORY_UNREACHABLE);
    assert!(!resp.body.contains("echoed"), "{}", resp.body);
    assert_eq!(mint_calls(&upstream).len(), 1, "no retry");
    assert_eq!(entries(&broker, "github_token_minted"), [] as [Value; 0]);
    assert_eq!(
        entries(&broker, "github_token_refused")[0]["grant_id"],
        grant
    );
}

/// A mint GitHub refuses as unreachable still costs the agent one of its hour's
/// tokens, as every call that reaches GitHub does.
#[tokio::test]
async fn unreachable_repository_costs_the_hourly_budget() {
    let upstream = HttpsUpstream::start().await;
    let api = GithubApi::pinned(
        upstream.origin().parse().unwrap(),
        upstream.origin().parse().unwrap(),
        upstream.ca_pem().as_bytes().to_vec(),
    );
    let (broker, key) = configured(TestBroker::with_github(api, Window::D30, 1).await).await;
    approve(&broker, &upstream, "bot", Window::D30).await;
    upstream.script_github_token(Scripted::with_body(422, r#"{"message":"gone"}"#));
    let resp = mint(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::CONFLICT, REPOSITORY_UNREACHABLE);
    let resp = mint(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::TOO_MANY_REQUESTS, HOURLY_LIMIT);
    assert_eq!(mint_calls(&upstream).len(), 1);
}

#[tokio::test]
async fn old_cli_body_says_upgrade() {
    let (broker, upstream, key, _) = granted().await;
    let resp = broker
        .api_post_json(&key, "/v1/github-token", &json!({}))
        .await;
    assert_refused(&broker, &resp, StatusCode::BAD_REQUEST, OLD_CLIENT);
    assert!(mint_calls(&upstream).is_empty());
}

#[tokio::test]
async fn grant_replaced_during_mint_gets_nothing() {
    let (broker, upstream, key, old) = granted().await;
    let (gate, call) = held_mint(&broker, &upstream, &key).await;
    // A grant over both repositories overlaps the old one, so it replaces it.
    let new = approve_repositories(
        &broker,
        &upstream,
        "bot",
        Window::D7,
        &[(1001, REPO_A), (1002, REPO_B)],
    )
    .await;
    assert_ne!(new, old);
    gate.open();
    let resp = call.await.unwrap();
    assert_refused(
        &broker,
        &resp,
        StatusCode::CONFLICT,
        "grant revoked during the call",
    );
    assert_eq!(entries(&broker, "github_token_refused")[0]["grant_id"], old);
}

#[tokio::test]
async fn hourly_limit_is_per_agent_across_grants() {
    let upstream = HttpsUpstream::start().await;
    let api = GithubApi::pinned(
        upstream.origin().parse().unwrap(),
        upstream.origin().parse().unwrap(),
        upstream.ca_pem().as_bytes().to_vec(),
    );
    let (broker, key) = configured(TestBroker::with_github(api, Window::D30, 2).await).await;
    approve(&broker, &upstream, "bot", Window::D30).await;
    approve_repositories(&broker, &upstream, "bot", Window::D30, &[(1002, REPO_B)]).await;
    upstream.script_github_token(created(&broker, TOKEN));
    assert_eq!(mint_for(&broker, &key, REPO_A).await.status, StatusCode::OK);
    upstream.script_github_token(created_for(&broker, TOKEN, 1002, REPO_B));
    assert_eq!(mint_for(&broker, &key, REPO_B).await.status, StatusCode::OK);
    for repository in [REPO_A, REPO_B] {
        let resp = mint_for(&broker, &key, repository).await;
        assert_refused(&broker, &resp, StatusCode::TOO_MANY_REQUESTS, HOURLY_LIMIT);
    }
    assert_eq!(mint_calls(&upstream).len(), 2);
}
