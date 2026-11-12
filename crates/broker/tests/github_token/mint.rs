//! Minting under a grant: what is returned, what is refused and what the audit log
//! holds. GitHub is a local HTTPS server that answers as each test scripts.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{Value, json};
use warden_broker::github_app::GithubApi;
use warden_broker::policy::GithubAppKey;
use warden_broker::requests::Clock as _;
use warden_broker::testkit::github_app::token_answer;
use warden_broker::testkit::github_app::{APP_ID, INSTALLATION_ID, RSA2048_PKCS8};
use warden_broker::testkit::upstream::{Gate, HttpsUpstream, Scripted};
use warden_broker::testkit::{TestBroker, TestResponse};
use warden_broker_proto::Window;
use warden_broker_proto::github_token::{HOURLY_LIMIT, NO_ACTIVE_GRANT, PERMISSIONS};

use super::{approve, configured, entries};

const TOKEN: &str = "ghs_test_0123456789";

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
    let grant = approve(&broker, "bot", Window::D30).await;
    (Arc::new(broker), upstream, key, grant)
}

/// What GitHub answers when it creates a token that ends an hour after the broker's
/// clock.
fn created(broker: &TestBroker, token: &str) -> Scripted {
    let expires = jiff::Timestamp::from_second(broker.clock.now() + 3600).unwrap();
    Scripted::with_body(
        201,
        json!({"token": token, "expires_at": expires.to_string()}).to_string(),
    )
}

async fn mint(broker: &TestBroker, key: &str) -> TestResponse {
    broker
        .api_post_json(key, "/v1/github-token", &json!({}))
        .await
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
    let call = tokio::spawn({
        let broker = broker.clone();
        let key = key.to_owned();
        async move { mint(&broker, &key).await }
    });
    upstream.wait_for_github_token_calls(1).await;
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
    approve(&broker, "bot", Window::D30).await;
    for _ in 0..2 {
        upstream.script_github_token(created(&broker, TOKEN));
        let resp = mint(&broker, &key).await;
        assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    }
    let resp = mint(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::TOO_MANY_REQUESTS, HOURLY_LIMIT);
    assert_eq!(
        upstream.received().len(),
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

    let received = upstream.received();
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
    assert!(upstream.received().is_empty(), "GitHub was never asked");
}

#[tokio::test]
async fn mint_after_the_window_is_403() {
    let (broker, upstream, key, _) = granted().await;
    broker.clock.advance(30 * 86_400);
    let resp = mint(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::FORBIDDEN, NO_ACTIVE_GRANT);
    assert!(upstream.received().is_empty());
}

#[tokio::test]
async fn a_body_that_is_not_an_empty_object_is_refused_and_audited() {
    let (broker, upstream, key, _) = granted().await;
    for body in [
        json!({"repositories": ["x"]}),
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
    }
    assert!(upstream.received().is_empty());
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
    let new = approve(&broker, "bot", Window::D7).await;
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
    assert!(upstream.received().is_empty(), "no token for another App");
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
    assert!(upstream.received().is_empty());
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
    let sent = upstream.received();
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
    // Written straight into the database: scoped approval comes later.
    broker
        .insert_scoped_github_grant("bot", &[("example-owner/example-repo", 1001)])
        .await;
    for _ in 0..2 {
        upstream.script_github_token(token_answer(
            TOKEN,
            broker.clock.now() + 3600,
            &[(1001, "example-owner/example-repo")],
            &PERMISSIONS,
            "selected",
        ));
        let resp = mint(&broker, &key).await;
        assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    }
    let broker = broker.restart().await;
    let resp = mint(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::TOO_MANY_REQUESTS, HOURLY_LIMIT);
    assert_eq!(upstream.received().len(), 2);
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
