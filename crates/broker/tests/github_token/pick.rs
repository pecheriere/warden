//! Which grant a token comes from when an agent holds several on one repository, and
//! with which permissions: an extra permission reaches a token only when the request
//! names it.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{Value, json};
use warden_broker::requests::Clock as _;
use warden_broker::testkit::github_app::token_answer;
use warden_broker::testkit::upstream::{Gate, HttpsUpstream, Scripted};
use warden_broker::testkit::{TestBroker, TestResponse};
use warden_broker_proto::Window;

use super::extras::{REPO, allow, approve_with_extras};
use super::permissions::set_default;
use super::{approve, configured_on_fake, entries, github_calls};

const TOKEN: &str = "ghs_test_0123456789";

/// The owner's default in these tests.
const DEFAULT: &str = "contents:write,pull_requests:write";

/// A broker whose agent `bot` holds one grant for `REPO` with the default
/// [`DEFAULT`] and the extra `actions:write`. Returns the grant.
async fn with_actions() -> (Arc<TestBroker>, String, HttpsUpstream, String) {
    let (broker, key, upstream) = configured_on_fake().await;
    allow(&broker, DEFAULT, "actions:write");
    let grant = approve_with_extras(
        &broker,
        &upstream,
        Window::D7,
        "actions:write",
        &[("actions", "write")],
    )
    .await;
    (Arc::new(broker), key, upstream, grant)
}

/// A broker whose agent `bot` holds two grants for `REPO`: an everyday one for 30 days
/// and one with `workflows:write` for an hour. Returns both, everyday first.
async fn everyday_and_sensitive() -> (Arc<TestBroker>, String, HttpsUpstream, String, String) {
    let (broker, key, upstream) = configured_on_fake().await;
    allow(&broker, DEFAULT, "workflows:write");
    let everyday = approve(&broker, &upstream, "bot", Window::D30).await;
    let sensitive = approve_with_extras(
        &broker,
        &upstream,
        Window::H1,
        "workflows:write",
        &[("workflows", "write")],
    )
    .await;
    assert_ne!(everyday, sensitive, "other extras, so both stay");
    (Arc::new(broker), key, upstream, everyday, sensitive)
}

/// GitHub's answer to a mint for `REPO` with `granted`.
fn answer(broker: &TestBroker, granted: &[(&str, &str)]) -> Scripted {
    token_answer(
        TOKEN,
        broker.clock.now() + 3600,
        &[(1001, REPO)],
        granted,
        "selected",
    )
}

/// Mint for `REPO`, naming `permissions` if given.
async fn mint(broker: &TestBroker, key: &str, permissions: Option<&str>) -> TestResponse {
    let mut body = json!({"repository": REPO});
    if let Some(permissions) = permissions {
        body["permissions"] = json!(permissions);
    }
    broker.api_post_json(key, "/v1/github-token", &body).await
}

/// The calls that asked GitHub to mint, oldest first.
fn mint_calls(upstream: &HttpsUpstream) -> Vec<Value> {
    github_calls(upstream)
        .into_iter()
        .filter(|call| call.method == "POST" && call.path_and_query.ends_with("/access_tokens"))
        .map(|call| serde_json::from_slice::<Value>(&call.body).unwrap())
        .filter(|body| body["repository_ids"] == json!([1001]))
        .filter(|body| body["permissions"] != json!({"metadata": "read"}))
        .collect()
}

/// The permissions the last mint call asked GitHub for.
fn asked(upstream: &HttpsUpstream) -> Value {
    mint_calls(upstream).last().expect("a mint call")["permissions"].clone()
}

#[tokio::test]
async fn plain_request_gets_the_default_set() {
    let (broker, key, upstream, grant) = with_actions().await;
    let default = [
        ("contents", "write"),
        ("metadata", "read"),
        ("pull_requests", "write"),
    ];
    upstream.script_github_token(answer(&broker, &default));
    let resp = mint(&broker, &key, None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(
        asked(&upstream),
        json!({"contents": "write", "metadata": "read", "pull_requests": "write"}),
        "the grant's `actions:write` is not asked for"
    );
    assert_eq!(
        resp.json()["permissions"],
        "contents:write,metadata:read,pull_requests:write"
    );
    assert_eq!(resp.json()["grant_id"], grant);
}

#[tokio::test]
async fn changed_default_narrows_a_plain_token_and_never_widens_it() {
    let (broker, key, upstream, _) = with_actions().await;
    // Narrowed: the token follows the owner's current default.
    set_default(&broker, "contents:read");
    upstream.script_github_token(answer(
        &broker,
        &[("contents", "read"), ("metadata", "read")],
    ));
    let resp = mint(&broker, &key, None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(
        asked(&upstream),
        json!({"contents": "read", "metadata": "read"})
    );
    // Widened: limited to what the grant holds.
    set_default(&broker, "contents:write,issues:write,pull_requests:write");
    upstream.script_github_token(answer(
        &broker,
        &[
            ("contents", "write"),
            ("metadata", "read"),
            ("pull_requests", "write"),
        ],
    ));
    let resp = mint(&broker, &key, None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(
        asked(&upstream),
        json!({"contents": "write", "metadata": "read", "pull_requests": "write"})
    );
}

#[tokio::test]
async fn named_extra_is_minted() {
    let (broker, key, upstream, grant) = with_actions().await;
    upstream.script_github_token(answer(
        &broker,
        &[("actions", "write"), ("metadata", "read")],
    ));
    let resp = mint(&broker, &key, Some("actions:write")).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(
        asked(&upstream),
        json!({"actions": "write", "metadata": "read"})
    );
    assert_eq!(resp.json()["permissions"], "actions:write,metadata:read");
    assert_eq!(resp.json()["grant_id"], grant);
}

#[tokio::test]
async fn named_sensitive_uses_the_sensitive_grant() {
    let (broker, key, upstream, everyday, sensitive) = everyday_and_sensitive().await;
    upstream.script_github_token(answer(
        &broker,
        &[
            ("contents", "write"),
            ("metadata", "read"),
            ("workflows", "write"),
        ],
    ));
    let resp = mint(&broker, &key, Some("contents:write,workflows:write")).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(resp.json()["grant_id"], sensitive);

    // Naming only what the everyday grant holds, or nothing, uses the everyday grant.
    upstream.script_github_token(answer(
        &broker,
        &[("contents", "write"), ("metadata", "read")],
    ));
    let resp = mint(&broker, &key, Some("contents:write")).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(resp.json()["grant_id"], everyday);
    upstream.script_github_token(answer(
        &broker,
        &[
            ("contents", "write"),
            ("metadata", "read"),
            ("pull_requests", "write"),
        ],
    ));
    let resp = mint(&broker, &key, None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(resp.json()["grant_id"], everyday);
    assert_eq!(
        asked(&upstream),
        json!({"contents": "write", "metadata": "read", "pull_requests": "write"})
    );

    let minted = entries(&broker, "github_token_minted");
    let from: Vec<&Value> = minted.iter().map(|entry| &entry["grant_id"]).collect();
    assert_eq!(
        from,
        [&json!(sensitive), &json!(everyday), &json!(everyday)]
    );
}

#[tokio::test]
async fn sensitive_grant_revoked_during_mint_gives_nothing() {
    let (broker, key, upstream, everyday, sensitive) = everyday_and_sensitive().await;
    let gate = Gate::new();
    upstream.script_github_token(
        answer(
            &broker,
            &[
                ("contents", "write"),
                ("metadata", "read"),
                ("workflows", "write"),
            ],
        )
        .held_by(&gate),
    );
    let expected = github_calls(&upstream).len() as u64 + 1;
    let call = tokio::spawn({
        let broker = broker.clone();
        let key = key.clone();
        async move { mint(&broker, &key, Some("contents:write,workflows:write")).await }
    });
    upstream.wait_for_github_token_calls(expected).await;
    let revoked = broker
        .post_json(&format!("/grants/{sensitive}/revoke"), &json!({}))
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.body);
    gate.open();

    let resp = call.await.unwrap();
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert!(
        resp.body.contains("grant revoked during the call"),
        "{}",
        resp.body
    );
    assert!(!resp.body.contains("ghs_"), "{}", resp.body);
    // The everyday grant still holds `contents:write`, but the mint named
    // `workflows:write`, so the recheck finds no grant holding it: nothing is given.
    let refused = entries(&broker, "github_token_refused");
    let last = refused.last().expect("a refusal entry");
    assert_eq!(last["grant_id"], sensitive.as_str());
    assert!(
        last["reason"]
            .as_str()
            .unwrap()
            .contains("grant revoked during the call"),
        "{last}"
    );

    // The everyday grant was left as it was, and mints.
    upstream.script_github_token(answer(
        &broker,
        &[
            ("contents", "write"),
            ("metadata", "read"),
            ("pull_requests", "write"),
        ],
    ));
    let resp = mint(&broker, &key, None).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(resp.json()["grant_id"], everyday);
}

#[tokio::test]
async fn unreadable_grant_permissions_refuse() {
    let (broker, key, upstream, _, sensitive) = everyday_and_sensitive().await;
    let pool = &broker.state().pool;
    let view: String = sqlx::query_scalar("SELECT view FROM grants WHERE id = ?")
        .bind(sensitive.as_str())
        .fetch_one(pool)
        .await
        .unwrap();
    let newer = view.replace("workflows:write", "new_thing:write,workflows:write");
    assert_ne!(newer, view);
    sqlx::query("UPDATE grants SET view = ? WHERE id = ?")
        .bind(newer)
        .bind(sensitive.as_str())
        .execute(pool)
        .await
        .unwrap();

    // The everyday grant would serve a plain mint, but the sensitive one cannot be
    // read: skipping it would hide the corruption, so the mint refuses.
    let before = upstream.received().len();
    let resp = mint(&broker, &key, None).await;
    assert_eq!(
        resp.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        resp.body
    );
    assert!(!resp.body.contains("new_thing"), "{}", resp.body);
    assert_eq!(upstream.received().len(), before, "GitHub was not asked");
    assert_eq!(entries(&broker, "github_token_minted"), [] as [Value; 0]);
}

#[tokio::test]
async fn unreadable_default_refuses_a_plain_mint() {
    let (broker, key, upstream, _) = with_actions().await;
    broker
        .backend
        .set_github_app_outage(Some("the vault is unreachable"));
    let before = upstream.received().len();
    let resp = mint(&broker, &key, None).await;
    assert!(resp.status.is_server_error(), "{}", resp.body);
    assert_eq!(upstream.received().len(), before, "GitHub was not asked");
    assert_eq!(entries(&broker, "github_token_minted"), [] as [Value; 0]);
}
