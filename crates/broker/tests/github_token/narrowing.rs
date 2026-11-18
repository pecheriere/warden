//! A mint may ask for fewer permissions than its grant holds, never more; and the
//! broker says in `/v1/info` that it understands that.

use axum::http::StatusCode;
use serde_json::{Value, json};
use warden_broker::testkit::github_app::token_answer;
use warden_broker::testkit::upstream::HttpsUpstream;
use warden_broker::testkit::{TestBroker, TestResponse};
use warden_broker_proto::Window;
use warden_broker_proto::github_token::PERMISSIONS_NOT_IN_GRANT;

use super::extras::{LEGACY, REPO, allow, approve_with_extras};
use super::{configured_on_fake, entries, github_calls};

const TOKEN: &str = "ghs_test_0123456789";

/// A broker whose agent `bot` holds a grant for `REPO` with the legacy default and
/// the extra `checks:read`.
async fn granted() -> (TestBroker, String, HttpsUpstream) {
    let (broker, key, upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "checks:read,actions:read");
    approve_with_extras(
        &broker,
        &upstream,
        Window::D7,
        "checks:read",
        &[("checks", "read")],
    )
    .await;
    (broker, key, upstream)
}

/// A mint for `REPO` that names `workflows:write`, which only a sensitive grant holds.
fn sensitive_mint() -> Value {
    json!({"repository": REPO, "permissions": "contents:write,workflows:write"})
}

async fn mint_with(broker: &TestBroker, key: &str, body: Value) -> TestResponse {
    broker.api_post_json(key, "/v1/github-token", &body).await
}

/// What GitHub answers when it mints for repository 1001 with `granted`.
fn answer(
    broker: &TestBroker,
    granted: &[(&str, &str)],
) -> warden_broker::testkit::upstream::Scripted {
    use warden_broker::requests::Clock as _;
    token_answer(
        TOKEN,
        broker.clock.now() + 3600,
        &[(1001, REPO)],
        granted,
        "selected",
    )
}

/// The permissions the last call that asked GitHub to mint named.
fn asked_permissions(upstream: &HttpsUpstream) -> Value {
    let call = github_calls(upstream)
        .into_iter()
        .rfind(|call| call.method == "POST" && call.path_and_query.ends_with("/access_tokens"))
        .expect("a mint call");
    serde_json::from_slice::<Value>(&call.body).unwrap()["permissions"].clone()
}

#[tokio::test]
async fn narrowed_mint_asks_for_the_subset() {
    let (broker, key, upstream) = granted().await;
    let held = [("contents", "write"), ("metadata", "read")];
    upstream.script_github_token(answer(&broker, &held));
    let resp = mint_with(
        &broker,
        &key,
        json!({"repository": REPO, "permissions": "contents:write,metadata:read"}),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(resp.json()["permissions"], "contents:write,metadata:read");
    assert_eq!(
        asked_permissions(&upstream),
        json!({"contents": "write", "metadata": "read"})
    );
    let minted = entries(&broker, "github_token_minted");
    assert_eq!(
        minted.last().unwrap()["permissions"],
        json!(["contents:write", "metadata:read"])
    );
}

#[tokio::test]
async fn absent_permissions_mean_the_default_set() {
    let (broker, key, upstream) = granted().await;
    // The grant's extra `checks:read` is not asked for: it was not named.
    let default = [
        ("contents", "write"),
        ("issues", "write"),
        ("metadata", "read"),
        ("pull_requests", "write"),
    ];
    upstream.script_github_token(answer(&broker, &default));
    let resp = mint_with(&broker, &key, json!({"repository": REPO})).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(
        asked_permissions(&upstream),
        json!({
            "contents": "write", "issues": "write",
            "metadata": "read", "pull_requests": "write"
        })
    );
}

#[tokio::test]
async fn narrowing_outside_grant_is_403_and_audited() {
    let (broker, key, upstream) = granted().await;
    let before = upstream.received().len();
    // `actions:read` is allowed to be asked for, but this grant does not hold it.
    let resp = mint_with(
        &broker,
        &key,
        json!({"repository": REPO, "permissions": "actions:read,checks:read"}),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    assert!(
        resp.body
            .contains(&format!("{PERMISSIONS_NOT_IN_GRANT}actions:read")),
        "{}",
        resp.body
    );
    assert_eq!(upstream.received().len(), before, "GitHub was not asked");
    let refused = entries(&broker, "github_token_refused");
    assert!(
        refused.last().unwrap()["reason"]
            .as_str()
            .unwrap()
            .contains(PERMISSIONS_NOT_IN_GRANT),
        "{refused:?}"
    );
    // A level above the grant's is outside it too.
    let resp = mint_with(
        &broker,
        &key,
        json!({"repository": REPO, "permissions": "checks:write"}),
    )
    .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    assert!(resp.body.contains("checks:write"), "{}", resp.body);
}

#[tokio::test]
async fn an_unknown_or_malformed_set_is_refused_without_echo() {
    let (broker, key, _upstream) = granted().await;
    for wanted in ["new_thing:write", "contents:admin", ""] {
        let resp = mint_with(
            &broker,
            &key,
            json!({"repository": REPO, "permissions": wanted}),
        )
        .await;
        assert_eq!(
            resp.status,
            StatusCode::BAD_REQUEST,
            "{wanted}: {}",
            resp.body
        );
        assert!(!resp.body.contains("new_thing"), "{}", resp.body);
    }
    assert_eq!(entries(&broker, "github_token_refused").len(), 3);
}

#[tokio::test]
async fn a_stored_grant_with_a_sensitive_permission_for_longer_than_1h_does_not_mint() {
    let (broker, key, upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "workflows:write");
    approve_with_extras(
        &broker,
        &upstream,
        Window::H1,
        "workflows:write",
        &[("workflows", "write")],
    )
    .await;
    let before = upstream.received().len();
    // As approved, within the hour, it mints.
    upstream.script_github_token(answer(
        &broker,
        &[("contents", "write"), ("workflows", "write")],
    ));
    let resp = mint_with(&broker, &key, sensitive_mint()).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    // A row that says 7 days, as no approval makes it, does not.
    sqlx::query("UPDATE grants SET window_secs = ?")
        .bind(7 * 24 * 3600_i64)
        .execute(&broker.state().pool)
        .await
        .unwrap();
    let calls = upstream.received().len();
    assert!(calls > before);
    let resp = mint_with(&broker, &key, sensitive_mint()).await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    assert!(resp.body.contains("sensitive permission"), "{}", resp.body);
    assert_eq!(upstream.received().len(), calls, "GitHub was not asked");
    let refused = entries(&broker, "github_token_refused");
    assert!(
        refused.last().unwrap()["reason"]
            .as_str()
            .unwrap()
            .contains("sensitive permission"),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_stored_grant_whose_not_after_column_alone_was_pushed_out_does_not_mint() {
    let (broker, key, upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "workflows:write");
    approve_with_extras(
        &broker,
        &upstream,
        Window::H1,
        "workflows:write",
        &[("workflows", "write")],
    )
    .await;
    upstream.script_github_token(answer(
        &broker,
        &[("contents", "write"), ("workflows", "write")],
    ));
    let resp = mint_with(&broker, &key, sensitive_mint()).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let refusals = entries(&broker, "github_token_refused").len();
    // Only the column that decides whether the grant is active, by a week.
    sqlx::query("UPDATE grants SET not_after = not_after + ?")
        .bind(7 * 24 * 3600_i64)
        .execute(&broker.state().pool)
        .await
        .unwrap();
    let calls = upstream.received().len();
    let resp = mint_with(&broker, &key, sensitive_mint()).await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    assert!(resp.body.contains("sensitive permission"), "{}", resp.body);
    assert_eq!(upstream.received().len(), calls, "GitHub was not asked");
    let refused = entries(&broker, "github_token_refused");
    assert_eq!(refused.len(), refusals + 1, "{refused:?}");
    assert!(
        refused.last().unwrap()["reason"]
            .as_str()
            .unwrap()
            .contains("sensitive permission"),
        "{refused:?}"
    );
}

#[tokio::test]
async fn info_says_github_token_permissions() {
    let broker = TestBroker::new().await;
    let resp = broker
        .api_send(
            axum::http::Request::get("/v1/info")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(resp.json()["github_token_permissions"], true);
}
