//! What the approval, pending, grants and history pages say about a GitHub token.

use axum::http::StatusCode;
use serde_json::json;
use warden_broker::testkit::TestBroker;
use warden_broker_proto::Window;
use warden_broker_proto::github_token::NOT_CONFIGURED;

use super::{configured_on_fake, resolved};

#[tokio::test]
async fn approval_page_names_app_installation_and_permissions() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::github_token_request(
                "push the fix",
                Window::D30,
                &["example-owner/example-repo"],
            ),
        )
        .await;
    upstream.script_github_token(resolved(&broker, &[(1001, "example-owner/example-repo")]));
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK);
    for says in [
        "123456",
        "7654321",
        "contents: write",
        "pull_requests: write",
        "issues: write",
        "metadata: read",
        "on every repository the App is installed on",
        "tokens last 1 hour and cannot be recalled when revoked",
        "30 days",
    ] {
        assert!(page.body.contains(says), "{says}: {}", page.body);
    }
    // Only the windows of this grant, none beyond the server's maximum.
    for window in ["1d", "7d", "30d"] {
        assert!(
            page.body.contains(&format!("value=\"{window}\"")),
            "{window}"
        );
    }
    for not_offered in ["90 days", "value=\"4h\"", "value=\"15m\""] {
        assert!(
            !page.body.contains(not_offered),
            "{not_offered}: {}",
            page.body
        );
    }
    let pending = broker.get("/pending").await;
    assert!(pending.body.contains("7654321"), "{}", pending.body);
    assert!(
        pending
            .body
            .contains("on every repository the App is installed on"),
        "{}",
        pending.body
    );
}

#[tokio::test]
async fn destination_changed_between_page_and_approve() {
    let (broker, _key, upstream) = configured_on_fake().await;
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::github_token_request(
                "push the fix",
                Window::D7,
                &["example-owner/example-repo"],
            ),
        )
        .await;
    let mut auth = broker.enroll_soft_passkey().await;
    upstream.script_github_token(resolved(&broker, &[(1001, "example-owner/example-repo")]));
    let begin = broker.begin_approval(&token, Window::D7).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    // Another installation of the same App.
    let other = warden_broker::policy::GithubAppKey::new(
        "123456".to_owned(),
        1,
        warden_broker::testkit::github_app::RSA2048_PKCS8,
    )
    .unwrap();
    broker.backend.set_github_app(Some(other));
    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(finish.status, StatusCode::CONFLICT, "{}", finish.body);
    assert_eq!(
        finish.json(),
        json!({"error": "policy changed; reload and review"})
    );
    assert!(
        broker
            .get("/grants")
            .await
            .body
            .contains("No active grants")
    );

    // The App removed altogether: a fresh ceremony cannot start, and nothing is granted.
    broker.backend.set_github_app(None);
    let begin = broker.begin_approval(&token, Window::D7).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
    assert!(
        begin.body.contains(NOT_CONFIGURED),
        "the refusal names the cause: {}",
        begin.body
    );
    assert!(
        broker
            .get("/grants")
            .await
            .body
            .contains("No active grants")
    );
}

#[tokio::test]
async fn grants_page_shows_github_token_grant_and_end() {
    let (broker, _key, upstream) = configured_on_fake().await;
    super::approve(&broker, &upstream, "bot", Window::D30).await;
    let grants = broker.get("/grants").await;
    for says in [
        "7654321",
        "(in 30 days)",
        "minted when the agent asks",
        "1 hour",
        "class=\"revoke\"",
        "data-kind=\"github-token\"",
    ] {
        assert!(grants.body.contains(says), "{says}: {}", grants.body);
    }
    assert!(
        !grants.body.contains("No calls in flight"),
        "{}",
        grants.body
    );
    assert!(grants.body.contains("class=\"renew\""), "{}", grants.body);
    let history = broker.get("/history").await;
    assert!(history.body.contains("github token"), "{}", history.body);
    assert!(history.body.contains("30d"), "{}", history.body);
}
