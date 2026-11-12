//! Who may ask for a GitHub token, for how long, and what approving a second one does.

use axum::http::StatusCode;
use warden_broker::testkit::TestBroker;
use warden_broker_proto::github_token::NOT_CONFIGURED;
use warden_broker_proto::{Access, Window};

use warden_broker::requests::MINTS_PER_HOUR;
use warden_broker::testkit::upstream::HttpsUpstream;

use super::{api_of, approve, configured, configured_on_fake, entries, resolved};

/// Post a GitHub token request for `window` as the agent with `key`.
async fn ask(
    broker: &TestBroker,
    key: &str,
    window: Window,
) -> warden_broker::testkit::TestResponse {
    let request =
        TestBroker::github_token_request("push the fix", window, &["example-owner/example-repo"]);
    broker
        .api_post_json(
            key,
            "/v1/requests",
            &serde_json::to_value(&request).unwrap(),
        )
        .await
}

#[tokio::test]
async fn request_refused_when_app_not_configured() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let resp = ask(&broker, &key, Window::D7).await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    assert!(resp.body.contains(NOT_CONFIGURED), "{}", resp.body);
    assert!(broker.capture.rung().is_empty(), "nobody is rung");
}

#[tokio::test]
async fn window_must_be_1d_7d_or_30d() {
    let (broker, key, upstream) = configured_on_fake().await;
    for window in [Window::M15, Window::H1, Window::H4, Window::D90] {
        let resp = ask(&broker, &key, window).await;
        assert_eq!(
            resp.status,
            StatusCode::BAD_REQUEST,
            "{window:?}: {}",
            resp.body
        );
        assert!(
            resp.body.contains("1d, 7d or 30d"),
            "{window:?}: {}",
            resp.body
        );
    }
    // Each in turn replaces the request waiting before it.
    for window in [Window::D1, Window::D7, Window::D30] {
        let resp = ask(&broker, &key, window).await;
        assert_eq!(
            resp.status,
            StatusCode::CREATED,
            "{window:?}: {}",
            resp.body
        );
    }
    // Chosen at approval: refused before any passkey is asked for.
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::github_token_request("goal", Window::D7, &["example-owner/example-repo"]),
        )
        .await;
    broker.enroll_soft_passkey().await;
    upstream.script_github_token(resolved(&broker, &[(1001, "example-owner/example-repo")]));
    for window in [Window::H1, Window::D90] {
        let begin = broker.begin_approval(&token, window).await;
        assert_eq!(
            begin.status,
            StatusCode::BAD_REQUEST,
            "{window:?}: {}",
            begin.body
        );
    }
}

#[tokio::test]
async fn window_above_server_max_refused() {
    let upstream = HttpsUpstream::start().await;
    let (broker, key) =
        configured(TestBroker::with_github(api_of(&upstream), Window::D7, MINTS_PER_HOUR).await)
            .await;
    let resp = ask(&broker, &key, Window::D30).await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    assert!(resp.body.contains("exceeds max 7d"), "{}", resp.body);
    let resp = ask(&broker, &key, Window::D7).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.body);
    // Chosen at approval, above the maximum: refused too.
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::github_token_request("goal", Window::D7, &["example-owner/example-repo"]),
        )
        .await;
    broker.enroll_soft_passkey().await;
    upstream.script_github_token(resolved(&broker, &[(1001, "example-owner/example-repo")]));
    let begin = broker.begin_approval(&token, Window::D30).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
}

#[tokio::test]
async fn info_publishes_the_server_max() {
    for max in Window::GITHUB_TOKEN {
        let broker = TestBroker::with_github_token_max(max).await;
        let info = broker
            .api_send(
                axum::http::Request::get("/v1/info")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(info.status, StatusCode::OK, "{}", info.body);
        assert_eq!(info.json()["github_token_max_window"], max.label());
    }
}

#[tokio::test]
async fn a_grant_lasts_exactly_the_window_approved() {
    let (broker, key, upstream) = configured_on_fake().await;
    let grant = approve(&broker, &upstream, "bot", Window::D30).await;
    let list = broker.api_get(&key, "/v1/grants").await.json();
    assert_eq!(list[0]["grant_id"], grant);
    assert_eq!(list[0]["access"]["kind"], "github_token");
    let (not_before, not_after) = (
        list[0]["not_before"].as_i64().unwrap(),
        list[0]["not_after"].as_i64().unwrap(),
    );
    assert_eq!(not_after - not_before, 30 * 86_400);
    let active = broker
        .state()
        .requests
        .active_github_token(&"bot".parse().unwrap())
        .await
        .unwrap()
        .expect("the grant is active");
    assert_eq!(active.grant_id.as_str(), grant);
    assert_eq!(active.grant.installation_id, 7_654_321);
    assert!(
        broker
            .state()
            .requests
            .active_github_token(&"other".parse().unwrap())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn approving_new_grant_ends_previous() {
    let (broker, key, upstream) = configured_on_fake().await;
    let old = approve(&broker, &upstream, "bot", Window::D7).await;
    let other_key = broker.add_agent("other").await;
    let other = approve(&broker, &upstream, "other", Window::D7).await;
    let new = approve(&broker, &upstream, "bot", Window::D30).await;
    assert_ne!(old, new);

    let list = broker.api_get(&key, "/v1/grants").await.json();
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 1, "one grant at a time: {list:?}");
    assert_eq!(list[0]["grant_id"], new.as_str());
    // Another agent's grant is left alone.
    let theirs = broker.api_get(&other_key, "/v1/grants").await.json();
    assert_eq!(theirs[0]["grant_id"], other.as_str());

    let ended = entries(&broker, "grant_revoked");
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert_eq!(ended[0]["grant_id"], old.as_str());
    // The new grant covers the same repository, so it replaces the old one.
    assert_eq!(ended[0]["by"], "replaced");
    let replaced = entries(&broker, "github_token_grant_replaced");
    assert_eq!(replaced.len(), 1, "{replaced:?}");
    assert_eq!(replaced[0]["grant_id"], old.as_str());
    assert_eq!(replaced[0]["by_grant"], new.as_str());
    let active = broker
        .state()
        .requests
        .active_github_token(&"bot".parse().unwrap())
        .await
        .unwrap()
        .expect("the new grant is active");
    assert_eq!(active.grant_id.as_str(), new);

    // The request that held the old grant now reads as revoked.
    let history = broker.state().requests.history(10).await.unwrap();
    let revoked = history
        .iter()
        .filter(|e| e.status == "revoked")
        .collect::<Vec<_>>();
    assert_eq!(revoked.len(), 1, "{revoked:?}");
    assert!(matches!(revoked[0].request.access, Access::GithubToken(_)));
}
