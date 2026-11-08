//! How long and how much a grant signs: its windows and the daily limit.

use axum::http::StatusCode;
use warden_broker::testkit::{FakeBackend, TestBroker};
use warden_broker_proto::Window;

use super::{approve, assert_refused, entries, granted, sign};

#[tokio::test]
async fn thirty_days_is_for_signing_only() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    broker
        .backend
        .set_api_secret(FakeBackend::example_api_secret(), "not-a-real-secret");
    // Asked for at the API, whatever the CLI would send.
    for (request, says) in [
        (TestBroker::pi_request("goal", Window::D30), "exceeds max"),
        (
            TestBroker::relay_request("goal", Window::D30),
            "exceeds max",
        ),
        (
            TestBroker::api_request("github", "goal", Window::D30),
            "exceeds max",
        ),
    ] {
        let resp = broker
            .api_post_json(
                &key,
                "/v1/requests",
                &serde_json::to_value(&request).unwrap(),
            )
            .await;
        assert_ne!(resp.status, StatusCode::CREATED, "{}", resp.body);
        assert!(
            resp.status == StatusCode::NOT_FOUND || resp.body.contains(says),
            "{}",
            resp.body
        );
    }
    // Chosen at approval: refused before any passkey is asked for.
    let (_, token) = broker
        .create_request("bot", TestBroker::pi_request("goal", Window::M15))
        .await;
    broker.enroll_soft_passkey().await;
    let begin = broker.begin_approval(&token, Window::D30).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
    // A policy cannot say so either.
    assert!("30d".parse::<Window>().is_err());
}

#[tokio::test]
async fn a_grant_lasts_exactly_the_window_approved() {
    let (broker, key, grant) = granted().await;
    let list = broker.api_get(&key, "/v1/grants").await.json();
    assert_eq!(list[0]["grant_id"], grant);
    assert_eq!(list[0]["access"]["kind"], "commit_signing");
    let (not_before, not_after) = (
        list[0]["not_before"].as_i64().unwrap(),
        list[0]["not_after"].as_i64().unwrap(),
    );
    assert_eq!(not_after - not_before, 30 * 86_400);
}

#[tokio::test]
async fn signing_grants_only_take_their_own_windows() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let short = TestBroker::commit_signing_request("goal", Window::H4);
    let resp = broker
        .api_post_json(&key, "/v1/requests", &serde_json::to_value(&short).unwrap())
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::commit_signing_request("goal", Window::D7),
        )
        .await;
    broker.enroll_soft_passkey().await;
    let begin = broker.begin_approval(&token, Window::H1).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
}

#[tokio::test]
async fn the_server_setting_is_the_maximum() {
    let body =
        |window| serde_json::to_value(TestBroker::commit_signing_request("goal", window)).unwrap();
    // The default: 30 days, not 90.
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let resp = broker
        .api_post_json(&key, "/v1/requests", &body(Window::D90))
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    assert!(resp.body.contains("exceeds max 30d"), "{}", resp.body);

    let short = TestBroker::with_commit_signing_max(Window::D7).await;
    let key = short.add_agent("bot").await;
    let resp = short
        .api_post_json(&key, "/v1/requests", &body(Window::D30))
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    let resp = short
        .api_post_json(&key, "/v1/requests", &body(Window::D7))
        .await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.body);

    let long = TestBroker::with_commit_signing_max(Window::D90).await;
    let key = long.add_agent("bot").await;
    let resp = long
        .api_post_json(&key, "/v1/requests", &body(Window::D90))
        .await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.body);
}

#[tokio::test]
async fn a_grant_stops_at_its_daily_limit_and_the_owner_hears_once() {
    let broker = TestBroker::with_commit_signing_per_day(2).await;
    let key = broker.add_agent("bot").await;
    let grant = approve(&broker, "bot").await;
    let other = broker.add_agent("other").await;
    approve(&broker, "other").await;
    assert_eq!(sign(&broker, &key).await.status, StatusCode::OK);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::OK);

    let reads = broker.backend.commit_signing_reads();
    let resp = sign(&broker, &key).await;
    assert_refused(
        &broker,
        &resp,
        StatusCode::TOO_MANY_REQUESTS,
        "limit of signatures",
    );
    assert_eq!(broker.backend.commit_signing_reads(), reads, "no key read");
    let bell = broker.capture.next().await;
    assert_eq!(bell.title, "warden: bot reached its commit signing limit");
    assert!(bell.url.path().ends_with("/grants"));
    assert_eq!(entries(&broker, "commit_signed").len(), 2);
    assert_eq!(
        sign(&broker, &key).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    let reached = entries(&broker, "commit_signing_limit_reached");
    assert_eq!(reached.len(), 1, "once a day");
    assert_eq!(reached[0]["grant_id"], grant);
    assert_eq!(reached[0]["limit"], 2);

    // Per grant: another agent's goes on.
    assert_eq!(sign(&broker, &other).await.status, StatusCode::OK);

    // The next UTC day starts again, and can be told about again.
    broker.clock.advance(86_400);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::OK);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::OK);
    assert_eq!(
        sign(&broker, &key).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(entries(&broker, "commit_signing_limit_reached").len(), 2);
}

#[tokio::test]
async fn the_daily_limit_holds_for_concurrent_calls() {
    let broker = TestBroker::with_commit_signing_per_day(3).await;
    let key = broker.add_agent("bot").await;
    approve(&broker, "bot").await;
    let (first, second, third, fourth, fifth) = tokio::join!(
        sign(&broker, &key),
        sign(&broker, &key),
        sign(&broker, &key),
        sign(&broker, &key),
        sign(&broker, &key),
    );
    let ok = [first, second, third, fourth, fifth]
        .iter()
        .filter(|r| r.status == StatusCode::OK)
        .count();
    assert_eq!(ok, 3);
}
