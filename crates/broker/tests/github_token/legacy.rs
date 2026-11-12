//! GitHub token grants and requests stored before grants were scoped: they name no
//! repository, so the broker ends them when it starts and never mints under one.

use axum::http::StatusCode;
use serde_json::json;
use warden_broker::github_app::GithubApi;
use warden_broker::testkit::TestBroker;
use warden_broker::testkit::upstream::HttpsUpstream;
use warden_broker_proto::github_token::NO_ACTIVE_GRANT;

use super::{configured, entries};

/// A broker with a legacy grant and a legacy pending request from `bot`, as an
/// upgrade finds them. The startup step has already run, before the rows are added.
async fn upgraded() -> (TestBroker, String, String, String) {
    let (broker, key) = configured(TestBroker::new().await).await;
    let grant = broker.insert_legacy_github_grant("bot").await;
    let request = broker.insert_legacy_github_request("bot").await;
    (broker, key, grant.to_string(), request.to_string())
}

#[tokio::test]
async fn startup_ends_unscoped_grants() {
    let (broker, _key, grant, pending) = upgraded().await;
    let requests = broker.state().requests.clone();
    assert_eq!(requests.end_unscoped_github().await.unwrap(), 2);

    assert!(
        requests
            .active_github_token(&"bot".parse().unwrap())
            .await
            .unwrap()
            .is_none()
    );
    let status = |id: &str| {
        let pool = broker.state().pool.clone();
        let id = id.to_owned();
        async move {
            sqlx::query_scalar::<_, String>("SELECT status FROM requests WHERE id = ?")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    assert_eq!(status(&pending).await, "expired");
    let granted: String = sqlx::query_scalar("SELECT request_id FROM grants WHERE id = ?")
        .bind(&grant)
        .fetch_one(&broker.state().pool)
        .await
        .unwrap();
    assert_eq!(status(&granted).await, "revoked");

    let ended = entries(&broker, "github_unscoped_ended");
    assert_eq!(ended.len(), 2, "{ended:?}");
    assert!(
        ended
            .iter()
            .any(|e| e["grant_id"] == grant.as_str() && e["request_id"] == granted.as_str())
    );
    assert!(
        ended
            .iter()
            .any(|e| e["grant_id"].is_null() && e["request_id"] == pending.as_str())
    );
}

#[tokio::test]
async fn ending_unscoped_is_idempotent() {
    let (broker, _key, _grant, _pending) = upgraded().await;
    let requests = broker.state().requests.clone();
    assert_eq!(requests.end_unscoped_github().await.unwrap(), 2);
    let written = std::fs::read_to_string(broker.audit_path()).unwrap();
    assert_eq!(requests.end_unscoped_github().await.unwrap(), 0);
    assert_eq!(
        std::fs::read_to_string(broker.audit_path()).unwrap(),
        written,
        "nothing more is written"
    );
}

#[tokio::test]
async fn a_scoped_grant_survives_the_startup_step() {
    let (broker, _key) = configured(TestBroker::new().await).await;
    let grant = broker
        .insert_scoped_github_grant("bot", &[("example-owner/example-repo", 1001)])
        .await;
    let broker = broker.restart().await;
    let active = broker
        .state()
        .requests
        .active_github_token(&"bot".parse().unwrap())
        .await
        .unwrap()
        .expect("still active");
    assert_eq!(active.grant_id, grant);
    assert_eq!(
        entries(&broker, "github_unscoped_ended"),
        Vec::<serde_json::Value>::new()
    );
}

#[tokio::test]
async fn legacy_grant_still_renders() {
    let (broker, _key, grant, _pending) = upgraded().await;
    let page = broker.get("/grants").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains(&grant), "{}", page.body);
    assert!(page.body.to_lowercase().contains("github"), "{}", page.body);
}

#[tokio::test]
async fn legacy_grant_is_never_minted() {
    let upstream = HttpsUpstream::start().await;
    let api = GithubApi::pinned(
        upstream.origin().parse().unwrap(),
        upstream.origin().parse().unwrap(),
        upstream.ca_pem().as_bytes().to_vec(),
    );
    let (broker, key) = configured(TestBroker::with_github_api(api).await).await;
    broker.insert_legacy_github_grant("bot").await;
    let resp = broker
        .api_post_json(&key, "/v1/github-token", &json!({}))
        .await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN, "{}", resp.body);
    assert!(resp.body.contains(NO_ACTIVE_GRANT), "{}", resp.body);
    assert!(upstream.received().is_empty(), "GitHub was not asked");
}

#[tokio::test]
async fn legacy_grant_not_offered_for_renewal() {
    let (broker, _key, grant, _pending) = upgraded().await;
    let requests = broker.state().requests.clone();
    // A scoped grant from the same time is the control: the step does notice it, so
    // the legacy grant is skipped on purpose and not because nothing is noticed.
    broker
        .insert_scoped_github_grant("bot", &[("example-owner/example-repo", 1001)])
        .await;
    broker.clock.advance(28 * 86_400);
    let ends_soon = || {
        broker
            .capture
            .rung()
            .into_iter()
            .filter(|bell| bell.title.contains("ends soon"))
            .count()
    };
    requests.notify_ending_grants().await;
    assert_eq!(ends_soon(), 1, "only the scoped grant is noticed");
    let notified = entries(&broker, "github_token_renewal_notified");
    assert_eq!(notified.len(), 1, "{notified:?}");
    assert!(
        notified.iter().all(|e| e["grant_id"] != grant.as_str()),
        "{notified:?}"
    );
    let resp = broker
        .post_json(&format!("/grants/{grant}/renew"), &json!({}))
        .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);
}
