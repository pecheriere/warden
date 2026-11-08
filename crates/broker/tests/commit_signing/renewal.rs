//! Renewing a signing grant, and the notice before one ends.

use axum::http::StatusCode;
use serde_json::json;
use warden_broker::testkit::TestBroker;
use warden_broker_proto::Window;

use super::{approve, entries, granted, sign};

/// The approval token at the end of `link`.
fn token_of(link: &str) -> String {
    link.rsplit('/').next().unwrap().to_owned()
}

#[tokio::test]
async fn renewing_takes_one_passkey_approval_and_replaces_the_grant() {
    let (broker, key, old) = granted().await;
    broker.clock.advance(28 * 86_400);
    let rung_before = broker.capture.rung().len();
    let renewed = broker
        .post_json(&format!("/grants/{old}/renew"), &json!({}))
        .await;
    assert_eq!(renewed.status, StatusCode::OK, "{}", renewed.body);
    let link = renewed.json()["link"].as_str().unwrap().to_owned();
    // The same length as the grant it renews.
    let page = broker.get(&format!("/approve/{}", token_of(&link))).await;
    assert!(
        page.body.contains(r#"value="30d" checked"#),
        "{}",
        page.body
    );
    assert!(page.body.contains("Renew commit signing"), "{}", page.body);
    // Starting it rings nobody, grants nothing and leaves the old grant working.
    assert_eq!(broker.capture.rung().len(), rung_before);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::OK);

    let approved = broker.approve(&token_of(&link), Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);

    let list = broker.api_get(&key, "/v1/grants").await.json();
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 1, "one grant at a time: {list:?}");
    assert_ne!(list[0]["grant_id"], old.as_str());
    let new = list[0]["grant_id"].as_str().unwrap().to_owned();
    let ended = entries(&broker, "grant_revoked");
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0]["grant_id"], old.as_str());
    assert_eq!(ended[0]["by"], "renewed");
    let approvals = entries(&broker, "approved");
    assert_eq!(approvals.len(), 2);
    assert_eq!(approvals[1]["grant_id"], new.as_str());

    // Past the end of the old window, signing goes on under the new one.
    broker.clock.advance(3 * 86_400);
    let resp = sign(&broker, &key).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(resp.json()["grant_id"], new.as_str());

    // Revoking the one there is stops signing: nothing is left behind it.
    let revoked = broker
        .post_json(&format!("/grants/{new}/revoke"), &json!({}))
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.body);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn only_an_active_signing_grant_can_be_renewed() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let (created, token) = broker
        .create_request("bot", TestBroker::pi_request("goal", Window::M15))
        .await;
    assert_eq!(
        broker.approve(&token, Window::M15).await.status,
        StatusCode::OK
    );
    let name = "bot".parse().unwrap();
    let status = broker
        .state()
        .requests
        .status(&name, &created.id, std::time::Duration::ZERO)
        .await
        .unwrap();
    let warden_broker_proto::RequestStatus::Approved(ssh) = status else {
        panic!("not approved");
    };
    let resp = broker
        .post_json(&format!("/grants/{}/renew", ssh.grant_id), &json!({}))
        .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);

    let signing = approve(&broker, "bot").await;
    broker.clock.advance(30 * 86_400);
    let resp = broker
        .post_json(&format!("/grants/{signing}/renew"), &json!({}))
        .await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);
}

#[tokio::test]
async fn a_request_already_waiting_is_what_renewing_opens() {
    let (broker, _, old) = granted().await;
    let (created, stale) = broker
        .create_request(
            "bot",
            TestBroker::commit_signing_request("again", Window::D7),
        )
        .await;
    let renewed = broker
        .post_json(&format!("/grants/{old}/renew"), &json!({}))
        .await;
    assert_eq!(renewed.status, StatusCode::OK, "{}", renewed.body);
    let link = renewed.json()["link"].as_str().unwrap().to_owned();
    // The same request, on a new link.
    assert_ne!(token_of(&link), stale);
    let pending = broker.state().requests.pending_expiries().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].0, created.id);
    // With the goal and window its agent gave, not the grant's, and the page says so.
    let page = broker.get(&format!("/approve/{}", token_of(&link))).await;
    assert!(page.body.contains("again"), "{}", page.body);
    assert!(page.body.contains(r#"value="7d" checked"#), "{}", page.body);
}

fn renewal_notices(broker: &TestBroker) -> Vec<warden_broker::notify::Doorbell> {
    broker
        .capture
        .rung()
        .into_iter()
        .filter(|bell| bell.title.contains("ends soon"))
        .collect()
}

#[tokio::test]
async fn the_owner_hears_once_a_few_days_before_a_grant_ends() {
    let (broker, _, grant) = granted().await;
    let requests = broker.state().requests.clone();

    broker.clock.advance(27 * 86_400 - 1);
    requests.notify_ending_commit_signing().await;
    assert_eq!(renewal_notices(&broker), []);

    broker.clock.advance(1);
    requests.notify_ending_commit_signing().await;
    let notices = renewal_notices(&broker);
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].title, "warden: commit signing for bot ends soon");
    assert!(
        notices[0].message.contains("3 days"),
        "{}",
        notices[0].message
    );
    assert!(notices[0].url.path().ends_with("/grants"));
    let told = entries(&broker, "commit_signing_renewal_notified");
    assert_eq!(told.len(), 1);
    assert_eq!(told[0]["grant_id"], grant);

    broker.clock.advance(86_400);
    requests.notify_ending_commit_signing().await;
    assert_eq!(renewal_notices(&broker).len(), 1, "told once");
}

#[tokio::test]
async fn a_short_grant_is_told_about_late_and_a_revoked_one_not_at_all() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::commit_signing_request("goal", Window::D1),
        )
        .await;
    assert_eq!(
        broker.approve(&token, Window::D1).await.status,
        StatusCode::OK
    );
    let requests = broker.state().requests.clone();
    requests.notify_ending_commit_signing().await;
    assert_eq!(
        renewal_notices(&broker),
        [],
        "not as soon as it is approved"
    );
    broker.clock.advance(18 * 3600);
    requests.notify_ending_commit_signing().await;
    assert_eq!(renewal_notices(&broker).len(), 1);

    let (other, _, grant) = granted().await;
    other.clock.advance(28 * 86_400);
    let revoked = other
        .post_json(&format!("/grants/{grant}/revoke"), &json!({}))
        .await;
    assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.body);
    other.state().requests.notify_ending_commit_signing().await;
    assert_eq!(renewal_notices(&other), []);
}

#[tokio::test]
async fn other_grants_are_never_told_about() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let (_, token) = broker
        .create_request("bot", TestBroker::pi_request("goal", Window::H1))
        .await;
    assert_eq!(
        broker.approve(&token, Window::H1).await.status,
        StatusCode::OK
    );
    broker.clock.advance(3599);
    broker.state().requests.notify_ending_commit_signing().await;
    assert_eq!(renewal_notices(&broker), []);
}
