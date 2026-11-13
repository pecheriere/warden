//! A request stored before goals and labels were held to the stricter rules for
//! new text still loads on every page, in the agent's lists and at the relay, and
//! can be revoked. A new request with the same text is refused.

use axum::http::StatusCode;
use serde_json::json;
use ssh_key::PublicKey;
use warden_broker::policy::RelayCredential;
use warden_broker::testkit::{FakeBackend, TestBroker};
use warden_broker_proto::{
    Access, CreateRequest, GrantView, PendingRequest, RequestStatus, TargetName, Window,
};
use zeroize::Zeroizing;

use super::status;

/// A goal with a line separator and a label with a blank filler: both accepted
/// by earlier versions, both refused for a new request.
const GOAL: &str = "copy the backups\u{2028}before the move";
const LABEL: &str = "ops\u{3164}work";

/// A relay request for `backup@nas` with [`GOAL`] and [`LABEL`], read as a
/// stored row is, and its bound key.
fn stored_request() -> (CreateRequest, PublicKey) {
    let mut value =
        serde_json::to_value(TestBroker::relay_request("copy the backups", Window::M30)).unwrap();
    value["goal"] = json!(GOAL);
    value["session"] = json!(LABEL);
    let request: CreateRequest = serde_json::from_value(value).unwrap();
    let Access::Ssh { public_key, .. } = &request.access else {
        panic!("expected an ssh request");
    };
    let public_key = PublicKey::from_openssh(public_key).unwrap();
    (request, public_key)
}

#[tokio::test]
async fn a_stored_request_with_old_text_loads_everywhere_and_can_be_revoked() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    broker.backend.set_relay_target(
        FakeBackend::relay_target(),
        RelayCredential::Password(Zeroizing::new("onward-password".to_owned())),
    );
    let (request, bound) = stored_request();
    assert!(request.check_new().is_err(), "the text must be old-only");
    // Stored as an earlier version stored it: past the API's check for new text.
    let (created, token) = broker.create_request("bot", request.clone()).await;

    let page = broker.get("/pending").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body.contains(created.fingerprint.as_str()),
        "{}",
        page.body
    );
    let listed = broker.api_get(&key, "/v1/requests").await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    let listed: Vec<PendingRequest> = serde_json::from_str(&listed.body).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].goal.as_str(), GOAL);

    let approved = broker.approve(&token, Window::M30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let RequestStatus::Approved(view) = status(&broker, &created.id).await else {
        panic!("expected approved");
    };

    for path in ["/grants", "/history"] {
        let page = broker.get(path).await;
        assert_eq!(page.status, StatusCode::OK, "{path}: {}", page.body);
        assert!(page.body.contains(created.fingerprint.as_str()), "{path}");
    }
    let grants = broker.api_get(&key, "/v1/grants").await;
    assert_eq!(grants.status, StatusCode::OK, "{}", grants.body);
    let grants: Vec<GrantView> = serde_json::from_str(&grants.body).unwrap();
    assert_eq!(grants.len(), 1);
    let nas = TargetName::try_from("nas".to_owned()).unwrap();
    let requests = &broker.state().requests;
    assert!(
        requests
            .active_relay_grant(&nas, &bound)
            .await
            .unwrap()
            .is_some()
    );

    let revoke = broker
        .post_json(
            &format!("/grants/{}/revoke", view.grant_id.as_str()),
            &json!({}),
        )
        .await;
    assert_eq!(revoke.status, StatusCode::OK, "{}", revoke.body);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Revoked);
    assert!(
        requests
            .active_relay_grant(&nas, &bound)
            .await
            .unwrap()
            .is_none()
    );

    // The same text in a new request is refused at the API.
    let sent = serde_json::to_value(&request).unwrap();
    let response = broker.api_post_json(&key, "/v1/requests", &sent).await;
    assert_eq!(
        response.status,
        StatusCode::BAD_REQUEST,
        "{}",
        response.body
    );
    assert!(response.body.contains("goal"), "{}", response.body);
    assert_eq!(
        broker.capture.rung().len(),
        1,
        "only the stored request rang"
    );
}
