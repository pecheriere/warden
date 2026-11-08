//! Relay targets: approving them, their live sessions and their bound keys.

use axum::http::StatusCode;
use serde_json::json;
use ssh_key::{Certificate, PublicKey};
use warden_broker::policy::RelayCredential;
use warden_broker::requests::Clock as _;
use warden_broker::testkit::{
    FakeBackend, NAS_HOST, RELAY_PUBLIC_HOST, RELAY_PUBLIC_PORT, TEST_START, TestBroker,
};
use warden_broker_proto::{
    Access, CreatedResponse, GrantAccess, Id, RequestStatus, TargetName, Window,
};
use zeroize::Zeroizing;

use super::{grant_count, pending, status};

/// A broker with agent `bot`, relay target `nas` and one pending 30m relay
/// request for `backup@nas`; also returns the request's bound public key.
async fn relay_pending(broker: TestBroker) -> (TestBroker, CreatedResponse, String, PublicKey) {
    broker.add_agent("bot").await;
    broker.backend.set_relay_target(
        FakeBackend::relay_target(),
        RelayCredential::Password(Zeroizing::new("onward-password".to_owned())),
    );
    let request = TestBroker::relay_request("copy the backups", Window::M30);
    let Access::Ssh { public_key, .. } = &request.access else {
        panic!("expected an ssh request");
    };
    let public_key = PublicKey::from_openssh(public_key).unwrap();
    let (created, token) = broker.create_request("bot", request).await;
    (broker, created, token, public_key)
}

#[tokio::test]
async fn relay_request_approves_without_certificate() {
    let (broker, created, token, _) = relay_pending(TestBroker::new().await).await;
    broker.clock.advance(7);

    let approved = broker.approve(&token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);

    let RequestStatus::Approved(view) = status(&broker, &created.id).await else {
        panic!("expected approved");
    };
    let now = broker.clock.now();
    assert_eq!(view.not_before, now);
    assert_eq!(view.not_after, now + 900);
    let GrantAccess::Relay(relay) = &view.access else {
        panic!("expected a relay grant, got {:?}", view.access);
    };
    assert_eq!(relay.target.as_str(), "nas");
    assert_eq!(relay.user.as_str(), "backup");
    assert_eq!(relay.relay_host, RELAY_PUBLIC_HOST);
    assert_eq!(relay.relay_port, RELAY_PUBLIC_PORT);
    let endpoint = broker.state().requests.relay().expect("relay configured");
    assert_eq!(relay.relay_host_key, endpoint.host_key);
    let host_key = PublicKey::from_openssh(&relay.relay_host_key).unwrap();
    assert_eq!(host_key.algorithm(), ssh_key::Algorithm::Ed25519);
    // Nothing in the grant is (or contains) a certificate.
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("cert"), "{json}");

    let types = broker.audit_types();
    assert!(types.contains(&"approved".to_owned()), "{types:?}");
    assert!(!types.contains(&"cert_issued".to_owned()), "{types:?}");

    // The grants page names the relay.
    let page = broker.get("/grants").await;
    assert!(page.body.contains("via the warden relay"), "{}", page.body);
}

#[tokio::test]
async fn grants_page_lists_live_session_under_its_grant() {
    let (broker, created, token, _) = relay_pending(TestBroker::new().await).await;
    let approved = broker.approve(&token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let RequestStatus::Approved(view) = status(&broker, &created.id).await else {
        panic!("expected approved");
    };
    let grant = view.grant_id;
    let area = format!(r#"<div class="live-area" data-grant="{grant}" data-kind="relay">"#);

    let page = broker.get("/grants").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body.contains(&format!(
            r#"{area}<p class="detail">No sessions open</p></div>"#
        )),
        "{}",
        page.body
    );

    let _session = broker.hold_live_session(&grant, "bot");
    // Another grant's session is not listed under this one.
    let _other = broker.hold_live_session(&Id::random(), "bot");
    let page = broker.get("/grants").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body.contains(&format!(
            r#"{area}<p class="live">1 session open</p><ul class="live-list" role="list"><li><span>Session since <time datetime=""#
        )),
        "{}",
        page.body
    );
    assert!(
        page.body
            .contains(r#"<span><span class="nowrap">0 B to target</span> · <span class="nowrap">0 B from target</span></span>"#),
        "{}",
        page.body
    );
    assert_eq!(
        page.body.matches("<li><span>Session since").count(),
        1,
        "{}",
        page.body
    );

    assert!(
        page.body
            .contains(r#"<span class="nowrap idle">Active now</span>"#),
        "{}",
        page.body
    );
    broker.clock.advance(125);
    let page = broker.get("/grants").await;
    assert!(
        page.body
            .contains(r#"<span class="nowrap idle">Idle 2 min</span>"#),
        "{}",
        page.body
    );
}

/// The page says when the certificate was issued and when it expires, the
/// same as the certificate itself, and never that it was used.
#[tokio::test]
async fn grants_page_shows_the_issued_certificate_and_not_its_use() {
    let (broker, created, token) = pending().await;
    let approved = broker.approve(&token, Window::M30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let RequestStatus::Approved(view) = status(&broker, &created.id).await else {
        panic!("expected approved");
    };
    let GrantAccess::Ssh(ssh) = view.access else {
        panic!("not a certificate grant");
    };
    let cert = Certificate::from_openssh(&ssh.certificate).unwrap();
    // Backdated 60 s to tolerate clock skew with the target.
    assert_eq!(
        i64::try_from(cert.valid_after()).unwrap() + 60,
        TEST_START,
        "issued at the start of the test"
    );
    assert_eq!(
        i64::try_from(cert.valid_before()).unwrap(),
        TEST_START + 1800
    );

    // Time passes: what the page says stays when it was issued.
    broker.clock.advance(60);
    let page = broker.get("/grants").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body.contains(
            r#"data-kind="cert"><p class="detail">Certificate issued <time datetime="2027-01-15T08:00:00Z">08:00 UTC</time>, expires <time datetime="2027-01-15T08:30:00Z">08:30 UTC</time>.</p><p class="detail">Certificate logins are not visible to warden, so this does not show whether it was used.</p></div>"#
        ),
        "{}",
        page.body
    );
}

#[tokio::test]
async fn relay_page_says_via_relay() {
    let (broker, created, token, _) = relay_pending(TestBroker::new().await).await;
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    let html = &page.body;
    assert!(html.contains(created.fingerprint.as_str()), "{html}");
    assert!(
        html.contains(&format!(
            "<code>ssh backup@nas ({NAS_HOST}:22)</code> via the warden relay"
        )),
        "{html}"
    );

    // A cert target's page does not mention the relay.
    let (_, token) = broker
        .create_request("bot", TestBroker::pi_request("look around", Window::M30))
        .await;
    let page = broker.get(&format!("/approve/{token}")).await;
    assert!(!page.body.contains("relay"), "{}", page.body);
}

#[tokio::test]
async fn relay_mode_change_invalidates_the_page() {
    let (broker, _, token) = pending().await;
    let digest = broker.page_target_digest(&token).await;
    // Same host, port and keys, but now relayed: not what the owner saw.
    let mut pi = broker.backend.target("pi");
    pi.mode = warden_broker::policy::SshMode::Relay;
    broker.backend.set_relay_target(
        pi,
        RelayCredential::Password(Zeroizing::new("onward-password".to_owned())),
    );
    let begin = broker
        .begin_approval_for(&token, Window::M15, &digest)
        .await;
    assert_eq!(begin.status, StatusCode::CONFLICT, "{}", begin.body);
    assert_eq!(grant_count(&broker).await, 0);
}

#[tokio::test]
async fn relay_approval_refused_when_relay_not_configured() {
    let (broker, created, token, _) = relay_pending(TestBroker::new().await).await;
    let mut auth = broker.enroll_soft_passkey().await;
    let begin = broker.begin_approval(&token, Window::M15).await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);

    // The broker comes back without WARDEN_RELAY_PUBLIC_ADDR.
    let broker = broker.restart_without_relay().await;
    assert!(broker.state().requests.relay().is_none());
    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    // The ceremony was in memory and is gone; a fresh begin is refused.
    assert_ne!(finish.status, StatusCode::OK, "{}", finish.body);
    let begin = broker.begin_approval(&token, Window::M15).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
    assert!(
        begin.json()["error"]
            .as_str()
            .unwrap()
            .contains("relay is not configured"),
        "{}",
        begin.body
    );
    assert_eq!(grant_count(&broker).await, 0);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);
}

#[tokio::test]
async fn active_relay_grant_matches_bound_key_and_target_only() {
    let (broker, _, token, bound) = relay_pending(TestBroker::new().await).await;
    let requests = &broker.state().requests;
    let nas = TargetName::try_from("nas".to_owned()).unwrap();
    // Nothing before approval.
    assert!(
        requests
            .active_relay_grant(&nas, &bound)
            .await
            .unwrap()
            .is_none()
    );

    let approved = broker.approve(&token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);

    let found = requests
        .active_relay_grant(&nas, &bound)
        .await
        .unwrap()
        .expect("active relay grant for the bound key");
    assert_eq!(found.agent.as_str(), "bot");
    assert_eq!(found.target, nas);
    assert_eq!(found.user.as_str(), "backup");
    assert_eq!(found.not_after, broker.clock.now() + 900);

    // Another key, or the right key on another target, finds nothing.
    let other =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone();
    assert!(
        requests
            .active_relay_grant(&nas, &other)
            .await
            .unwrap()
            .is_none()
    );
    let pi = TargetName::try_from("pi".to_owned()).unwrap();
    assert!(
        requests
            .active_relay_grant(&pi, &bound)
            .await
            .unwrap()
            .is_none()
    );
    // A comment on the offered key does not matter, only the key itself.
    let mut commented = bound.clone();
    commented.set_comment("someone@example.com");
    assert!(
        requests
            .active_relay_grant(&nas, &commented)
            .await
            .unwrap()
            .is_some()
    );

    // Expired: nothing.
    broker.clock.advance(900);
    assert!(
        requests
            .active_relay_grant(&nas, &bound)
            .await
            .unwrap()
            .is_none()
    );
    broker.clock.advance(-900);

    // Revoked: nothing.
    let revoke = broker
        .post_json(
            &format!("/grants/{}/revoke", found.grant_id.as_str()),
            &json!({}),
        )
        .await;
    assert_eq!(revoke.status, StatusCode::OK, "{}", revoke.body);
    assert!(
        requests
            .active_relay_grant(&nas, &bound)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn cert_grant_is_never_an_active_relay_grant() {
    let (broker, _, token) = pending().await;
    let approved = broker.approve(&token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let grants = broker.state().requests.active_grants().await.unwrap();
    let Access::Ssh { public_key, .. } = &grants[0].request.access else {
        panic!("expected an ssh request");
    };
    let key = PublicKey::from_openssh(public_key).unwrap();
    let pi = TargetName::try_from("pi".to_owned()).unwrap();
    assert!(
        broker
            .state()
            .requests
            .active_relay_grant(&pi, &key)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn bound_key_reuse_is_409_on_the_api() {
    let broker = TestBroker::new().await;
    let bot = broker.add_agent("bot").await;
    let other = broker.add_agent("other").await;
    let request = TestBroker::pi_request("look around", Window::M30);
    let body = serde_json::to_value(&request).unwrap();
    let first = broker.api_post_json(&bot, "/v1/requests", &body).await;
    assert_eq!(first.status, StatusCode::CREATED, "{}", first.body);
    let second = broker.api_post_json(&other, "/v1/requests", &body).await;
    assert_eq!(second.status, StatusCode::CONFLICT, "{}", second.body);
    assert_eq!(
        second.json(),
        json!({"error": "this public key is already bound to another request or grant"})
    );
}
