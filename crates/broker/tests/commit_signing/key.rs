//! The signing key: missing, unusable, replaced or unreadable, kept out of
//! every answer, and its public half.

use std::fs;

use axum::http::StatusCode;
use serde_json::Value;
use ssh_key::LineEnding;
use ssh_key::rand_core::OsRng;
use warden_broker::testkit::{CaState, TestBroker};
use warden_broker_proto::Window;
use warden_broker_proto::commit_signing::{NO_ACTIVE_GRANT, NOT_CONFIGURED};

use super::{AUTHOR, PARENT, assert_refused, entries, granted, sign, sign_as};

#[tokio::test]
async fn a_broker_without_a_key_says_so_and_signs_nothing() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    broker.backend.set_commit_signing_key(None);
    let asked = TestBroker::commit_signing_request("goal", Window::D30);
    let resp = broker
        .api_post_json(&key, "/v1/requests", &serde_json::to_value(&asked).unwrap())
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    assert!(resp.body.contains(NOT_CONFIGURED), "{}", resp.body);
    // With a grant, as the key can then go missing, it says that too.
    let (broker, key, _) = granted().await;
    broker.backend.set_commit_signing_key(None);
    let public = broker.api_get(&key, "/v1/commit-signing/key").await;
    assert!(public.body.contains(NOT_CONFIGURED), "{}", public.body);
}

#[tokio::test]
async fn an_agent_with_no_grant_cannot_make_the_broker_read_the_key() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let public = broker.api_get(&key, "/v1/commit-signing/key").await;
    assert_eq!(public.status, StatusCode::FORBIDDEN, "{}", public.body);
    assert!(public.body.contains(NO_ACTIVE_GRANT), "{}", public.body);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::FORBIDDEN);
    let asked =
        serde_json::to_value(TestBroker::commit_signing_request("goal", Window::D30)).unwrap();
    let created = broker.api_post_json(&key, "/v1/requests", &asked).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(broker.backend.commit_signing_reads(), 0);
    // Nor once a grant has ended.
    let (broker, key, _) = granted().await;
    broker.clock.advance(30 * 86_400);
    let reads = broker.backend.commit_signing_reads();
    let public = broker.api_get(&key, "/v1/commit-signing/key").await;
    assert_eq!(public.status, StatusCode::FORBIDDEN, "{}", public.body);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::FORBIDDEN);
    assert_eq!(broker.backend.commit_signing_reads(), reads);
}

#[tokio::test]
async fn a_ca_that_cannot_be_used_blocks_approval_and_having_none_does_not() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::commit_signing_request("goal", Window::D30),
        )
        .await;
    broker.enroll_soft_passkey().await;
    broker.backend.set_ca_state(CaState::Unusable);
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(
        page.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        page.body
    );
    assert!(page.body.contains("SSH CA cannot be read"), "{}", page.body);
    let begin = broker.begin_approval(&token, Window::D30).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
    assert!(
        begin.body.contains("SSH CA cannot be read"),
        "{}",
        begin.body
    );
    // With no CA at all, there is nothing it could be the same as.
    broker.backend.set_ca_state(CaState::Absent);
    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
}

#[tokio::test]
async fn the_ca_key_cannot_be_approved_for_signing() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let good = broker.backend.commit_signing_private_key();
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::commit_signing_request("goal", Window::D30),
        )
        .await;
    broker.enroll_soft_passkey().await;
    broker
        .backend
        .set_commit_signing_key(Some(broker.backend.ca_private_key()));
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(
        page.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        page.body
    );
    assert!(page.body.contains("also the SSH CA key"), "{}", page.body);
    let begin = broker.begin_approval(&token, Window::D30).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
    assert!(begin.body.contains("also the SSH CA key"), "{}", begin.body);
    // A CA that cannot be read refuses too: nothing says the keys differ.
    broker.backend.set_commit_signing_key(Some(good));
    broker.backend.set_ca_outage(Some("out"));
    let begin = broker.begin_approval(&token, Window::D30).await;
    assert_eq!(
        begin.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        begin.body
    );
    broker.backend.set_ca_outage(None);
    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
}

#[tokio::test]
async fn an_unreadable_key_refuses_with_nothing_about_why() {
    let (broker, key, grant) = granted().await;
    broker
        .backend
        .set_commit_signing_outage(Some("connect at 192.0.2.7 refused"));
    let resp = sign(&broker, &key).await;
    assert_refused(
        &broker,
        &resp,
        StatusCode::SERVICE_UNAVAILABLE,
        "secret backend unavailable",
    );
    assert!(!resp.body.contains("192.0.2.7"));
    let refused = entries(&broker, "commit_signing_refused");
    assert_eq!(refused[0]["grant_id"], grant);
    assert!(!refused[0].to_string().contains("192.0.2.7"));
    broker.backend.set_commit_signing_outage(None);
    assert_eq!(sign(&broker, &key).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_new_key_ends_what_was_approved_for_the_old_one() {
    let (broker, key, _) = granted().await;
    broker.backend.set_commit_signing_key(Some(
        ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap(),
    ));
    let resp = sign(&broker, &key).await;
    assert_refused(&broker, &resp, StatusCode::CONFLICT, "key changed");
    assert_eq!(entries(&broker, "commit_signed"), [] as [Value; 0]);
}

#[tokio::test]
async fn the_key_stays_out_of_every_answer_and_the_audit_log() {
    let (broker, key, grant) = granted().await;
    let private = broker.backend.commit_signing_private_key();
    let pem = private.to_openssh(LineEnding::LF).unwrap();
    // The lines of the armor, each long enough not to turn up by chance.
    let needles: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    assert_ne!(needles, [] as [&str; 0]);
    let mut seen = vec![
        sign(&broker, &key).await.body,
        broker.api_get(&key, "/v1/commit-signing/key").await.body,
        broker.api_get(&key, "/v1/grants").await.body,
        broker.get("/grants").await.body,
        broker.get("/history").await.body,
    ];
    let tag = format!("object {PARENT}\ntype commit\ntag v1\ntagger {AUTHOR}\n\nm\n");
    seen.push(sign_as(&broker, &key, "git", tag.as_bytes()).await.body);
    seen.push(fs::read_to_string(broker.audit_path()).unwrap());
    seen.push(format!(
        "{:?}",
        broker.state().backend.commit_signing_key().await.unwrap()
    ));
    let views: Vec<String> = sqlx::query_scalar("SELECT view FROM grants")
        .fetch_all(&broker.state().pool)
        .await
        .unwrap();
    seen.extend(views);
    assert!(seen.iter().any(|text| text.contains(&grant)));
    for text in &seen {
        for needle in &needles {
            assert!(!text.contains(needle), "the key is in: {text}");
        }
    }
}

#[tokio::test]
async fn the_public_key_is_what_setup_needs() {
    let (broker, key, _) = granted().await;
    let view = broker.api_get(&key, "/v1/commit-signing/key").await;
    assert_eq!(view.status, StatusCode::OK, "{}", view.body);
    let view = view.json();
    let public = broker.backend.commit_signing_public_key();
    assert_eq!(view["public_key"], public.to_openssh().unwrap());
    assert_eq!(
        view["fingerprint"],
        public.fingerprint(ssh_key::HashAlg::Sha256).to_string()
    );
    // Agents only.
    let anonymous = broker.api_get("nope", "/v1/commit-signing/key").await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
}
