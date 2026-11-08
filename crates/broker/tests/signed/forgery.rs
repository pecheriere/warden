//! Captured, altered or forged requests: replays, stale timestamps, another
//! audience, tampering, and the wrong agent or key.

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ssh_encoding::Decode as _;
use ssh_key::{Algorithm, HashAlg, PrivateKey, SshSig};
use warden_broker::agents;
use warden_broker::test_keys::P256;
use warden_broker::testkit::{TestBroker, request_signature};
use warden_broker_proto::signing::{
    Audience, NAMESPACE, NONCE_HEADER, Nonce, SIGNATURE_HEADER, canonical_message,
};

use super::{
    UNAUTHORIZED, again, create_body, encode, head, header, name, nonce_rows, parts_of, resend,
    set_signature, sign_with,
};

#[tokio::test]
async fn replayed_nonce_refused() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let body = create_body("deploy");
    let first = head(broker.signed_request(&key, "bot", "POST", "/v1/requests", body.clone()));

    let resp = broker.api_send(again(&first, &body)).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.body);
    let resp = broker.api_send(again(&first, &body)).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    assert_eq!(resp.body, UNAUTHORIZED);
    assert_eq!(
        broker.audit_summaries().len(),
        1,
        "the replay created nothing"
    );

    // A fresh signature over the same request is a new request.
    let fresh = broker
        .api_signed(&key, "bot", "GET", "/v1/grants", b"")
        .await;
    assert_eq!(fresh.status, StatusCode::OK);
}

#[tokio::test]
async fn stale_or_future_timestamp_refused() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;

    // Signed now, arriving 61 s later: refused; 60 s later: accepted. The
    // refusal did not use up the nonce.
    let stale = head(broker.signed_request(&key, "bot", "GET", "/v1/grants", Vec::new()));
    broker.clock.advance(61);
    let resp = broker.api_send(again(&stale, b"")).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    assert_eq!(resp.body, UNAUTHORIZED);
    broker.clock.advance(-1);
    let resp = broker.api_send(again(&stale, b"")).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);

    // Signed with a clock 61 s ahead of the broker's: refused; 60 s: accepted.
    let future = head(broker.signed_request(&key, "bot", "GET", "/v1/grants", Vec::new()));
    broker.clock.advance(-61);
    let resp = broker.api_send(again(&future, b"")).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    broker.clock.advance(1);
    let resp = broker.api_send(again(&future, b"")).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
}

#[tokio::test]
async fn other_audience_refused() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let agent = name("bot");
    let mut parts = head(broker.signed_request(&key, "bot", "GET", "/v1/grants", Vec::new()));
    let nonce = Nonce::try_from(header(&parts, NONCE_HEADER).to_owned()).unwrap();

    let elsewhere = Audience::random();
    let signature = request_signature(&key, &parts_of(&parts, &elsewhere, &agent, &nonce, b""));
    set_signature(&mut parts, &signature);
    let resp = broker.api_send(again(&parts, b"")).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    assert_eq!(resp.body, UNAUTHORIZED);

    // The same construction with this broker's audience is accepted.
    let own = broker.state().audience.clone();
    let signature = request_signature(&key, &parts_of(&parts, &own, &agent, &nonce, b""));
    set_signature(&mut parts, &signature);
    let resp = broker.api_send(again(&parts, b"")).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
}

#[tokio::test]
async fn tampered_method_target_body_refused() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let created = broker
        .api_signed(&key, "bot", "POST", "/v1/requests", &create_body("first"))
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let id = created.json()["id"].as_str().unwrap().to_owned();
    let rows = nonce_rows(&broker).await;

    let body = create_body("deploy");
    let post = head(broker.signed_request(&key, "bot", "POST", "/v1/requests", body.clone()));
    let poll_target = format!("/v1/requests/{id}?wait=0");
    let poll = head(broker.signed_request(&key, "bot", "GET", &poll_target, Vec::new()));
    let grants = head(broker.signed_request(&key, "bot", "POST", "/v1/grants", Vec::new()));
    let cancel_target = format!("/v1/requests/{id}/cancel");
    let cancel = head(broker.signed_request(&key, "bot", "POST", &cancel_target, Vec::new()));

    for (what, req) in [
        (
            "other body",
            resend(&post, "POST", "/v1/requests", &create_body("other")),
        ),
        (
            "body appended",
            resend(&post, "POST", "/v1/requests", &[&body[..], b" "].concat()),
        ),
        ("empty body", resend(&post, "POST", "/v1/requests", b"")),
        (
            "other query",
            resend(&poll, "GET", &format!("/v1/requests/{id}?wait=1"), b""),
        ),
        (
            "query dropped",
            resend(&poll, "GET", &format!("/v1/requests/{id}"), b""),
        ),
        (
            "query added",
            resend(&grants, "GET", "/v1/grants?wait=0", b""),
        ),
        ("other method", resend(&grants, "GET", "/v1/grants", b"")),
        (
            "other path",
            resend(&cancel, "POST", &format!("/v1/grants/{id}/revoke"), b""),
        ),
    ] {
        let resp = broker.api_send(req).await;
        assert_eq!(
            resp.status,
            StatusCode::UNAUTHORIZED,
            "{what}: {}",
            resp.body
        );
        assert_eq!(resp.body, UNAUTHORIZED, "{what}");
    }
    assert_eq!(
        nonce_rows(&broker).await,
        rows,
        "refused requests left no nonce"
    );

    // Sent as signed, they still go through.
    let resp = broker.api_send(again(&post, &body)).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.body);
    let resp = broker.api_send(again(&poll, b"")).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let resp = broker.api_send(again(&cancel, b"")).await;
    assert_eq!(resp.status, StatusCode::NO_CONTENT, "{}", resp.body);
}

#[tokio::test]
async fn wrong_agent_or_key_refused() {
    let broker = TestBroker::new().await;
    let bot = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let other = broker.add_signing_agent("other", P256).await;
    let _legacy = broker.add_agent("legacy").await;
    let stranger = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();

    let refused = [
        (
            "another agent's key",
            broker.signed_request(&other, "bot", "GET", "/v1/grants", Vec::new()),
        ),
        (
            "a key claiming another agent",
            broker.signed_request(&bot, "other", "GET", "/v1/grants", Vec::new()),
        ),
        (
            "an unregistered key",
            broker.signed_request(&stranger, "bot", "GET", "/v1/grants", Vec::new()),
        ),
        (
            "an unknown agent",
            broker.signed_request(&stranger, "ghost", "GET", "/v1/grants", Vec::new()),
        ),
        (
            "a bearer-key agent",
            broker.signed_request(&stranger, "legacy", "GET", "/v1/grants", Vec::new()),
        ),
    ];
    for (what, req) in refused {
        let resp = broker.api_send(req).await;
        assert_eq!(
            resp.status,
            StatusCode::UNAUTHORIZED,
            "{what}: {}",
            resp.body
        );
        assert_eq!(resp.body, UNAUTHORIZED, "{what}");
    }

    // A blob naming bot's key around a valid signature by another key.
    let mut parts = head(broker.signed_request(&other, "bot", "GET", "/v1/grants", Vec::new()));
    let blob = STANDARD.decode(header(&parts, SIGNATURE_HEADER)).unwrap();
    let by_other = SshSig::decode(&mut blob.as_slice()).unwrap();
    let relabelled = SshSig::new(
        bot.public_key().key_data().clone(),
        NAMESPACE,
        HashAlg::Sha512,
        by_other.signature().clone(),
    )
    .unwrap();
    set_signature(&mut parts, &encode(&relabelled));
    let resp = broker.api_send(again(&parts, b"")).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);

    // The registered key, in the wrong namespace: refused; with sha256:
    // accepted.
    let parts = head(broker.signed_request(&bot, "bot", "GET", "/v1/grants", Vec::new()));
    let agent = name("bot");
    let nonce = Nonce::try_from(header(&parts, NONCE_HEADER).to_owned()).unwrap();
    let audience = broker.state().audience.clone();
    let message = canonical_message(&parts_of(&parts, &audience, &agent, &nonce, b"")).unwrap();
    for (namespace, hash, expected) in [
        ("file", HashAlg::Sha512, StatusCode::UNAUTHORIZED),
        ("git", HashAlg::Sha256, StatusCode::UNAUTHORIZED),
        (NAMESPACE, HashAlg::Sha256, StatusCode::OK),
    ] {
        let mut parts = head(again(&parts, b""));
        set_signature(&mut parts, &sign_with(&bot, namespace, hash, &message));
        let resp = broker.api_send(again(&parts, b"")).await;
        assert_eq!(resp.status, expected, "{namespace} {hash}: {}", resp.body);
    }

    // A revoked agent's signatures are refused.
    agents::revoke(&broker.state().pool, &agent, 1)
        .await
        .unwrap();
    let resp = broker
        .api_signed(&bot, "bot", "GET", "/v1/grants", b"")
        .await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    assert_eq!(resp.body, UNAUTHORIZED);
}
