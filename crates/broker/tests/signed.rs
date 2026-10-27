//! Signed agent requests (`warden-request-v1`, `docs/agent-protocol.md`
//! section 3): what the broker accepts, and every way a captured, altered or
//! forged request is refused.

use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http_body_util::channel::Channel;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use ssh_encoding::{Decode as _, Encode as _};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, SshSig};
use warden_broker::agents::{self, AgentPublicKey};
use warden_broker::requests::{self, Clock as _};
use warden_broker::signed::{BODY_READ_TIMEOUT, NONCE_RETENTION_SECS};
use warden_broker::testkit::{HttpsUpstream, TEST_OWNER, TestBroker, request_signature};
use warden_broker_proto::signing::{
    AGENT_HEADER, Audience, NAMESPACE, NONCE_HEADER, Nonce, SIGNATURE_HEADER, SignedRequestParts,
    TIMESTAMP_HEADER, canonical_message,
};
use warden_broker_proto::{AgentName, Id, RequestStatus, Window};

const UNAUTHORIZED: &str = r#"{"error":"unauthorized"}"#;

/// Largest body of the ordinary agent routes (`api::BODY_LIMIT`).
const BODY_LIMIT: usize = 16 * 1024;

fn p256() -> Algorithm {
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    }
}

fn name(agent: &str) -> AgentName {
    AgentName::try_from(agent.to_owned()).unwrap()
}

/// A valid `POST /v1/requests` body.
fn create_body(goal: &str) -> Vec<u8> {
    serde_json::to_vec(&TestBroker::pi_request(goal, Window::M15)).unwrap()
}

/// Rows in the nonce table.
async fn nonce_rows(broker: &TestBroker) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM agent_nonces")
        .fetch_one(&broker.state().pool)
        .await
        .unwrap()
}

/// The head of a signed request, to resend it as it is or altered.
fn head(req: Request<Body>) -> Parts {
    req.into_parts().0
}

/// A request with the headers of `parts` (signature included), and the
/// given method, target and body.
fn resend(parts: &Parts, method: &str, target: &str, body: &[u8]) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(target)
        .body(Body::from(body.to_vec()))
        .unwrap();
    *req.headers_mut() = parts.headers.clone();
    req
}

/// `parts` resent exactly as signed, with `body`.
fn again(parts: &Parts, body: &[u8]) -> Request<Body> {
    resend(
        parts,
        parts.method.as_str(),
        parts.uri.path_and_query().unwrap().as_str(),
        body,
    )
}

fn header<'a>(parts: &'a Parts, name: &str) -> &'a str {
    parts.headers[name].to_str().unwrap()
}

/// The signed inputs of `parts`, with `audience`.
fn parts_of<'a>(
    parts: &'a Parts,
    audience: &'a Audience,
    agent: &'a AgentName,
    nonce: &'a Nonce,
    body: &[u8],
) -> SignedRequestParts<'a> {
    SignedRequestParts {
        audience,
        agent,
        method: parts.method.as_str(),
        target: parts.uri.path_and_query().unwrap().as_str(),
        timestamp: header(parts, TIMESTAMP_HEADER).parse().unwrap(),
        nonce,
        body_sha256: Sha256::digest(body).into(),
    }
}

/// An SSHSIG over `message` with an arbitrary namespace and hash, as a
/// `Warden-Signature` value.
fn sign_with(key: &PrivateKey, namespace: &str, hash: HashAlg, message: &str) -> String {
    encode(&key.sign(namespace, hash, message.as_bytes()).unwrap())
}

fn encode(signature: &SshSig) -> String {
    let mut blob = Vec::new();
    signature.encode(&mut blob).unwrap();
    STANDARD.encode(blob)
}

fn set_signature(parts: &mut Parts, value: &str) {
    parts
        .headers
        .insert(SIGNATURE_HEADER, HeaderValue::from_str(value).unwrap());
}

#[tokio::test]
async fn signed_request_accepted() {
    for algorithm in [Algorithm::Ed25519, p256()] {
        let broker = TestBroker::new().await;
        let key = broker.add_signing_agent("bot", algorithm.clone()).await;

        let created = broker
            .api_signed(&key, "bot", "POST", "/v1/requests", &create_body("deploy"))
            .await;
        assert_eq!(
            created.status,
            StatusCode::CREATED,
            "{algorithm}: {}",
            created.body
        );
        let id = created.json()["id"].as_str().unwrap().to_owned();

        // A long poll signs its query and the empty body.
        let polled = broker
            .api_signed(
                &key,
                "bot",
                "GET",
                &format!("/v1/requests/{id}?wait=1"),
                b"",
            )
            .await;
        assert_eq!(polled.status, StatusCode::OK, "{}", polled.body);
        assert_eq!(polled.json()["status"], "pending");

        let grants = broker
            .api_signed(&key, "bot", "GET", "/v1/grants", b"")
            .await;
        assert_eq!(grants.status, StatusCode::OK, "{}", grants.body);
        assert_eq!(grants.body, "[]");

        let cancelled = broker
            .api_signed(
                &key,
                "bot",
                "POST",
                &format!("/v1/requests/{id}/cancel"),
                b"",
            )
            .await;
        assert_eq!(
            cancelled.status,
            StatusCode::NO_CONTENT,
            "{}",
            cancelled.body
        );

        // Authenticated: the grant lookup itself answers.
        let revoke = broker
            .api_signed(
                &key,
                "bot",
                "POST",
                &format!("/v1/grants/{}/revoke", Id::random()),
                b"",
            )
            .await;
        assert_eq!(revoke.status, StatusCode::NOT_FOUND, "{}", revoke.body);

        assert_eq!(nonce_rows(&broker).await, 5);
    }
}

#[tokio::test]
async fn signed_proxy_call_and_grant_revocation() {
    let broker = TestBroker::new().await;
    let upstream = HttpsUpstream::start().await;
    broker
        .backend
        .set_api_secret(upstream.policy("svc"), "s3cret-value-for-tests");
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let mut request = TestBroker::api_request("svc", "call the test api", Window::M30);
    if let warden_broker_proto::Access::Api { methods, .. } = &mut request.access {
        *methods = Some(vec!["POST".to_owned()]);
    }
    let (created, token) = broker.create_request("bot", request).await;
    let done = broker.approve(&token, Window::M30).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    let RequestStatus::Approved(view) = broker
        .state()
        .requests
        .status(&name("bot"), &created.id, Duration::ZERO)
        .await
        .unwrap()
    else {
        panic!("expected approved")
    };
    let grant = view.grant_id;

    // Well above the ordinary 16 KiB limit, within the proxy route's.
    let payload = vec![b'p'; 512 * 1024];
    let body = serde_json::to_vec(&json!({
        "method": "POST",
        "url": upstream.url("/v1/items"),
        "headers": [],
        "body_b64": STANDARD.encode(&payload),
    }))
    .unwrap();
    assert!(body.len() > BODY_LIMIT);
    let resp = broker
        .api_signed(
            &key,
            "bot",
            "POST",
            &format!("/v1/grants/{grant}/http"),
            &body,
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(resp.json()["status"], 200);
    assert_eq!(upstream.received()[0].body, payload);

    let revoked = broker
        .api_signed(
            &key,
            "bot",
            "POST",
            &format!("/v1/grants/{grant}/revoke"),
            b"",
        )
        .await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT, "{}", revoked.body);
}

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
    let other = broker.add_signing_agent("other", p256()).await;
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

fn value(s: &str) -> HeaderValue {
    HeaderValue::from_str(s).unwrap()
}

fn text(headers: &HeaderMap, name: &str) -> String {
    headers[name].to_str().unwrap().to_owned()
}

/// A named change that makes the `Warden-*` headers of a valid request
/// malformed.
type HeaderChange = (&'static str, fn(&mut HeaderMap));

/// Every malformation step 1 must refuse.
const MALFORMED: &[HeaderChange] = &[
    ("no agent", |h| drop(h.remove(AGENT_HEADER))),
    ("no timestamp", |h| drop(h.remove(TIMESTAMP_HEADER))),
    ("no nonce", |h| drop(h.remove(NONCE_HEADER))),
    ("no signature", |h| drop(h.remove(SIGNATURE_HEADER))),
    ("repeated nonce", |h| {
        let nonce = h[NONCE_HEADER].clone();
        h.append(NONCE_HEADER, nonce);
    }),
    ("repeated signature", |h| {
        let signature = h[SIGNATURE_HEADER].clone();
        h.append(SIGNATURE_HEADER, signature);
    }),
    ("repeated agent", |h| {
        h.append(AGENT_HEADER, value("bot"));
    }),
    ("uppercase nonce", |h| {
        let upper = text(h, NONCE_HEADER).to_uppercase();
        h.insert(NONCE_HEADER, value(&upper));
    }),
    ("padded timestamp", |h| {
        let padded = format!("0{}", text(h, TIMESTAMP_HEADER));
        h.insert(TIMESTAMP_HEADER, value(&padded));
    }),
    ("invalid agent name", |h| {
        h.insert(AGENT_HEADER, value("Bot"));
    }),
    ("oversized signature", |h| {
        h.insert(SIGNATURE_HEADER, value(&"A".repeat(4097)));
    }),
    ("signature not base64", |h| {
        h.insert(SIGNATURE_HEADER, value("not base64!"));
    }),
    ("signature with trailing bytes", |h| {
        let mut blob = STANDARD.decode(text(h, SIGNATURE_HEADER)).unwrap();
        blob.push(0);
        h.insert(SIGNATURE_HEADER, value(&STANDARD.encode(blob)));
    }),
    ("reserved warden header", |h| {
        h.insert("Warden-Extra", value("1"));
    }),
    ("signature without padding", |h| {
        let padded = text(h, SIGNATURE_HEADER);
        let unpadded = padded.trim_end_matches('=');
        assert_ne!(unpadded, padded, "an Ed25519 SSHSIG is padded");
        h.insert(SIGNATURE_HEADER, value(unpadded));
    }),
];

#[tokio::test]
async fn malformed_signature_headers_refused() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let parts = head(broker.signed_request(&key, "bot", "GET", "/v1/grants", Vec::new()));

    for (what, change) in MALFORMED {
        let mut req = again(&parts, b"");
        change(req.headers_mut());
        let resp = broker.api_send(req).await;
        assert_eq!(
            resp.status,
            StatusCode::UNAUTHORIZED,
            "{what}: {}",
            resp.body
        );
        assert_eq!(resp.body, UNAUTHORIZED, "{what}");
    }
    assert_eq!(nonce_rows(&broker).await, 0);

    let resp = broker.api_send(again(&parts, b"")).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
}

#[tokio::test]
async fn both_bearer_and_signature_refused() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let bearer = broker.add_agent("legacy").await;

    // A valid signature with an Authorization header.
    let mut req = broker.signed_request(&key, "bot", "GET", "/v1/grants", Vec::new());
    req.headers_mut().insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {bearer}")).unwrap(),
    );
    req.headers_mut()
        .insert("Tailscale-User-Login", HeaderValue::from_static(TEST_OWNER));
    let resp = broker.api_send(req).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    assert_eq!(resp.body, UNAUTHORIZED);

    // A valid bearer key from the owner, with any Warden-* header.
    for extra in [
        AGENT_HEADER,
        NONCE_HEADER,
        SIGNATURE_HEADER,
        "Warden-Whatever",
    ] {
        let req = Request::get("/v1/grants")
            .header("Tailscale-User-Login", TEST_OWNER)
            .header("Authorization", format!("Bearer {bearer}"))
            .header(extra, "legacy")
            .body(Body::empty())
            .unwrap();
        let resp = broker.api_send(req).await;
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED, "{extra}");
        assert_eq!(resp.body, UNAUTHORIZED);
    }
    assert_eq!(nonce_rows(&broker).await, 0);

    // Each alone works.
    let resp = broker.api_get(&bearer, "/v1/grants").await;
    assert_eq!(resp.status, StatusCode::OK);
    let resp = broker
        .api_signed(&key, "bot", "GET", "/v1/grants", b"")
        .await;
    assert_eq!(resp.status, StatusCode::OK);
}

#[tokio::test]
async fn key_agent_needs_no_owner_login_bearer_still_does() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let bearer = broker.add_agent("legacy").await;

    // No login (a tagged device), or another user's: the signature decides.
    let resp = broker
        .api_signed(&key, "bot", "GET", "/v1/grants", b"")
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let mut req = broker.signed_request(&key, "bot", "GET", "/v1/grants", Vec::new());
    req.headers_mut().insert(
        "Tailscale-User-Login",
        HeaderValue::from_static("mallory@example.com"),
    );
    let resp = broker.api_send(req).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);

    // A bearer key still needs the owner's login.
    let req = Request::get("/v1/grants")
        .header("Authorization", format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap();
    let resp = broker.api_send(req).await;
    assert_eq!(resp.status, StatusCode::FORBIDDEN);
    let resp = broker.api_get(&bearer, "/v1/grants").await;
    assert_eq!(resp.status, StatusCode::OK);
}

#[tokio::test]
async fn oversized_body_refused_before_verification() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let big = vec![b' '; BODY_LIMIT + 1];

    // Validly signed, too large: 413.
    let resp = broker
        .api_signed(&key, "bot", "POST", "/v1/requests", &big)
        .await;
    assert_eq!(resp.status, StatusCode::PAYLOAD_TOO_LARGE, "{}", resp.body);

    // Badly signed and too large: 413 too, the body is read first.
    let mut parts = head(broker.signed_request(&key, "bot", "POST", "/v1/requests", Vec::new()));
    let stranger = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
    set_signature(
        &mut parts,
        &sign_with(&stranger, NAMESPACE, HashAlg::Sha512, "x"),
    );
    let resp = broker.api_send(again(&parts, &big)).await;
    assert_eq!(resp.status, StatusCode::PAYLOAD_TOO_LARGE, "{}", resp.body);

    // Exactly the limit is read and checked (and is not a valid request).
    let resp = broker
        .api_signed(&key, "bot", "POST", "/v1/requests", &big[1..])
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    assert_eq!(nonce_rows(&broker).await, 1);
}

#[tokio::test]
async fn unauthenticated_cannot_insert_nonces() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let _legacy = broker.add_agent("legacy").await;
    let stranger = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();

    for _ in 0..20 {
        for (agent, signer) in [
            ("bot", &stranger),
            ("ghost", &stranger),
            ("legacy", &stranger),
        ] {
            let resp = broker
                .api_signed(signer, agent, "GET", "/v1/grants", b"")
                .await;
            assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
        }
        // Validly signed but stale.
        let stale = broker.signed_request(&key, "bot", "GET", "/v1/grants", Vec::new());
        broker.clock.advance(61);
        assert_eq!(
            broker.api_send(stale).await.status,
            StatusCode::UNAUTHORIZED
        );
        broker.clock.advance(-61);
    }
    assert_eq!(nonce_rows(&broker).await, 0);

    let resp = broker
        .api_signed(&key, "bot", "GET", "/v1/grants", b"")
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(nonce_rows(&broker).await, 1);
}

#[tokio::test]
async fn nonces_expire() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let parts = head(broker.signed_request(&key, "bot", "GET", "/v1/grants", Vec::new()));
    let resp = broker.api_send(again(&parts, b"")).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(nonce_rows(&broker).await, 1);

    broker.clock.advance(599);
    assert_eq!(broker.state().requests.sweep_nonces().await.unwrap(), 0);
    assert_eq!(nonce_rows(&broker).await, 1);
    broker.clock.advance(1);
    assert_eq!(broker.state().requests.sweep_nonces().await.unwrap(), 1);
    assert_eq!(nonce_rows(&broker).await, 0);

    // Forgotten, but long stale: the replay is still refused.
    let resp = broker.api_send(again(&parts, b"")).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
}

/// Run `ssh-keygen` with `args`; `None` if it is not installed.
async fn ssh_keygen(args: &[&str], auth_sock: Option<&Path>, stdin: &[u8]) -> Option<Vec<u8>> {
    use tokio::io::AsyncWriteExt as _;
    let mut cmd = tokio::process::Command::new("ssh-keygen");
    cmd.args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    match auth_sock {
        Some(sock) => cmd.env("SSH_AUTH_SOCK", sock),
        None => cmd.env_remove("SSH_AUTH_SOCK"),
    };
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("ssh-keygen: {e}"),
    };
    let mut input = child.stdin.take().unwrap();
    input.write_all(stdin).await.unwrap();
    drop(input);
    let out = child.wait_with_output().await.unwrap();
    assert!(
        out.status.success(),
        "ssh-keygen {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(out.stdout)
}

/// The canonical message, written out by hand from the protocol document.
fn message_by_hand(
    audience: &Audience,
    agent: &str,
    method: &str,
    target: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> String {
    format!(
        "warden-request-v1\naudience:{audience}\nagent:{agent}\nmethod:{method}\ntarget:{target}\n\
         timestamp:{timestamp}\nnonce:{nonce}\nbody-sha256:{}\n",
        hex::encode(Sha256::digest(body))
    )
}

/// An agent whose key `ssh-keygen` holds: in a file, or in an `ssh-agent`.
struct OpenSshSigner<'a> {
    agent: &'a str,
    /// The `.pub` file to enroll.
    public: &'a Path,
    /// What `ssh-keygen -Y sign -f` is given: the private key file, or the
    /// `.pub` file when the key is in the agent at `auth_sock`.
    sign_with: &'a Path,
    auth_sock: Option<&'a Path>,
}

/// Enroll `signer`, sign `method target body` with `ssh-keygen -Y sign` and
/// send it over real HTTP to the API at `api`.
async fn openssh_round_trip(
    broker: &TestBroker,
    api: &url::Url,
    signer: &OpenSshSigner<'_>,
    (method, target, body): (&str, &str, &[u8]),
) -> StatusCode {
    let line = std::fs::read_to_string(signer.public).unwrap();
    let key = AgentPublicKey::parse(&line).unwrap();
    let agent = signer.agent;
    agents::add_key_audited(
        &broker.state().pool,
        &broker.state().audit,
        &name(agent),
        &key,
    )
    .await
    .unwrap();
    let timestamp = broker.clock.now();
    let nonce = Nonce::random();
    let audience = broker.state().audience.clone();
    let message = message_by_hand(
        &audience,
        agent,
        method,
        target,
        timestamp,
        nonce.as_str(),
        body,
    );
    let armored = ssh_keygen(
        &[
            "-Y",
            "sign",
            "-n",
            "warden-request-v1",
            "-f",
            signer.sign_with.to_str().unwrap(),
        ],
        signer.auth_sock,
        message.as_bytes(),
    )
    .await
    .expect("ssh-keygen is installed");
    let armored = String::from_utf8(armored).unwrap();
    // The header value: the armor without its BEGIN/END lines, joined.
    let lines: Vec<&str> = armored.lines().collect();
    assert!(
        lines
            .first()
            .unwrap()
            .starts_with("-----BEGIN SSH SIGNATURE")
    );
    let signature: String = lines[1..lines.len() - 1].concat();

    let url = api.join(target.trim_start_matches('/')).unwrap();
    assert_eq!(&url[url::Position::BeforePath..], target);
    let resp = reqwest::Client::new()
        .request(method.parse().unwrap(), url)
        .header(AGENT_HEADER, agent)
        .header(TIMESTAMP_HEADER, timestamp.to_string())
        .header(NONCE_HEADER, nonce.as_str())
        .header(SIGNATURE_HEADER, signature)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .unwrap();
    resp.status()
}

#[tokio::test]
async fn openssh_ssh_keygen_signature_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name);
    let keygen = |kind: &'static [&'static str], file: std::path::PathBuf| async move {
        let file = file.to_str().unwrap().to_owned();
        let mut args = vec!["-q", "-N", "", "-C", "interop-test"];
        args.extend_from_slice(kind);
        args.extend_from_slice(&["-f", &file]);
        ssh_keygen(&args, None, b"").await
    };
    if keygen(&["-t", "ed25519"], path("ed")).await.is_none() {
        eprintln!("ssh-keygen not installed; skipping the OpenSSH interop test");
        return;
    }
    keygen(&["-t", "ecdsa", "-b", "256"], path("p256"))
        .await
        .unwrap();
    keygen(&["-t", "ecdsa", "-b", "256"], path("p256-agent"))
        .await
        .unwrap();

    let broker = TestBroker::new().await;
    let urls = broker.spawn().await;

    // Ed25519 key file, a POST with a body.
    let signer = OpenSshSigner {
        agent: "ed-bot",
        public: &path("ed.pub"),
        sign_with: &path("ed"),
        auth_sock: None,
    };
    let body = create_body("interop");
    let status =
        openssh_round_trip(&broker, &urls.api, &signer, ("POST", "/v1/requests", &body)).await;
    assert_eq!(status, StatusCode::CREATED);

    // ECDSA P-256 key file, a GET with a query.
    let signer = OpenSshSigner {
        agent: "p256-bot",
        public: &path("p256.pub"),
        sign_with: &path("p256"),
        auth_sock: None,
    };
    let status = openssh_round_trip(
        &broker,
        &urls.api,
        &signer,
        ("GET", "/v1/grants?interop=1", b""),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // ECDSA P-256 held only by an ssh-agent (as a Secure Enclave or TPM key
    // is): ssh-keygen is given the public key and asks the agent.
    let sock = path("agent.sock");
    let mut agent = tokio::process::Command::new("ssh-agent")
        .args(["-D", "-a", sock.to_str().unwrap()])
        .stdout(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("ssh-agent ships with ssh-keygen");
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let added = tokio::process::Command::new("ssh-add")
        .arg(path("p256-agent"))
        .env("SSH_AUTH_SOCK", &sock)
        .output()
        .await
        .unwrap();
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    // No private key file beside the .pub: only the agent can sign.
    std::fs::remove_file(path("p256-agent")).unwrap();
    let signer = OpenSshSigner {
        agent: "enclave-bot",
        public: &path("p256-agent.pub"),
        sign_with: &path("p256-agent.pub"),
        auth_sock: Some(&sock),
    };
    let status = openssh_round_trip(&broker, &urls.api, &signer, ("GET", "/v1/grants", b"")).await;
    assert_eq!(status, StatusCode::OK);
    agent.kill().await.unwrap();
}

#[tokio::test]
async fn stalled_body_times_out_before_verification() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let parts = head(broker.signed_request(&key, "bot", "POST", "/v1/requests", Vec::new()));
    // A body whose sender stays open and never sends anything.
    let (sender, stalled) = Channel::<Bytes, Infallible>::new(1);
    let mut req = Request::post("/v1/requests")
        .body(Body::new(stalled))
        .unwrap();
    *req.headers_mut() = parts.headers.clone();

    let started = Instant::now();
    let resp = broker.api_send(req).await;
    let waited = started.elapsed();
    assert_eq!(resp.status, StatusCode::REQUEST_TIMEOUT, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"request body timed out"}"#);
    assert!(waited >= BODY_READ_TIMEOUT, "{waited:?}");
    assert!(
        waited < BODY_READ_TIMEOUT + Duration::from_secs(5),
        "{waited:?}"
    );
    assert_eq!(nonce_rows(&broker).await, 0);
    drop(sender);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_replays_accept_exactly_one() {
    const COPIES: usize = 16;
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let urls = broker.spawn().await;
    let parts = head(broker.signed_request(&key, "bot", "GET", "/v1/grants", Vec::new()));
    let url = urls.api.join("v1/grants").unwrap();
    let client = reqwest::Client::new();

    let start = Arc::new(tokio::sync::Barrier::new(COPIES));
    let mut sends = tokio::task::JoinSet::new();
    for _ in 0..COPIES {
        let request = client.get(url.clone()).headers(parts.headers.clone());
        let start = start.clone();
        sends.spawn(async move {
            start.wait().await;
            request.send().await.unwrap().status()
        });
    }
    let statuses = sends.join_all().await;
    let ok = statuses.iter().filter(|s| **s == StatusCode::OK).count();
    let refused = statuses
        .iter()
        .filter(|s| **s == StatusCode::UNAUTHORIZED)
        .count();
    assert_eq!((ok, refused), (1, COPIES - 1), "{statuses:?}");
    assert_eq!(nonce_rows(&broker).await, 1);
}

#[tokio::test]
async fn sweep_loop_forgets_expired_nonces() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let resp = broker
        .api_signed(&key, "bot", "GET", "/v1/grants", b"")
        .await;
    assert_eq!(resp.status, StatusCode::OK);

    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let sweeper = tokio::spawn(requests::sweep_loop(
        broker.state().requests.clone(),
        Duration::from_millis(10),
        stop_rx,
    ));
    // Several sweeps run while the nonce is still within its retention.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(nonce_rows(&broker).await, 1);

    broker.clock.advance(NONCE_RETENTION_SECS);
    let deadline = Instant::now() + Duration::from_secs(5);
    while nonce_rows(&broker).await != 0 {
        assert!(Instant::now() < deadline, "the sweeper kept the nonce");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    stop.send_replace(true);
    sweeper.await.unwrap();
}

#[tokio::test]
async fn funnel_requests_refused_on_every_api_route() {
    const FUNNEL: &str = "Tailscale-Funnel-Request";
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let bearer = broker.add_agent("legacy").await;

    // A validly signed request that came in through Funnel: refused before
    // its body is read or its nonce recorded.
    for (method, target, body) in [
        ("GET", "/v1/grants", Vec::new()),
        ("POST", "/v1/requests", create_body("via funnel")),
    ] {
        let mut req = broker.signed_request(&key, "bot", method, target, body);
        req.headers_mut().insert(FUNNEL, value("?1"));
        let resp = broker.api_send(req).await;
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED, "{target}");
        assert_eq!(resp.body, UNAUTHORIZED, "{target}");
    }
    assert_eq!(nonce_rows(&broker).await, 0);

    // A bearer key with the owner's login, through Funnel: refused too.
    let req = Request::get("/v1/grants")
        .header("Tailscale-User-Login", TEST_OWNER)
        .header("Authorization", format!("Bearer {bearer}"))
        .header(FUNNEL, "?1")
        .body(Body::empty())
        .unwrap();
    let resp = broker.api_send(req).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    assert_eq!(resp.body, UNAUTHORIZED);

    // The unauthenticated routes too, whatever the header's value.
    for path in ["/v1/info", "/healthz", "/nowhere"] {
        let req = Request::get(path)
            .header(FUNNEL, "")
            .body(Body::empty())
            .unwrap();
        let resp = broker.api_send(req).await;
        assert_eq!(resp.status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(resp.body, UNAUTHORIZED, "{path}");
    }

    // Without the header, the same calls work.
    let resp = broker
        .api_signed(&key, "bot", "GET", "/v1/grants", b"")
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(
        broker.api_get(&bearer, "/v1/grants").await.status,
        StatusCode::OK
    );
    let resp = broker
        .api_send(Request::get("/v1/info").body(Body::empty()).unwrap())
        .await;
    assert_eq!(resp.status, StatusCode::OK);
}
