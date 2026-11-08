//! The authentication headers: malformed `Warden-*` headers, bearer and
//! signature together, the owner login, and Funnel requests.

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ssh_key::Algorithm;
use warden_broker::testkit::{TEST_OWNER, TestBroker};
use warden_broker_proto::signing::{
    AGENT_HEADER, NONCE_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER,
};

use super::{UNAUTHORIZED, again, create_body, head, nonce_rows};

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
