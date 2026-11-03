//! Signed requests that fail after the ordinary checks: a good signature in a
//! blob altered where the signature does not reach, and a broker that cannot
//! finish checking because its database fails.

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ssh_key::Algorithm;
use warden_broker::test_keys::P256;
use warden_broker::testkit::TestBroker;
use warden_broker_proto::Window;
use warden_broker_proto::signing::SIGNATURE_HEADER;

/// What is done to an SSHSIG blob, and its name for a failure message.
type Alteration = (&'static str, fn(&[u8]) -> Vec<u8>);

/// Where an SSHSIG blob's version field starts: after the `SSHSIG` magic.
const VERSION_AT: usize = 6;

fn create_body() -> Vec<u8> {
    serde_json::to_vec(&TestBroker::pi_request("deploy", Window::M15)).unwrap()
}

async fn count(broker: &TestBroker, query: &'static str) -> i64 {
    sqlx::query_scalar(query)
        .fetch_one(&broker.state().pool)
        .await
        .unwrap()
}

/// Where the length-prefixed string at `at` ends.
fn string_end(blob: &[u8], at: usize) -> usize {
    let length: [u8; 4] = blob[at..at + 4].try_into().unwrap();
    at + 4 + usize::try_from(u32::from_be_bytes(length)).unwrap()
}

/// The span of the reserved string: after the version, public key and namespace.
fn reserved_span(blob: &[u8]) -> (usize, usize) {
    let key_end = string_end(blob, VERSION_AT + 4);
    let namespace_end = string_end(blob, key_end);
    (namespace_end, string_end(blob, namespace_end))
}

/// The hash algorithm's span, which follows the reserved string.
fn hash_span(blob: &[u8]) -> (usize, usize) {
    let (_, hash_at) = reserved_span(blob);
    (hash_at, string_end(blob, hash_at))
}

fn spliced(blob: &[u8], (start, end): (usize, usize), with: &[u8]) -> Vec<u8> {
    [&blob[..start], with, &blob[end..]].concat()
}

fn post(headers: HeaderMap, body: Vec<u8>) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/requests")
        .body(Body::from(body))
        .unwrap();
    *request.headers_mut() = headers;
    request
}

/// The signature covers the message, not the blob's version or reserved field,
/// so a blob altered there still verifies unless it is refused for what it is. A
/// hash outside the protocol is refused as well. Sent unaltered, the same request
/// is accepted: it was good apart from that, and being refused did not use up its
/// nonce. Both key types: they verify through different code.
#[tokio::test]
async fn a_good_signature_in_an_altered_blob_is_refused() {
    let alterations: [Alteration; 3] = [
        ("version 0", |blob| {
            let span = (VERSION_AT, VERSION_AT + 4);
            spliced(blob, span, &0_u32.to_be_bytes())
        }),
        ("something in the reserved field", |blob| {
            spliced(blob, reserved_span(blob), b"\0\0\0\x01x")
        }),
        ("a hash that is not allowed", |blob| {
            spliced(blob, hash_span(blob), b"\0\0\0\x04sha1")
        }),
    ];
    let every_case = [Algorithm::Ed25519, P256]
        .into_iter()
        .flat_map(|algorithm| alterations.map(|alteration| (algorithm.clone(), alteration)));
    for (algorithm, (name, alter)) in every_case {
        let name = format!("{algorithm}: {name}");
        let broker = TestBroker::new().await;
        let key = broker.add_signing_agent("bot", algorithm).await;
        let body = create_body();
        let signed = broker.signed_request(&key, "bot", "POST", "/v1/requests", body.clone());
        let good = signed.headers().clone();
        let blob = STANDARD.decode(&good[SIGNATURE_HEADER]).unwrap();
        let mut bad = good.clone();
        bad.insert(
            SIGNATURE_HEADER,
            HeaderValue::from_str(&STANDARD.encode(alter(&blob))).unwrap(),
        );

        let refused = broker.api_send(post(bad, body.clone())).await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{name}");
        assert_eq!(refused.body, r#"{"error":"unauthorized"}"#, "{name}");
        assert_eq!(
            count(&broker, "SELECT COUNT(*) FROM requests").await,
            0,
            "{name}"
        );
        assert_eq!(
            count(&broker, "SELECT COUNT(*) FROM agent_nonces").await,
            0,
            "{name}"
        );

        let accepted = broker.api_send(post(good, body)).await;
        assert_eq!(accepted.status, StatusCode::CREATED, "{name}");
    }
}

/// Without a record of the nonce a replay could not be told from the original,
/// so a request whose nonce cannot be recorded does not go through.
#[tokio::test]
async fn a_request_whose_nonce_cannot_be_recorded_does_not_go_through() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    sqlx::query("DROP TABLE agent_nonces")
        .execute(&broker.state().pool)
        .await
        .unwrap();

    let resp = broker
        .api_signed(&key, "bot", "POST", "/v1/requests", &create_body())
        .await;
    assert_eq!(
        resp.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        resp.body
    );
    assert!(!resp.body.contains("agent_nonces"), "{}", resp.body);
    assert_eq!(count(&broker, "SELECT COUNT(*) FROM requests").await, 0);
}

/// An agent's key that cannot be read is no reason to let a request in, nor to
/// describe the failure to whoever sent it.
#[tokio::test]
async fn a_request_whose_key_cannot_be_looked_up_does_not_go_through() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    broker.state().pool.close().await;

    let resp = broker
        .api_signed(&key, "bot", "POST", "/v1/requests", &create_body())
        .await;
    assert_eq!(
        resp.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        resp.body
    );
    assert!(!resp.body.contains("closed"), "{}", resp.body);
}
