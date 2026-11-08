//! Signed agent requests (`warden-request-v1`, `docs/agent-protocol.md`
//! section 3): what the broker accepts, and every way a captured, altered or
//! forged request is refused.

use axum::body::Body;
use axum::http::request::Parts;
use axum::http::{HeaderValue, Request};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest as _, Sha256};
use ssh_encoding::Encode as _;
use ssh_key::{HashAlg, PrivateKey, SshSig};
use warden_broker::test_keys;
use warden_broker::testkit::TestBroker;
use warden_broker_proto::signing::{
    Audience, Nonce, SIGNATURE_HEADER, SignedRequestParts, TIMESTAMP_HEADER,
};
use warden_broker_proto::{AgentName, Window};

mod accepted;
mod body;
mod forgery;
mod headers;
mod nonces;
mod openssh;

const UNAUTHORIZED: &str = r#"{"error":"unauthorized"}"#;

/// Largest body of the ordinary agent routes (`api::BODY_LIMIT`).
const BODY_LIMIT: usize = 16 * 1024;

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
    encode(&test_keys::sign(key, namespace, hash, message.as_bytes()))
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
