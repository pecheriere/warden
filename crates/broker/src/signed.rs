//! Signed agent requests, protocol `warden-request-v1`
//! (`docs/agent-protocol.md`, section 3).
//!
//! [`verify`] is a middleware on every agent route. A request without any
//! `Warden-*` header passes through untouched, to the bearer-key check of
//! [`crate::identity::AuthedAgent`]. A request with one is checked here, in
//! the documented order, stopping at the first failure:
//!
//! 1. the four `Warden-*` headers are present, each once, and well formed,
//!    the signature at most [`MAX_SIGNATURE_LEN`] characters, no other
//!    (reserved) `Warden-*` header and no `Authorization` header is present;
//! 2. the agent exists, is not revoked and has a registered signing key;
//! 3. the timestamp is within [`MAX_CLOCK_SKEW_SECS`] of the broker's clock;
//! 4. the body is read within the route's body limit (413 beyond it) and
//!    within [`BODY_READ_TIMEOUT`] (408 beyond it);
//! 5. the SSHSIG verifies: namespace [`NAMESPACE`], hash `sha512` or
//!    `sha256`, made by exactly the registered key, over the canonical
//!    message rebuilt from the request as received;
//! 6. the nonce is recorded as new for the agent; only now, so callers that
//!    cannot sign cannot fill the nonce table.
//!
//! Every failure except the body's size and time limits is a 401 with the fixed body
//! `{"error":"unauthorized"}`; the reason is logged, never key material or
//! signature bytes. A request that passes carries a [`SignedAgent`]
//! extension and its body, already read, for the handler.

use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{FromRequest as _, OriginalUri, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest as _, Sha256};
use sqlx::SqlitePool;
use ssh_encoding::{Decode as _, Reader as _};
use ssh_key::{HashAlg, PublicKey, SshSig};
use warden_broker_proto::signing::{
    AGENT_HEADER, MAX_CLOCK_SKEW_SECS, NAMESPACE, NONCE_HEADER, Nonce, SIGNATURE_HEADER,
    SignedRequestParts, TIMESTAMP_HEADER, canonical_message, parse_timestamp,
};
use warden_broker_proto::{AgentName, ApiError};

use crate::AppState;
use crate::agents::{self, AgentError};
use crate::identity::AuthRejection;

/// Longest accepted `Warden-Signature`, in characters; longer values are
/// refused before they are decoded. Real signatures are under 400.
pub const MAX_SIGNATURE_LEN: usize = 4096;

/// How long a used nonce is remembered, in seconds: longer than the whole
/// window in which its signature could be accepted (the clock skew allowed
/// on either side).
pub const NONCE_RETENTION_SECS: i64 = 600;

/// How long reading the body of a signed request may take before it is
/// verified. A caller naming a known agent cannot hold a connection open
/// with a trickled body longer than this; it gets a 408.
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The protocol's headers; any other `Warden-*` name is reserved and refused.
const SIGNING_HEADERS: [&str; 4] = [
    AGENT_HEADER,
    TIMESTAMP_HEADER,
    NONCE_HEADER,
    SIGNATURE_HEADER,
];

/// The only SSHSIG version there is.
const SSHSIG_VERSION: u32 = 1;

/// Prefix of the protocol's header names, lowercase as `http` stores them.
const HEADER_PREFIX: &str = "warden-";

/// Request extension: the agent whose signature [`verify`] checked. Only
/// this module can make one, so its presence proves the check passed.
#[derive(Debug, Clone)]
pub struct SignedAgent(AgentName);

impl SignedAgent {
    /// The agent that signed the request.
    #[must_use]
    pub const fn agent(&self) -> &AgentName {
        &self.0
    }
}

/// Whether `headers` carry any `Warden-*` header, which makes the request a
/// signed one: it is then authenticated by its signature or not at all.
#[must_use]
pub fn has_signing_headers(headers: &HeaderMap) -> bool {
    headers
        .keys()
        .any(|name| name.as_str().starts_with(HEADER_PREFIX))
}

/// Why a signed request was refused.
#[derive(Debug)]
enum Refusal {
    /// An authentication failure; the reason is only logged.
    Unauthorized(&'static str),
    /// The body could not be read within the route's limit (or at all).
    Body(StatusCode),
    /// The body did not arrive within [`BODY_READ_TIMEOUT`].
    BodyTimeout,
    /// The database failed.
    Internal,
}

impl Refusal {
    fn into_response(self, agent: Option<&AgentName>) -> Response {
        match self {
            Self::Unauthorized(reason) => {
                // The agent is recorded only once its header has parsed.
                tracing::warn!(
                    agent = agent.map(tracing::field::display),
                    reason,
                    "signed request refused"
                );
                AuthRejection::Unauthorized.into_response()
            }
            Self::Body(status) => (
                status,
                axum::Json(ApiError {
                    error: "request body rejected".to_owned(),
                }),
            )
                .into_response(),
            Self::BodyTimeout => {
                tracing::warn!(
                    agent = agent.map(tracing::field::display),
                    "signed request body too slow"
                );
                (
                    StatusCode::REQUEST_TIMEOUT,
                    axum::Json(ApiError {
                        error: "request body timed out".to_owned(),
                    }),
                )
                    .into_response()
            }
            Self::Internal => AuthRejection::Internal.into_response(),
        }
    }
}

/// The `Warden-*` headers of a request, parsed.
struct SignatureHeaders {
    agent: AgentName,
    timestamp: i64,
    nonce: Nonce,
    signature: SshSig,
}

/// The single value of header `name` as text.
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, Refusal> {
    let mut values = headers.get_all(name).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(Refusal::Unauthorized("Warden-* header missing or repeated"));
    };
    value
        .to_str()
        .map_err(|_| Refusal::Unauthorized("Warden-* header is not visible ASCII"))
}

/// Decode a `Warden-Signature` value: canonical standard base64 of exactly
/// one SSHSIG blob.
fn decode_signature(value: &str) -> Result<SshSig, Refusal> {
    if value.len() > MAX_SIGNATURE_LEN {
        return Err(Refusal::Unauthorized("Warden-Signature too long"));
    }
    let blob = STANDARD
        .decode(value)
        .map_err(|_| Refusal::Unauthorized("Warden-Signature is not base64"))?;
    let mut reader = blob.as_slice();
    let signature = SshSig::decode(&mut reader)
        .map_err(|_| Refusal::Unauthorized("Warden-Signature is not an SSHSIG"))?;
    if !reader.is_finished() {
        return Err(Refusal::Unauthorized("Warden-Signature has trailing bytes"));
    }
    Ok(signature)
}

impl SignatureHeaders {
    /// Step 1: the headers are present, each once, and well formed, and no
    /// `Authorization` header comes with them.
    fn parse(headers: &HeaderMap) -> Result<Self, Refusal> {
        if headers.contains_key(header::AUTHORIZATION) {
            return Err(Refusal::Unauthorized(
                "Authorization and Warden-* headers together",
            ));
        }
        if headers.keys().any(|name| {
            name.as_str().starts_with(HEADER_PREFIX)
                && !SIGNING_HEADERS
                    .iter()
                    .any(|known| name.as_str().eq_ignore_ascii_case(known))
        }) {
            return Err(Refusal::Unauthorized("reserved Warden-* header"));
        }
        let agent = AgentName::try_from(single(headers, AGENT_HEADER)?.to_owned())
            .map_err(|_| Refusal::Unauthorized("Warden-Agent is not an agent name"))?;
        let timestamp = parse_timestamp(single(headers, TIMESTAMP_HEADER)?)
            .map_err(|_| Refusal::Unauthorized("Warden-Timestamp is malformed"))?;
        let nonce = Nonce::try_from(single(headers, NONCE_HEADER)?.to_owned())
            .map_err(|_| Refusal::Unauthorized("Warden-Nonce is malformed"))?;
        let signature = decode_signature(single(headers, SIGNATURE_HEADER)?)?;
        Ok(Self {
            agent,
            timestamp,
            nonce,
            signature,
        })
    }
}

/// Step 5: `signature` is an SSHSIG over `message` in this protocol's
/// namespace, with an allowed hash, by exactly `key`.
fn check_signature(key: &PublicKey, signature: &SshSig, message: &[u8]) -> Result<(), Refusal> {
    if signature.version() != SSHSIG_VERSION {
        return Err(Refusal::Unauthorized("unsupported SSHSIG version"));
    }
    if signature.namespace() != NAMESPACE {
        return Err(Refusal::Unauthorized("signature for another namespace"));
    }
    if !signature.reserved().is_empty() {
        return Err(Refusal::Unauthorized("SSHSIG reserved field not empty"));
    }
    if !matches!(signature.hash_alg(), HashAlg::Sha512 | HashAlg::Sha256) {
        return Err(Refusal::Unauthorized("signature hash not allowed"));
    }
    if signature.public_key() != key.key_data() {
        return Err(Refusal::Unauthorized("signed by another key"));
    }
    key.verify(NAMESPACE, message, signature)
        .map_err(|_| Refusal::Unauthorized("signature does not verify"))
}

/// Middleware: authenticate a signed request (see the module
/// documentation) or pass an unsigned one on unchanged.
///
/// Must sit inside the route's [`axum::extract::DefaultBodyLimit`], whose
/// limit it applies when it reads the body.
pub async fn verify(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if !has_signing_headers(req.headers()) {
        return next.run(req).await;
    }
    let headers = match SignatureHeaders::parse(req.headers()) {
        Ok(headers) => headers,
        Err(refusal) => return refusal.into_response(None),
    };
    let agent = headers.agent.clone();
    match authenticate(&state, headers, req).await {
        Ok(req) => next.run(req).await,
        Err(refusal) => refusal.into_response(Some(&agent)),
    }
}

/// Steps 2 to 6 for a request whose headers parsed; the request to hand on,
/// with its body and a [`SignedAgent`].
async fn authenticate(
    state: &AppState,
    headers: SignatureHeaders,
    req: Request,
) -> Result<Request, Refusal> {
    let SignatureHeaders {
        agent,
        timestamp,
        nonce,
        signature,
    } = headers;

    // 2. A key-signed agent, not revoked.
    let key = match agents::signing_key(&state.pool, &agent).await {
        Ok(Some(key)) => key,
        Ok(None) => return Err(Refusal::Unauthorized("agent has no signing key")),
        Err(AgentError::Unknown) => return Err(Refusal::Unauthorized("unknown agent")),
        Err(AgentError::Revoked) => return Err(Refusal::Unauthorized("agent revoked")),
        Err(e) => {
            tracing::error!(agent = %agent, error = %e, "agent signing key lookup failed");
            return Err(Refusal::Internal);
        }
    };

    // 3. The clock.
    let now = state.clock.now();
    if now.abs_diff(timestamp) > MAX_CLOCK_SKEW_SECS.unsigned_abs() {
        return Err(Refusal::Unauthorized(
            "timestamp outside the allowed clock skew",
        ));
    }

    // 4. The body, within the limit the route's DefaultBodyLimit set. The
    // body is read through a request carrying the same extensions, so the
    // limit applies exactly as it would to the handler's extractor.
    let (mut parts, body) = req.into_parts();
    let mut body_req = Request::new(body);
    body_req.extensions_mut().clone_from(&parts.extensions);
    let bytes = tokio::time::timeout(BODY_READ_TIMEOUT, Bytes::from_request(body_req, &()))
        .await
        .map_err(|_| Refusal::BodyTimeout)?
        .map_err(|rejection| Refusal::Body(rejection.status()))?;

    // 5. The signature, over the request as received: the original target
    // (not one a nested router stripped), byte for byte.
    let uri = parts
        .extensions
        .get::<OriginalUri>()
        .map_or(&parts.uri, |original| &original.0);
    let Some(target) = uri.path_and_query() else {
        return Err(Refusal::Unauthorized("request has no path"));
    };
    let body_sha256: [u8; 32] = Sha256::digest(&bytes).into();
    let message = canonical_message(&SignedRequestParts {
        audience: &state.audience,
        agent: &agent,
        method: parts.method.as_str(),
        target: target.as_str(),
        timestamp,
        nonce: &nonce,
        body_sha256,
    })
    .map_err(|_| Refusal::Unauthorized("request cannot be signed"))?;
    check_signature(&key, &signature, message.as_bytes())?;

    // 6. The nonce, new for this agent; recorded only now.
    match record_nonce(&state.pool, &agent, &nonce, now).await {
        Ok(true) => {}
        Ok(false) => return Err(Refusal::Unauthorized("nonce already used")),
        Err(e) => {
            tracing::error!(agent = %agent, error = %e, "recording a nonce failed");
            return Err(Refusal::Internal);
        }
    }

    parts.extensions.insert(SignedAgent(agent));
    Ok(Request::from_parts(parts, Body::from(bytes)))
}

/// Record that `agent` used `nonce` at `now`; `false` if it already had.
async fn record_nonce(
    pool: &SqlitePool,
    agent: &AgentName,
    nonce: &Nonce,
    now: i64,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO agent_nonces (agent, nonce, expires_at) VALUES (?, ?, ?) \
         ON CONFLICT (agent, nonce) DO NOTHING",
    )
    .bind(agent.as_str())
    .bind(nonce.as_str())
    .bind(now.saturating_add(NONCE_RETENTION_SECS))
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Forget the nonces whose retention ended at or before `now`; returns how
/// many.
///
/// # Errors
/// Database failure.
pub async fn sweep_nonces(pool: &SqlitePool, now: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM agent_nonces WHERE expires_at <= ?")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, EcdsaCurve, PrivateKey};

    use super::{
        HeaderMap, MAX_SIGNATURE_LEN, NAMESPACE, Refusal, check_signature, decode_signature,
        has_signing_headers,
    };
    use ssh_key::HashAlg;

    fn reason(result: Result<(), Refusal>) -> &'static str {
        match result {
            Err(Refusal::Unauthorized(reason)) => reason,
            other => panic!("expected a 401, got {other:?}"),
        }
    }

    #[test]
    fn any_warden_header_makes_a_signed_request() {
        let mut headers = HeaderMap::new();
        assert!(!has_signing_headers(&headers));
        headers.insert("authorization", HeaderValue::from_static("Bearer x"));
        headers.insert("x-warden-agent", HeaderValue::from_static("bot"));
        assert!(!has_signing_headers(&headers));
        headers.insert("Warden-Anything", HeaderValue::from_static("1"));
        assert!(has_signing_headers(&headers));
    }

    #[test]
    fn signature_must_be_by_the_key_in_the_namespace_with_an_allowed_hash() {
        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        ] {
            let key = PrivateKey::random(&mut OsRng, algorithm).unwrap();
            let public = key.public_key();
            let other = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
            let message = b"warden-request-v1\n";
            for hash in [HashAlg::Sha512, HashAlg::Sha256] {
                let good = key.sign(NAMESPACE, hash, message).unwrap();
                check_signature(public, &good, message).unwrap();
                assert_eq!(
                    reason(check_signature(public, &good, b"other")),
                    "signature does not verify"
                );
            }
            let file = key.sign("file", HashAlg::Sha512, message).unwrap();
            assert_eq!(
                reason(check_signature(public, &file, message)),
                "signature for another namespace"
            );
            let foreign = other.sign(NAMESPACE, HashAlg::Sha512, message).unwrap();
            assert_eq!(
                reason(check_signature(public, &foreign, message)),
                "signed by another key"
            );
        }
    }

    #[test]
    fn signature_header_is_bounded_canonical_base64_of_one_blob() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let pem = key
            .sign(NAMESPACE, HashAlg::Sha512, b"m")
            .unwrap()
            .to_pem(ssh_key::LineEnding::LF)
            .unwrap();
        let value: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        assert!(decode_signature(&value).is_ok());
        let unpadded = value.trim_end_matches('=');
        assert_ne!(unpadded, value);
        for bad in [
            unpadded.to_owned(),
            format!("{value}AAAA"),
            format!(" {value}"),
            "A".repeat(MAX_SIGNATURE_LEN + 1),
            String::new(),
        ] {
            assert!(
                matches!(decode_signature(&bad), Err(Refusal::Unauthorized(_))),
                "{bad:?} accepted"
            );
        }
    }
}
