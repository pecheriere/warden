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
//!    within the time [`BodyReadTimeout`] allows for that limit (408
//!    beyond it);
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

use std::num::NonZeroU64;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{FromRequest as _, OriginalUri, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p256::ecdsa::signature::Verifier as _;
use sha2::{Digest as _, Sha256};
use sqlx::SqlitePool;
use ssh_encoding::{Decode as _, Reader as _};
use ssh_key::public::{EcdsaPublicKey, KeyData};
use ssh_key::{HashAlg, Mpint, PublicKey, SshSig};
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
/// verified: the larger of [`BodyReadTimeout::floor`] and the route's body
/// limit at [`BodyReadTimeout::bytes_per_sec`]. A caller naming a known
/// agent cannot hold a connection open with a trickled body longer than
/// this; it gets a 408.
///
/// The broker always uses [`BodyReadTimeout::default`] (at least 10 s, at
/// 128 KiB/s: 10 s for 16 KiB, 16 s for 2 MiB); tests shorten it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyReadTimeout {
    /// The shortest time allowed, whatever the limit.
    pub floor: Duration,
    /// The slowest rate a full-size body must arrive at.
    pub bytes_per_sec: NonZeroU64,
}

impl Default for BodyReadTimeout {
    fn default() -> Self {
        Self {
            floor: Duration::from_secs(10),
            // 128 KiB/s; checked non-zero at compile time.
            bytes_per_sec: const { NonZeroU64::new(128 * 1024).unwrap() },
        }
    }
}

impl BodyReadTimeout {
    /// The time allowed for a body of at most `limit` bytes, to the
    /// millisecond (rounded up).
    #[must_use]
    pub fn for_limit(self, limit: usize) -> Duration {
        let millis = u64::try_from(limit)
            .unwrap_or(u64::MAX)
            .saturating_mul(1000)
            .div_ceil(self.bytes_per_sec.get());
        Duration::from_millis(millis).max(self.floor)
    }
}

/// The state of [`verify`] on one route: the broker's, and the route's body
/// limit, which [`verify`] needs to time the body.
#[derive(Clone)]
pub struct SignedRoute {
    state: AppState,
    body_limit: usize,
}

impl SignedRoute {
    /// [`verify`] for a route whose bodies are at most `body_limit` bytes
    /// (the limit of its [`axum::extract::DefaultBodyLimit`]).
    #[must_use]
    pub const fn new(state: AppState, body_limit: usize) -> Self {
        Self { state, body_limit }
    }
}

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
    /// The body did not arrive within the route's [`BodyReadTimeout`].
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
    if !sshsig_verifies(key, signature, message) {
        return Err(Refusal::Unauthorized("signature does not verify"));
    }
    Ok(())
}

/// Whether `signature` is by `key` over `message`, in `signature`'s own
/// namespace and with its own hash: the caller has checked those. False for
/// a key that is neither Ed25519 nor ECDSA P-256, the only types enrolment
/// accepts.
///
/// P-256 goes to the `p256` crate rather than `key.verify`, which `ssh-key`
/// 0.6 only implements with crypto-bigint 0.5 (RUSTSEC-2026-0387). This can
/// return to `key.verify` with `ssh-key` 0.7.
#[must_use]
pub fn sshsig_verifies(key: &PublicKey, signature: &SshSig, message: &[u8]) -> bool {
    match key.key_data() {
        KeyData::Ed25519(_) => key
            .verify(signature.namespace(), message, signature)
            .is_ok(),
        KeyData::Ecdsa(EcdsaPublicKey::NistP256(point)) => {
            p256_sshsig_verifies(point.as_bytes(), key, signature, message).unwrap_or(false)
        }
        _ => false,
    }
}

/// `None` where a part cannot be parsed, which is a failure like `false`.
fn p256_sshsig_verifies(
    point: &[u8],
    key: &PublicKey,
    signature: &SshSig,
    message: &[u8],
) -> Option<bool> {
    let raw = signature.signature();
    if signature.public_key() != key.key_data() || raw.algorithm() != key.algorithm() {
        return Some(false);
    }
    let signed = SshSig::signed_data(signature.namespace(), signature.hash_alg(), message).ok()?;
    let parsed = p256_signature(raw.as_bytes())?;
    let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).ok()?;
    Some(verifying.verify(&signed, &parsed).is_ok())
}

/// An SSH ECDSA signature blob (`mpint r`, `mpint s`) as a P-256 signature.
/// `from_scalars` refuses `r` or `s` of zero or not below the curve's order.
fn p256_signature(mut blob: &[u8]) -> Option<p256::ecdsa::Signature> {
    let reader = &mut blob;
    let r = field_bytes(&Mpint::decode(reader).ok()?)?;
    let s = field_bytes(&Mpint::decode(reader).ok()?)?;
    if !reader.is_finished() {
        return None;
    }
    p256::ecdsa::Signature::from_scalars(r, s).ok()
}

/// A non-negative `mpint` as big-endian P-256 field bytes, if it fits.
fn field_bytes(value: &Mpint) -> Option<p256::FieldBytes> {
    let bytes = value.as_positive_bytes()?;
    let mut out = p256::FieldBytes::default();
    let start = out.len().checked_sub(bytes.len())?;
    out[start..].copy_from_slice(bytes);
    Some(out)
}

/// Middleware: authenticate a signed request (see the module
/// documentation) or pass an unsigned one on unchanged.
///
/// Must sit inside the route's [`axum::extract::DefaultBodyLimit`], whose
/// limit it applies when it reads the body, and be given the same limit in
/// its [`SignedRoute`].
pub async fn verify(State(route): State<SignedRoute>, req: Request, next: Next) -> Response {
    if !has_signing_headers(req.headers()) {
        return next.run(req).await;
    }
    let headers = match SignatureHeaders::parse(req.headers()) {
        Ok(headers) => headers,
        Err(refusal) => return refusal.into_response(None),
    };
    let agent = headers.agent.clone();
    let timeout = route
        .state
        .config
        .body_read_timeout
        .for_limit(route.body_limit);
    match authenticate(&route.state, headers, timeout, req).await {
        Ok(req) => next.run(req).await,
        Err(refusal) => refusal.into_response(Some(&agent)),
    }
}

/// Steps 2 to 6 for a request whose headers parsed; the request to hand on,
/// with its body and a [`SignedAgent`].
async fn authenticate(
    state: &AppState,
    headers: SignatureHeaders,
    body_timeout: Duration,
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

    // 4. The body, within the limit the route's DefaultBodyLimit set and the
    // time allowed for it. The
    // body is read through a request carrying the same extensions, so the
    // limit applies exactly as it would to the handler's extractor.
    let (mut parts, body) = req.into_parts();
    let mut body_req = Request::new(body);
    body_req.extensions_mut().clone_from(&parts.extensions);
    let bytes = tokio::time::timeout(body_timeout, Bytes::from_request(body_req, &()))
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
    use serde_json::Value;
    use ssh_encoding::Encode as _;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, Mpint, PrivateKey, PublicKey, SshSig};

    use std::time::Duration;

    use super::{
        BodyReadTimeout, HeaderMap, MAX_SIGNATURE_LEN, NAMESPACE, Refusal, check_signature,
        decode_signature, has_signing_headers, p256_signature, sshsig_verifies,
    };
    use crate::test_keys::{P256, random_key, sign};
    use ssh_key::HashAlg;

    fn reason(result: Result<(), Refusal>) -> &'static str {
        match result {
            Err(Refusal::Unauthorized(reason)) => reason,
            other => panic!("expected a 401, got {other:?}"),
        }
    }

    #[test]
    fn body_read_timeout_scales_with_the_body_limit() {
        let default = BodyReadTimeout::default();
        assert_eq!(default.floor, Duration::from_secs(10));
        assert_eq!(default.bytes_per_sec.get(), 128 * 1024);
        // The ordinary routes' 16 KiB: the floor.
        assert_eq!(default.for_limit(16 * 1024), Duration::from_secs(10));
        // The 2 MiB of a proxied call: 16 s.
        assert_eq!(default.for_limit(2 * 1024 * 1024), Duration::from_secs(16));
        assert_eq!(
            default.for_limit(2 * 1024 * 1024 + 1),
            Duration::from_millis(16_001)
        );
        assert_eq!(default.for_limit(0), Duration::from_secs(10));
        assert!(default.for_limit(usize::MAX) > Duration::from_secs(10));
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
        for algorithm in [Algorithm::Ed25519, P256] {
            let key = random_key(algorithm);
            let public = key.public_key();
            let other = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
            let message = b"warden-request-v1\n";
            for hash in [HashAlg::Sha512, HashAlg::Sha256] {
                let good = sign(&key, NAMESPACE, hash, message);
                check_signature(public, &good, message).unwrap();
                assert_eq!(
                    reason(check_signature(public, &good, b"other")),
                    "signature does not verify"
                );
            }
            let file = sign(&key, "file", HashAlg::Sha512, message);
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

    /// The P-256 signature made by `ssh-keygen -Y sign` and published in
    /// `docs/agent-protocol.md` verifies, bound to its message and its key.
    #[test]
    fn published_p256_vector_verifies() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../proto/tests/fixtures/signing-v1.json"))
                .unwrap();
        let p256 = &fixture["ecdsa_p256"];
        let public = PublicKey::from_openssh(p256["public_key"].as_str().unwrap()).unwrap();
        let index = usize::try_from(p256["vector"].as_u64().unwrap()).unwrap();
        let vectors = fixture["vectors"].as_array().unwrap();
        let message = vectors[index]["message"].as_str().unwrap().as_bytes();
        let other = vectors[1 - index]["message"].as_str().unwrap().as_bytes();
        let armored = format!(
            "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
            p256["signature"]
                .as_str()
                .unwrap()
                .as_bytes()
                .chunks(70)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        );
        let signature = SshSig::from_pem(armored).unwrap();
        check_signature(&public, &signature, message).unwrap();
        assert!(!sshsig_verifies(&public, &signature, other));
        let ed25519 = PublicKey::from_openssh(fixture["public_key"].as_str().unwrap()).unwrap();
        assert!(!sshsig_verifies(&ed25519, &signature, message));
    }

    /// The `mpint r`, `mpint s` blob of a signature.
    fn blob(r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        Mpint::from_positive_bytes(r)
            .unwrap()
            .encode(&mut out)
            .unwrap();
        Mpint::from_positive_bytes(s)
            .unwrap()
            .encode(&mut out)
            .unwrap();
        out
    }

    /// `r` and `s` must be canonical, in range and all there is: the group
    /// order `n` and above, zero, a value too long, a negative value and
    /// trailing bytes are refused.
    #[test]
    fn p256_signature_blob_is_strict() {
        const ORDER: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let one = [1_u8];
        // Shorter than the field is fine: it is padded.
        assert!(p256_signature(&blob(&one, &one)).is_some());
        let mut below = ORDER;
        below[31] -= 1;
        assert!(p256_signature(&blob(&below, &below)).is_some());

        assert!(p256_signature(&blob(&ORDER, &one)).is_none());
        assert!(p256_signature(&blob(&one, &ORDER)).is_none());
        assert!(p256_signature(&blob(&[0xff; 32], &one)).is_none());
        assert!(p256_signature(&blob(&[0_u8; 0], &one)).is_none());
        assert!(p256_signature(&blob(&one, &[0_u8; 0])).is_none());
        assert!(p256_signature(&blob(&[1; 33], &one)).is_none());
        let mut trailing = blob(&one, &one);
        trailing.push(0);
        assert!(p256_signature(&trailing).is_none());
        // 0x80 without the leading zero that makes it positive: negative.
        let negative = [0, 0, 0, 1, 0x80, 0, 0, 0, 1, 1];
        assert!(p256_signature(&negative).is_none());
        assert!(p256_signature(&[]).is_none());
    }

    /// A valid signature wrapped with another key's algorithm name, and keys
    /// enrolment does not accept, verify nothing.
    #[test]
    fn signature_type_must_match_the_key() {
        let key = random_key(P256);
        let message = b"m";
        let good = sign(&key, NAMESPACE, HashAlg::Sha512, message);
        assert!(sshsig_verifies(key.public_key(), &good, message));

        let ed = random_key(Algorithm::Ed25519);
        let wrong_type = SshSig::new(
            key.public_key().key_data().clone(),
            NAMESPACE,
            HashAlg::Sha512,
            ed.sign(NAMESPACE, HashAlg::Sha512, b"m")
                .unwrap()
                .signature()
                .clone(),
        )
        .unwrap();
        assert!(!sshsig_verifies(key.public_key(), &wrong_type, message));

        let p384 = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBJIBXLctzYt9bmZlMumBipjA4vHiyyHO3nzzd23kZbPXxSvhyPEOmOu5QNqWE20d1FTeOp4A7Qd+j6+0XEEByQpwrwRdzR57rXWdtzURc0kdZt0Lqb7+C8kM/AIZ688HvQ==";
        let p384 = PublicKey::from_openssh(p384).unwrap();
        assert!(!sshsig_verifies(&p384, &good, message));
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
