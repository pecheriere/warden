//! `POST /v1/commit-signing/sign` and `GET /v1/commit-signing/key`.
//!
//! The broker signs for an agent only in the `git` namespace, only a payload that
//! parses strictly as a commit, and only under that agent's own active grant, which
//! is looked up for every signature. Each signature is recorded before it leaves
//! the broker, and each refusal is recorded too, whatever the reason.
//!
//! The commit's fields come from the signed payload itself. Nothing the agent says
//! about a repository, branch or pull request is asked for: a commit does not name
//! them, so such a claim could not be checked.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest as _, Sha256};
use warden_broker_proto::commit_signing::{
    CommitSigningKeyView, DAILY_LIMIT, NAMESPACE, NO_ACTIVE_GRANT, SignCommitRequest,
    SignCommitResponse,
};
use warden_broker_proto::{AgentName, Id};

use super::{ApiJson, Failure, off_runtime};
use crate::AppState;
use crate::audit::AuditEvent;
use crate::commit_signing::{self as signer, payload};
use crate::identity::AuthedAgent;
use crate::requests::{ActiveCommitSigning, RequestError};

/// What the agent is told when the broker's key is no longer the one the owner
/// approved.
const KEY_CHANGED: &str = "the commit signing key changed; request a new grant";

/// `GET /v1/commit-signing/key`: the public half of the broker's key, which
/// `warden setup git` writes to the configuration. Getting at it means reading the
/// private key from the backend, so only an agent with an active grant can cause that.
pub(super) async fn public_key(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
) -> Result<Json<CommitSigningKeyView>, Failure> {
    if state
        .requests
        .active_commit_signing(&agent)
        .await?
        .is_none()
    {
        return Err(refused(StatusCode::FORBIDDEN, NO_ACTIVE_GRANT));
    }
    let policy = state.requests.commit_signing_policy().await?;
    Ok(Json(CommitSigningKeyView {
        public_key: policy.public_key,
        fingerprint: policy.key_fingerprint,
    }))
}

/// `POST /v1/commit-signing/sign`: sign the commit in the body. Runs on its own task,
/// so that a disconnecting agent can neither stop it halfway nor keep it out of the
/// audit log. A body that does not parse is a refusal like any other, and recorded.
pub(super) async fn sign(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
    body: Result<ApiJson<SignCommitRequest>, Failure>,
) -> Result<Json<SignCommitResponse>, Failure> {
    let body = body.map(|ApiJson(body)| body);
    tokio::spawn(audited(state, agent, body))
        .await
        .map_err(|_| Failure::Request(RequestError::Internal("signing task failed")))?
        .map(Json)
}

/// What is known of a call when it is refused, for the audit entry.
#[derive(Default)]
struct Seen {
    grant_id: Option<Id>,
    payload_sha256: Option<String>,
}

async fn audited(
    state: AppState,
    agent: AgentName,
    body: Result<SignCommitRequest, Failure>,
) -> Result<SignCommitResponse, Failure> {
    let mut seen = Seen::default();
    let result = attempt(&state, &agent, body, &mut seen).await;
    if let Err(failure) = &result {
        let reason = failure.outcome();
        tracing::info!(agent = %agent, reason = %reason, "commit signing refused");
        state
            .requests
            .record_commit_signing_refusal(&agent, seen.grant_id, reason, seen.payload_sha256)
            .await;
    }
    result
}

fn refused(status: StatusCode, message: impl Into<String>) -> Failure {
    Failure::Client(status, message.into())
}

async fn attempt(
    state: &AppState,
    agent: &AgentName,
    body: Result<SignCommitRequest, Failure>,
    seen: &mut Seen,
) -> Result<SignCommitResponse, Failure> {
    // Unreadable state refuses here: `?` on a storage failure, before anything else.
    let grant = state.requests.active_commit_signing(agent).await?;
    seen.grant_id = grant.as_ref().map(|grant| grant.grant_id.clone());
    // Fixed text, as it goes in the audit log: a parser's message can quote the body.
    let body = body.map_err(|failure| match failure {
        Failure::Client(status, _) => refused(status, "the request body is not valid"),
        other @ Failure::Request(_) => other,
    })?;
    if body.namespace != NAMESPACE {
        return Err(refused(
            StatusCode::BAD_REQUEST,
            format!("only the {NAMESPACE} namespace is signed"),
        ));
    }
    let bytes = STANDARD
        .decode(&body.payload_b64)
        .map_err(|_| refused(StatusCode::BAD_REQUEST, "the payload is not base64"))?;
    let payload_sha256 = hex::encode(Sha256::digest(&bytes));
    seen.payload_sha256 = Some(payload_sha256.clone());
    let parsed = payload::parse(&bytes).map_err(|why| {
        let status = match why {
            payload::PayloadRefusal::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            _ => StatusCode::BAD_REQUEST,
        };
        refused(status, why.to_string())
    })?;
    let ActiveCommitSigning { grant_id, grant } =
        grant.ok_or_else(|| refused(StatusCode::FORBIDDEN, NO_ACTIVE_GRANT))?;
    if !state.requests.take_signature(&grant_id).await? {
        state
            .requests
            .signature_limit_reached(agent, &grant_id)
            .await;
        return Err(refused(StatusCode::TOO_MANY_REQUESTS, DAILY_LIMIT));
    }

    let key = state
        .backend
        .commit_signing_key()
        .await
        .map_err(RequestError::from)?;
    let policy = state
        .requests
        .commit_signing_policy_of(&key)
        .map_err(RequestError::from)?;
    if policy.destination_digest() != grant.digest {
        return Err(refused(StatusCode::CONFLICT, KEY_CHANGED));
    }
    let (signed, bytes, parsed) = off_runtime(move || {
        let signed = signer::sign(&key, &bytes, &parsed);
        // The key goes here, on the thread that used it, and its `Drop` wipes it.
        drop(key);
        (signed, bytes, parsed)
    })
    .await?;
    drop(bytes);
    let signed = signed.map_err(|_| RequestError::Internal("signing failed"))?;

    let event = AuditEvent::CommitSigned {
        grant_id: grant_id.clone(),
        agent: agent.clone(),
        commit: signed.commit.clone(),
        payload_sha256,
        parents: parsed.parents,
        tree: parsed.tree,
        author: parsed.author,
        key_fingerprint: policy.key_fingerprint,
    };
    state
        .audit
        .append(event)
        .await
        .map_err(RequestError::from)?;
    // Writing the log can take long, and a revocation does not wait for it: a grant
    // that has ended meanwhile gets nothing.
    let still_active = state.requests.active_commit_signing(agent).await?;
    if still_active.is_none_or(|active| active.grant_id != grant_id) {
        return Err(refused(StatusCode::FORBIDDEN, NO_ACTIVE_GRANT));
    }
    tracing::info!(agent = %agent, grant = %grant_id, commit = %signed.commit, "commit signed");
    Ok(SignCommitResponse {
        signature: signed.signature,
        grant_id,
        commit: signed.commit,
    })
}
