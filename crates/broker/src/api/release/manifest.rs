//! `POST /v1/release/manifest`: sign the manifest the agent built and attach it,
//! with its signature, to the draft release.
//!
//! The manifest is checked and the draft is read before the step is claimed, so a
//! refusal for either costs the owner nothing and the agent may try again. Nothing
//! the agent sent, and nothing GitHub said, appears in an error or the audit log:
//! the manifest's rules have fixed messages.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest as _, Sha256};
use warden_broker_proto::release::{
    ManifestResponse, ReleaseTarget, STEP_NOT_IN_GRANT, SignManifestRequest,
};
use warden_broker_proto::{AgentName, Id};

use super::{BAD_BODY, Ready, claim, github_failed, prepare, record_refusal, refused};
use crate::AppState;
use crate::api::{ApiJson, Failure};
use crate::audit::AuditEvent;
use crate::github_release::ReleaseClient;
use crate::identity::AuthedAgent;
use crate::release_signing::{check_manifest, sign_manifest};
use crate::requests::{ReleaseStep, RequestError};

/// The tag has no release.
pub(super) const NO_DRAFT: &str = "the tag has no draft release";
/// The release was published already.
pub(super) const PUBLISHED: &str = "the release is already published";

/// The broker could not sign the manifest; nothing more is said.
const SIGNING_FAILED: &str = "signing the manifest failed";

/// `POST /v1/release/manifest`. Runs on its own task, so that a disconnecting
/// agent can neither stop it halfway nor keep it out of the audit log.
pub(in crate::api) async fn manifest(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
    body: Result<ApiJson<SignManifestRequest>, Failure>,
) -> Result<Json<ManifestResponse>, Failure> {
    let body = body.map(|ApiJson(request)| request);
    tokio::spawn(audited(state, agent, body))
        .await
        .map_err(|_| Failure::Request(RequestError::Internal("release step task failed")))?
        .map(Json)
}

async fn audited(
    state: AppState,
    agent: AgentName,
    body: Result<SignManifestRequest, Failure>,
) -> Result<ManifestResponse, Failure> {
    let mut grant_id = None;
    let result = sign(&state, &agent, body, &mut grant_id).await;
    if let Err(failure) = &result {
        record_refusal(&state, &agent, ReleaseStep::Manifest, grant_id, failure).await;
    }
    result
}

async fn sign(
    state: &AppState,
    agent: &AgentName,
    body: Result<SignManifestRequest, Failure>,
    seen: &mut Option<Id>,
) -> Result<ManifestResponse, Failure> {
    let step = ReleaseStep::Manifest;
    let (target, request) = match body {
        Ok(request) => (
            Ok(ReleaseTarget {
                repository: request.repository.clone(),
                tag: request.tag.clone(),
            }),
            Some(request),
        ),
        Err(failure) => (Err(failure), None),
    };
    let (target, Ready { release, key, app }) = prepare(state, agent, target, step, seen).await?;
    let grant = release.grant();
    // `prepare` returned, so the body parsed.
    let request = request.ok_or_else(|| refused(StatusCode::BAD_REQUEST, BAD_BODY))?;

    // The grant covers the step, and the key is the one the owner approved: its
    // manifest spec says what the file is called and which namespace signs it.
    let spec = key
        .manifest()
        .ok_or_else(|| refused(StatusCode::CONFLICT, STEP_NOT_IN_GRANT))?;
    let expected_name = spec.file_name(grant.tag.version());
    let bytes = STANDARD
        .decode(request.content_b64.as_bytes())
        .map_err(|_| refused(StatusCode::BAD_REQUEST, BAD_BODY))?;
    check_manifest(&expected_name, grant.tag.version(), &request.name, &bytes)
        .map_err(|e| refused(StatusCode::BAD_REQUEST, e.to_string()))?;

    // Read-only checks, before the step is claimed.
    let now = state.clock.now();
    let github = ReleaseClient::connect(&state.github, &app, &grant.repository, now)
        .await
        .map_err(|e| github_failed(agent, step, &e))?;
    drop(app);
    let draft = github
        .release_for_tag(&grant.tag)
        .await
        .map_err(|e| github_failed(agent, step, &e))?
        .ok_or_else(|| refused(StatusCode::CONFLICT, NO_DRAFT))?;
    if !draft.draft {
        return Err(refused(StatusCode::CONFLICT, PUBLISHED));
    }
    claim(state, agent, &target, &release, step).await?;

    let signature = sign_manifest(&key, spec.namespace(), &bytes).map_err(|_| {
        tracing::error!(agent = %agent, "signing the release manifest failed");
        refused(StatusCode::INTERNAL_SERVER_ERROR, SIGNING_FAILED)
    })?;
    let signature_name = format!("{expected_name}.sig");
    drop(key);
    for old in draft
        .assets
        .iter()
        .filter(|asset| asset.name == expected_name || asset.name == signature_name)
    {
        github
            .delete_asset(old.id)
            .await
            .map_err(|e| github_failed(agent, step, &e))?;
    }
    github
        .upload_asset(draft.id, &expected_name, &bytes)
        .await
        .map_err(|e| github_failed(agent, step, &e))?;
    github
        .upload_asset(draft.id, &signature_name, signature.as_bytes())
        .await
        .map_err(|e| github_failed(agent, step, &e))?;

    let sha256 = hex::encode(Sha256::digest(&bytes));
    let signature_sha256 = hex::encode(Sha256::digest(signature.as_bytes()));
    state
        .requests
        .record_manifest(release.grant_id(), &sha256, &signature_sha256)
        .await?;
    state
        .audit
        .append(AuditEvent::ReleaseManifestSigned {
            grant_id: release.grant_id().clone(),
            agent: agent.clone(),
            repository: grant.repository.clone(),
            tag: grant.tag.clone(),
            name: expected_name.clone(),
            sha256: sha256.clone(),
        })
        .await
        .map_err(RequestError::from)?;
    // If this fails the grant simply runs out its window, which gives no step back.
    if let Err(e) = state.requests.end_if_done(release.grant_id(), now).await {
        tracing::warn!(error = %e, "could not end the release grant");
    }
    tracing::info!(agent = %agent, grant = %release.grant_id(), "release manifest signed");
    Ok(ManifestResponse {
        grant_id: release.grant_id().clone(),
        name: expected_name,
        signature_name,
        sha256,
    })
}
