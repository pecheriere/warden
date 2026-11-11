//! `POST /v1/release/publish`: make the draft release public.
//!
//! Every check is read-only and runs before the step is claimed: the release is a
//! draft, and when the grant has a manifest step, the manifest was signed and the
//! draft still holds exactly the two files that step attached. A refusal for any of
//! them costs the owner nothing. Nothing GitHub said appears in an error or the
//! audit log.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use warden_broker_proto::release::{PublishResponse, ReleaseTarget};
use warden_broker_proto::{AgentName, Id};

use super::manifest::{NO_DRAFT, PUBLISHED};
use super::{Ready, claim, github_failed, prepare, record_refusal, refused};
use crate::AppState;
use crate::api::{ApiJson, Failure};
use crate::audit::AuditEvent;
use crate::github_release::{Asset, ReleaseClient};
use crate::identity::AuthedAgent;
use crate::requests::{RecordedManifest, ReleaseStep, RequestError};

/// The grant has a manifest step and it has not finished.
const MANIFEST_NOT_SIGNED: &str = "the manifest has not been signed";
/// The draft lacks one of the two files the manifest step attached, or one is not
/// the file that was signed.
const FILES_DIFFER: &str = "the draft's files are not the ones signed";
/// GitHub gave no digest for one of the two files, so they cannot be compared.
const NO_DIGESTS: &str = "GitHub did not report the files' digests";

/// `POST /v1/release/publish`. Runs on its own task, so that a disconnecting agent
/// can neither stop it halfway nor keep it out of the audit log.
pub(in crate::api) async fn publish(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
    body: Result<ApiJson<ReleaseTarget>, Failure>,
) -> Result<Json<PublishResponse>, Failure> {
    let body = body.map(|ApiJson(target)| target);
    tokio::spawn(audited(state, agent, body))
        .await
        .map_err(|_| Failure::Request(RequestError::Internal("release step task failed")))?
        .map(Json)
}

async fn audited(
    state: AppState,
    agent: AgentName,
    body: Result<ReleaseTarget, Failure>,
) -> Result<PublishResponse, Failure> {
    let mut grant_id = None;
    let result = run(&state, &agent, body, &mut grant_id).await;
    if let Err(failure) = &result {
        record_refusal(&state, &agent, ReleaseStep::Publish, grant_id, failure).await;
    }
    result
}

/// Whether the draft's `assets` hold `name` with the digest `sha256`, once.
fn holds(assets: &[Asset], name: &str, sha256: &str) -> Result<bool, Failure> {
    let mut named = assets.iter().filter(|asset| asset.name == name);
    let (Some(asset), None) = (named.next(), named.next()) else {
        return Ok(false);
    };
    let digest = asset
        .digest
        .as_deref()
        .ok_or_else(|| refused(StatusCode::CONFLICT, NO_DIGESTS))?;
    Ok(digest.strip_prefix("sha256:") == Some(sha256))
}

/// Refuse unless the draft holds the manifest and signature the manifest step
/// recorded, under the names it gave them.
fn check_files(assets: &[Asset], name: &str, recorded: &RecordedManifest) -> Result<(), Failure> {
    let signature_name = format!("{name}.sig");
    // Both are read before either decides, so that a missing digest is told apart
    // from a file that was swapped.
    let manifest = holds(assets, name, &recorded.manifest_sha256);
    let signature = holds(assets, &signature_name, &recorded.signature_sha256);
    match (manifest, signature) {
        (Err(e), _) | (_, Err(e)) => Err(e),
        (Ok(true), Ok(true)) => Ok(()),
        _ => Err(refused(StatusCode::CONFLICT, FILES_DIFFER)),
    }
}

async fn run(
    state: &AppState,
    agent: &AgentName,
    body: Result<ReleaseTarget, Failure>,
    seen: &mut Option<Id>,
) -> Result<PublishResponse, Failure> {
    let step = ReleaseStep::Publish;
    let (target, Ready { release, key, app }) = prepare(state, agent, body, step, seen).await?;
    let grant = release.grant();
    let now = state.clock.now();
    // The key is not needed to publish; the App token is.
    drop(key);

    // Read-only checks, before the step is claimed.
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
    if let Some(name) = &grant.steps.manifest {
        let recorded = state
            .requests
            .recorded_manifest(&release)
            .await?
            .ok_or_else(|| refused(StatusCode::CONFLICT, MANIFEST_NOT_SIGNED))?;
        check_files(&draft.assets, name, &recorded)?;
    }
    claim(state, agent, &target, &release, step).await?;

    github
        .publish(draft.id)
        .await
        .map_err(|e| github_failed(agent, step, &e))?;
    state
        .audit
        .append(AuditEvent::ReleasePublished {
            grant_id: release.grant_id().clone(),
            agent: agent.clone(),
            repository: grant.repository.clone(),
            tag: grant.tag.clone(),
        })
        .await
        .map_err(RequestError::from)?;
    // If this fails the grant simply runs out its window, which gives no step back.
    if let Err(e) = state.requests.end_if_done(release.grant_id(), now).await {
        tracing::warn!(error = %e, "could not end the release grant");
    }
    tracing::info!(agent = %agent, grant = %release.grant_id(), "release published");
    Ok(PublishResponse {
        grant_id: release.grant_id().clone(),
        tag: grant.tag.clone(),
    })
}
