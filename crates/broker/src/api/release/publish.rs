//! `POST /v1/release/publish`: make the draft release public.
//!
//! Every check is read-only and runs before the step is claimed: the release is a
//! draft, the tag is in place on the approved commit and signed by the release key
//! (publishing a draft whose tag is missing would make GitHub create an unsigned
//! one at whatever commit the draft names), and when the grant has a manifest step,
//! the manifest was signed and the draft still holds exactly the two files that step
//! attached. A refusal for any of
//! them costs the owner nothing. Nothing GitHub said appears in an error or the
//! audit log.
//!
//! GitHub has no conditional publish, so a write can land between the checks and
//! the publish. Afterwards the broker compares the files the release was published
//! with, as GitHub's answer to the publish lists them, and the tag, with what it
//! checked; when they differ it records `release_published_changed`, tells the
//! owner and refuses the call, although the release is published.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use warden_broker_proto::release::{PublishResponse, ReleaseTarget};
use warden_broker_proto::{AgentName, Id};

use super::manifest::{NO_DRAFT, PUBLISHED};
use super::{Ready, claim, github_failed, prepare, record_refusal, record_start, refused};
use crate::AppState;
use crate::api::{ApiJson, Failure};
use crate::audit::AuditEvent;
use crate::github_release::{Asset, Release, ReleaseClient};
use crate::identity::AuthedAgent;
use crate::policy::ReleaseSigningKey;
use crate::requests::{ActiveRelease, RecordedManifest, ReleaseStep, RequestError};

/// The tag is missing, is on another commit, or is not the release key's signed
/// annotated tag.
const TAG_NOT_IN_PLACE: &str = "the tag is not in place on the approved commit";
/// The grant has a manifest step and it has not finished.
const MANIFEST_NOT_SIGNED: &str = "the manifest has not been signed";
/// The draft lacks one of the two files the manifest step attached, or one is not
/// the file that was signed.
const FILES_DIFFER: &str = "the draft's files are not the ones signed";
/// GitHub gave no digest for one of the two files, so they cannot be compared.
const NO_DIGESTS: &str = "GitHub did not report the files' digests";
/// The release was published, but not as it was checked.
const PUBLISHED_CHANGED: &str =
    "the release was published, but its files or tag changed after they were checked";

/// What can differ after the publish, as the audit entry and the owner's notice
/// say it.
const FILES_CHANGED: &str = "its manifest or signature is not the one signed";
const TAG_CHANGED: &str = "its tag is not the one checked";
const TAG_UNREADABLE: &str = "its tag could not be read back";

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

/// Refuse unless the tag is in place: made by the tag step when the grant has one,
/// and an annotated tag on the approved commit that the release key signed. The id
/// of its tag object.
async fn check_tag(
    state: &AppState,
    agent: &AgentName,
    github: &ReleaseClient<'_>,
    release: &ActiveRelease,
    key: &ReleaseSigningKey,
) -> Result<String, Failure> {
    let grant = release.grant();
    if grant.steps.tag
        && !state
            .requests
            .step_claimed(release, ReleaseStep::Tag)
            .await?
    {
        return Err(refused(StatusCode::CONFLICT, TAG_NOT_IN_PLACE));
    }
    let existing = github
        .tag_target(&grant.tag)
        .await
        .map_err(|e| github_failed(agent, ReleaseStep::Publish, &e))?;
    existing
        .filter(|tag| {
            tag.commit.as_ref() == Some(&grant.commit)
                && tag.raw.as_deref().is_some_and(|raw| key.verifies_tag(raw))
        })
        .map(|tag| tag.object_sha)
        .ok_or_else(|| refused(StatusCode::CONFLICT, TAG_NOT_IN_PLACE))
}

/// What differs between the release as published and what was checked before:
/// the two files the manifest step attached, as `published` lists them, and the
/// tag object `tag_object`.
async fn changed_since_checked(
    github: &ReleaseClient<'_>,
    release: &ActiveRelease,
    published: &Release,
    manifest: Option<(&str, &RecordedManifest)>,
    tag_object: &str,
) -> Option<&'static str> {
    if let Some((name, recorded)) = manifest
        && check_files(&published.assets, name, recorded).is_err()
    {
        return Some(FILES_CHANGED);
    }
    match github.tag_target(&release.grant().tag).await {
        Ok(Some(tag)) if tag.object_sha == tag_object => None,
        Ok(_) => Some(TAG_CHANGED),
        Err(_) => Some(TAG_UNREADABLE),
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
    // The key checks the tag below and is not needed after that.
    let tag_object = check_tag(state, agent, &github, &release, &key).await?;
    drop(key);
    let recorded = match &grant.steps.manifest {
        Some(name) => {
            let recorded = state
                .requests
                .recorded_manifest(&release)
                .await?
                .ok_or_else(|| refused(StatusCode::CONFLICT, MANIFEST_NOT_SIGNED))?;
            check_files(&draft.assets, name, &recorded)?;
            Some((name.as_str(), recorded))
        }
        None => None,
    };
    claim(state, agent, &target, &release, step).await?;
    record_start(state, agent, &release, step, None).await?;

    let published = github
        .publish(draft.id, &grant.tag)
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
    let manifest = recorded.as_ref().map(|(name, recorded)| (*name, recorded));
    if let Some(reason) =
        changed_since_checked(&github, &release, &published, manifest, &tag_object).await
    {
        tracing::error!(agent = %agent, grant = %release.grant_id(), reason, "a release was published unlike it was checked");
        state
            .requests
            .release_published_changed(agent, &release, reason)
            .await;
        return Err(refused(StatusCode::BAD_GATEWAY, PUBLISHED_CHANGED));
    }
    tracing::info!(agent = %agent, grant = %release.grant_id(), "release published");
    Ok(PublishResponse {
        grant_id: release.grant_id().clone(),
        tag: grant.tag.clone(),
    })
}
