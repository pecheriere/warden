//! The steps of a release: `POST /v1/release/tag` here, `POST /v1/release/manifest`
//! in [`manifest`] and `POST /v1/release/publish` in [`publish`].
//!
//! Each step runs only under the release grant the agent holds for that release,
//! looked up for every call. The order is the same for every step: find the grant
//! (403), check the step is part of it (409), read the key and the App again and
//! compare them with what the owner approved (409), run the read-only checks, claim
//! the step (409), act, audit, and end the grant if that was its last step. A step
//! that fails after its claim stays used. Nothing GitHub said, and nothing about
//! the keys, appears in an error, a log line or the audit log.

mod manifest;
mod publish;

pub(super) use self::manifest::manifest;
pub(super) use self::publish::publish;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use warden_broker_proto::release::{
    NO_ACTIVE_GRANT, NOT_CONFIGURED, ReleaseTarget, STEP_DONE, STEP_NOT_IN_GRANT, TagResponse,
};
use warden_broker_proto::{AgentName, Id};

use super::{ApiJson, Failure, POLICY_CHANGED};
use crate::AppState;
use crate::audit::AuditEvent;
use crate::github_release::{CreateTag, GithubError, ReleaseClient};
use crate::identity::AuthedAgent;
use crate::policy::{PolicyError, ReleaseAppKey, ReleaseSigningKey};
use crate::release_signing::{sign_tag, tag_object_id, tag_payload};
use crate::requests::{ActiveRelease, ReleasePolicy, ReleaseStep, RequestError};

/// What the agent is told when GitHub could not do what was asked. Fixed: nothing
/// GitHub said is passed on.
const GITHUB_UNAVAILABLE: &str = "GitHub could not complete the step; try again later";
/// The tag already exists, or is not at the commit the owner approved.
const TAG_EXISTS: &str = "the tag already exists";
/// The approved commit is no longer on the default branch.
const COMMIT_MOVED: &str = "the approved commit is not on the repository's default branch";
/// GitHub made a tag object other than the one the broker signed.
const TAG_DIFFERS: &str = "GitHub did not create the tag that was signed";
/// What the body of a step must be.
pub(super) const BAD_BODY: &str = "the request body is not valid";

pub(super) fn refused(status: StatusCode, message: impl Into<String>) -> Failure {
    Failure::Client(status, message.into())
}

/// A grant, the key and the App as they are now, once they agree with what the
/// owner approved.
pub(super) struct Ready {
    pub(super) release: ActiveRelease,
    pub(super) key: ReleaseSigningKey,
    pub(super) app: ReleaseAppKey,
}

/// `POST /v1/release/tag`: sign the tag and create it. Runs on its own task, so that
/// a disconnecting agent can neither stop it halfway nor keep it out of the audit
/// log.
pub(super) async fn tag(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
    body: Result<ApiJson<ReleaseTarget>, Failure>,
) -> Result<Json<TagResponse>, Failure> {
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
) -> Result<TagResponse, Failure> {
    let mut grant_id = None;
    let result = create_tag(&state, &agent, body, &mut grant_id).await;
    if let Err(failure) = &result {
        record_refusal(&state, &agent, ReleaseStep::Tag, grant_id, failure).await;
    }
    result
}

/// Log and audit (throttled) that `failure` refused `step`.
pub(super) async fn record_refusal(
    state: &AppState,
    agent: &AgentName,
    step: ReleaseStep,
    grant_id: Option<Id>,
    failure: &Failure,
) {
    let reason = failure.outcome();
    tracing::info!(agent = %agent, step = step.name(), reason = %reason, "release step refused");
    state
        .requests
        .record_release_refusal(agent, grant_id, step.name(), reason)
        .await;
}

/// Find the grant `agent` holds for `target` and check that `step` may run under
/// what is configured now. Sets `seen` as soon as a grant is found.
pub(super) async fn prepare(
    state: &AppState,
    agent: &AgentName,
    target: Result<ReleaseTarget, Failure>,
    step: ReleaseStep,
    seen: &mut Option<Id>,
) -> Result<(ReleaseTarget, Ready), Failure> {
    // Fixed text, as it goes in the audit log: a parser's message can quote the body.
    let target = target.map_err(|failure| match failure {
        Failure::Client(status, _) => refused(status, BAD_BODY),
        other @ Failure::Request(_) => other,
    })?;
    // Unreadable state refuses here: `?` on a storage failure, before anything else.
    let release = state
        .requests
        .active_release(agent, &target.repository, &target.tag)
        .await?
        .ok_or_else(|| refused(StatusCode::FORBIDDEN, NO_ACTIVE_GRANT))?;
    *seen = Some(release.grant_id().clone());
    if !step.covered_by(&release.grant().steps) {
        return Err(refused(StatusCode::CONFLICT, STEP_NOT_IN_GRANT));
    }
    let key = state
        .backend
        .release_signing(&release.grant().repository)
        .await
        .map_err(not_configured)?;
    let app = state.backend.release_app().await.map_err(not_configured)?;
    if ReleasePolicy::new(&key, &app, &release.grant().tag).digest() != release.grant().digest {
        return Err(refused(StatusCode::CONFLICT, POLICY_CHANGED));
    }
    // Said before GitHub is asked anything: a step done is done, whatever GitHub
    // looks like now.
    if state.requests.step_claimed(&release, step).await? {
        return Err(refused(StatusCode::CONFLICT, STEP_DONE));
    }
    Ok((target, Ready { release, key, app }))
}

fn not_configured(e: PolicyError) -> Failure {
    match e {
        PolicyError::NoReleaseKey | PolicyError::NoReleaseApp => {
            refused(StatusCode::BAD_REQUEST, NOT_CONFIGURED)
        }
        other => RequestError::from(other).into(),
    }
}

/// Claim `step` of `release`. A revocation since the grant was read gives the same
/// refusal as no grant; any other reason the claim fails is that the step was used.
pub(super) async fn claim(
    state: &AppState,
    agent: &AgentName,
    target: &ReleaseTarget,
    release: &ActiveRelease,
    step: ReleaseStep,
) -> Result<(), Failure> {
    if state
        .requests
        .claim_step(release, step, state.clock.now())
        .await?
    {
        return Ok(());
    }
    let still_active = state
        .requests
        .active_release(agent, &target.repository, &target.tag)
        .await?
        .is_some_and(|active| active.grant_id() == release.grant_id());
    Err(if still_active {
        refused(StatusCode::CONFLICT, STEP_DONE)
    } else {
        refused(StatusCode::FORBIDDEN, NO_ACTIVE_GRANT)
    })
}

pub(super) fn github_failed(agent: &AgentName, step: ReleaseStep, e: &GithubError) -> Failure {
    // The error's text is fixed and carries nothing GitHub said.
    tracing::warn!(agent = %agent, step = step.name(), error = %e, "a release call to GitHub failed");
    refused(StatusCode::SERVICE_UNAVAILABLE, GITHUB_UNAVAILABLE)
}

async fn create_tag(
    state: &AppState,
    agent: &AgentName,
    body: Result<ReleaseTarget, Failure>,
    seen: &mut Option<Id>,
) -> Result<TagResponse, Failure> {
    let step = ReleaseStep::Tag;
    let (target, Ready { release, key, app }) = prepare(state, agent, body, step, seen).await?;
    let grant = release.grant();
    let now = state.clock.now();

    // Read-only checks, before the step is claimed: a refusal here costs the owner
    // nothing.
    let github = ReleaseClient::connect(&state.github, &app, &grant.repository, now)
        .await
        .map_err(|e| github_failed(agent, step, &e))?;
    drop(app);
    if github
        .tag_target(&grant.tag)
        .await
        .map_err(|e| github_failed(agent, step, &e))?
        .is_some()
    {
        return Err(refused(StatusCode::CONFLICT, TAG_EXISTS));
    }
    if !github
        .on_default_branch(&grant.commit)
        .await
        .map_err(|e| github_failed(agent, step, &e))?
    {
        return Err(refused(StatusCode::CONFLICT, COMMIT_MOVED));
    }
    claim(state, agent, &target, &release, step).await?;

    let message = format!("{} {}", grant.repository.name(), grant.tag.version());
    let payload = tag_payload(
        &grant.commit,
        &grant.tag,
        key.tagger_name(),
        key.tagger_email(),
        now,
        &message,
    );
    let signature = sign_tag(&key, &payload).map_err(|_| {
        tracing::error!(agent = %agent, "signing the release tag failed");
        refused(StatusCode::INTERNAL_SERVER_ERROR, "signing the tag failed")
    })?;
    let expected = tag_object_id(&payload, &signature);
    let tagged_at = jiff::Timestamp::from_second(now)
        .map_err(|_| Failure::Request(RequestError::Internal("the clock is out of range")))?;
    let created = github
        .create_tag(&CreateTag {
            tag: grant.tag.clone(),
            message: format!("{message}\n{signature}"),
            object: grant.commit.clone(),
            tagger_name: key.tagger_name().to_owned(),
            tagger_email: key.tagger_email().to_owned(),
            tagged_at,
        })
        .await
        .map_err(|e| github_failed(agent, step, &e))?;
    drop(key);
    // The ref is made only for the object that was signed.
    if created != expected {
        tracing::error!(agent = %agent, "GitHub made a different tag object than the one signed");
        return Err(refused(StatusCode::BAD_GATEWAY, TAG_DIFFERS));
    }
    github
        .create_ref(&grant.tag, &created)
        .await
        .map_err(|e| github_failed(agent, step, &e))?;

    state
        .audit
        .append(AuditEvent::ReleaseTagCreated {
            grant_id: release.grant_id().clone(),
            agent: agent.clone(),
            repository: grant.repository.clone(),
            tag: grant.tag.clone(),
            commit: grant.commit.clone(),
            object: created.clone(),
        })
        .await
        .map_err(RequestError::from)?;
    // Every step it covers may be claimed now. If this fails the grant simply runs
    // out its window, which gives no step back.
    if let Err(e) = state.requests.end_if_done(release.grant_id(), now).await {
        tracing::warn!(error = %e, "could not end the release grant");
    }
    tracing::info!(agent = %agent, grant = %release.grant_id(), "release tag created");
    Ok(TagResponse {
        grant_id: release.grant_id().clone(),
        tag: grant.tag.clone(),
        object: created,
        commit: grant.commit.clone(),
    })
}
