//! `POST /v1/github-token`.
//!
//! The broker mints a GitHub App installation token for an agent only under that
//! agent's own active grant that covers the repository the request names, which is
//! looked up for every mint, and only for that repository's id. Each token is
//! recorded before it leaves the broker, and each refusal is recorded too. The
//! token, the JWT that asked for it and anything GitHub said never appear in an
//! error, a log line or the audit log.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use secrecy::ExposeSecret as _;
use warden_broker_proto::github_token::{
    AMBIGUOUS_GRANT, APP_CHANGED, GithubTokenRequest, GithubTokenResponse, HOURLY_LIMIT,
    NO_ACTIVE_GRANT, OLD_CLIENT, PERMISSIONS, REPOSITORY_UNREACHABLE,
};
use warden_broker_proto::{AgentName, Id};

use super::{ApiJson, Failure};
use crate::AppState;
use crate::audit::AuditEvent;
use crate::github_app;
use crate::identity::AuthedAgent;
use crate::requests::{ActiveGithubToken, GithubLookup, RequestError};

/// What the agent is told when GitHub gave no token. Fixed: nothing GitHub said, and
/// nothing about why, is passed on.
const GITHUB_UNAVAILABLE: &str = "GitHub could not issue a token; try again later";

/// How the 409 for a grant that ended while the token was being minted begins; the
/// CLI recognises the first words.
const REVOKED_DURING: &str = "grant revoked during the call";
const EXPIRED_DURING: &str = "grant expired during the call";

/// `POST /v1/github-token`: mint a token for the repository the body names, under
/// the agent's grant that covers it. Runs on its own task, so that a disconnecting
/// agent can neither stop it halfway nor keep it out of the audit log. A body that
/// does not name a repository is a refusal like any other, and recorded.
pub(super) async fn mint(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
    body: Result<ApiJson<serde_json::Value>, Failure>,
) -> Result<Json<GithubTokenResponse>, Failure> {
    // Fixed text, as it goes in the audit log: a parser's message can quote the body.
    let body = body.map_err(|failure| match failure {
        Failure::Client(status, _) => refused(status, "the request body is not valid"),
        other @ Failure::Request(_) => other,
    });
    let body = body.and_then(|ApiJson(value)| {
        // An empty object is what a CLI sent before grants were scoped.
        if value.as_object().is_some_and(serde_json::Map::is_empty) {
            return Err(refused(StatusCode::BAD_REQUEST, OLD_CLIENT));
        }
        serde_json::from_value::<GithubTokenRequest>(value)
            .map_err(|_| refused(StatusCode::BAD_REQUEST, "the request body is not valid"))
    });
    tokio::spawn(audited(state, agent, body))
        .await
        .map_err(|_| Failure::Request(RequestError::Internal("minting task failed")))?
        .map(Json)
}

async fn audited(
    state: AppState,
    agent: AgentName,
    body: Result<GithubTokenRequest, Failure>,
) -> Result<GithubTokenResponse, Failure> {
    let mut grant_id = None;
    let result = attempt(&state, &agent, body, &mut grant_id).await;
    if let Err(failure) = &result {
        let reason = failure.outcome();
        tracing::info!(agent = %agent, reason = %reason, "GitHub token refused");
        state
            .requests
            .record_github_token_refusal(&agent, grant_id, reason)
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
    body: Result<GithubTokenRequest, Failure>,
    seen: &mut Option<Id>,
) -> Result<GithubTokenResponse, Failure> {
    let request = body?;
    // Unreadable state refuses here: `?` on a storage failure, before anything else.
    let lookup = state
        .requests
        .active_github_token_for(agent, &request.repository)
        .await?;
    let ActiveGithubToken {
        grant_id,
        grant,
        repository,
    } = match lookup {
        GithubLookup::None => return Err(refused(StatusCode::FORBIDDEN, NO_ACTIVE_GRANT)),
        GithubLookup::Ambiguous => return Err(refused(StatusCode::CONFLICT, AMBIGUOUS_GRANT)),
        GithubLookup::One(active) => active,
    };
    *seen = Some(grant_id.clone());

    let key = state
        .backend
        .github_app()
        .await
        .map_err(RequestError::from)?;
    let current = key.policy(state.requests.github_token_max());
    if current.destination_digest() != grant.digest {
        return Err(refused(StatusCode::CONFLICT, APP_CHANGED));
    }
    // Taken before GitHub is asked, so that refused calls cost GitHub nothing. A call
    // GitHub then refuses as unreachable still counts against the hour.
    if !state.requests.take_mint(agent).await? {
        return Err(refused(StatusCode::TOO_MANY_REQUESTS, HOURLY_LIMIT));
    }
    let minted = github_app::mint(&state.github, &key, repository.id, state.clock.now())
        .await
        .map_err(|e| {
            // The error's text is fixed and carries nothing GitHub said. A token that
            // was not limited as asked was dropped unread, and nothing is retried.
            tracing::warn!(agent = %agent, error = %e, "minting a GitHub token failed");
            match e {
                github_app::MintError::NotAccessible | github_app::MintError::WrongScope => {
                    refused(StatusCode::CONFLICT, REPOSITORY_UNREACHABLE)
                }
                github_app::MintError::Key
                | github_app::MintError::Unreachable
                | github_app::MintError::Refused(_)
                | github_app::MintError::Malformed
                | github_app::MintError::TooLarge
                | github_app::MintError::Compressed => {
                    refused(StatusCode::SERVICE_UNAVAILABLE, GITHUB_UNAVAILABLE)
                }
            }
        })?;

    let event = AuditEvent::GithubTokenMinted {
        grant_id: grant_id.clone(),
        agent: agent.clone(),
        installation_id: key.installation_id(),
        permissions: PERMISSIONS
            .iter()
            .map(|(name, level)| format!("{name}:{level}"))
            .collect(),
        expires_at: minted.expires_at,
        repository: Some(repository.name.clone()),
        repository_id: Some(repository.id),
    };
    drop(key);
    state
        .audit
        .append(event)
        .await
        .map_err(RequestError::from)?;
    // The call to GitHub and the log both take time, and a revocation does not wait
    // for them: a grant that has ended meanwhile, or been replaced, gets nothing.
    let still_active = state
        .requests
        .active_github_token_for(agent, &repository.name)
        .await?;
    if !matches!(&still_active, GithubLookup::One(active)
        if active.grant_id == grant_id && active.repository.id == repository.id)
    {
        return Err(ended(state, agent, &grant_id).await);
    }
    tracing::info!(agent = %agent, grant = %grant_id, "GitHub token minted");
    Ok(GithubTokenResponse {
        token: minted.token.expose_secret().to_owned(),
        expires_at: minted.expires_at,
        grant_id,
        repository: repository.name.clone(),
        repository_id: repository.id,
    })
}

/// The failure for grant `grant_id`, which is no longer active: a 409 that says
/// revoked, unless it expired. Anything unclear is called revoked: the refusal is
/// the same. A failed lookup is the failure instead.
async fn ended(state: &AppState, agent: &AgentName, grant_id: &Id) -> Failure {
    let expired = match state.requests.agent_grant(agent, grant_id).await {
        Ok((view, revoked)) => !revoked && state.clock.now() >= view.not_after,
        Err(RequestError::NotFound) => false,
        Err(e) => return e.into(),
    };
    refused(
        StatusCode::CONFLICT,
        if expired {
            EXPIRED_DURING
        } else {
            REVOKED_DURING
        },
    )
}
