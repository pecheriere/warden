//! `POST /v1/github-token`.
//!
//! The broker mints a GitHub App installation token for an agent only under that
//! agent's own active grant, which is looked up for every mint. Each token is
//! recorded before it leaves the broker, and each refusal is recorded too. The
//! token, the JWT that asked for it and anything GitHub said never appear in an
//! error, a log line or the audit log.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use secrecy::ExposeSecret as _;
use warden_broker_proto::github_token::{
    APP_CHANGED, GithubTokenResponse, GrantScope, HOURLY_LIMIT, NO_ACTIVE_GRANT, PERMISSIONS,
    REPOSITORY_UNREACHABLE,
};
use warden_broker_proto::{AgentName, Id};

use super::{ApiJson, Failure};
use crate::AppState;
use crate::audit::AuditEvent;
use crate::github_app;
use crate::identity::AuthedAgent;
use crate::requests::{ActiveGithubToken, RequestError};

/// What the agent is told when GitHub gave no token. Fixed: nothing GitHub said, and
/// nothing about why, is passed on.
const GITHUB_UNAVAILABLE: &str = "GitHub could not issue a token; try again later";

/// How the 409 for a grant that ended while the token was being minted begins; the
/// CLI recognises the first words.
const REVOKED_DURING: &str = "grant revoked during the call";
const EXPIRED_DURING: &str = "grant expired during the call";

/// `POST /v1/github-token`: mint a token under the agent's grant. Runs on its own
/// task, so that a disconnecting agent can neither stop it halfway nor keep it out
/// of the audit log. A body that is not `{}` is a refusal like any other, and
/// recorded.
pub(super) async fn mint(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
    body: Result<ApiJson<serde_json::Map<String, serde_json::Value>>, Failure>,
) -> Result<Json<GithubTokenResponse>, Failure> {
    // An empty object and nothing else: not an array, and no field.
    let body = body.and_then(|ApiJson(fields)| {
        if fields.is_empty() {
            Ok(())
        } else {
            Err(refused(
                StatusCode::BAD_REQUEST,
                "the request body is not valid",
            ))
        }
    });
    tokio::spawn(audited(state, agent, body))
        .await
        .map_err(|_| Failure::Request(RequestError::Internal("minting task failed")))?
        .map(Json)
}

async fn audited(
    state: AppState,
    agent: AgentName,
    body: Result<(), Failure>,
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
    body: Result<(), Failure>,
    seen: &mut Option<Id>,
) -> Result<GithubTokenResponse, Failure> {
    // Unreadable state refuses here: `?` on a storage failure, before anything else.
    let active = state.requests.active_github_token(agent).await?;
    *seen = active.as_ref().map(|active| active.grant_id.clone());
    // Fixed text, as it goes in the audit log: a parser's message can quote the body.
    body.map_err(|failure| match failure {
        Failure::Client(status, _) => refused(status, "the request body is not valid"),
        other @ Failure::Request(_) => other,
    })?;
    let ActiveGithubToken { grant_id, grant } =
        active.ok_or_else(|| refused(StatusCode::FORBIDDEN, NO_ACTIVE_GRANT))?;

    let key = state
        .backend
        .github_app()
        .await
        .map_err(RequestError::from)?;
    let current = key.policy(state.requests.github_token_max());
    if current.destination_digest() != grant.digest {
        return Err(refused(StatusCode::CONFLICT, APP_CHANGED));
    }
    // A grant that names no repository mints nothing: there is nothing to scope the
    // token to. Until the request names the repository, only a grant of exactly
    // one can be served.
    let GrantScope::Repositories(covered) = &grant.repositories else {
        return Err(refused(StatusCode::FORBIDDEN, NO_ACTIVE_GRANT));
    };
    let [repository] = covered.as_slice() else {
        return Err(refused(StatusCode::FORBIDDEN, NO_ACTIVE_GRANT));
    };
    // Taken before GitHub is asked, so that refused calls cost GitHub nothing.
    if !state.requests.take_mint(&grant_id).await? {
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
                _ => refused(StatusCode::SERVICE_UNAVAILABLE, GITHUB_UNAVAILABLE),
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
    };
    drop(key);
    state
        .audit
        .append(event)
        .await
        .map_err(RequestError::from)?;
    // The call to GitHub and the log both take time, and a revocation does not wait
    // for them: a grant that has ended meanwhile, or been replaced, gets nothing.
    let still_active = state.requests.active_github_token(agent).await?;
    if still_active.is_none_or(|active| active.grant_id != grant_id) {
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
