//! `POST /v1/github-token`.
//!
//! The broker mints a GitHub App installation token for an agent only under one of
//! that agent's own active grants that cover the repository the request names, the
//! least privileged one holding what the request names, which is looked up for every
//! mint, and only for that repository's id. A token carries an extra permission only
//! when the request names it. Each token is
//! recorded before it leaves the broker, and each refusal is recorded too. The
//! token, the JWT that asked for it and anything GitHub said never appear in an
//! error, a log line or the audit log.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use secrecy::ExposeSecret as _;
use warden_broker_proto::github_permissions::PermissionSet;
use warden_broker_proto::github_token::{
    AMBIGUOUS_GRANT, APP_CHANGED, GithubTokenRequest, GithubTokenResponse, HOURLY_LIMIT,
    NO_ACTIVE_GRANT, OLD_CLIENT, OTHER_GRANT_APPLIES, PERMISSIONS_NOT_IN_GRANT,
    REPOSITORY_UNREACHABLE,
};
use warden_broker_proto::{AgentName, Id, Window};

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

/// A grant that holds a sensitive permission lasts at most 1h, so one stored with a
/// longer window is not trusted.
const SENSITIVE_GRANT_TOO_LONG: &str =
    "this grant holds a sensitive permission for longer than 1h and cannot mint";

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
    let wanted = request.permissions.as_ref();
    // Unreadable state refuses here: `?` on a storage failure, before GitHub or the
    // key is touched.
    let lookup = state
        .requests
        .active_github_token_for(agent, &request.repository, wanted)
        .await?;
    let active = match lookup {
        GithubLookup::None => return Err(refused(StatusCode::FORBIDDEN, NO_ACTIVE_GRANT)),
        GithubLookup::Ambiguous(first) => {
            *seen = Some(first);
            return Err(refused(StatusCode::CONFLICT, AMBIGUOUS_GRANT));
        }
        GithubLookup::One(active) => active,
    };
    *seen = Some(active.grant_id.clone());
    // Creation, approval and renewal never make such a grant; a stored one that is
    // (a row changed since) is not minted from. The lookup read the set strictly.
    if active.window_secs > Window::H1.secs() && active.permissions.sensitive().next().is_some() {
        return Err(refused(StatusCode::FORBIDDEN, SENSITIVE_GRANT_TOO_LONG));
    }
    // Read once, before GitHub is asked: an owner's default that cannot be read
    // refuses here, and the check after the mint compares only the grant.
    let mint = state.requests.github_mint_set(&active, wanted).await?;
    let permissions = narrowed(wanted, mint)?;
    let ActiveGithubToken {
        grant_id,
        grant,
        repository,
        ..
    } = active;

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
    let minted = github_app::mint(
        &state.github,
        &key,
        repository.id,
        &permissions,
        state.clock.now(),
    )
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
        permissions: minted.granted.iter().map(|p| p.to_string()).collect(),
        expires_at: minted.token.expires_at,
        repository: Some(repository.name.clone()),
        repository_id: Some(repository.id),
    };
    drop(key);
    state
        .audit
        .append(event)
        .await
        .map_err(RequestError::from)?;
    still_the_grant(state, agent, &request, &grant_id, repository.id).await?;
    tracing::info!(agent = %agent, grant = %grant_id, "GitHub token minted");
    Ok(GithubTokenResponse {
        token: minted.token.token.expose_secret().to_owned(),
        expires_at: minted.token.expires_at,
        grant_id,
        repository: repository.name.clone(),
        repository_id: repository.id,
        permissions: Some(minted.granted.into()),
    })
}

/// The check after GitHub answered and the mint was logged: the same pick for the same
/// `request` must find `grant_id`, still active, for `repository_id`. The call to
/// GitHub and the log both take time, and a revocation does not wait for them.
async fn still_the_grant(
    state: &AppState,
    agent: &AgentName,
    request: &GithubTokenRequest,
    grant_id: &Id,
    repository_id: u64,
) -> Result<(), Failure> {
    // A grant that has ended meanwhile, or been replaced, gets nothing. Only storage
    // is read: the set to mint with was settled before GitHub was asked.
    let still_active = state
        .requests
        .active_github_token_for(agent, &request.repository, request.permissions.as_ref())
        .await?;
    match &still_active {
        GithubLookup::One(active)
            if active.grant_id == *grant_id && active.repository.id == repository_id =>
        {
            Ok(())
        }
        GithubLookup::Ambiguous(_) => Err(refused(StatusCode::CONFLICT, AMBIGUOUS_GRANT)),
        GithubLookup::One(other) if other.grant_id != *grant_id => {
            Err(ended(state, agent, grant_id, OTHER_GRANT_APPLIES).await)
        }
        GithubLookup::One(_) | GithubLookup::None => {
            Err(ended(state, agent, grant_id, REVOKED_DURING).await)
        }
    }
}

/// The permissions to mint with: `mint`, what the lookup found for the request, or
/// the narrower set the agent asks for. One the grant does not hold is refused before
/// GitHub or the key is touched, naming the first known permission it lacks.
fn narrowed(wanted: Option<&PermissionSet>, mint: PermissionSet) -> Result<PermissionSet, Failure> {
    let Some(wanted) = wanted else {
        return Ok(mint);
    };
    match wanted.missing_from(&mint).first() {
        Some(missing) => Err(refused(
            StatusCode::FORBIDDEN,
            format!("{PERMISSIONS_NOT_IN_GRANT}{missing}"),
        )),
        None => Ok(wanted.clone()),
    }
}

/// The failure for grant `grant_id`, which the check after the mint no longer
/// finds: a 409 that says it expired or was revoked if it did, and otherwise
/// `live`, which says why a grant still live was not the one found. Anything unclear
/// is called revoked: the refusal is the same. A failed lookup is the failure instead.
async fn ended(state: &AppState, agent: &AgentName, grant_id: &Id, live: &'static str) -> Failure {
    let reason = match state.requests.agent_grant(agent, grant_id).await {
        Ok((_, true)) | Err(RequestError::NotFound) => REVOKED_DURING,
        Ok((view, false)) if state.clock.now() >= view.not_after => EXPIRED_DURING,
        Ok((_, false)) => live,
        Err(e) => return e.into(),
    };
    refused(StatusCode::CONFLICT, reason)
}
