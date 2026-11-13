//! `GET /v1/offers/repository/{owner}/{name}`: what this agent may ask for in one
//! repository.
//!
//! Like `GET /v1/offers`, it decides no access, asks no one and is not an audited
//! request. Whether the agent App's installation covers the repository is what
//! GitHub answers when the broker asks it for a metadata-only token for that
//! repository, the way it resolves the repositories of a token request; the token
//! is dropped unused inside [`github_app::resolve`] and never reaches this module.
//! Only GitHub saying the installation cannot reach the repository is
//! `not_covered`: anything else that is not a token is `unavailable`.
//!
//! Answers are kept for [`RepositoryOfferCache::TTL_SECS`] seconds, so repeated
//! questions about one repository do not each ask GitHub.
//!
//! [`RepositoryOfferCache::TTL_SECS`]: crate::offers_cache::RepositoryOfferCache::TTL_SECS

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use warden_broker_proto::offers::{GithubTokenStatus, ReleaseStatus, RepositoryOffer};
use warden_broker_proto::release::RepoName;

use crate::AppState;
use crate::api::Failure;
use crate::github_app::{self, MintError};
use crate::identity::AuthedAgent;
use crate::policy::PolicyError;
use crate::requests::RequestError;

// `pub(in crate::api)`, not `pub(super)`: the router in `api` names it.
pub(in crate::api) async fn answer(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<RepositoryOffer>, Failure> {
    let repo = RepoName::try_from(format!("{owner}/{name}"))
        .map_err(|e| Failure::Client(StatusCode::BAD_REQUEST, e.to_string()))?;
    let now = state.clock.now();
    if let Some(offer) = state.repository_offers.get(&repo, now) {
        tracing::info!(agent = %agent, repository = %repo, cached = true, "repository offer answered");
        return Ok(Json(offer));
    }

    // Commit signing is a yes or a no, with no room for "could not tell": a backend
    // that cannot say is the error the other agent calls give.
    let commit_signing = state
        .backend
        .has_commit_signing_key()
        .await
        .map_err(|e| Failure::Request(RequestError::Unavailable(e.to_string())))?;
    let offer = RepositoryOffer {
        github_token: github_token(&state, &repo, now).await,
        release: release(&state, &repo).await,
        commit_signing,
        repository: repo,
    };
    state.repository_offers.put(offer.clone(), now);
    tracing::info!(agent = %agent, repository = %offer.repository, cached = false, "repository offer answered");
    Ok(Json(offer))
}

/// Whether the agent App's installation covers `repo`, by GitHub's answer.
async fn github_token(state: &AppState, repo: &RepoName, now: i64) -> GithubTokenStatus {
    let key = match state.backend.github_app().await {
        Ok(key) => key,
        Err(PolicyError::NoGithubApp) => return GithubTokenStatus::NotConfigured,
        Err(e) => {
            tracing::warn!(error = %e, "the GitHub App could not be read for a repository offer");
            return GithubTokenStatus::Unavailable;
        }
    };
    match github_app::resolve(&state.github, &key, std::slice::from_ref(repo), now).await {
        Ok(_) => GithubTokenStatus::Covered,
        // A 422 to the token request, or a 201 naming the repository under another
        // owner: GitHub's own answer that the installation does not reach it.
        Err(MintError::NotAccessible) => GithubTokenStatus::NotCovered,
        Err(e) => {
            // The text of a `MintError` is fixed: nothing GitHub said is in it.
            tracing::warn!(error = %e, "GitHub could not tell whether it covers a repository");
            GithubTokenStatus::Unavailable
        }
    }
}

/// Whether `repo` can be released: a release signing key names it and a release
/// App exists. Whether GitHub trusts the key is not checked here.
async fn release(state: &AppState, repo: &RepoName) -> ReleaseStatus {
    let outcome = match state.backend.release_signing(repo).await {
        // Only that the key exists matters: it is dropped at the end of this arm.
        Ok(_key) => state.backend.has_release_app().await.map(|app| {
            if app {
                ReleaseStatus::Ready
            } else {
                ReleaseStatus::NoReleaseApp
            }
        }),
        Err(PolicyError::NoReleaseKey) => Ok(ReleaseStatus::NoKey),
        Err(e) => Err(e),
    };
    outcome.unwrap_or_else(|e| {
        tracing::warn!(error = %e, "the release setup could not be read for a repository offer");
        ReleaseStatus::Unavailable
    })
}

#[cfg(test)]
mod tests;
