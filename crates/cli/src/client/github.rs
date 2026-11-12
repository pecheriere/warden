//! The calls of GitHub tokens: minting one for a repository, and asking the broker
//! whether it scopes GitHub grants to repositories.

use reqwest::{Method, StatusCode};
use url::Url;
use warden_broker_proto::InfoResponse;
use warden_broker_proto::github_token::{GithubTokenRequest, GithubTokenResponse};
use warden_broker_proto::release::RepoName;
use zeroize::Zeroizing;

use super::{CallError, Client, failure, fetch_info, json_body};
use crate::{EXIT_ERROR, Exit};

/// What the agent is told when the broker predates repository-scoped GitHub grants.
const OLD_BROKER: &str = "the broker does not support repository-scoped GitHub grants: upgrade \
                          the broker before asking for GitHub access";

impl Client {
    /// Have the broker mint a GitHub token for `repository` under this agent's
    /// active grant. The body is parsed here, so that no error can quote the token.
    ///
    /// # Errors
    /// If the server is unreachable or refuses.
    pub async fn github_token(
        &self,
        repository: &RepoName,
    ) -> Result<GithubTokenResponse, CallError> {
        let url = self.url("v1/github-token")?;
        let body = json_body(&GithubTokenRequest {
            repository: repository.clone(),
        })?;
        let resp = self.call(Method::POST, url, Some(body)).await?;
        if resp.status() != StatusCode::OK {
            return Err(failure(resp).await);
        }
        let body = Zeroizing::new(
            resp.bytes()
                .await
                .map_err(|e| {
                    CallError::Unavailable(format!("cannot read the broker's response: {e}"))
                })?
                .to_vec(),
        );
        serde_json::from_slice(&body)
            .map_err(|_| CallError::Refused("the broker sent an unexpected response".to_owned()))
    }
}

/// Whether the broker whose `/v1/info` answer is `info` scopes GitHub grants to
/// repositories. A broker that cannot be asked is treated as one that does not.
///
/// # Errors
/// [`Exit`] with [`EXIT_ERROR`] when it does not say so.
pub(crate) fn scoped_or_refuse(info: Result<InfoResponse, CallError>) -> anyhow::Result<()> {
    match info {
        Ok(info) if info.scoped_github_tokens => Ok(()),
        Ok(_) | Err(_) => Err(Exit::new(EXIT_ERROR, OLD_BROKER).into()),
    }
}

/// Refuse unless the broker at `server` scopes GitHub grants to repositories.
/// Called before a GitHub request is created, and before a token is minted that the
/// cache does not hold, so that nothing is asked of a broker that would grant more
/// than the agent names.
///
/// # Errors
/// [`Exit`] with [`EXIT_ERROR`] when the broker does not say it does, or cannot be
/// asked.
pub(crate) async fn require_scoped(server: &Url) -> anyhow::Result<()> {
    scoped_or_refuse(fetch_info(server).await)
}

#[cfg(test)]
mod tests;
