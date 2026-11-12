//! Minting GitHub App installation tokens: the broker signs a short-lived App
//! JWT with the App's private key and exchanges it at GitHub for a token
//! limited to [`PERMISSIONS`]. Neither the JWT nor the token is ever logged,
//! and no error carries text from GitHub, which could echo them.

use http::{Method, StatusCode};
use reqwest::Client;
use serde_json::json;
use url::Url;
use warden_broker_proto::github_token::PERMISSIONS;
use warden_broker_proto::release::RepoName;
use zeroize::Zeroizing;

use self::answer::Answer;
use crate::github_http::{self, Failure, Payload};
use crate::policy::GithubAppKey;

/// Where GitHub's API and its uploads host are, and whom to trust there.
#[derive(Debug, Clone)]
pub struct GithubApi {
    base: Url,
    uploads: Url,
    ca_pem: Option<Vec<u8>>,
}

impl GithubApi {
    /// `https://api.github.com` and `https://uploads.github.com`, trusting the
    /// system roots.
    ///
    /// # Panics
    /// Never: the URLs are constants.
    #[must_use]
    pub fn public() -> Self {
        Self {
            base: Url::parse("https://api.github.com").expect("constant URL"),
            uploads: Url::parse("https://uploads.github.com").expect("constant URL"),
            ca_pem: None,
        }
    }

    /// `base` and `uploads`, trusting only the CAs in `ca_pem`. For tests.
    #[must_use]
    pub const fn pinned(base: Url, uploads: Url, ca_pem: Vec<u8>) -> Self {
        Self {
            base,
            uploads,
            ca_pem: Some(ca_pem),
        }
    }

    /// The API's origin, where tokens, tags and releases are.
    #[must_use]
    pub const fn base(&self) -> &Url {
        &self.base
    }

    /// The uploads host's origin, where release assets go.
    #[must_use]
    pub const fn uploads(&self) -> &Url {
        &self.uploads
    }

    pub(crate) fn client(&self) -> Result<Client, Failure> {
        github_http::client(self.ca_pem.as_deref())
    }
}

mod answer;

pub use crate::github_http::InstallationToken;

/// Why no token was minted. The messages are fixed and carry nothing GitHub said.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MintError {
    /// The App's key could not sign the JWT.
    #[error("the GitHub App key could not sign")]
    Key,
    /// No TLS session could be made, or the call broke or timed out.
    #[error("GitHub could not be reached")]
    Unreachable,
    /// GitHub answered with a status other than 201.
    #[error("GitHub refused the request")]
    Refused(u16),
    /// The answer was not the expected JSON, or its expiry is not credible.
    #[error("GitHub's answer was not understood")]
    Malformed,
    /// The answer is larger than the limit.
    #[error("GitHub's answer was too large")]
    TooLarge,
    /// The answer is encoded in a way the broker does not read.
    #[error("GitHub's answer was compressed")]
    Compressed,
    /// GitHub says the App cannot reach a repository asked for.
    #[error("GitHub says the App cannot reach that repository")]
    NotAccessible,
    /// The token's answer shows it was not limited as asked.
    #[error("GitHub's token was not limited as asked")]
    WrongScope,
}

impl From<Failure> for MintError {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Key => Self::Key,
            Failure::Unreachable => Self::Unreachable,
            Failure::TooLarge => Self::TooLarge,
            Failure::Encoded => Self::Compressed,
        }
    }
}

/// The status GitHub answers with when a repository asked for is not reachable by
/// the installation (measured against the real API: all-or-nothing for a list).
const INACCESSIBLE_STATUS: u16 = 422;

/// A repository as GitHub names it: its id and its name in GitHub's case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRepository {
    /// GitHub's id for the repository.
    pub id: u64,
    /// `owner/name` as GitHub spells it today.
    pub name: RepoName,
}

/// The App JWT, for the App `key` names.
fn jwt(key: &GithubAppKey, now: i64) -> Result<Zeroizing<String>, MintError> {
    Ok(github_http::app_jwt(key.app_id(), now, |msg| {
        // The fixed reason is replaced by `Failure::Key`: it is not passed on.
        key.sign_rs256(msg)
            .map_err(|_| "the App's key could not sign")
    })?)
}

fn permissions_body(permissions: &[(&str, &str)]) -> serde_json::Value {
    permissions
        .iter()
        .map(|(name, level)| ((*name).to_owned(), json!(level)))
        .collect::<serde_json::Map<_, _>>()
        .into()
}

/// Ask GitHub for a token with `body` and parse the answer. Nothing is checked
/// beyond the shape, the token and its expiry: the callers check the scope.
async fn request(
    api: &GithubApi,
    key: &GithubAppKey,
    body: &serde_json::Value,
    now: i64,
) -> Result<Answer, MintError> {
    let signer = key.clone();
    // RSA signing takes milliseconds of CPU: keep it off the async workers.
    let jwt = tokio::task::spawn_blocking(move || jwt(&signer, now))
        .await
        .map_err(|_| MintError::Key)??;
    let url = api
        .base
        .join(&format!(
            "app/installations/{}/access_tokens",
            key.installation_id()
        ))
        .map_err(|_| MintError::Unreachable)?;
    let request = github_http::request(
        &api.client()?,
        Method::POST,
        url,
        jwt.as_str(),
        github_http::JSON,
        Payload::Json(body.to_string()),
    )?;
    let response = github_http::send(request).await?;
    let status = response.status();
    if status.as_u16() == INACCESSIBLE_STATUS {
        // The body is never read: nothing GitHub says is passed on.
        return Err(MintError::NotAccessible);
    }
    if status != StatusCode::CREATED {
        return Err(MintError::Refused(status.as_u16()));
    }
    let raw = github_http::read_body(response, github_http::MAX_RESPONSE_BYTES).await?;
    Answer::parse(&raw, now)
}

/// Mint an installation token for `key`'s installation with the fixed
/// [`PERMISSIONS`], limited to the repository with id `repository_id`. `now` is
/// Unix seconds. There is no way to mint a token without naming a repository.
///
/// The client trusts the system roots (or the pinned CA), refuses redirects and
/// never retries.
///
/// # Errors
/// A [`MintError`]; nothing partial is returned. [`MintError::WrongScope`] when
/// GitHub's answer does not show a token limited to exactly that repository
/// with no more than the permissions asked.
pub async fn mint(
    api: &GithubApi,
    key: &GithubAppKey,
    repository_id: u64,
    now: i64,
) -> Result<InstallationToken, MintError> {
    let body = json!({
        "permissions": permissions_body(&PERMISSIONS),
        "repository_ids": [repository_id],
    });
    let answer = request(api, key, &body, now).await?;
    answer.check_minted(repository_id)?;
    Ok(answer.token)
}

/// What `names` are today, by GitHub's account: each one's id and its name in
/// GitHub's case. The token that tells it is limited to reading metadata and is
/// dropped unused.
///
/// The owner part of a name is not sent (GitHub takes bare names within the
/// installation's account); it is checked against the answer instead.
///
/// # Errors
/// A [`MintError`]; [`MintError::NotAccessible`] when GitHub cannot reach one of
/// them, [`MintError::WrongScope`] when the answer is not one entry per name.
pub async fn resolve(
    api: &GithubApi,
    key: &GithubAppKey,
    names: &[RepoName],
    now: i64,
) -> Result<Vec<ResolvedRepository>, MintError> {
    let bare: Vec<&str> = names.iter().map(RepoName::name).collect();
    let body = json!({
        "permissions": permissions_body(&[("metadata", "read")]),
        "repositories": bare,
    });
    request(api, key, &body, now).await?.check_names(names)
}

/// What the repositories with `ids` are called today, for renewing a grant whose
/// repositories may have been renamed. The token is dropped unused.
///
/// # Errors
/// As [`resolve`]; the answer must hold exactly those ids.
pub async fn current_names(
    api: &GithubApi,
    key: &GithubAppKey,
    ids: &[u64],
    now: i64,
) -> Result<Vec<ResolvedRepository>, MintError> {
    let body = json!({
        "permissions": permissions_body(&[("metadata", "read")]),
        "repository_ids": ids,
    });
    request(api, key, &body, now).await?.check_ids(ids)
}

#[cfg(test)]
mod tests;
