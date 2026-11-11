//! Minting GitHub App installation tokens: the broker signs a short-lived App
//! JWT with the App's private key and exchanges it at GitHub for a token
//! limited to [`PERMISSIONS`]. Neither the JWT nor the token is ever logged,
//! and no error carries text from GitHub, which could echo them.

use http::{Method, StatusCode};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use url::Url;
use warden_broker_proto::github_token::PERMISSIONS;
use zeroize::Zeroizing;

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

#[derive(Deserialize)]
struct Answer {
    token: String,
    expires_at: String,
}

/// The App JWT, for the App `key` names.
fn jwt(key: &GithubAppKey, now: i64) -> Result<Zeroizing<String>, MintError> {
    Ok(github_http::app_jwt(key.app_id(), now, |msg| {
        // The fixed reason is replaced by `Failure::Key`: it is not passed on.
        key.sign_rs256(msg)
            .map_err(|_| "the App's key could not sign")
    })?)
}

/// Mint an installation token for `key`'s installation with the fixed
/// [`PERMISSIONS`] and no repository restriction. `now` is Unix seconds.
///
/// The client trusts the system roots (or the pinned CA), refuses redirects and
/// never retries.
///
/// # Errors
/// A [`MintError`]; nothing partial is returned.
pub async fn mint(
    api: &GithubApi,
    key: &GithubAppKey,
    now: i64,
) -> Result<InstallationToken, MintError> {
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
    let permissions: serde_json::Map<String, serde_json::Value> = PERMISSIONS
        .iter()
        .map(|(name, level)| ((*name).to_owned(), json!(level)))
        .collect();
    let body = json!({ "permissions": permissions }).to_string();
    let request = github_http::request(
        &api.client()?,
        Method::POST,
        url,
        jwt.as_str(),
        github_http::JSON,
        Payload::Json(body),
    )?;
    let response = github_http::send(request).await?;
    if response.status() != StatusCode::CREATED {
        // The body is never read: nothing GitHub says is passed on.
        return Err(MintError::Refused(response.status().as_u16()));
    }
    let raw = github_http::read_body(response, github_http::MAX_RESPONSE_BYTES).await?;
    parse(&raw, now)
}

/// The token and expiry in `raw`, which must expire after `now` and within
/// two hours.
fn parse(raw: &[u8], now: i64) -> Result<InstallationToken, MintError> {
    let Answer { token, expires_at } =
        serde_json::from_slice(raw).map_err(|_| MintError::Malformed)?;
    github_http::checked_token(token, &expires_at, now).ok_or(MintError::Malformed)
}

#[cfg(test)]
mod tests;
