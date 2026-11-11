//! The broker's own GitHub client for releases, run with the release App's
//! credentials and never an agent's.
//!
//! It finds the release App's installation on a repository, then mints a token
//! for that one repository with `contents: write` and `metadata: read` and
//! nothing more. Every call goes through [`crate::github_http`]: HTTPS only, no
//! redirects, no retries, no encoded answers, a bounded body.
//!
//! No text GitHub sent reaches an error, a log line or an audit entry: a
//! [`GithubError`] is one of four fixed cases, and the status of a refusal is a
//! number. A key or token appears only in a request's `Authorization` header.

use http::{Method, StatusCode};
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use warden_broker_proto::release::RepoName;

use crate::github_app::{GithubApi, InstallationToken};
use crate::github_http::{self, Failure};
use crate::policy::ReleaseAppKey;

/// Why a call to GitHub gave nothing usable. The messages are fixed and carry
/// nothing GitHub said.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GithubError {
    /// No TLS session could be made, the call broke or timed out, or the App's
    /// key could not sign.
    #[error("GitHub could not be reached")]
    Unreachable,
    /// GitHub answered with a status the call does not expect.
    #[error("GitHub refused the request")]
    Refused(StatusCode),
    /// GitHub answered `404`: the repository does not exist, or the release App
    /// is not installed on it.
    #[error("GitHub does not have what was asked for")]
    NotFound,
    /// The answer was not the expected JSON, was larger than the limit or was
    /// encoded, or the token it carried is wider or longer-lived than asked.
    #[error("GitHub's answer was not understood")]
    Unreadable,
}

impl From<Failure> for GithubError {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Key | Failure::Unreachable => Self::Unreachable,
            Failure::TooLarge | Failure::Encoded => Self::Unreadable,
        }
    }
}

/// The permissions of a release token: all of them, nothing else.
#[derive(Serialize)]
struct Permissions {
    contents: &'static str,
    metadata: &'static str,
}

const PERMISSIONS: Permissions = Permissions {
    contents: "write",
    metadata: "read",
};

/// The body that asks for a token, in this order.
#[derive(Serialize)]
struct TokenRequest<'a> {
    repositories: [&'a str; 1],
    permissions: Permissions,
}

#[derive(Deserialize)]
struct InstallationAnswer {
    id: u64,
}

#[derive(Deserialize)]
struct TokenAnswer {
    token: String,
    expires_at: String,
    permissions: std::collections::BTreeMap<String, String>,
}

/// The release App's JWT, signed off the async workers (RSA takes milliseconds).
async fn app_jwt(app: &ReleaseAppKey, now: i64) -> Result<zeroize::Zeroizing<String>, GithubError> {
    let signer = app.clone();
    tokio::task::spawn_blocking(move || {
        github_http::app_jwt(signer.app_id(), now, |msg| signer.sign_rs256(msg))
    })
    .await
    .map_err(|_| GithubError::Unreachable)?
    .map_err(GithubError::from)
}

/// Send one request as the App and return the body of a `success` answer.
async fn call(
    api: &GithubApi,
    credential: &str,
    method: Method,
    path: &str,
    body: Option<String>,
    success: StatusCode,
) -> Result<zeroize::Zeroizing<Vec<u8>>, GithubError> {
    let url = api
        .base()
        .join(path)
        .map_err(|_| GithubError::Unreachable)?;
    let request = github_http::request(&api.client()?, method, url, credential, body)?;
    let response = github_http::send(request).await?;
    match response.status() {
        status if status == success => Ok(github_http::read_body(response).await?),
        // The body is never read: nothing GitHub says is passed on.
        StatusCode::NOT_FOUND => Err(GithubError::NotFound),
        status => Err(GithubError::Refused(status)),
    }
}

/// The id of the release App's installation on `repo`.
///
/// `GET /repos/{owner}/{name}/installation`, as the App. `now` is Unix seconds.
///
/// # Errors
/// [`GithubError::NotFound`] when the App is not installed on `repo`, or another
/// [`GithubError`].
pub async fn installation_for(
    api: &GithubApi,
    app: &ReleaseAppKey,
    repo: &RepoName,
    now: i64,
) -> Result<u64, GithubError> {
    let jwt = app_jwt(app, now).await?;
    let path = format!("repos/{}/{}/installation", repo.owner(), repo.name());
    let raw = call(api, jwt.as_str(), Method::GET, &path, None, StatusCode::OK).await?;
    let InstallationAnswer { id } =
        serde_json::from_slice(&raw).map_err(|_| GithubError::Unreadable)?;
    Ok(id)
}

/// A token for `installation`, limited to `repo` and to `contents: write` with
/// `metadata: read`.
///
/// # Errors
/// [`GithubError::Unreadable`] when the answer's permissions differ from those
/// asked for, or its expiry is not after `now` and within two hours of it;
/// another [`GithubError`] when the call fails.
pub async fn release_token(
    api: &GithubApi,
    app: &ReleaseAppKey,
    installation: u64,
    repo: &RepoName,
    now: i64,
) -> Result<InstallationToken, GithubError> {
    let jwt = app_jwt(app, now).await?;
    let body = serde_json::to_string(&TokenRequest {
        repositories: [repo.name()],
        permissions: PERMISSIONS,
    })
    .map_err(|_| GithubError::Unreadable)?;
    let path = format!("app/installations/{installation}/access_tokens");
    let raw = call(
        api,
        jwt.as_str(),
        Method::POST,
        &path,
        Some(body),
        StatusCode::CREATED,
    )
    .await?;
    let TokenAnswer {
        token,
        expires_at,
        permissions,
    } = serde_json::from_slice(&raw).map_err(|_| GithubError::Unreadable)?;
    let exact = permissions.len() == 2
        && permissions.get("contents").map(String::as_str) == Some(PERMISSIONS.contents)
        && permissions.get("metadata").map(String::as_str) == Some(PERMISSIONS.metadata);
    if !exact {
        return Err(GithubError::Unreadable);
    }
    github_http::checked_token(token, &expires_at, now).ok_or(GithubError::Unreadable)
}

/// A client for one repository, holding a release token for it.
pub struct ReleaseClient<'a> {
    api: &'a GithubApi,
    token: InstallationToken,
    repo: RepoName,
}

impl<'a> ReleaseClient<'a> {
    /// Find the release App's installation on `repo` and mint a token for it.
    ///
    /// # Errors
    /// A [`GithubError`] from either call; nothing partial is returned.
    pub async fn connect(
        api: &'a GithubApi,
        app: &ReleaseAppKey,
        repo: &RepoName,
        now: i64,
    ) -> Result<Self, GithubError> {
        let installation = installation_for(api, app, repo, now).await?;
        let token = release_token(api, app, installation, repo, now).await?;
        Ok(Self {
            api,
            token,
            repo: repo.clone(),
        })
    }

    /// The repository the token is limited to.
    #[must_use]
    pub const fn repo(&self) -> &RepoName {
        &self.repo
    }

    /// When the token stops working, in seconds since the Unix epoch.
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.token.expires_at
    }
}

impl std::fmt::Debug for ReleaseClient<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReleaseClient")
            .field("api", &self.api)
            .field(
                "token",
                &format_args!(
                    "[REDACTED, {} bytes]",
                    self.token.token.expose_secret().len()
                ),
            )
            .field("repo", &self.repo)
            .finish()
    }
}

#[cfg(test)]
mod tests;
