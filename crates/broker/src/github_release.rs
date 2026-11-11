//! The broker's own GitHub client for releases, run with the release App's
//! credentials and never an agent's.
//!
//! It finds the release App's installation on a repository, then mints a token
//! for that one repository with `contents: write` and `metadata: read` and
//! nothing more. [`ReleaseClient`] then reads commits, tags, the changelog and
//! releases and creates tags, refs, assets and the publication (see `rest`).
//! Every call goes through `crate::github_http`: HTTPS only, no
//! redirects, no retries, no encoded answers, a bounded body.
//!
//! No text GitHub sent reaches an error, a log line or an audit entry: a
//! [`GithubError`] is one of four fixed cases, and the status of a refusal is a
//! number. A key or token appears only in a request's `Authorization` header.

mod rest;
mod tag_object;

use http::{Method, StatusCode};
use secrecy::ExposeSecret as _;
use serde::Deserialize;
use serde_json::json;
use url::Url;
use warden_broker_proto::release::RepoName;

use crate::github_app::GithubApi;
use crate::github_http::{self, Failure, InstallationToken, Payload};
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
const CONTENTS_PERMISSION: &str = "write";
const METADATA_PERMISSION: &str = "read";

#[derive(Deserialize)]
struct InstallationAnswer {
    id: u64,
}

#[derive(Deserialize)]
struct TokenAnswer {
    token: String,
    expires_at: String,
    permissions: std::collections::BTreeMap<String, String>,
    repository_selection: String,
    #[serde(default)]
    repositories: Vec<RepositoryAnswer>,
}

#[derive(Deserialize)]
struct RepositoryAnswer {
    name: String,
    full_name: Option<String>,
}

impl TokenAnswer {
    /// Whether the token is for `repo` alone, as asked: selected repositories,
    /// exactly one, and it is `repo`, ignoring ASCII case as GitHub does.
    fn is_limited_to(&self, repo: &RepoName) -> bool {
        let [only] = self.repositories.as_slice() else {
            return false;
        };
        self.repository_selection == "selected"
            && only.name.eq_ignore_ascii_case(repo.name())
            && only.full_name.as_ref().is_none_or(|full| {
                full.eq_ignore_ascii_case(&format!("{}/{}", repo.owner(), repo.name()))
            })
    }

    /// Whether the token has `contents: write` and `metadata: read` only.
    fn has_exactly_the_permissions_asked(&self) -> bool {
        self.permissions.len() == 2
            && self.permissions.get("contents").map(String::as_str) == Some(CONTENTS_PERMISSION)
            && self.permissions.get("metadata").map(String::as_str) == Some(METADATA_PERMISSION)
    }
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

/// One request to GitHub and what it must answer.
struct Call {
    method: Method,
    url: Url,
    accept: &'static str,
    payload: Payload,
    /// The status of a good answer; its body is the result.
    success: StatusCode,
    /// The most bytes of that body accepted.
    limit: usize,
}

impl Call {
    /// A JSON call, with a 64 KiB limit on the answer.
    fn json(method: Method, url: Url, payload: Payload, success: StatusCode) -> Self {
        Self {
            method,
            url,
            accept: github_http::JSON,
            payload,
            success,
            limit: github_http::MAX_RESPONSE_BYTES,
        }
    }
}

/// `base` with `segments` appended to its path, each as one segment: a `/` in
/// one is encoded, so no name can add a segment.
fn endpoint(base: &Url, segments: &[&str]) -> Result<Url, GithubError> {
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|()| GithubError::Unreachable)?
        .pop_if_empty()
        .extend(segments);
    Ok(url)
}

/// Send `call` with `credential` as the bearer token and return the body of a
/// good answer.
async fn call(
    api: &GithubApi,
    credential: &str,
    call: Call,
) -> Result<zeroize::Zeroizing<Vec<u8>>, GithubError> {
    let request = github_http::request(
        &api.client()?,
        call.method,
        call.url,
        credential,
        call.accept,
        call.payload,
    )?;
    let response = github_http::send(request).await?;
    match response.status() {
        status if status == call.success => Ok(github_http::read_body(response, call.limit).await?),
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
    let url = endpoint(
        api.base(),
        &["repos", repo.owner(), repo.name(), "installation"],
    )?;
    let get = Call::json(Method::GET, url, Payload::Empty, StatusCode::OK);
    let raw = call(api, jwt.as_str(), get).await?;
    let InstallationAnswer { id } =
        serde_json::from_slice(&raw).map_err(|_| GithubError::Unreadable)?;
    Ok(id)
}

/// A token for `installation`, limited to `repo` and to `contents: write` with
/// `metadata: read`.
///
/// # Errors
/// [`GithubError::Unreadable`] when the answer's permissions or repositories
/// differ from those asked for, or its expiry is not after `now` and within two hours of it;
/// another [`GithubError`] when the call fails.
pub async fn release_token(
    api: &GithubApi,
    app: &ReleaseAppKey,
    installation: u64,
    repo: &RepoName,
    now: i64,
) -> Result<InstallationToken, GithubError> {
    let jwt = app_jwt(app, now).await?;
    let body = json!({
        "repositories": [repo.name()],
        "permissions": {"contents": CONTENTS_PERMISSION, "metadata": METADATA_PERMISSION},
    })
    .to_string();
    let installation = installation.to_string();
    let url = endpoint(
        api.base(),
        &["app", "installations", &installation, "access_tokens"],
    )?;
    let post = Call::json(Method::POST, url, Payload::Json(body), StatusCode::CREATED);
    let raw = call(api, jwt.as_str(), post).await?;
    let answer: TokenAnswer = serde_json::from_slice(&raw).map_err(|_| GithubError::Unreadable)?;
    if !answer.has_exactly_the_permissions_asked() || !answer.is_limited_to(repo) {
        return Err(GithubError::Unreadable);
    }
    github_http::checked_token(answer.token, &answer.expires_at, now).ok_or(GithubError::Unreadable)
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

pub use rest::{Asset, ChangelogSection, CommitInfo, CreateTag, ExistingTag, Release};

#[cfg(test)]
mod tests;
