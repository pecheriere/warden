//! Client for the broker's agent API.
//!
//! Every call goes through one helper, [`Client::call`], which authenticates
//! it: with the bearer key, or by signing the exact method, request target
//! and body bytes it sends (`docs/agent-protocol.md`, section 3), with a
//! fresh timestamp and nonce for every attempt.
//!
//! The CLI never sets `Tailscale-User-Login`: in production Tailscale Serve
//! injects it after authenticating this machine.

use std::fmt;
use std::time::Duration;

use anyhow::{Context as _, Result};
use reqwest::header::CONTENT_TYPE;
use reqwest::{Method, Response, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use url::{Position, Url};
use warden_broker_proto::commit_signing::{
    CommitSigningKeyView, SignCommitRequest, SignCommitResponse,
};
use warden_broker_proto::doctor::sanitize;
use warden_broker_proto::{
    ApiError, CreateRequest, CreatedResponse, GrantView, Id, InfoResponse, PendingRequest,
    ProxyRequest, ProxyResponse, RequestStatus,
};
use zeroize::Zeroizing;

use crate::config::{self, Config, check_server_url};
use crate::sign::Signer;

/// Longest the server may hold a status request (`wait`), in seconds.
pub const MAX_WAIT_SECS: u64 = 30;

/// How the client authenticates its calls.
pub enum Auth {
    /// `Authorization: Bearer <agent key>` (legacy).
    Bearer(Zeroizing<String>),
    /// Signed requests through an `ssh-agent`.
    Signed(Box<Signer>),
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bearer(_) => f.write_str("Bearer(<redacted>)"),
            Self::Signed(signer) => f.debug_tuple("Signed").field(signer).finish(),
        }
    }
}

/// Authenticated agent API client.
#[derive(Debug)]
pub struct Client {
    http: reqwest::Client,
    base: Url,
    auth: Auth,
}

/// The HTTP client every call uses: bounded connect and total time (long
/// polls hold the request for up to [`MAX_WAIT_SECS`]), no redirects.
fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(MAX_WAIT_SECS + 20))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("warden/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("cannot build the HTTP client")
}

/// `base` with a trailing `/`, so that relative API paths join under it.
fn as_directory(base: &Url) -> Url {
    let mut base = base.clone();
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    base
}

/// The request target of `url` as it goes on the request line: the path
/// and, if there is one, `?` and the query. `url` is already normalised by
/// the `url` crate, and the HTTP stack sends these bytes unchanged.
fn request_target(url: &Url) -> &str {
    &url[Position::BeforePath..Position::AfterQuery]
}

/// The broker's signing protocols and audience (`GET /v1/info`, which needs
/// no authentication).
///
/// # Errors
/// If the server is unreachable or answers something else.
pub async fn fetch_info(server: &Url) -> Result<InfoResponse, CallError> {
    check_server_url(server).map_err(|e| CallError::Refused(format!("{e:#}")))?;
    let http = http_client().map_err(|e| CallError::Refused(format!("{e:#}")))?;
    let url = join(&as_directory(server), "v1/info")?;
    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| CallError::Unavailable(format!("cannot reach the broker: {e}")))?;
    json(resp, StatusCode::OK).await
}

fn join(base: &Url, path: &str) -> Result<Url, CallError> {
    base.join(path)
        .map_err(|e| CallError::Refused(format!("cannot build the request URL: {e}")))
}

/// The JSON encoding of `value`, sent and (in key mode) signed as is.
fn json_body<T: Serialize>(value: &T) -> Result<Vec<u8>, CallError> {
    serde_json::to_vec(value)
        .map_err(|e| CallError::Refused(format!("cannot encode the request: {e}")))
}

mod github;
mod offers;
mod release;

pub(crate) use github::{require_scoped, scoped_or_refuse};
pub(crate) use offers::{OffersError, read as read_offer};

impl Client {
    /// A client for the API at `base`, authenticating with `auth`.
    ///
    /// # Errors
    /// If `base` is not an acceptable server URL or the HTTP client cannot be
    /// built.
    pub fn new(base: &Url, auth: Auth) -> Result<Self> {
        check_server_url(base)?;
        if matches!(auth, Auth::Signed(_)) {
            crate::config::check_root_url(base)?;
        }
        Ok(Self {
            http: http_client()?,
            base: as_directory(base),
            auth,
        })
    }

    /// A client for the broker of `config`, authenticating as its agent.
    ///
    /// # Errors
    /// If the signer or the bearer key is not available, or see [`Self::new`].
    pub fn for_config(config: &Config) -> Result<Self> {
        let auth = match config.signer()? {
            Some(signer) => Auth::Signed(Box::new(signer)),
            None => Auth::Bearer(config::agent_key(config)?),
        };
        Self::new(&config.server, auth)
    }

    fn url(&self, path: &str) -> Result<Url, CallError> {
        join(&self.base, path)
    }

    /// Send one authenticated call: `method url`, with `body` as JSON if
    /// given. In key mode the signature covers the method, the target taken
    /// from the final `url` and the exact body bytes, with a fresh timestamp
    /// and nonce, so every call (each long poll and retry included) is
    /// signed anew.
    async fn call(
        &self,
        method: Method,
        url: Url,
        body: Option<Vec<u8>>,
    ) -> Result<Response, CallError> {
        let mut req = self.http.request(method.clone(), url.clone());
        match &self.auth {
            Auth::Bearer(key) => req = req.bearer_auth(key.as_str()),
            Auth::Signed(signer) => {
                let headers = signer
                    .sign_request(
                        method.as_str(),
                        request_target(&url),
                        body.as_deref().unwrap_or_default(),
                    )
                    .await
                    .map_err(|e| CallError::Refused(format!("{e:#}")))?;
                for (name, value) in headers {
                    req = req.header(name, value);
                }
            }
        }
        if let Some(body) = body {
            req = req.header(CONTENT_TYPE, "application/json").body(body);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| CallError::Unavailable(format!("cannot reach the broker: {e}")))?;
        if resp.status() == StatusCode::UNAUTHORIZED
            && let Auth::Signed(signer) = &self.auth
        {
            return Err(self.signature_refused(signer, resp).await);
        }
        Ok(resp)
    }

    /// Explain a 401 to a signed call: the broker's audience changed (another
    /// broker, or its data was reset), or else what to check.
    async fn signature_refused(&self, signer: &Signer, resp: Response) -> CallError {
        let refused = failure(resp).await;
        match fetch_info(&self.base).await {
            Ok(info) if &info.audience != signer.audience() => CallError::Refused(format!(
                "{refused}: the broker's audience is now {}, not {} as pinned at login: this \
                 is another broker, or its data was reset. Ask the owner, then run \
                 `warden login` again with --audience {}",
                info.audience,
                signer.audience(),
                info.audience
            )),
            _ => CallError::Refused(format!(
                "{refused}: the signed request was not accepted; check that the agent is enrolled \
                 with the key {} and not revoked (warden-server agent list), and that this \
                 machine's clock is within 60 s of the broker's",
                signer.fingerprint()
            )),
        }
    }

    /// Create a request.
    ///
    /// # Errors
    /// If the server is unreachable or refuses.
    pub async fn create(&self, req: &CreateRequest) -> Result<CreatedResponse, CallError> {
        // The broker checks this too; refusing here says so without a round trip.
        req.check_new()
            .map_err(|e| CallError::Refused(e.to_string()))?;
        let resp = self
            .call(
                Method::POST,
                self.url("v1/requests")?,
                Some(json_body(req)?),
            )
            .await?;
        json(resp, StatusCode::CREATED).await
    }

    /// The status of request `id`, waiting up to `wait` seconds for a change.
    ///
    /// # Errors
    /// If the server is unreachable or refuses.
    pub async fn status(&self, id: &Id, wait: u64) -> Result<RequestStatus, CallError> {
        let mut url = self.url(&format!("v1/requests/{id}"))?;
        url.query_pairs_mut()
            .append_pair("wait", &wait.min(MAX_WAIT_SECS).to_string());
        let resp = self.call(Method::GET, url, None).await?;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            // The agent has as many waits open as the broker allows: one
            // ending frees a place, so this is worth retrying.
            return Err(CallError::Unavailable(failure(resp).await.to_string()));
        }
        Ok(match json(resp, StatusCode::OK).await? {
            RequestStatus::Error { message } => RequestStatus::Error {
                message: sanitize(&message),
            },
            other => other,
        })
    }

    /// Cancel the agent's pending request `id`.
    ///
    /// # Errors
    /// If the server is unreachable or refuses (unknown, or no longer
    /// pending).
    pub async fn cancel(&self, id: &Id) -> Result<(), CallError> {
        let url = self.url(&format!("v1/requests/{id}/cancel"))?;
        let resp = self.call(Method::POST, url, None).await?;
        if resp.status() == StatusCode::NO_CONTENT {
            Ok(())
        } else {
            Err(failure(resp).await)
        }
    }

    /// The agent's live grants.
    ///
    /// # Errors
    /// If the server is unreachable or refuses.
    pub async fn grants(&self) -> Result<Vec<GrantView>, CallError> {
        let resp = self.call(Method::GET, self.url("v1/grants")?, None).await?;
        json(resp, StatusCode::OK).await
    }

    /// The agent's pending requests, or `None` from a broker too old to list
    /// them, which answers 405 on that route.
    ///
    /// # Errors
    /// If the server is unreachable or refuses.
    pub async fn pending(&self) -> Result<Option<Vec<PendingRequest>>, CallError> {
        let resp = self
            .call(Method::GET, self.url("v1/requests")?, None)
            .await?;
        if resp.status() == StatusCode::METHOD_NOT_ALLOWED {
            return Ok(None);
        }
        json(resp, StatusCode::OK).await.map(Some)
    }

    /// The public half of the broker's commit signing key.
    ///
    /// # Errors
    /// If the server is unreachable, refuses, or holds no such key.
    pub async fn commit_signing_key(&self) -> Result<CommitSigningKeyView, CallError> {
        let url = self.url("v1/commit-signing/key")?;
        let resp = self.call(Method::GET, url, None).await?;
        json(resp, StatusCode::OK).await
    }

    /// Have the broker sign a commit under this agent's active grant.
    ///
    /// # Errors
    /// If the server is unreachable or refuses.
    pub async fn sign_commit(
        &self,
        request: &SignCommitRequest,
    ) -> Result<SignCommitResponse, CallError> {
        let url = self.url("v1/commit-signing/sign")?;
        let resp = self
            .call(Method::POST, url, Some(json_body(request)?))
            .await?;
        json(resp, StatusCode::OK).await
    }

    /// Have the broker make `call` through api grant `id`.
    ///
    /// # Errors
    /// If the server is unreachable or refuses.
    pub async fn proxy(&self, id: &Id, call: &ProxyRequest) -> Result<ProxyResponse, CallError> {
        let url = self.url(&format!("v1/grants/{id}/http"))?;
        let resp = self.call(Method::POST, url, Some(json_body(call)?)).await?;
        json(resp, StatusCode::OK).await
    }

    /// Revoke grant `id`.
    ///
    /// # Errors
    /// If the server is unreachable or refuses.
    pub async fn revoke(&self, id: &Id) -> Result<(), CallError> {
        let url = self.url(&format!("v1/grants/{id}/revoke"))?;
        let resp = self.call(Method::POST, url, None).await?;
        if resp.status() == StatusCode::NO_CONTENT {
            Ok(())
        } else {
            Err(failure(resp).await)
        }
    }
}

/// Why an API call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// The broker could not be reached or failed on its side (transport
    /// error, timeout, 5xx). Trying again later may succeed.
    Unavailable(String),
    /// The broker refused the call (4xx) or answered something unusable.
    /// Trying again will not help.
    Refused(String),
    /// The broker says the grant was revoked (409). Trying again will not
    /// help: access has to be requested again.
    Revoked(String),
    /// The broker says the grant expired (409), maybe while the call was
    /// out. Trying again will not help: access has to be requested again.
    Expired(String),
    /// The broker stopped the call while it was out, as it could not tell if the
    /// grant still holds (503). The grant may work again, but the upstream may
    /// have acted on this call, so repeating it blindly could repeat a change.
    CallStopped(String),
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(m)
            | Self::Refused(m)
            | Self::Revoked(m)
            | Self::Expired(m)
            | Self::CallStopped(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for CallError {}

async fn json<T: DeserializeOwned>(resp: Response, expected: StatusCode) -> Result<T, CallError> {
    if resp.status() != expected {
        return Err(failure(resp).await);
    }
    resp.json().await.map_err(|e| {
        if e.is_decode() {
            CallError::Refused(sanitize(&format!(
                "the broker sent an unexpected response: {e}"
            )))
        } else {
            // The body was cut off, for example by a restart.
            CallError::Unavailable(format!("cannot read the broker's response: {e}"))
        }
    })
}

/// How the broker's 409 for a revoked grant begins (a call that finds the
/// grant revoked, or sees it revoked while it was out).
const GRANT_REVOKED: &str = "grant revoked";

/// How the broker's 409 for an expired grant begins (a call that finds the
/// grant expired, or sees it expire while it was out).
const GRANT_EXPIRED: &str = "grant expired";

/// The broker's 503 for a call it stopped because it could not read the grant.
const GRANT_STATE_UNAVAILABLE: &str = "grant state unavailable during the call";

/// The server's error for a failed call, classified by its status, with
/// the broker's message made safe to print.
async fn failure(resp: Response) -> CallError {
    let status = resp.status();
    let what = if status.is_server_error() {
        "broker error"
    } else {
        "broker refused"
    };
    let body = resp.json::<ApiError>().await.ok();
    let message = match &body {
        Some(body) => format!("{what} ({status}): {}", sanitize(&body.error)),
        None => format!("{what} ({status})"),
    };
    let error = body.map_or_else(String::new, |b| b.error);
    let conflict = if status == StatusCode::CONFLICT {
        error.as_str()
    } else {
        ""
    };
    if status == StatusCode::SERVICE_UNAVAILABLE && error == GRANT_STATE_UNAVAILABLE {
        CallError::CallStopped(message)
    } else if status.is_server_error() {
        CallError::Unavailable(message)
    } else if conflict.starts_with(GRANT_REVOKED) {
        CallError::Revoked(message)
    } else if conflict.starts_with(GRANT_EXPIRED) {
        CallError::Expired(message)
    } else {
        CallError::Refused(message)
    }
}

#[cfg(test)]
mod tests;
