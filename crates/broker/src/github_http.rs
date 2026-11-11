//! What every call the broker makes to GitHub shares: the HTTP client (HTTPS
//! only, no redirects, no proxy, no retries), the App JWT, the request headers,
//! the refusal of encoded answers and the bounded read of a body.
//!
//! Nothing here reads, keeps or returns text GitHub sent: a failure is one of
//! [`Failure`]'s fixed cases, so no error can echo a token.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::header::{ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use http::{HeaderMap, HeaderValue, Method};
use reqwest::{Certificate, Client, RequestBuilder, Response, redirect};
use secrecy::SecretString;
use serde_json::json;
use url::Url;
use zeroize::Zeroizing;

/// Time allowed for connecting (TCP and TLS).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed for the whole call.
const TIMEOUT: Duration = Duration::from_secs(30);
/// Largest answer accepted; a real one is a few hundred bytes.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// How far in the past the JWT's `iat` is set, for clock drift (GitHub's advice).
const JWT_BACKDATE_SECS: i64 = 60;
/// How long the JWT lives; GitHub allows at most 10 minutes.
const JWT_LIFETIME_SECS: i64 = 540;
/// The latest expiry accepted, from now: GitHub's tokens last an hour.
const MAX_TOKEN_LIFETIME_SECS: i64 = 2 * 3600;
/// The API version the requests and the answers' shapes are written for.
const API_VERSION: &str = "2022-11-28";

/// An installation token and when GitHub says it stops working.
pub struct InstallationToken {
    /// The token. A secret.
    pub token: SecretString,
    /// Expiry, in seconds since the Unix epoch.
    pub expires_at: i64,
}

impl std::fmt::Debug for InstallationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallationToken")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Why a call to GitHub did not give a body to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The App's key could not sign, or the credential cannot go in a header.
    Key,
    /// No TLS session could be made, or the call broke or timed out.
    Unreachable,
    /// The answer is larger than the limit.
    TooLarge,
    /// The answer is encoded in a way the broker does not read.
    Encoded,
}

/// A client that trusts the system roots, or only the CAs in `ca_pem`.
pub(crate) fn client(ca_pem: Option<&[u8]>) -> Result<Client, Failure> {
    let mut builder = Client::builder()
        .https_only(true)
        .redirect(redirect::Policy::none())
        .referer(false)
        .no_proxy()
        .retry(reqwest::retry::never())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TIMEOUT);
    if let Some(pem) = ca_pem {
        let roots = Certificate::from_pem_bundle(pem).map_err(|_| Failure::Unreachable)?;
        if roots.is_empty() {
            return Err(Failure::Unreachable);
        }
        // Only these roots, as in `proxy::client::client_for`.
        builder = builder.tls_certs_only(roots);
    }
    builder.build().map_err(|e| {
        tracing::error!(error = %e.without_url(), "building the GitHub HTTP client failed");
        Failure::Unreachable
    })
}

/// The App JWT: `RS256`, issued a minute ago, valid for nine minutes, for the
/// App `app_id`; `sign` produces the `RS256` signature of the signing input.
pub(crate) fn app_jwt(
    app_id: &str,
    now: i64,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, &'static str>,
) -> Result<Zeroizing<String>, Failure> {
    let header = json!({"alg": "RS256", "typ": "JWT"});
    let claims = json!({
        "iat": now - JWT_BACKDATE_SECS,
        "exp": now + JWT_LIFETIME_SECS,
        "iss": app_id,
    });
    let encode = |value: &serde_json::Value| URL_SAFE_NO_PAD.encode(value.to_string());
    let mut token = Zeroizing::new(format!("{}.{}", encode(&header), encode(&claims)));
    let signature = sign(token.as_bytes()).map_err(|_| Failure::Key)?;
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(signature));
    Ok(token)
}

/// A request with the GitHub headers and `credential` as a bearer token. A body,
/// when given, is JSON.
pub(crate) fn request(
    client: &Client,
    method: Method,
    url: Url,
    credential: &str,
    json_body: Option<String>,
) -> Result<RequestBuilder, Failure> {
    let mut bearer =
        HeaderValue::from_str(&format!("Bearer {credential}")).map_err(|_| Failure::Key)?;
    bearer.set_sensitive(true);
    let mut request = client
        .request(method, url)
        .header(AUTHORIZATION, bearer)
        .header(ACCEPT, "application/vnd.github+json")
        .header("x-github-api-version", API_VERSION)
        .header(
            USER_AGENT,
            concat!("warden-broker/", env!("CARGO_PKG_VERSION")),
        )
        .header(ACCEPT_ENCODING, "identity");
    if let Some(body) = json_body {
        request = request.header(CONTENT_TYPE, "application/json").body(body);
    }
    Ok(request)
}

/// Send `request`. The status is the caller's to judge, before it reads anything.
pub(crate) async fn send(request: RequestBuilder) -> Result<Response, Failure> {
    request.send().await.map_err(failed)
}

/// The whole body of `response`, which must be unencoded and no larger than the
/// limit, announced or not.
pub(crate) async fn read_body(mut response: Response) -> Result<Zeroizing<Vec<u8>>, Failure> {
    refuse_encoded(response.headers())?;
    if response
        .content_length()
        .is_some_and(|len| usize::try_from(len).map_or(true, |len| len > MAX_RESPONSE_BYTES))
    {
        return Err(Failure::TooLarge);
    }
    let mut raw = Zeroizing::new(Vec::with_capacity(MAX_RESPONSE_BYTES));
    while let Some(chunk) = response.chunk().await.map_err(failed)? {
        if chunk.len() > MAX_RESPONSE_BYTES - raw.len() {
            return Err(Failure::TooLarge);
        }
        raw.extend_from_slice(&chunk);
    }
    Ok(raw)
}

/// The token and expiry GitHub answered with, if the token is not empty and the
/// expiry is after `now` and within [`MAX_TOKEN_LIFETIME_SECS`] of it.
pub(crate) fn checked_token(
    token: String,
    expires_at: &str,
    now: i64,
) -> Option<InstallationToken> {
    let token = SecretString::from(token);
    let expires_at = expires_at.parse::<jiff::Timestamp>().ok()?.as_second();
    let empty = secrecy::ExposeSecret::expose_secret(&token).is_empty();
    if empty || expires_at <= now || expires_at > now.saturating_add(MAX_TOKEN_LIFETIME_SECS) {
        return None;
    }
    Some(InstallationToken { token, expires_at })
}

/// The fixed error for a failed send or body read. The detail goes to the log
/// without the URL.
fn failed(e: reqwest::Error) -> Failure {
    tracing::warn!(error = %e.without_url(), "the GitHub call failed");
    Failure::Unreachable
}

/// Refuse any `Content-Encoding` other than `identity`, and any
/// `Transfer-Encoding` other than `chunked`/`identity`.
fn refuse_encoded(headers: &HeaderMap) -> Result<(), Failure> {
    let only = |name: http::HeaderName, allowed: &[&str]| {
        headers.get_all(name).iter().all(|value| {
            value.to_str().is_ok_and(|text| {
                text.split(',')
                    .map(str::trim)
                    .filter(|token| !token.is_empty())
                    .all(|token| allowed.iter().any(|ok| token.eq_ignore_ascii_case(ok)))
            })
        })
    };
    if only(http::header::CONTENT_ENCODING, &["identity"])
        && only(http::header::TRANSFER_ENCODING, &["chunked", "identity"])
    {
        Ok(())
    } else {
        Err(Failure::Encoded)
    }
}
