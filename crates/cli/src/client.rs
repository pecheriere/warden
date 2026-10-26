//! Client for the broker's agent API.
//!
//! The CLI never sets `Tailscale-User-Login`: in production Tailscale Serve
//! injects it after authenticating this machine.

use std::fmt;
use std::time::Duration;

use anyhow::{Context as _, Result};
use reqwest::{Response, StatusCode};
use serde::de::DeserializeOwned;
use url::Url;
use warden_broker_proto::{ApiError, CreateRequest, CreatedResponse, GrantView, Id, RequestStatus};
use zeroize::Zeroizing;

use crate::config::check_server_url;

/// Longest the server may hold a status request (`wait`), in seconds.
pub const MAX_WAIT_SECS: u64 = 30;

/// Authenticated agent API client.
pub struct Client {
    http: reqwest::Client,
    base: Url,
    key: Zeroizing<String>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("base", &self.base.as_str())
            .field("key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client for the API at `base`, authenticating with `key`.
    ///
    /// # Errors
    /// If `base` is not an acceptable server URL or the HTTP client cannot be
    /// built.
    pub fn new(base: &Url, key: Zeroizing<String>) -> Result<Self> {
        check_server_url(base)?;
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            // Long polls hold the request for up to MAX_WAIT_SECS.
            .timeout(Duration::from_secs(MAX_WAIT_SECS + 20))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("warden/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("cannot build the HTTP client")?;
        let mut base = base.clone();
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }
        Ok(Self { http, base, key })
    }

    fn url(&self, path: &str) -> Result<Url, CallError> {
        self.base
            .join(path)
            .map_err(|e| CallError::Refused(format!("cannot build the request URL: {e}")))
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<Response, CallError> {
        req.bearer_auth(self.key.as_str())
            .send()
            .await
            .map_err(|e| CallError::Unavailable(format!("cannot reach the broker: {e}")))
    }

    /// Create a request.
    ///
    /// # Errors
    /// If the server is unreachable or refuses.
    pub async fn create(&self, req: &CreateRequest) -> Result<CreatedResponse, CallError> {
        let resp = self
            .send(self.http.post(self.url("v1/requests")?).json(req))
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
        let resp = self.send(self.http.get(url)).await?;
        json(resp, StatusCode::OK).await
    }

    /// The agent's live grants.
    ///
    /// # Errors
    /// If the server is unreachable or refuses.
    pub async fn grants(&self) -> Result<Vec<GrantView>, CallError> {
        let resp = self.send(self.http.get(self.url("v1/grants")?)).await?;
        json(resp, StatusCode::OK).await
    }

    /// Revoke grant `id`.
    ///
    /// # Errors
    /// If the server is unreachable or refuses.
    pub async fn revoke(&self, id: &Id) -> Result<(), CallError> {
        let url = self.url(&format!("v1/grants/{id}/revoke"))?;
        let resp = self.send(self.http.post(url)).await?;
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
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(m) | Self::Refused(m) => f.write_str(m),
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
            CallError::Refused(format!("the broker sent an unexpected response: {e}"))
        } else {
            // The body was cut off, for example by a restart.
            CallError::Unavailable(format!("cannot read the broker's response: {e}"))
        }
    })
}

/// The server's error for a failed call, classified by its status.
async fn failure(resp: Response) -> CallError {
    let status = resp.status();
    let what = if status.is_server_error() {
        "broker error"
    } else {
        "broker refused"
    };
    let message = match resp.json::<ApiError>().await {
        Ok(body) => format!("{what} ({status}): {}", body.error),
        Err(_) => format!("{what} ({status})"),
    };
    if status.is_server_error() {
        CallError::Unavailable(message)
    } else {
        CallError::Refused(message)
    }
}

#[cfg(test)]
mod tests {
    use warden_broker_proto::Id;
    use zeroize::Zeroizing;

    use super::{CallError, Client};

    #[test]
    fn debug_redacts_the_agent_key() {
        let key = format!("wdn_{}", "S".repeat(43));
        let client = Client::new(
            &url::Url::parse("https://warden.example/api").unwrap(),
            Zeroizing::new(key.clone()),
        )
        .unwrap();
        let shown = format!("{client:?}");
        assert!(!shown.contains(&key), "{shown}");
        assert!(shown.contains("redacted"));
        assert_eq!(
            client.url("v1/grants").unwrap().as_str(),
            "https://warden.example/api/v1/grants"
        );
    }

    /// A broker that answers every request with `status` and `body`.
    async fn answering(status: u16, body: &'static str) -> url::Url {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                let mut buf = [0_u8; 4096];
                let _ = conn.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = conn.write_all(resp.as_bytes()).await;
            }
        });
        url::Url::parse(&format!("http://{addr}/")).unwrap()
    }

    fn client(url: &url::Url) -> Client {
        Client::new(url, Zeroizing::new(format!("wdn_{}", "S".repeat(43)))).unwrap()
    }

    #[tokio::test]
    async fn server_errors_and_unreachable_broker_are_unavailable() {
        let id = Id::random();
        let five = client(&answering(503, r#"{"error":"connect down"}"#).await);
        assert_eq!(
            five.status(&id, 0).await,
            Err(CallError::Unavailable(
                "broker error (503 Service Unavailable): connect down".to_owned()
            ))
        );

        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            url::Url::parse(&format!("http://{}/", l.local_addr().unwrap())).unwrap()
        };
        assert!(matches!(
            client(&closed).status(&id, 0).await,
            Err(CallError::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn client_errors_and_garbage_are_refused() {
        let id = Id::random();
        let four = client(&answering(404, r#"{"error":"not found"}"#).await);
        assert_eq!(
            four.status(&id, 0).await,
            Err(CallError::Refused(
                "broker refused (404 Not Found): not found".to_owned()
            ))
        );
        let garbage = client(&answering(200, r#"{"status":"nope"}"#).await);
        assert!(matches!(
            garbage.status(&id, 0).await,
            Err(CallError::Refused(_))
        ));
    }

    #[test]
    fn cleartext_remote_server_is_refused() {
        let url = url::Url::parse("http://warden.example/").unwrap();
        assert!(Client::new(&url, Zeroizing::new(String::new())).is_err());
    }
}
