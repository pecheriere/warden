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
use warden_broker_proto::{
    ApiError, CreateRequest, CreatedResponse, GrantView, Id, InfoResponse, ProxyRequest,
    ProxyResponse, RequestStatus,
};
use zeroize::Zeroizing;

use crate::config::check_server_url;
use crate::http::sanitize;
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
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(m) | Self::Refused(m) | Self::Revoked(m) => f.write_str(m),
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
    if status.is_server_error() {
        CallError::Unavailable(message)
    } else if status == StatusCode::CONFLICT
        && body.is_some_and(|b| b.error.starts_with(GRANT_REVOKED))
    {
        CallError::Revoked(message)
    } else {
        CallError::Refused(message)
    }
}

#[cfg(test)]
mod tests {
    use warden_broker_proto::{Id, RequestStatus};
    use zeroize::Zeroizing;

    use super::{Auth, CallError, Client};

    fn bearer(key: &str) -> Auth {
        Auth::Bearer(Zeroizing::new(key.to_owned()))
    }

    #[test]
    fn debug_redacts_the_agent_key() {
        let key = format!("wdn_{}", "S".repeat(43));
        let client = Client::new(
            &url::Url::parse("https://warden.example/api").unwrap(),
            bearer(&key),
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
        Client::new(url, bearer(&format!("wdn_{}", "S".repeat(43)))).unwrap()
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

    #[tokio::test]
    async fn revoked_grant_is_told_apart_from_other_conflicts() {
        let call = warden_broker_proto::ProxyRequest {
            method: "GET".to_owned(),
            url: "https://api.example.com/".to_owned(),
            headers: Vec::new(),
            body_b64: None,
        };
        let id = Id::random();
        for (message, body) in [
            ("grant revoked", r#"{"error":"grant revoked"}"#),
            (
                "grant revoked during the call",
                r#"{"error":"grant revoked during the call"}"#,
            ),
        ] {
            assert_eq!(
                client(&answering(409, body).await).proxy(&id, &call).await,
                Err(CallError::Revoked(format!(
                    "broker refused (409 Conflict): {message}"
                )))
            );
        }
        let expired = client(&answering(409, r#"{"error":"grant expired"}"#).await);
        assert!(matches!(
            expired.proxy(&id, &call).await,
            Err(CallError::Refused(_))
        ));
    }

    /// The broker's words reach the terminal only with control, format and
    /// separator characters replaced.
    #[tokio::test]
    async fn broker_messages_are_sanitized() {
        let id = Id::random();
        let refused =
            client(&answering(400, r#"{"error":"bad\u001b[2J\u202ething\u2028x\u0085y"}"#).await);
        assert_eq!(
            refused.status(&id, 0).await,
            Err(CallError::Refused(
                "broker refused (400 Bad Request): bad?[2J?thing?x?y".to_owned()
            ))
        );
        let failed = client(
            &answering(
                200,
                r#"{"status":"error","message":"no\u009bnotifier\u200b\u2029"}"#,
            )
            .await,
        );
        assert_eq!(
            failed.status(&id, 0).await,
            Ok(RequestStatus::Error {
                message: "no?notifier??".to_owned()
            })
        );
    }

    #[test]
    fn cleartext_remote_server_is_refused() {
        let url = url::Url::parse("http://warden.example/").unwrap();
        assert!(Client::new(&url, bearer("")).is_err());
    }

    /// One request as it arrived on the wire.
    struct Captured {
        method: String,
        target: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl Captured {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    /// A broker that records each raw request and answers `status` and
    /// `body`.
    async fn recording(
        status: u16,
        body: &'static str,
    ) -> (url::Url, tokio::sync::mpsc::UnboundedReceiver<Captured>) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                let mut raw = Vec::new();
                let mut buf = [0_u8; 4096];
                let head_end = loop {
                    let n = conn.read(&mut buf).await.unwrap();
                    assert!(n > 0, "connection closed mid-request");
                    raw.extend_from_slice(&buf[..n]);
                    if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i;
                    }
                };
                let head = String::from_utf8(raw[..head_end].to_vec()).unwrap();
                let mut lines = head.split("\r\n");
                let mut line = lines.next().unwrap().split(' ');
                let method = line.next().unwrap().to_owned();
                let target = line.next().unwrap().to_owned();
                let headers: Vec<(String, String)> = lines
                    .map(|l| {
                        let (n, v) = l.split_once(':').unwrap();
                        (n.to_owned(), v.trim().to_owned())
                    })
                    .collect();
                let len: usize = headers
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
                    .map_or(0, |(_, v)| v.parse().unwrap());
                let mut received = raw[head_end + 4..].to_vec();
                while received.len() < len {
                    let n = conn.read(&mut buf).await.unwrap();
                    received.extend_from_slice(&buf[..n]);
                }
                tx.send(Captured {
                    method,
                    target,
                    headers,
                    body: received,
                })
                .unwrap();
                let resp = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = conn.write_all(resp.as_bytes()).await;
            }
        });
        (url::Url::parse(&format!("http://{addr}/")).unwrap(), rx)
    }

    /// In key mode the signature covers the method, the request target and
    /// the body exactly as they went on the wire, with no `Authorization`;
    /// every call carries a fresh nonce.
    #[tokio::test]
    async fn signed_calls_sign_what_is_sent() {
        use sha2::{Digest as _, Sha256};
        use ssh_key::rand_core::OsRng;
        use ssh_key::{Algorithm, PrivateKey};
        use warden_broker_proto::signing::{
            Audience, NAMESPACE, Nonce, SignedRequestParts, canonical_message, parse_timestamp,
        };

        use crate::sign::testing::TestAgent;
        use crate::sign::{Signer, parse_signing_key};

        let agent = TestAgent::start();
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        agent.add(&key).await;
        let audience = Audience::random();
        let signer = Signer::new(
            "bot".parse().unwrap(),
            audience.clone(),
            parse_signing_key(&key.public_key().to_openssh().unwrap()).unwrap(),
            agent.socket.clone(),
        );
        let (url, mut seen) = recording(200, r#"{"status":"pending"}"#).await;
        let client = Client::new(&url, Auth::Signed(Box::new(signer))).unwrap();

        let id = Id::random();
        assert_eq!(client.status(&id, 30).await, Ok(RequestStatus::Pending));
        assert_eq!(client.status(&id, 30).await, Ok(RequestStatus::Pending));
        let call = warden_broker_proto::ProxyRequest {
            method: "POST".to_owned(),
            url: "https://api.example.com/a b?q=é".to_owned(),
            headers: vec![("X-A".to_owned(), "1".to_owned())],
            body_b64: Some("eyJ4IjoxfQ==".to_owned()),
        };
        // The answer is not a proxy response: only the request matters.
        assert!(client.proxy(&id, &call).await.is_err());

        let mut nonces = Vec::new();
        for expected in [
            ("GET", format!("/v1/requests/{id}?wait=30")),
            ("GET", format!("/v1/requests/{id}?wait=30")),
            ("POST", format!("/v1/grants/{id}/http")),
        ] {
            let got = seen.recv().await.unwrap();
            assert_eq!(
                (got.method.as_str(), got.target.clone()),
                (expected.0, expected.1)
            );
            assert_eq!(got.header("authorization"), None);
            assert_eq!(got.header("warden-agent"), Some("bot"));
            let nonce = Nonce::try_from(got.header("warden-nonce").unwrap().to_owned()).unwrap();
            let message = canonical_message(&SignedRequestParts {
                audience: &audience,
                agent: &"bot".parse().unwrap(),
                method: &got.method,
                target: &got.target,
                timestamp: parse_timestamp(got.header("warden-timestamp").unwrap()).unwrap(),
                nonce: &nonce,
                body_sha256: Sha256::digest(&got.body).into(),
            })
            .unwrap();
            let blob = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                got.header("warden-signature").unwrap(),
            )
            .unwrap();
            let sig =
                <ssh_key::SshSig as ssh_encoding::Decode>::decode(&mut blob.as_slice()).unwrap();
            key.public_key()
                .verify(NAMESPACE, message.as_bytes(), &sig)
                .unwrap();
            if got.method == "POST" {
                assert_eq!(got.header("content-type"), Some("application/json"));
                assert_eq!(got.body, serde_json::to_vec(&call).unwrap());
            } else {
                assert!(got.body.is_empty());
            }
            nonces.push(nonce);
        }
        assert_ne!(nonces[0], nonces[1]);
    }

    /// A bearer client sends its key and no `Warden-*` header.
    #[tokio::test]
    async fn bearer_calls_are_unsigned() {
        let (url, mut seen) = recording(200, "[]").await;
        let key = format!("wdn_{}", "S".repeat(43));
        let client = Client::new(&url, bearer(&key)).unwrap();
        assert_eq!(client.grants().await, Ok(Vec::new()));
        let got = seen.recv().await.unwrap();
        assert_eq!(
            got.header("authorization"),
            Some(format!("Bearer {key}").as_str())
        );
        assert!(
            !got.headers
                .iter()
                .any(|(n, _)| n.to_ascii_lowercase().starts_with("warden-"))
        );
    }

    /// A signing client refuses a server URL with a path: the API is at the
    /// root and the path is signed.
    #[test]
    fn signed_client_needs_a_root_url() {
        let signer = crate::sign::Signer::new(
            "bot".parse().unwrap(),
            warden_broker_proto::signing::Audience::random(),
            crate::sign::parse_signing_key(
                &ssh_key::PrivateKey::random(
                    &mut ssh_key::rand_core::OsRng,
                    ssh_key::Algorithm::Ed25519,
                )
                .unwrap()
                .public_key()
                .to_openssh()
                .unwrap(),
            )
            .unwrap(),
            "/s".into(),
        );
        let url = url::Url::parse("https://warden.example/api/").unwrap();
        let err = Client::new(&url, Auth::Signed(Box::new(signer))).unwrap_err();
        assert!(err.to_string().contains("no path"), "{err}");
    }
}
