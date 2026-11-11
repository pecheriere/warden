//! A local HTTPS server standing in for an API behind a secret: a throwaway
//! CA, a `localhost` certificate it signed, and handlers that echo, redirect,
//! stream too much or too slowly, hang until the caller gives up, or claim a
//! compressed body.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http_body_util::{BodyExt as _, Channel};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use tokio::sync::watch;
use tokio::task::AbortHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::aws_lc_rs;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use url::Url;

use super::github_release::GithubReleaseFake;
use crate::policy::{ApiSecretPolicy, ValueFormat};

/// Body length served by `/huge` and `/huge-chunked`: twice the default
/// response limit.
pub const HUGE_BYTES: usize = 2 * 1024 * 1024;

/// First bytes `/slow` sends before stalling.
pub const SLOW_PREFIX: &[u8] = b"partial body that must never reach the agent";

/// Body served by `/binary`: not valid UTF-8.
pub const BINARY_BODY: &[u8] = b"\xff\xfe\x00binary\x80";

/// How long `/delayed` waits before answering.
pub const DELAY: Duration = Duration::from_secs(1);

/// A request the upstream received.
#[derive(Debug, Clone)]
pub struct Received {
    /// Method.
    pub method: String,
    /// Path and query, as sent.
    pub path_and_query: String,
    /// Headers.
    pub headers: HeaderMap,
    /// Body.
    pub body: Vec<u8>,
}

/// A response a test scripts for the GitHub token route.
#[derive(Debug, Clone)]
pub struct Scripted {
    /// Status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
    /// When set, the response is held back until the gate opens.
    pub gate: Option<Gate>,
    /// Whether the body goes in 1 KiB chunks, with no `Content-Length`.
    pub chunked: bool,
}

impl Scripted {
    /// `status` with no headers and an empty body.
    #[must_use]
    pub const fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            gate: None,
            chunked: false,
        }
    }

    /// `status` with `body`.
    #[must_use]
    pub fn with_body(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            body: body.into(),
            ..Self::status(status)
        }
    }

    /// Add a response header.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Send the body in 1 KiB chunks, with no `Content-Length`.
    #[must_use]
    pub const fn chunked(mut self) -> Self {
        self.chunked = true;
        self
    }

    /// Hold the response until `gate` opens.
    #[must_use]
    pub fn held_by(mut self, gate: &Gate) -> Self {
        self.gate = Some(gate.clone());
        self
    }
}

/// A condition a scripted response waits on: closed until [`Gate::open`].
#[derive(Debug, Clone)]
pub struct Gate(Arc<watch::Sender<bool>>);

impl Gate {
    /// A closed gate.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(watch::Sender::new(false)))
    }

    /// Let every response held by this gate go.
    pub fn open(&self) {
        self.0.send_replace(true);
    }
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

/// A running HTTPS server on `https://localhost:<port>`, trusted only
/// through [`HttpsUpstream::ca_pem`]. Stopped on drop.
///
/// Routes (any method):
/// - `/echo`: every request header and the body, raw and in several
///   encodings, in the body and in `x-echo-*` response headers;
/// - `/name-echo`: the `Authorization` value without its `Bearer ` prefix,
///   echoed into a response header *name* (`x-seen-<value>`; the HTTP stack
///   lowercases it);
/// - `/redirect`: `302` to another origin, carrying the request's
///   `Authorization` value percent-encoded in the `Location` query;
/// - `/huge`, `/huge-chunked`: [`HUGE_BYTES`] bytes, with and without
///   `Content-Length`;
/// - `/slow`: [`SLOW_PREFIX`], then nothing for a minute;
/// - `/delayed` and any path under it: `late answer`, after [`DELAY`];
/// - `/held`: `late answer`, once [`HttpsUpstream::release_held`] is called;
/// - `/hang`: no answer at all, until the caller closes the connection;
/// - `/drip`: `200`, the `Authorization` value in clear, then a chunk every few
///   milliseconds without end, until the caller closes the connection;
/// - `POST /app/installations/<id>/access_tokens`: the next response queued with
///   [`HttpsUpstream::script_github_token`] (`500` when none is), held until its
///   [`Gate`] opens when it has one;
/// - the routes of [`GithubReleaseFake`], which [`HttpsUpstream::github_release`]
///   scripts and records;
/// - `/gzip`: a body labelled `Content-Encoding: gzip`;
/// - `/status/<code>`: that status, body `status <code>`;
/// - `/binary`: [`BINARY_BODY`], which is not UTF-8;
/// - anything else: `200` with `hello from upstream`.
pub struct HttpsUpstream {
    origin: Url,
    ca_pem: String,
    received: Arc<Mutex<Vec<Received>>>,
    abandoned: Arc<watch::Sender<u64>>,
    released: Arc<watch::Sender<bool>>,
    scripts: Arc<Mutex<VecDeque<Scripted>>>,
    token_calls: Arc<watch::Sender<u64>>,
    github_release: GithubReleaseFake,
    server: AbortHandle,
}

impl Drop for HttpsUpstream {
    fn drop(&mut self) {
        self.server.abort();
    }
}

type Log = Arc<Mutex<Vec<Received>>>;

/// What the handlers share.
#[derive(Clone)]
struct Shared {
    log: Log,
    /// How many `/hang` and `/drip` calls the caller walked away from.
    abandoned: Arc<watch::Sender<u64>>,
    /// Whether `/held` may answer.
    released: Arc<watch::Sender<bool>>,
    /// Responses for the GitHub token route, oldest first.
    scripts: Arc<Mutex<VecDeque<Scripted>>>,
    /// How many calls the GitHub token route has received.
    token_calls: Arc<watch::Sender<u64>>,
    /// The fake GitHub of the release client.
    github_release: GithubReleaseFake,
}

/// Counts one abandoned call when dropped, which is what happens to a handler
/// when its connection closes.
struct Abandonment(Arc<watch::Sender<u64>>);

impl Drop for Abandonment {
    fn drop(&mut self) {
        self.0.send_modify(|count| *count += 1);
    }
}

impl HttpsUpstream {
    /// Generate the CA and certificate and start serving.
    ///
    /// # Panics
    /// If certificate generation, TLS setup or binding fails.
    pub async fn start() -> Self {
        let (ca_pem, chain, key) = certificates();
        let config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("TLS server certificate");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind upstream listener");
        let port = listener.local_addr().expect("upstream address").port();
        let received: Log = Arc::default();
        let abandoned = Arc::new(watch::Sender::new(0));
        let released = Arc::new(watch::Sender::new(false));
        let scripts: Arc<Mutex<VecDeque<Scripted>>> = Arc::default();
        let token_calls = Arc::new(watch::Sender::new(0));
        let github_release = GithubReleaseFake::default();
        let router = Router::new().fallback(handle).with_state(Shared {
            log: received.clone(),
            abandoned: abandoned.clone(),
            released: released.clone(),
            scripts: scripts.clone(),
            token_calls: token_calls.clone(),
            github_release: github_release.clone(),
        });
        let server = tokio::spawn(serve(listener, acceptor, router)).abort_handle();
        Self {
            origin: Url::parse(&format!("https://localhost:{port}")).expect("upstream origin"),
            ca_pem,
            received,
            abandoned,
            released,
            scripts,
            token_calls,
            github_release,
            server,
        }
    }

    /// `https://localhost:<port>`.
    #[must_use]
    pub fn origin(&self) -> String {
        self.origin.origin().ascii_serialization()
    }

    /// The absolute URL of `path_and_query` (which starts with `/`).
    #[must_use]
    pub fn url(&self, path_and_query: &str) -> String {
        format!("{}{path_and_query}", self.origin())
    }

    /// PEM of the CA that signed the server's certificate.
    #[must_use]
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// API secret `name` for this server: its origin, pinned CA, header
    /// `Authorization: Bearer {{secret}}`, `GET` and `POST`, prefix `/`,
    /// max window 1h.
    ///
    /// # Panics
    /// If `name` is not a valid secret name.
    #[must_use]
    pub fn policy(&self, name: &str) -> ApiSecretPolicy {
        ApiSecretPolicy {
            name: name.to_owned().try_into().expect("valid secret name"),
            origin: self.origin.origin(),
            header: header::AUTHORIZATION,
            format: ValueFormat::default(),
            methods: vec![http::Method::GET, http::Method::POST],
            path_prefix: "/".to_owned(),
            ca_pem: Some(self.ca_pem.clone()),
            max_window: warden_broker_proto::Window::H1,
        }
    }

    /// Every request received so far, oldest first.
    ///
    /// # Panics
    /// If the log lock is poisoned.
    #[must_use]
    pub fn received(&self) -> Vec<Received> {
        self.received.lock().expect("upstream log poisoned").clone()
    }

    /// Wait until `count` calls to `/hang` or `/drip` have lost their caller,
    /// which only a closed connection does. The caller bounds the wait.
    ///
    /// # Panics
    /// If the upstream is gone, which cannot happen while `self` lives.
    pub async fn wait_for_abandoned(&self, count: u64) {
        self.abandoned
            .subscribe()
            .wait_for(|abandoned| *abandoned >= count)
            .await
            .expect("the upstream holds the sender");
    }

    /// Let calls to `/held` answer.
    pub fn release_held(&self) {
        self.released.send_replace(true);
    }

    /// Queue the response for the next call to the GitHub token route.
    ///
    /// # Panics
    /// If the script lock is poisoned.
    pub fn script_github_token(&self, response: Scripted) {
        self.scripts
            .lock()
            .expect("upstream script poisoned")
            .push_back(response);
    }

    /// Wait until the GitHub token route has received `count` calls, answered or
    /// still held. The caller bounds the wait.
    ///
    /// # Panics
    /// If the upstream is gone, which cannot happen while `self` lives.
    pub async fn wait_for_github_token_calls(&self, count: u64) {
        self.token_calls
            .subscribe()
            .wait_for(|calls| *calls >= count)
            .await
            .expect("the upstream holds the sender");
    }

    /// The fake GitHub the release client talks to: install repositories on it,
    /// read what it was asked, make it fail.
    #[must_use]
    pub const fn github_release(&self) -> &GithubReleaseFake {
        &self.github_release
    }

    /// How many calls to `/hang` or `/drip` have lost their caller so far.
    #[must_use]
    pub fn abandoned(&self) -> u64 {
        *self.abandoned.borrow()
    }
}

/// The CA certificate PEM, and the server's chain and key.
fn certificates() -> (String, Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "warden test upstream CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().expect("CA key");
    let ca = ca_params.self_signed(&ca_key).expect("CA certificate");
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_params = CertificateParams::new(vec!["localhost".to_owned()]).expect("server params");
    let leaf_key = KeyPair::generate().expect("server key");
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("server certificate");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    (ca.pem(), vec![leaf.der().clone()], key)
}

/// Accept TLS connections for `router` until aborted; aborting closes them.
async fn serve(listener: tokio::net::TcpListener, acceptor: TlsAcceptor, router: Router) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let (acceptor, router) = (acceptor.clone(), router.clone());
                connections.spawn(async move {
                    // A failed handshake (an untrusting client) or a broken
                    // connection only ends that connection.
                    let Ok(tls) = acceptor.accept(stream).await else { return };
                    let service = hyper_util::service::TowerToHyperService::new(router);
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                        .await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn handle(State(shared): State<Shared>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes().to_vec())
        .unwrap_or_default();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path().to_owned(), ToString::to_string);
    shared
        .log
        .lock()
        .expect("upstream log poisoned")
        .push(Received {
            method: parts.method.to_string(),
            path_and_query: path_and_query.clone(),
            headers: parts.headers.clone(),
            body: body.clone(),
        });
    if let Some(response) = shared
        .github_release
        .route(&parts.method, &path_and_query, &parts.headers, &body)
        .await
    {
        return response;
    }
    if parts.method == http::Method::POST && is_github_token_route(parts.uri.path()) {
        return github_token(&shared).await;
    }
    match parts.uri.path() {
        "/echo" => echo(&parts.headers, &body),
        "/name-echo" => name_echo(&parts.headers),
        "/redirect" => redirect(&parts.headers),
        "/huge" => respond(StatusCode::OK, &[], Body::from(vec![b'a'; HUGE_BYTES])),
        "/huge-chunked" => respond(StatusCode::OK, &[], huge_chunked()),
        "/slow" => respond(StatusCode::OK, &[], slow()),
        path if path == "/delayed" || path.starts_with("/delayed/") => {
            tokio::time::sleep(DELAY).await;
            respond(StatusCode::OK, &[], Body::from("late answer"))
        }
        "/held" => {
            // The sender lives in `shared`, so this cannot fail.
            let _ = shared
                .released
                .subscribe()
                .wait_for(|released| *released)
                .await;
            respond(StatusCode::OK, &[], Body::from("late answer"))
        }
        "/hang" => {
            let _abandonment = Abandonment(shared.abandoned);
            std::future::pending().await
        }
        "/drip" => respond(
            StatusCode::OK,
            &[],
            drip(&parts.headers, Abandonment(shared.abandoned)),
        ),
        "/binary" => respond(StatusCode::OK, &[], Body::from(BINARY_BODY)),
        path if path.starts_with("/status/") => {
            let code = path["/status/".len()..]
                .parse::<u16>()
                .ok()
                .and_then(|c| StatusCode::from_u16(c).ok())
                .unwrap_or(StatusCode::BAD_REQUEST);
            respond(code, &[], Body::from(format!("status {}", code.as_u16())))
        }
        "/gzip" => respond(
            StatusCode::OK,
            &[("content-encoding", "gzip".to_owned())],
            Body::from(b"\x1f\x8b\x08\x00 not really gzip".to_vec()),
        ),
        _ => respond(
            StatusCode::OK,
            &[("content-type", "text/plain".to_owned())],
            Body::from("hello from upstream"),
        ),
    }
}

fn is_github_token_route(path: &str) -> bool {
    path.strip_prefix("/app/installations/")
        .and_then(|rest| rest.strip_suffix("/access_tokens"))
        .is_some_and(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
}

/// The next scripted response, after its gate opens; `500` when none is queued.
async fn github_token(shared: &Shared) -> Response {
    shared.token_calls.send_modify(|calls| *calls += 1);
    let scripted = shared
        .scripts
        .lock()
        .expect("upstream script poisoned")
        .pop_front();
    match scripted {
        Some(scripted) => answer_scripted(scripted).await,
        None => respond(StatusCode::INTERNAL_SERVER_ERROR, &[], Body::empty()),
    }
}

/// `scripted` as a response, after its gate opens.
pub(super) async fn answer_scripted(scripted: Scripted) -> Response {
    if let Some(Gate(gate)) = &scripted.gate {
        // The sender lives in the gate this response holds, so this cannot fail.
        let _ = gate.subscribe().wait_for(|open| *open).await;
    }
    let body = if scripted.chunked {
        in_chunks(scripted.body)
    } else {
        Body::from(scripted.body)
    };
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::from_u16(scripted.status).expect("scripted status");
    for (name, value) in &scripted.headers {
        response.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("scripted header name"),
            HeaderValue::from_str(value).expect("scripted header value"),
        );
    }
    response
}

fn respond(status: StatusCode, headers: &[(&'static str, String)], body: Body) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    for (name, value) in headers {
        if let Ok(value) = HeaderValue::from_str(value) {
            response
                .headers_mut()
                .append(HeaderName::from_static(name), value);
        }
    }
    response
}

/// Each header value raw, in standard and URL-safe base64, inside a larger
/// base64 blob (as HTTP Basic credentials are), percent-encoded in upper and
/// lower case, and JSON-escaped with `\/`; the body raw and in base64. The
/// same values, raw and in base64, come back as `x-echo-<name>` and
/// `x-echo-b64-<name>` headers.
fn echo(headers: &HeaderMap, body: &[u8]) -> Response {
    let mut text = String::new();
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        let raw = String::from_utf8_lossy(value.as_bytes()).into_owned();
        let pct = utf8_percent_encode(&raw, NON_ALPHANUMERIC).to_string();
        let json = serde_json::to_string(&raw)
            .unwrap_or_default()
            .replace('/', "\\/");
        let lines = [
            format!("raw {name}: {raw}"),
            format!("b64 {name}: {}", STANDARD.encode(&raw)),
            format!("b64url {name}: {}", URL_SAFE_NO_PAD.encode(&raw)),
            format!("b64blob {name}: {}", STANDARD.encode(format!("user:{raw}"))),
            format!("pct {name}: {pct}"),
            format!("pct-lower {name}: {}", lowercase_escapes(&pct)),
            format!("json {name}: {json}"),
        ];
        for line in lines {
            text.push_str(&line);
            text.push('\n');
        }
        for (prefix, echoed) in [
            ("x-echo-", raw.clone()),
            ("x-echo-b64-", STANDARD.encode(&raw)),
        ] {
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(format!("{prefix}{name}").as_bytes()),
                HeaderValue::from_str(&echoed),
            ) {
                out.append(n, v);
            }
        }
    }
    text.push_str("body: ");
    text.push_str(&String::from_utf8_lossy(body));
    text.push_str("\nbody-b64: ");
    text.push_str(&STANDARD.encode(body));
    text.push('\n');
    let mut response = respond(StatusCode::OK, &[], Body::from(text));
    response.headers_mut().extend(out);
    response
}

/// `x-seen-<credential>: 1`, with the credential taken from `Authorization`,
/// and a harmless `x-plain` header.
fn name_echo(headers: &HeaderMap) -> Response {
    let mut response = respond(
        StatusCode::OK,
        &[("x-plain", "fine".to_owned())],
        Body::empty(),
    );
    let credential = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").unwrap_or(v));
    if let Some(name) =
        credential.and_then(|c| HeaderName::from_bytes(format!("x-seen-{c}").as_bytes()).ok())
    {
        response
            .headers_mut()
            .append(name, HeaderValue::from_static("1"));
    }
    response
}

fn lowercase_escapes(pct: &str) -> String {
    let mut out = String::with_capacity(pct.len());
    let mut hex_left = 0;
    for c in pct.chars() {
        if hex_left > 0 {
            out.push(c.to_ascii_lowercase());
            hex_left -= 1;
        } else {
            if c == '%' {
                hex_left = 2;
            }
            out.push(c);
        }
    }
    out
}

fn redirect(headers: &HeaderMap) -> Response {
    let auth = headers
        .get(header::AUTHORIZATION)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default();
    let location = format!(
        "https://elsewhere.example/collect?auth={}",
        utf8_percent_encode(&auth, NON_ALPHANUMERIC)
    );
    respond(
        StatusCode::FOUND,
        &[("location", location)],
        Body::from("moved"),
    )
}

/// [`HUGE_BYTES`] in 64 KiB chunks, with no `Content-Length`.
/// `body` in 1 KiB chunks, so that its length is not known up front.
fn in_chunks(body: Vec<u8>) -> Body {
    let (mut tx, stream) = Channel::<Bytes>::new(1);
    tokio::spawn(async move {
        for chunk in body.chunks(1024) {
            if tx.send_data(Bytes::copy_from_slice(chunk)).await.is_err() {
                return;
            }
        }
    });
    Body::new(stream)
}

fn huge_chunked() -> Body {
    let (mut tx, body) = Channel::<Bytes>::new(1);
    tokio::spawn(async move {
        let chunk = Bytes::from(vec![b'b'; 64 * 1024]);
        for _ in 0..HUGE_BYTES / chunk.len() {
            if tx.send_data(chunk.clone()).await.is_err() {
                return;
            }
        }
    });
    Body::new(body)
}

/// The `Authorization` value, then short chunks until the caller is gone, which
/// is what `abandonment` then records. A chunk this size every few milliseconds
/// stays under the response limit for far longer than any call may last.
fn drip(headers: &HeaderMap, abandonment: Abandonment) -> Body {
    let echoed = headers
        .get(header::AUTHORIZATION)
        .map(|v| Bytes::copy_from_slice(v.as_bytes()))
        .unwrap_or_default();
    let (mut tx, body) = Channel::<Bytes>::new(1);
    tokio::spawn(async move {
        let _abandonment = abandonment;
        let mut next = echoed;
        while tx.send_data(next).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(5)).await;
            next = Bytes::from_static(b".");
        }
    });
    Body::new(body)
}

/// [`SLOW_PREFIX`], then a minute of silence before the rest.
fn slow() -> Body {
    let (mut tx, body) = Channel::<Bytes>::new(1);
    tokio::spawn(async move {
        if tx.send_data(Bytes::from_static(SLOW_PREFIX)).await.is_ok() {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let _ = tx.send_data(Bytes::from_static(b" and the rest")).await;
        }
    });
    Body::new(body)
}
