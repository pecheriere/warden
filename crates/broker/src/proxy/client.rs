//! The outbound side of the proxy: sending a checked request with the secret
//! header to the policy's origin, and turning the answer into what the agent
//! may see.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::header::{
    ACCEPT_ENCODING, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, TRANSFER_ENCODING,
};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use reqwest::{Certificate, Client, redirect};
use warden_broker_proto::ProxyResponse;

use super::redact::{Needles, redact};
use super::rules::{OUTBOUND_ACCEPT_ENCODING, Prepared};
use crate::policy::{ApiSecretPolicy, SecretValue};

/// Size and time limits of one proxied call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyLimits {
    /// Largest request body the agent may send, decoded.
    pub max_request_bytes: usize,
    /// Largest response body accepted from upstream.
    pub max_response_bytes: usize,
    /// Time allowed for the whole call: connecting, sending, and reading the
    /// full response.
    pub timeout: Duration,
    /// Time allowed for connecting (TCP and TLS).
    pub connect_timeout: Duration,
}

impl Default for ProxyLimits {
    /// 1 MiB each way, 30 s in total, 10 s to connect.
    fn default() -> Self {
        Self {
            max_request_bytes: 1024 * 1024,
            max_response_bytes: 1024 * 1024,
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// An upstream response read in full, before redaction.
#[derive(Debug)]
pub struct Upstream {
    /// Status code.
    pub status: StatusCode,
    /// Response headers as received.
    pub headers: HeaderMap,
    /// The whole body, at most [`ProxyLimits::max_response_bytes`].
    pub body: Vec<u8>,
}

/// Why a call produced no response for the agent. The messages are fixed:
/// none carries upstream text, which could quote the secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProxyError {
    /// No connection or TLS session could be made, or it broke.
    #[error("upstream unreachable")]
    Unreachable,
    /// The call did not finish within the time limit.
    #[error("upstream timed out")]
    Timeout,
    /// The response body is larger than the limit; nothing is returned.
    #[error("response exceeds {0} bytes")]
    TooLarge(usize),
    /// The response is compressed, so redaction could not see into it.
    #[error("compressed responses are not supported")]
    Compressed,
    /// The policy's pinned CA could not be loaded.
    #[error("the pinned CA certificate is unusable")]
    PinnedCa,
    /// The secret cannot be written into an HTTP header.
    #[error("the secret is not a valid header value")]
    Credential,
    /// The HTTP client could not be built.
    #[error("the HTTP client could not be set up")]
    Client,
}

impl ProxyError {
    /// The status the agent gets: 504 for a timeout, 500 for a broker-side
    /// fault, 502 for everything upstream did wrong.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::Credential | Self::Client => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Unreachable | Self::TooLarge(_) | Self::Compressed | Self::PinnedCa => {
                StatusCode::BAD_GATEWAY
            }
        }
    }
}

/// Send `prepared` to the policy's origin with the secret in the policy's
/// header, and read the whole response.
///
/// A fresh client is built for every call, trusting only the policy's
/// pinned CA when it has one (the system roots otherwise), so no trust
/// decision is shared between policies. Redirects are returned, never
/// followed; no proxy is used; requests are never retried; the response
/// must be uncompressed. The header value is marked sensitive.
///
/// # Errors
/// A [`ProxyError`]; nothing partial is returned.
pub async fn forward(
    policy: &ApiSecretPolicy,
    secret: &SecretValue,
    prepared: Prepared,
    limits: &ProxyLimits,
) -> Result<Upstream, ProxyError> {
    let client = client_for(policy, limits)?;
    let rendered = policy.format.render(secret.expose());
    let mut value = HeaderValue::from_str(&rendered).map_err(|_| ProxyError::Credential)?;
    value.set_sensitive(true);
    let mut headers = prepared.headers;
    headers.insert(policy.header.clone(), value);
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_static(OUTBOUND_ACCEPT_ENCODING),
    );
    let request = client
        .request(prepared.method, prepared.url)
        .headers(headers)
        .body(prepared.body);
    let call = async {
        let mut response = request.send().await.map_err(failed)?;
        refuse_encoded(response.headers())?;
        let max = limits.max_response_bytes;
        if response
            .content_length()
            .is_some_and(|len| usize::try_from(len).map_or(true, |len| len > max))
        {
            return Err(ProxyError::TooLarge(max));
        }
        let status = response.status();
        let headers = std::mem::take(response.headers_mut());
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(failed)? {
            if chunk.len() > max - body.len() {
                return Err(ProxyError::TooLarge(max));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Upstream {
            status,
            headers,
            body,
        })
    };
    tokio::time::timeout(limits.timeout, call)
        .await
        .map_err(|_| ProxyError::Timeout)?
}

/// A client for one call under `policy`.
fn client_for(policy: &ApiSecretPolicy, limits: &ProxyLimits) -> Result<Client, ProxyError> {
    let mut builder = Client::builder()
        .https_only(true)
        .redirect(redirect::Policy::none())
        .referer(false)
        .no_proxy()
        .retry(reqwest::retry::never())
        .connect_timeout(limits.connect_timeout)
        .timeout(limits.timeout);
    if let Some(pem) = &policy.ca_pem {
        let roots =
            Certificate::from_pem_bundle(pem.as_bytes()).map_err(|_| ProxyError::PinnedCa)?;
        if roots.is_empty() {
            return Err(ProxyError::PinnedCa);
        }
        // Only these roots: in reqwest 0.13, `tls_certs_only` takes the
        // `with_root_certificates` branch of the rustls setup, whose root
        // store starts empty and holds just `roots`; the platform verifier
        // (and with it the system roots) is not used. `add_root_certificate`
        // alone would merge with the system roots instead. Re-check this
        // on every reqwest upgrade.
        builder = builder.tls_certs_only(roots);
    }
    builder.build().map_err(|e| {
        tracing::error!(error = %e.without_url(), "building the proxy HTTP client failed");
        ProxyError::Client
    })
}

/// The fixed error for a failed send or body read. The detail goes to the
/// server log without the URL (its query is the agent's business).
fn failed(e: reqwest::Error) -> ProxyError {
    let timed_out = e.is_timeout();
    tracing::warn!(error = %e.without_url(), "proxied call failed");
    if timed_out {
        ProxyError::Timeout
    } else {
        ProxyError::Unreachable
    }
}

/// Refuse a response whose body is encoded in a way redaction cannot see
/// through: any `Content-Encoding` other than `identity`, or a
/// `Transfer-Encoding` other than `chunked`/`identity`.
fn refuse_encoded(headers: &HeaderMap) -> Result<(), ProxyError> {
    let only = |name: HeaderName, allowed: &[&str]| {
        headers.get_all(name).iter().all(|value| {
            value.to_str().is_ok_and(|text| {
                text.split(',')
                    .map(str::trim)
                    .filter(|token| !token.is_empty())
                    .all(|token| allowed.iter().any(|ok| token.eq_ignore_ascii_case(ok)))
            })
        })
    };
    if only(CONTENT_ENCODING, &["identity"]) && only(TRANSFER_ENCODING, &["chunked", "identity"]) {
        Ok(())
    } else {
        Err(ProxyError::Compressed)
    }
}

/// Response headers that describe the connection or the body's framing, not
/// the response: never passed on. `Content-Length` is dropped too, since
/// redaction may change the body's length.
const DROPPED_HEADERS: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// What the agent gets back: hop-by-hop headers (the fixed list, plus any
/// named in `Connection`), `Content-Length` and headers whose name holds
/// the secret dropped, every other header value and the body redacted, and
/// the total number of redactions (a dropped name counts its matches).
#[must_use]
pub fn redact_response(upstream: &Upstream, needles: &Needles) -> ProxyResponse {
    let named_by_connection: Vec<String> = upstream
        .headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect();
    let mut redactions = 0_u32;
    let mut headers = Vec::with_capacity(upstream.headers.len());
    for (name, value) in &upstream.headers {
        let name = name.as_str();
        if name == CONTENT_LENGTH.as_str()
            || DROPPED_HEADERS.contains(&name)
            || named_by_connection.iter().any(|n| n == name)
        {
            continue;
        }
        // A name carrying the secret cannot be redacted into a valid
        // header name: the whole header goes.
        let (_, in_name) = redact(name.as_bytes(), needles);
        if in_name > 0 {
            redactions = redactions.saturating_add(in_name);
            continue;
        }
        let (clean, count) = redact(value.as_bytes(), needles);
        redactions = redactions.saturating_add(count);
        headers.push((
            name.to_owned(),
            String::from_utf8_lossy(&clean).into_owned(),
        ));
    }
    let (body, count) = redact(&upstream.body, needles);
    redactions = redactions.saturating_add(count);
    ProxyResponse {
        status: upstream.status.as_u16(),
        headers,
        body_b64: STANDARD.encode(body),
        redactions,
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use http::{HeaderMap, HeaderValue, StatusCode};

    use super::{ProxyError, Upstream, redact_response, refuse_encoded};
    use crate::proxy::Needles;

    const SECRET: &str = "s3cr3t-value-0123";

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn encoded_responses_are_refused() {
        for ok in [
            headers(&[]),
            headers(&[("content-encoding", "identity")]),
            headers(&[("content-encoding", "IDENTITY")]),
            headers(&[("transfer-encoding", "chunked")]),
        ] {
            assert_eq!(refuse_encoded(&ok), Ok(()), "{ok:?}");
        }
        for bad in [
            headers(&[("content-encoding", "gzip")]),
            headers(&[("content-encoding", "identity, br")]),
            headers(&[
                ("content-encoding", "identity"),
                ("content-encoding", "zstd"),
            ]),
            headers(&[("transfer-encoding", "gzip, chunked")]),
        ] {
            assert_eq!(refuse_encoded(&bad), Err(ProxyError::Compressed), "{bad:?}");
        }
    }

    #[test]
    fn response_drops_hop_headers_and_redacts_everything() {
        let needles = Needles::new(SECRET, &format!("Bearer {SECRET}"));
        let upstream = Upstream {
            status: StatusCode::FOUND,
            headers: headers(&[
                ("connection", "x-private, close"),
                ("x-private", "hop"),
                ("keep-alive", "timeout=5"),
                ("content-length", "40"),
                (
                    "location",
                    &format!("https://elsewhere.example/?t={SECRET}"),
                ),
                ("x-b64", &STANDARD.encode(SECRET)),
                ("x-plain", "fine"),
            ]),
            body: format!("token={SECRET}&again={SECRET}").into_bytes(),
        };
        let response = redact_response(&upstream, &needles);
        assert_eq!(response.status, 302);
        assert_eq!(
            response.headers,
            [
                (
                    "location".to_owned(),
                    "https://elsewhere.example/?t=[REDACTED]".to_owned()
                ),
                ("x-b64".to_owned(), "[REDACTED]".to_owned()),
                ("x-plain".to_owned(), "fine".to_owned()),
            ]
        );
        assert_eq!(
            STANDARD.decode(&response.body_b64).unwrap(),
            b"token=[REDACTED]&again=[REDACTED]"
        );
        assert_eq!(response.redactions, 4);
    }

    #[test]
    fn header_names_carrying_the_secret_are_dropped_and_counted() {
        let secret = "abcdef0123456789";
        let needles = Needles::new(secret, &format!("Bearer {secret}"));
        let upstream = Upstream {
            status: StatusCode::OK,
            headers: headers(&[
                ("x-abcdef0123456789", "v"),
                ("x-token-abcdef0123456789-end", "w"),
                ("x-plain", "fine"),
            ]),
            body: Vec::new(),
        };
        let response = redact_response(&upstream, &needles);
        assert_eq!(
            response.headers,
            [("x-plain".to_owned(), "fine".to_owned())]
        );
        assert_eq!(response.redactions, 2);
    }

    #[test]
    fn error_statuses_and_messages_are_fixed() {
        assert_eq!(ProxyError::Timeout.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(ProxyError::Unreachable.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(ProxyError::Compressed.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(ProxyError::TooLarge(10).status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            ProxyError::TooLarge(10).to_string(),
            "response exceeds 10 bytes"
        );
        assert_eq!(
            ProxyError::Compressed.to_string(),
            "compressed responses are not supported"
        );
    }
}
