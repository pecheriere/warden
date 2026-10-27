//! Whether an agent's HTTP request may be sent with an API secret: the URL,
//! method, headers and body are checked against the secret's policy before
//! anything leaves the broker.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use url::Url;
use warden_broker_proto::{ProxyRequest, under_prefix};

use crate::policy::{ApiSecretPolicy, check_path_prefix, is_reserved_header};

/// A request that passed [`check`], ready to be sent once the secret header
/// is added. Holds nothing the agent did not send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    /// Request method, one the policy allows.
    pub method: Method,
    /// Absolute URL on the policy's origin, under its path prefix.
    pub url: Url,
    /// The agent's headers, none of them reserved or the secret's header.
    pub headers: HeaderMap,
    /// Decoded request body.
    pub body: Vec<u8>,
}

/// Why a request was refused. The message is shown to the agent and never
/// contains the secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The URL is not on the secret's origin (scheme, host and port).
    #[error("URL origin is not allowed for this secret")]
    Origin,
    /// The path is outside the allowed prefix or not in plain form.
    #[error(
        "URL path is not allowed: it must be under the allowed path prefix and \
         contain no dot segments, encoded dots or slashes, backslashes, \"//\" or \";\""
    )]
    Path,
    /// The method is not allowed for this secret.
    #[error("method is not allowed for this secret")]
    Method,
    /// A header is malformed or may not be set by the agent.
    #[error("header refused: {0}")]
    Header(String),
    /// The body is malformed or too large.
    #[error("body refused: {0}")]
    Body(String),
    /// The URL is malformed or carries parts that are not allowed.
    #[error("URL refused: {0}")]
    Url(String),
}

/// Check `req` against `policy` and build the request to send.
///
/// # Errors
/// A [`Refusal`] naming the first rule the request breaks.
pub fn check(
    policy: &ApiSecretPolicy,
    req: &ProxyRequest,
    max_body: usize,
) -> Result<Prepared, Refusal> {
    let url = check_url(policy, &req.url)?;
    let method = check_method(policy, &req.method)?;
    let headers = check_headers(policy, &req.headers)?;
    let body = match &req.body_b64 {
        Some(b64) => decode_body(b64, max_body)?,
        None => Vec::new(),
    };
    Ok(Prepared {
        method,
        url,
        headers,
        body,
    })
}

/// The `Accept-Encoding` the outbound client sends: responses must arrive
/// uncompressed so redaction can see the secret. Agents may not set it.
pub const OUTBOUND_ACCEPT_ENCODING: &str = "identity";

/// The only spelling of the scheme accepted in the URL as sent.
const SCHEME_PREFIX: &str = "https://";

/// Headers an agent may not set although they are not reserved:
/// `Accept-Encoding`, `Range` and `If-Range` would let the response carry the
/// secret compressed or in fragments that redaction cannot see; the method
/// and URL overrides make some servers apply another method or path than the
/// one checked; the forwarding and host-override headers (`Via` included)
/// make some servers (and the proxies in front of them) route to another
/// virtual host or path prefix, or trust another client.
const REFUSED_HEADERS: [&str; 19] = [
    "accept-encoding",
    "range",
    "if-range",
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
    "x-original-url",
    "x-rewrite-url",
    "forwarded",
    "x-forwarded-host",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "x-forwarded-server",
    "x-forwarded-prefix",
    "x-host",
    "x-original-host",
    "via",
];

/// Parse the URL and check it against the policy. The path is inspected as
/// sent, before the URL parser normalises it, and the parsed path must equal
/// it, so the path that was checked is the path that is sent.
fn check_url(policy: &ApiSecretPolicy, raw: &str) -> Result<Url, Refusal> {
    // Printable ASCII without spaces: no CR/LF/NUL or other control bytes,
    // which the URL parser would otherwise strip or encode silently.
    if !raw.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Refusal::Url(
            "must be printable ASCII without spaces or control characters".to_owned(),
        ));
    }
    let url = Url::parse(raw).map_err(|e| Refusal::Url(e.to_string()))?;
    if url.scheme() != "https" || url.origin() != policy.origin {
        return Err(Refusal::Origin);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Refusal::Url("user info is not allowed".to_owned()));
    }
    if url.fragment().is_some() {
        return Err(Refusal::Url("a fragment is not allowed".to_owned()));
    }
    let Some(rest) = raw.strip_prefix(SCHEME_PREFIX) else {
        return Err(Refusal::Url(format!("must start with {SCHEME_PREFIX}")));
    };
    // The URL parser reads `\` as `/` in https URLs, wherever it appears.
    if rest.contains('\\') {
        return Err(Refusal::Path);
    }
    let after_authority = rest.find(['/', '?']).map_or("", |at| &rest[at..]);
    let raw_path = after_authority
        .find('?')
        .map_or(after_authority, |at| &after_authority[..at]);
    let sent_path = if raw_path.is_empty() { "/" } else { raw_path };
    if check_path_prefix(sent_path).is_err() {
        return Err(Refusal::Path);
    }
    if url.path() != sent_path || !under_prefix(sent_path, &policy.path_prefix) {
        return Err(Refusal::Path);
    }
    Ok(url)
}

/// The method, if the policy lists it. `CONNECT` and `TRACE` are never
/// allowed: one would tunnel past every rule, the other echoes the request,
/// secret header included.
fn check_method(policy: &ApiSecretPolicy, raw: &str) -> Result<Method, Refusal> {
    let method = Method::from_bytes(raw.as_bytes()).map_err(|_| Refusal::Method)?;
    if method == Method::CONNECT || method == Method::TRACE || !policy.methods.contains(&method) {
        return Err(Refusal::Method);
    }
    Ok(method)
}

/// The agent's headers, refusing malformed ones, the secret's own header and
/// headers that frame or route the request. Values never appear in refusals.
fn check_headers(policy: &ApiSecretPolicy, raw: &[(String, String)]) -> Result<HeaderMap, Refusal> {
    let mut headers = HeaderMap::with_capacity(raw.len());
    for (name, value) in raw {
        if [name, value]
            .iter()
            .any(|s| s.bytes().any(|b| matches!(b, b'\r' | b'\n' | b'\0')))
        {
            return Err(Refusal::Header(
                "names and values must not contain CR, LF or NUL".to_owned(),
            ));
        }
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| Refusal::Header("invalid header name".to_owned()))?;
        if name == policy.header
            || is_reserved_header(&name)
            || REFUSED_HEADERS.contains(&name.as_str())
        {
            return Err(Refusal::Header(format!("\"{name}\" may not be set")));
        }
        let value = HeaderValue::from_str(value)
            .map_err(|_| Refusal::Header(format!("invalid value for \"{name}\"")))?;
        headers.append(name, value);
    }
    Ok(headers)
}

/// The standard-base64 body, at most `max` bytes once decoded. Longer
/// encodings are refused before decoding.
fn decode_body(b64: &str, max: usize) -> Result<Vec<u8>, Refusal> {
    let too_large = || Refusal::Body(format!("exceeds {max} bytes"));
    if b64.len() > max.div_ceil(3).saturating_mul(4) {
        return Err(too_large());
    }
    let body = STANDARD
        .decode(b64)
        .map_err(|_| Refusal::Body("not valid standard base64".to_owned()))?;
    if body.len() > max {
        return Err(too_large());
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use http::{HeaderName, Method};
    use url::Url;
    use warden_broker_proto::{ProxyRequest, SecretName, Window};

    use super::{Refusal, check};
    use crate::policy::{ApiSecretPolicy, ValueFormat};

    const MAX: usize = 1024;

    fn policy(prefix: &str, methods: &[Method]) -> ApiSecretPolicy {
        ApiSecretPolicy {
            name: SecretName::try_from("github".to_owned()).unwrap(),
            origin: Url::parse("https://api.example.com").unwrap().origin(),
            header: HeaderName::from_static("x-api-key"),
            format: ValueFormat::default(),
            methods: methods.to_vec(),
            path_prefix: prefix.to_owned(),
            ca_pem: None,
            max_window: Window::H1,
        }
    }

    fn get(url: &str) -> ProxyRequest {
        ProxyRequest {
            method: "GET".to_owned(),
            url: url.to_owned(),
            headers: Vec::new(),
            body_b64: None,
        }
    }

    fn with_header(name: &str, value: &str) -> ProxyRequest {
        let mut req = get("https://api.example.com/v1/x");
        req.headers.push((name.to_owned(), value.to_owned()));
        req
    }

    #[test]
    fn rules_accept_simple_get() {
        let p = policy("/v1", &[Method::GET]);
        let mut req = get("https://api.example.com/v1/repos?page=2&q=a%20b");
        req.headers
            .push(("Accept".to_owned(), "application/json".to_owned()));
        req.headers.push(("X-Trace".to_owned(), "1".to_owned()));
        req.headers.push(("x-trace".to_owned(), "2".to_owned()));
        let prepared = check(&p, &req, MAX).unwrap();
        assert_eq!(prepared.method, Method::GET);
        assert_eq!(
            prepared.url.as_str(),
            "https://api.example.com/v1/repos?page=2&q=a%20b"
        );
        assert_eq!(prepared.headers["accept"], "application/json");
        let traces: Vec<_> = prepared.headers.get_all("x-trace").iter().collect();
        assert_eq!(traces, ["1", "2"]);
        assert!(prepared.body.is_empty());

        // Host case and the explicit default port are the same origin.
        let prepared = check(&p, &get("https://API.Example.COM:443/v1"), MAX).unwrap();
        assert_eq!(prepared.url.as_str(), "https://api.example.com/v1");

        // An empty path is the root path.
        let root = policy("/", &[Method::GET]);
        let prepared = check(&root, &get("https://api.example.com"), MAX).unwrap();
        assert_eq!(prepared.url.path(), "/");

        let mut post = get("https://api.example.com/v1/x");
        post.method = "POST".to_owned();
        post.body_b64 = Some(STANDARD.encode(b"{\"a\":1}"));
        let p = policy("/v1", &[Method::GET, Method::POST]);
        let prepared = check(&p, &post, MAX).unwrap();
        assert_eq!(prepared.method, Method::POST);
        assert_eq!(prepared.body, b"{\"a\":1}");
    }

    #[test]
    fn rules_refuse_other_origin_scheme_port() {
        let p = policy("/", &[Method::GET]);
        for url in [
            "http://api.example.com/v1",
            "https://api.example.com:8443/v1",
            "https://example.com/v1",
            "https://api.example.com.evil.example/v1",
            "https://api.example.com./v1",
            "https://evil.example/v1#@api.example.com",
            "https://api.example.com@evil.example/v1",
            "wss://api.example.com/v1",
            "file:///etc/passwd",
        ] {
            assert_eq!(check(&p, &get(url), MAX), Err(Refusal::Origin), "{url}");
        }
        for url in [
            "",
            "not a url",
            "/v1/x",
            "https://",
            "https://user@api.example.com/v1",
            "https://user:pw@api.example.com/v1",
            "https://:pw@api.example.com/v1",
            "https://api.example.com/v1#frag",
            "https://api.example.com/v1#",
            "https:api.example.com/v1",
            "https:/api.example.com/v1",
            "HTTPS://api.example.com/v1/x",
            " https://api.example.com/v1",
            "https://api.example.com/v1/x\r\nHost: evil.example",
            "https://api.example.com/v1/x\n",
            "https://api.example.com/v1/x\0",
            "https://api.example.com/v1/\tx",
            "https://api.example.com/v1/a b",
            "https://api.example.com/v1/caf\u{e9}",
        ] {
            assert!(
                matches!(check(&p, &get(url), MAX), Err(Refusal::Url(_))),
                "{url:?}"
            );
        }
    }

    #[test]
    fn rules_refuse_traversal_and_encoded_separators() {
        // Review Focus 1: none of these may reach a path outside `/api/`.
        let p = policy("/api/", &[Method::GET]);
        for path in [
            "/api/../admin",
            "/api/..",
            "/api/./x",
            "/api/.",
            "/api/x/../../admin",
            "/api/%2e%2e/admin",
            "/api/%2E%2E/admin",
            "/api/%2e./admin",
            "/api/.%2E/admin",
            "/api/%2e/x",
            "/api/x%2fadmin",
            "/api/x%2Fadmin",
            "/api/%2F..%2Fadmin",
            "/api/x%5cadmin",
            "/api/x%5Cadmin",
            "/api/x%252e%252e/admin",
            "/api/%c0%ae%c0%ae/admin",
            "/api/%C0%AE/x",
            "/api/%c1%9c/x",
            "/api/%C1%9C/x",
            "/api/%u002e%u002e/admin",
            "/api/%U002E/x",
            "/api/x%3bjsessionid=1",
            "/api/x%3B/y",
            "/api\\..\\admin",
            "/api/x\\y",
            "/api//admin",
            "//api/x",
            "/api/x//y",
            "/api/x;jsessionid=1",
            "/api/..;/admin",
            "/api;/x",
            "/admin",
            "/apix",
            "/api",
            "/",
        ] {
            let url = format!("https://api.example.com{path}");
            assert_eq!(check(&p, &get(&url), MAX), Err(Refusal::Path), "{path}");
        }
        // A backslash anywhere after the scheme is refused, even before the
        // path (special-scheme parsers treat it as a slash).
        assert_eq!(
            check(&p, &get("https://api.example.com\\api/x"), MAX),
            Err(Refusal::Path)
        );
        // Dots inside a segment and encodings of other bytes are fine.
        for path in ["/api/v1.2/x", "/api/.well-known", "/api/a..b", "/api/a%20b"] {
            let url = format!("https://api.example.com{path}");
            assert!(check(&p, &get(&url), MAX).is_ok(), "{path}");
        }
        // The query is not a path: `..` there does not move the path.
        assert!(
            check(
                &p,
                &get("https://api.example.com/api/x?next=/../a;b//c"),
                MAX
            )
            .is_ok()
        );
    }

    #[test]
    fn prefix_matches_on_segment_boundary() {
        let cases: &[(&str, &str, bool)] = &[
            ("/api", "/api", true),
            ("/api", "/api/", true),
            ("/api", "/api/x", true),
            ("/api", "/api?x=1", true),
            ("/api", "/apiary", false),
            ("/api", "/ap", false),
            ("/api", "/API/x", false),
            ("/api", "/", false),
            ("/api/", "/api/", true),
            ("/api/", "/api/x", true),
            ("/api/", "/api", false),
            ("/api/", "/apiary", false),
            ("/v1/repos", "/v1/repos/a", true),
            ("/v1/repos", "/v1/repository", false),
            ("/", "/", true),
            ("/", "/anything/at/all", true),
            ("/", "", true),
        ];
        for &(prefix, path, allowed) in cases {
            let p = policy(prefix, &[Method::GET]);
            let url = format!("https://api.example.com{path}");
            let got = check(&p, &get(&url), MAX);
            if allowed {
                assert!(got.is_ok(), "{prefix} {path}: {got:?}");
            } else {
                assert_eq!(got, Err(Refusal::Path), "{prefix} {path}");
            }
        }
    }

    #[test]
    fn rules_refuse_injected_and_hop_headers() {
        let p = policy("/", &[Method::GET]);
        for name in [
            "X-Api-Key",
            "x-api-key",
            "X-API-KEY",
            "Host",
            "HOST",
            "Content-Length",
            "Transfer-Encoding",
            "Connection",
            "Keep-Alive",
            "Proxy-Authorization",
            "proxy-connection",
            "TE",
            "Trailer",
            "Upgrade",
            "Forwarded",
            "X-Forwarded-Host",
            "x-forwarded-for",
            "X-Forwarded-Proto",
            "X-Forwarded-Port",
            "X-Real-IP",
            "X-Forwarded-Server",
            "x-forwarded-prefix",
            "X-Host",
            "X-Original-Host",
            "Via",
        ] {
            assert!(
                matches!(
                    check(&p, &with_header(name, "v"), MAX),
                    Err(Refusal::Header(_))
                ),
                "{name}"
            );
        }
        // Malformed names and values, including header injection.
        for (name, value) in [
            ("", "v"),
            ("bad name", "v"),
            ("bad:name", "v"),
            ("x-a\r\nx-b", "v"),
            ("x-a", "v\r\nHost: evil.example"),
            ("x-a", "v\nx"),
            ("x-a", "v\rx"),
            ("x-a", "v\0x"),
            ("x-a\0", "v"),
        ] {
            assert!(
                matches!(
                    check(&p, &with_header(name, value), MAX),
                    Err(Refusal::Header(_))
                ),
                "{name:?}: {value:?}"
            );
        }
        // The refusal never echoes the value.
        let Err(refusal) = check(&p, &with_header("x-a", "s3cr3t\n"), MAX) else {
            panic!("accepted");
        };
        assert!(!refusal.to_string().contains("s3cr3t"));
        // Authorization is an ordinary header when the secret uses another.
        assert!(check(&p, &with_header("Authorization", "Bearer mine"), MAX).is_ok());
    }

    #[test]
    fn rules_refuse_encoding_range_and_override_headers() {
        let p = policy("/", &[Method::GET]);
        for name in [
            "Accept-Encoding",
            "accept-encoding",
            "ACCEPT-ENCODING",
            "Range",
            "range",
            "If-Range",
            "IF-RANGE",
            "X-HTTP-Method-Override",
            "x-http-method",
            "X-Method-Override",
            "X-Original-URL",
            "x-rewrite-url",
        ] {
            assert!(
                matches!(
                    check(&p, &with_header(name, "x"), MAX),
                    Err(Refusal::Header(_))
                ),
                "{name}"
            );
        }
        assert_eq!(super::OUTBOUND_ACCEPT_ENCODING, "identity");
    }

    #[test]
    fn rules_refuse_method() {
        let p = policy(
            "/",
            &[
                Method::GET,
                Method::CONNECT,
                Method::TRACE,
                Method::from_bytes(b"PURGE").unwrap(),
            ],
        );
        for method in [
            "POST", "DELETE", "get", "Get", "CONNECT", "TRACE", "", "G T", "GET\r\n",
        ] {
            let mut req = get("https://api.example.com/x");
            req.method = method.to_owned();
            assert_eq!(check(&p, &req, MAX), Err(Refusal::Method), "{method:?}");
        }
        let mut req = get("https://api.example.com/x");
        req.method = "PURGE".to_owned();
        assert!(check(&p, &req, MAX).is_ok());
    }

    #[test]
    fn rules_refuse_oversized_body() {
        let p = policy("/", &[Method::POST]);
        let mut req = get("https://api.example.com/x");
        req.method = "POST".to_owned();
        for len in [0, 1, 2, 3, MAX - 1, MAX] {
            req.body_b64 = Some(STANDARD.encode(vec![7u8; len]));
            assert_eq!(check(&p, &req, MAX).unwrap().body.len(), len);
        }
        for len in [MAX + 1, MAX + 2, MAX + 3, 4 * MAX] {
            req.body_b64 = Some(STANDARD.encode(vec![7u8; len]));
            assert!(
                matches!(check(&p, &req, MAX), Err(Refusal::Body(_))),
                "{len}"
            );
        }
        for bad in ["!!!!", "aGk", "aGk=\n", "aGk=aGk="] {
            req.body_b64 = Some(bad.to_owned());
            assert!(
                matches!(check(&p, &req, MAX), Err(Refusal::Body(_))),
                "{bad}"
            );
        }
    }
}
