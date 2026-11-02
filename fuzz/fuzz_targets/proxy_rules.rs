//! The rules an agent's proxied call must pass before the secret is attached:
//! a request that passes may only go where the policy says.
//!
//! Input: a first byte picking the path prefix, then fields split on `0xFF`:
//! method, URL, body, and two header names and values. The rest of the input
//! is also read as the route's JSON body.

#![no_main]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::{HeaderName, Method};
use libfuzzer_sys::fuzz_target;
use url::Url;
use warden_broker::policy::{ApiSecretPolicy, ValueFormat};
use warden_broker::proxy::{Prepared, check};
use warden_broker_proto::{ProxyRequest, SecretName, Window};
use warden_fuzz::{fields, text};

const PREFIXES: [&str; 4] = ["/", "/api", "/api/", "/v1/repos"];
const MAX_BODY: usize = 1024;
/// Marks header values, so a refusal that repeats one can be seen.
const SENTINEL: &str = "zq7sentinel";
/// Headers that may never pass: the secret's own, framing and routing,
/// compression and ranges (which hide the secret from redaction), and overrides.
const NEVER_SENT: [&str; 17] = [
    "x-api-key",
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "proxy-authorization",
    "accept-encoding",
    "range",
    "if-range",
    "x-http-method-override",
    "x-original-url",
    "forwarded",
    "x-forwarded-host",
    "x-forwarded-for",
    "x-host",
    "via",
];

fn policy(prefix: &str) -> Option<ApiSecretPolicy> {
    Some(ApiSecretPolicy {
        name: SecretName::try_from("home-api".to_owned()).ok()?,
        origin: Url::parse("https://api.example.com").ok()?.origin(),
        header: HeaderName::from_static("x-api-key"),
        format: ValueFormat::default(),
        // CONNECT and TRACE must never pass, even listed in a policy.
        methods: vec![Method::GET, Method::POST, Method::CONNECT, Method::TRACE],
        path_prefix: prefix.to_owned(),
        ca_pem: None,
        max_window: Window::H1,
    })
}

/// The path as the agent wrote it, without using the URL parser.
fn written_path(url: &str) -> &str {
    let rest = url.strip_prefix("https://").unwrap_or(url);
    let after_authority = rest.find(['/', '?']).map_or("", |at| &rest[at..]);
    let path = after_authority
        .find('?')
        .map_or(after_authority, |at| &after_authority[..at]);
    if path.is_empty() { "/" } else { path }
}

fn check_path(path: &str, prefix: &str) {
    assert!(
        path == prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| prefix.ends_with('/') || rest.starts_with('/')),
        "{path} is outside {prefix}"
    );
    assert!(!path.contains('\\') && !path.contains(';') && !path.contains("//"));
    assert!(!path.split('/').any(|s| matches!(s, "." | "..")));
    let lower = path.to_ascii_lowercase();
    for encoded in ["%2e", "%2f", "%5c", "%3b", "%25", "%c0", "%c1", "%u"] {
        assert!(!lower.contains(encoded), "{path} holds {encoded}");
    }
}

fn check_prepared(policy: &ApiSecretPolicy, req: &ProxyRequest, prepared: &Prepared) {
    let url = &prepared.url;
    assert_eq!(url.origin(), policy.origin);
    assert_eq!(url.scheme(), "https");
    assert!(url.username().is_empty() && url.password().is_none());
    assert!(url.fragment().is_none());
    // The path checked is the path sent, and sending does not change it.
    assert_eq!(url.path(), written_path(&req.url));
    check_path(url.path(), &policy.path_prefix);
    assert_eq!(Url::parse(url.as_str()).ok().as_ref(), Some(url));

    assert!(policy.methods.contains(&prepared.method));
    assert_ne!(prepared.method, Method::CONNECT);
    assert_ne!(prepared.method, Method::TRACE);

    for name in prepared.headers.keys() {
        assert!(
            !NEVER_SENT.contains(&name.as_str()) && !name.as_str().starts_with("proxy-"),
            "{name} passed"
        );
    }

    assert!(prepared.body.len() <= MAX_BODY);
    match &req.body_b64 {
        Some(b64) => assert_eq!(&STANDARD.encode(&prepared.body), b64),
        None => assert_eq!(prepared.body, [] as [u8; 0]),
    }
}

fn run(policy: &ApiSecretPolicy, req: &ProxyRequest) {
    match check(policy, req, MAX_BODY) {
        Ok(prepared) => check_prepared(policy, req, &prepared),
        Err(refusal) => {
            let in_name = req.headers.iter().any(|(name, _)| name.contains(SENTINEL));
            assert!(
                in_name || !refusal.to_string().contains(SENTINEL),
                "a refusal repeats a header value"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((select, rest)) = data.split_first() else {
        return;
    };
    let prefix = PREFIXES[usize::from(*select) % PREFIXES.len()];
    let Some(policy) = policy(prefix) else {
        panic!("the fixed policy is valid");
    };

    if let Ok(req) = serde_json::from_slice::<ProxyRequest>(rest) {
        run(&policy, &req);
    }

    let [method, url, body, name1, value1, name2, value2] = fields::<7>(rest);
    let req = ProxyRequest {
        method: text(method).to_owned(),
        url: text(url).to_owned(),
        headers: [(name1, value1), (name2, value2)]
            .into_iter()
            .filter(|(name, _)| !name.is_empty())
            .map(|(name, value)| (text(name).to_owned(), format!("{SENTINEL}{}", text(value))))
            .collect(),
        body_b64: (!body.is_empty()).then(|| text(body).to_owned()),
    };
    run(&policy, &req);
});
