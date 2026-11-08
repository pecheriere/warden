//! Unit tests for API secret policies, scopes and value formats.

use http::{HeaderName, Method};
use url::Url;
use warden_broker_proto::{ApiGrant, SecretName, Window};

use super::{ApiScope, ApiSecretPolicy, ValueFormat};

fn api(origin: &str, prefix: &str, methods: &[Method], header: &str) -> ApiSecretPolicy {
    ApiSecretPolicy {
        name: SecretName::try_from("github".to_owned()).unwrap(),
        origin: Url::parse(origin).unwrap().origin(),
        header: HeaderName::from_bytes(header.as_bytes()).unwrap(),
        format: ValueFormat::default(),
        methods: methods.to_vec(),
        path_prefix: prefix.to_owned(),
        ca_pem: None,
        max_window: Window::H1,
    }
}

#[test]
fn digest_changes_with_origin_prefix_methods_header_not_with_value() {
    let get = [Method::GET];
    let base = api("https://api.example.com", "/v1/", &get, "authorization");
    let digest = base.destination_digest();
    assert_eq!(digest.len(), 64);

    // Where the secret goes, and how, is covered.
    for other in [
        api("https://api2.example.com", "/v1/", &get, "authorization"),
        api(
            "https://api.example.com:8443",
            "/v1/",
            &get,
            "authorization",
        ),
        api("https://api.example.com", "/v2/", &get, "authorization"),
        api("https://api.example.com", "/", &get, "authorization"),
        api(
            "https://api.example.com",
            "/v1/",
            &[Method::POST],
            "authorization",
        ),
        api(
            "https://api.example.com",
            "/v1/",
            &[Method::GET, Method::POST],
            "authorization",
        ),
        api("https://api.example.com", "/v1/", &get, "x-api-key"),
    ] {
        assert_ne!(digest, other.destination_digest(), "{other:?}");
    }
    let mut formatted = base.clone();
    formatted.format = ValueFormat::parse("token {{secret}}").unwrap();
    assert_ne!(digest, formatted.destination_digest());
    let mut pinned = base.clone();
    pinned.ca_pem = Some("-----BEGIN CERTIFICATE-----".to_owned());
    assert_ne!(digest, pinned.destination_digest());

    // Method order and the window are not; the value is not even part of
    // the policy, so rotating the credential keeps the digest.
    let both = api(
        "https://api.example.com",
        "/v1/",
        &[Method::GET, Method::POST],
        "authorization",
    );
    let reversed = api(
        "https://api.example.com",
        "/v1/",
        &[Method::POST, Method::GET],
        "authorization",
    );
    assert_eq!(both.destination_digest(), reversed.destination_digest());
    let mut longer = base.clone();
    longer.max_window = Window::H4;
    assert_eq!(digest, longer.destination_digest());
    assert_eq!(
        digest,
        api("https://api.example.com", "/v1/", &get, "Authorization").destination_digest()
    );
}

#[test]
fn grant_sorts_methods_and_carries_digest() {
    let post_get = api(
        "https://api.example.com",
        "/v1/",
        &[Method::POST, Method::GET],
        "authorization",
    );
    let grant = full_grant(&post_get);
    assert_eq!(grant.methods, ["GET", "POST"]);
    assert_eq!(grant.digest, post_get.destination_digest());

    // Equal grants exactly when the destination is the same: a change
    // the other grant fields do not show (format, CA) still differs.
    let mut get_post = post_get.clone();
    get_post.methods.reverse();
    assert_eq!(full_grant(&get_post), grant);
    let mut formatted = post_get.clone();
    formatted.format = ValueFormat::parse("token {{secret}}").unwrap();
    assert_ne!(full_grant(&formatted), grant);
    let mut pinned = post_get;
    pinned.ca_pem = Some("-----BEGIN CERTIFICATE-----".to_owned());
    assert_ne!(full_grant(&pinned), grant);
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

fn item(prefix: &str, methods: &[Method]) -> ApiSecretPolicy {
    api("https://api.example.com", prefix, methods, "authorization")
}

fn full_grant(policy: &ApiSecretPolicy) -> ApiGrant {
    policy.grant_for(&ApiScope {
        methods: policy.methods.clone(),
        path_prefix: policy.path_prefix.clone(),
    })
}

#[test]
fn scope_from_stored_grant_rejects_invalid_methods() {
    let item = item("/v1/", &[Method::POST, Method::GET]);
    let grant = full_grant(&item);
    let scope = ApiScope::try_from(&grant).unwrap();
    assert_eq!(names(&scope), ["GET", "POST"]);
    assert_eq!(scope.path_prefix(), "/v1/");

    let mut damaged = grant;
    damaged.methods.push("get it".to_owned());
    assert!(ApiScope::try_from(&damaged).is_err());
}

fn names(scope: &ApiScope) -> Vec<&str> {
    scope.methods.iter().map(Method::as_str).collect()
}

#[test]
fn empty_scope_is_never_labelled_read_only() {
    let empty = ApiScope {
        methods: Vec::new(),
        path_prefix: "/".to_owned(),
    };
    assert!(!empty.is_read_only());
    assert_eq!(
        empty.subject("github"),
        "api github (CAN MODIFY: unverified scope)"
    );
    let get = ApiScope {
        methods: vec![Method::GET],
        path_prefix: "/".to_owned(),
    };
    assert!(get.is_read_only());
    assert_eq!(get.subject("github"), "api github (read-only)");
}

#[test]
fn default_scope_is_read_only_subset() {
    let both = item(
        "/v1/",
        &[Method::POST, Method::HEAD, Method::GET, Method::DELETE],
    );
    let scope = both.scope(None, None).unwrap();
    assert_eq!(names(&scope), ["GET", "HEAD"]);
    assert_eq!(scope.path_prefix(), "/v1/");

    let get = item("/", &[Method::GET, Method::POST]);
    assert_eq!(names(&get.scope(None, None).unwrap()), ["GET"]);
}

#[test]
fn no_read_only_method_rejected() {
    let writes = item("/", &[Method::POST, Method::PUT]);
    assert_eq!(
        writes.scope(None, None).unwrap_err(),
        "secret github allows no read-only method; ask for methods explicitly"
    );
    // Asking explicitly works.
    let scope = writes.scope(Some(&strings(&["PUT"])), None).unwrap();
    assert_eq!(names(&scope), ["PUT"]);
}

#[test]
fn explicit_methods_must_be_in_item() {
    let p = item("/", &[Method::GET, Method::POST]);
    let scope = p.scope(Some(&strings(&["POST", "GET"])), None).unwrap();
    assert_eq!(names(&scope), ["GET", "POST"]);
    assert_eq!(
        p.scope(Some(&strings(&["GET", "DELETE"])), None)
            .unwrap_err(),
        "secret github does not allow DELETE"
    );
    for bad in [
        strings(&[]),
        strings(&["GET", "GET"]),
        strings(&["get"]),
        strings(&["GET,POST"]),
        strings(&[""]),
        strings(&[" GET"]),
        strings(&["GET "]),
    ] {
        let err = p.scope(Some(&bad), None).unwrap_err();
        assert!(err.starts_with("secret github: methods "), "{bad:?}: {err}");
    }
}

#[test]
fn method_count_limit_is_eight() {
    let nine = [
        "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "LINK", "UNLINK",
    ];
    let methods: Vec<Method> = nine
        .iter()
        .map(|m| Method::from_bytes(m.as_bytes()).unwrap())
        .collect();
    let p = item("/", &methods);
    let eight = strings(&nine[..8]);
    assert_eq!(p.scope(Some(&eight), None).unwrap().methods.len(), 8);
    assert_eq!(
        p.scope(Some(&strings(&nine)), None).unwrap_err(),
        "secret github: methods must list 1 to 8 methods"
    );
}

#[test]
fn requested_prefix_is_capped_at_512_bytes() {
    let p = item("/", &[Method::GET]);
    let at_cap = format!("/{}", "a".repeat(511));
    let over = format!("/{}", "a".repeat(512));
    assert_eq!(p.scope(None, Some(&at_cap)).unwrap().path_prefix(), at_cap);
    assert_eq!(
        p.scope(None, Some(&over)).unwrap_err(),
        "secret github: path prefix is too long (at most 512 bytes)"
    );
}

#[test]
fn connect_trace_never_requestable() {
    let p = item("/", &[Method::GET, Method::CONNECT, Method::TRACE]);
    for denied in ["CONNECT", "TRACE"] {
        assert_eq!(
            p.scope(Some(&strings(&["GET", denied])), None).unwrap_err(),
            format!("secret github does not allow {denied}")
        );
    }
    // The default scope never picks them either.
    assert_eq!(names(&p.scope(None, None).unwrap()), ["GET"]);
}

#[test]
fn requested_prefix_must_be_under_item_prefix() {
    let under = |item_prefix: &str, wanted: &str| {
        item(item_prefix, &[Method::GET]).scope(None, Some(wanted))
    };
    assert_eq!(under("/api", "/api/x").unwrap().path_prefix, "/api/x");
    assert_eq!(under("/api", "/api").unwrap().path_prefix, "/api");
    assert_eq!(under("/", "/anything/").unwrap().path_prefix, "/anything/");
    assert_eq!(
        item("/api/", &[Method::GET])
            .scope(None, None)
            .unwrap()
            .path_prefix,
        "/api/"
    );
    assert_eq!(
        under("/api", "/apiary").unwrap_err(),
        "secret github: path prefix must be under /api"
    );
    assert_eq!(
        under("/api/", "/api").unwrap_err(),
        "secret github: path prefix must be under /api/"
    );
    for bad in [
        "/api/../x",
        "/api/./x",
        "/api//x",
        "/api/%2e%2e/x",
        "/api/%2E/x",
        "/api/%2f",
        "/api/%5c",
        "/api/%5C",
        "/api/x;y",
        "/api/x?y",
        "api/x",
        "",
    ] {
        let err = under("/api/", bad).unwrap_err();
        assert!(
            err.starts_with("secret github: path prefix "),
            "{bad}: {err}"
        );
    }
}

#[test]
fn narrowed_and_grant_for_use_scope_and_item_digest() {
    let p = item("/v1/", &[Method::GET, Method::POST, Method::HEAD]);
    let scope = p.scope(None, Some("/v1/repos")).unwrap();
    let narrowed = p.narrowed(&scope);
    assert_eq!(narrowed.methods, scope.methods);
    assert_eq!(narrowed.path_prefix, "/v1/repos");
    assert_eq!(narrowed.origin, p.origin);
    assert_eq!(narrowed.header, p.header);
    assert_eq!(narrowed.name, p.name);

    let grant = p.grant_for(&scope);
    assert_eq!(grant.methods, ["GET", "HEAD"]);
    assert_eq!(grant.path_prefix, "/v1/repos");
    // The digest is the item's, not the narrowed policy's.
    assert_eq!(grant.digest, p.destination_digest());
    assert_ne!(grant.digest, narrowed.destination_digest());
}

#[test]
fn value_format_parse_and_render() {
    let f = ValueFormat::parse("Basic {{secret}}").unwrap();
    assert_eq!(f.render("abc").as_str(), "Basic abc");
    assert_eq!(ValueFormat::default().render("abc").as_str(), "Bearer abc");
    assert!(ValueFormat::parse("no placeholder").is_err());
    assert!(ValueFormat::parse("{{secret}}{{secret}}").is_err());
    assert!(ValueFormat::parse("x\r\n{{secret}}").is_err());
    assert!(ValueFormat::parse("{{secret}}\0").is_err());
}
