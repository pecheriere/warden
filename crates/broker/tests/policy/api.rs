//! API secret items: parsing, validation and fresh reads.

use serde_json::{Value, json};
use warden_broker::policy::{ApiSecretPolicy, PolicyError, SecretBackend, ValueFormat};
use warden_broker_proto::{SecretName, Window};
use wiremock::MockServer;

use crate::{
    VAULT_ID, backend, connect_mock, ed25519_openssh, fill, list, mount_item, mount_items,
    set_field,
};

const ITEM_API: &str = include_str!("../fixtures/item-api.json");
// A throwaway self-signed CA certificate; its key was discarded.
const THROWAWAY_CA_PEM: &str = include_str!("../fixtures/throwaway-test-only-ca.pem");
const API_ID: &str = "api00000000000000000000g00";
const CREDENTIAL: &str = "test-credential-0123456789abcdef";

/// The grant for the whole policy, with no narrowing.
fn full_grant(policy: &ApiSecretPolicy) -> warden_broker_proto::ApiGrant {
    let methods: Vec<String> = policy
        .methods
        .iter()
        .map(|m| m.as_str().to_owned())
        .collect();
    let scope = policy.scope(Some(&methods), None).unwrap();
    policy.grant_for(&scope)
}

fn secret(name: &str) -> SecretName {
    SecretName::try_from(name.to_owned()).unwrap()
}

/// The `github` API item with its credential filled in.
fn api_item() -> Value {
    fill(ITEM_API, "{{CREDENTIAL}}", CREDENTIAL)
}

/// Mount the item list and `item` as the `github` API item.
async fn api_server(item: &Value) -> MockServer {
    let server = connect_mock().await;
    mount_items(&server, &list()).await;
    mount_item(&server, API_ID, item).await;
    server
}

async fn api_with(item: &Value) -> Result<ApiSecretPolicy, PolicyError> {
    let server = api_server(item).await;
    backend(&server).api_secret(&secret("github")).await
}

#[track_caller]
fn assert_invalid(result: Result<ApiSecretPolicy, PolicyError>, want_field: &str) {
    match result {
        Err(PolicyError::Invalid {
            item,
            field,
            reason,
        }) => {
            assert_eq!(item, "github");
            assert_eq!(field, want_field, "reason: {reason}");
            assert!(!reason.contains(CREDENTIAL), "credential echoed: {reason}");
        }
        Ok(_) => panic!("expected Invalid for {want_field}, got Ok"),
        Err(other) => panic!("expected Invalid for {want_field}, got {other}"),
    }
}

fn with_website(href: &str) -> Value {
    let mut item = api_item();
    item["urls"] = json!([{ "label": "website", "primary": true, "href": href }]);
    item
}

#[tokio::test]
async fn parses_api_secret_with_defaults() {
    let p = api_with(&api_item()).await.unwrap();
    assert_eq!(p.name, secret("github"));
    assert_eq!(p.origin.ascii_serialization(), "https://api.example.com");
    assert_eq!(p.header.as_str(), "authorization");
    assert_eq!(p.format, ValueFormat::default());
    assert_eq!(p.format.prefix(), "Bearer ");
    assert_eq!(p.format.suffix(), "");
    assert_eq!(p.methods, vec![http::Method::GET]);
    assert_eq!(p.path_prefix, "/");
    assert_eq!(p.ca_pem, None);
    assert_eq!(p.max_window, Window::M30);

    let g = full_grant(&p);
    assert_eq!(g.secret, secret("github"));
    assert_eq!(g.origin, "https://api.example.com");
    assert_eq!(g.methods, vec!["GET".to_owned()]);
    assert_eq!(g.path_prefix, "/");
    assert_eq!(g.header, "authorization");

    // Every optional field set explicitly, and a non-default port.
    let mut item = with_website("https://api.example.com:8443/");
    set_field(&mut item, "header", Some("X-Api-Key"));
    set_field(&mut item, "format", Some("token={{secret}};"));
    set_field(&mut item, "methods", Some("GET, POST,DELETE"));
    set_field(&mut item, "path_prefix", Some("/v1/repos/"));
    set_field(&mut item, "ca_pem", Some(THROWAWAY_CA_PEM));
    let p = api_with(&item).await.unwrap();
    assert_eq!(
        p.origin.ascii_serialization(),
        "https://api.example.com:8443"
    );
    assert_eq!(p.header.as_str(), "x-api-key");
    assert_eq!(p.format.prefix(), "token=");
    assert_eq!(p.format.suffix(), ";");
    assert_eq!(p.format.render("abc").as_str(), "token=abc;");
    assert_eq!(
        p.methods,
        vec![http::Method::GET, http::Method::POST, http::Method::DELETE]
    );
    assert_eq!(p.path_prefix, "/v1/repos/");
    assert_eq!(p.ca_pem.as_deref(), Some(THROWAWAY_CA_PEM.trim()));

    // The value comes with the policy, from the same item.
    let server = api_server(&api_item()).await;
    let b = backend(&server);
    let policy = b.api_secret(&secret("github")).await.unwrap();
    let (with_value, value) = b.api_secret_with_value(&secret("github")).await.unwrap();
    assert_eq!(value.expose(), CREDENTIAL);
    assert_eq!(full_grant(&with_value), full_grant(&policy));
}

#[tokio::test]
async fn unknown_or_untagged_api_secret_not_found() {
    let server = api_server(&api_item()).await;
    let b = backend(&server);
    // "pi" exists, but as an SSH target, not as an API secret.
    for name in ["ghost", "pi"] {
        let err = b.api_secret(&secret(name)).await.unwrap_err();
        assert!(
            matches!(&err, PolicyError::UnknownSecret(n) if n == name),
            "{err:?}"
        );
        let err = b.api_secret_with_value(&secret(name)).await.unwrap_err();
        assert!(matches!(&err, PolicyError::UnknownSecret(_)), "{err:?}");
    }
}

#[tokio::test]
async fn website_must_be_bare_https_origin() {
    for good in [
        "https://api.example.com",
        "https://api.example.com/",
        "  https://API.example.com:443  ",
    ] {
        let p = api_with(&with_website(good)).await.unwrap();
        assert_eq!(p.origin.ascii_serialization(), "https://api.example.com");
    }
    for bad in [
        "http://api.example.com",
        "https://api.example.com/v1",
        "https://api.example.com/?",
        "https://api.example.com?x=1",
        "https://api.example.com#top",
        "https://alice@api.example.com",
        "https://alice:pw@api.example.com",
        "api.example.com",
        "https://",
        "",
        "ftp://api.example.com",
    ] {
        assert_invalid(api_with(&with_website(bad)).await, "website");
    }
    // No website at all: never a default.
    let mut item = api_item();
    item.as_object_mut().unwrap().remove("urls");
    assert_invalid(api_with(&item).await, "website");
    item["urls"] = json!([]);
    assert_invalid(api_with(&item).await, "website");
}

#[tokio::test]
async fn website_uses_primary_url_else_first() {
    let mut item = api_item();
    item["urls"] = json!([
        { "label": "docs", "href": "https://docs.example.com" },
        { "label": "website", "primary": true, "href": "https://api.example.com" }
    ]);
    let p = api_with(&item).await.unwrap();
    assert_eq!(p.origin.ascii_serialization(), "https://api.example.com");

    item["urls"] = json!([
        { "href": "https://first.example.com" },
        { "href": "https://second.example.com" }
    ]);
    let p = api_with(&item).await.unwrap();
    assert_eq!(p.origin.ascii_serialization(), "https://first.example.com");
}

#[tokio::test]
async fn format_needs_exactly_one_placeholder() {
    for bad in [
        "Bearer",
        "Bearer {{SECRET}}",
        "{{secret}} {{secret}}",
        "Bearer {secret}",
        "Bearer\t{{secret}}",
        "Bearer\n{{secret}}",
        "Bé {{secret}}",
    ] {
        let mut item = api_item();
        set_field(&mut item, "format", Some(bad));
        assert_invalid(api_with(&item).await, "format");
    }
    let mut item = api_item();
    set_field(&mut item, "format", Some("{{secret}}"));
    let p = api_with(&item).await.unwrap();
    assert_eq!(p.format.render(CREDENTIAL).as_str(), CREDENTIAL);
}

#[tokio::test]
async fn header_must_be_valid_and_not_reserved() {
    for bad in [
        "Bad Header",
        "X-Key:",
        "Host",
        "content-length",
        "Transfer-Encoding",
        "Connection",
        "Proxy-Authorization",
        "TE",
        "Upgrade",
    ] {
        let mut item = api_item();
        set_field(&mut item, "header", Some(bad));
        assert_invalid(api_with(&item).await, "header");
    }
}

#[tokio::test]
async fn methods_parsed_and_uppercase_only() {
    let mut item = api_item();
    set_field(&mut item, "methods", Some(" POST ,GET,POST "));
    let p = api_with(&item).await.unwrap();
    assert_eq!(p.methods, vec![http::Method::POST, http::Method::GET]);
    // The grant lists them sorted, the order the destination digest uses.
    assert_eq!(full_grant(&p).methods, vec!["GET", "POST"]);

    for bad in [
        "get",
        "GET,",
        "GET,,POST",
        "GET POST",
        "Get",
        "GET;POST",
        "GÉT",
    ] {
        let mut item = api_item();
        set_field(&mut item, "methods", Some(bad));
        assert_invalid(api_with(&item).await, "methods");
    }
}

#[tokio::test]
async fn path_prefix_must_start_with_slash() {
    for good in ["/", "/v1", "/v1/", "/repos/alice/x-y_z~1%20"] {
        let mut item = api_item();
        set_field(&mut item, "path_prefix", Some(good));
        assert_eq!(api_with(&item).await.unwrap().path_prefix, good);
    }
    for bad in [
        "v1/",
        "https://api.example.com/v1",
        "/v1?x=1",
        "/v1#frag",
        "/v1/../admin",
        "/./v1",
        "/v1//x",
        "/v 1",
        "/v1\\x",
        "/v1/%2f",
        "/v1/%2E%2e/x",
        "/v1/%5c",
        "/v1;x",
    ] {
        let mut item = api_item();
        set_field(&mut item, "path_prefix", Some(bad));
        assert_invalid(api_with(&item).await, "path_prefix");
    }
}

#[tokio::test]
async fn missing_credential_or_max_window_is_invalid() {
    for label in ["credential", "max_window"] {
        let mut item = api_item();
        set_field(&mut item, label, None);
        assert_invalid(api_with(&item).await, label);

        let mut item = api_item();
        set_field(&mut item, label, Some("   "));
        assert_invalid(api_with(&item).await, label);
    }
    let mut item = api_item();
    set_field(&mut item, "max_window", Some("2h"));
    assert_invalid(api_with(&item).await, "max_window");

    // A required label given twice is ambiguous.
    let mut item = api_item();
    item["fields"].as_array_mut().unwrap().push(
        json!({"id": "dup", "type": "CONCEALED", "label": "credential", "value": "another-credential-value"}),
    );
    assert_invalid(api_with(&item).await, "credential");

    // The value fetch fails the same way.
    let mut item = api_item();
    set_field(&mut item, "max_window", None);
    let server = api_server(&item).await;
    let err = backend(&server)
        .api_secret_with_value(&secret("github"))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, PolicyError::Invalid { field, .. } if field == "max_window"),
        "{err:?}"
    );
}

#[tokio::test]
async fn short_credential_is_invalid() {
    for bad in [
        "short",
        "elevenchars",
        "  elevenchars  ",
        "has\ncontrol-char",
        "nön-ascii-credential",
    ] {
        let mut item = api_item();
        set_field(&mut item, "credential", Some(bad));
        let result = api_with(&item).await;
        if let Err(PolicyError::Invalid { reason, .. }) = &result {
            assert!(!reason.contains(bad.trim()), "value echoed: {reason}");
        }
        assert_invalid(result, "credential");
    }
    // Twelve characters is enough; surrounding whitespace is trimmed.
    let mut item = api_item();
    set_field(&mut item, "credential", Some("  twelve-chars \n"));
    let server = api_server(&item).await;
    let b = backend(&server);
    b.api_secret(&secret("github")).await.unwrap();
    let (_, value) = b.api_secret_with_value(&secret("github")).await.unwrap();
    assert_eq!(value.expose(), "twelve-chars");
}

#[tokio::test]
async fn ca_pem_must_parse() {
    for bad in [
        "not a certificate",
        "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n",
        "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
    ] {
        let mut item = api_item();
        set_field(&mut item, "ca_pem", Some(bad));
        assert_invalid(api_with(&item).await, "ca_pem");
    }
    // A private key is not a certificate.
    let mut item = api_item();
    set_field(&mut item, "ca_pem", Some(&ed25519_openssh()));
    assert_invalid(api_with(&item).await, "ca_pem");

    // Two certificates are accepted, and a blank field means "system roots".
    let mut item = api_item();
    let two = format!("{THROWAWAY_CA_PEM}\n{THROWAWAY_CA_PEM}");
    set_field(&mut item, "ca_pem", Some(&two));
    assert!(api_with(&item).await.unwrap().ca_pem.is_some());
    let mut item = api_item();
    set_field(&mut item, "ca_pem", Some("  "));
    assert_eq!(api_with(&item).await.unwrap().ca_pem, None);
}

#[tokio::test]
async fn value_fetch_does_not_echo_on_decode_error() {
    // The credential's value has the wrong JSON type: serde's own message
    // would quote it.
    let mut item = api_item();
    item["fields"] = json!([
        { "id": "credential", "label": "credential", "value": ["TOP-SECRET-MARKER"] }
    ]);
    let server = api_server(&item).await;
    let b = backend(&server);
    let err = b
        .api_secret_with_value(&secret("github"))
        .await
        .unwrap_err();
    assert!(matches!(err, PolicyError::Unavailable(_)), "{err:?}");
    assert!(!err.to_string().contains("TOP-SECRET-MARKER"), "{err}");
    let err = b.api_secret(&secret("github")).await.unwrap_err();
    assert!(!err.to_string().contains("TOP-SECRET-MARKER"), "{err}");

    let mut item = api_item();
    item["fields"] = json!("TOP-SECRET-MARKER");
    let server = api_server(&item).await;
    let err = backend(&server)
        .api_secret_with_value(&secret("github"))
        .await
        .unwrap_err();
    assert!(matches!(err, PolicyError::Unavailable(_)), "{err:?}");
    assert!(!err.to_string().contains("TOP-SECRET-MARKER"), "{err}");
}

#[tokio::test]
async fn api_secret_debug_redacted() {
    let server = api_server(&api_item()).await;
    let b = backend(&server);
    let (policy, value) = b.api_secret_with_value(&secret("github")).await.unwrap();
    assert_eq!(format!("{value:?}"), "SecretValue(<redacted>)");
    let shown = format!("{policy:?} {:?}", full_grant(&policy));
    assert!(!shown.contains(CREDENTIAL), "{shown}");
    assert!(!shown.contains("test-credential"), "{shown}");
}

#[tokio::test]
async fn api_secret_reads_fresh_item_every_time() {
    let server = api_server(&api_item()).await;
    let b = backend(&server);
    let item_fetches = || async {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == format!("/v1/vaults/{VAULT_ID}/items/{API_ID}"))
            .count()
    };
    b.api_secret(&secret("github")).await.unwrap();
    assert_eq!(item_fetches().await, 1);
    b.api_secret(&secret("github")).await.unwrap();
    assert_eq!(item_fetches().await, 2);
    // Policy and value come from a single fetch of the item.
    b.api_secret_with_value(&secret("github")).await.unwrap();
    assert_eq!(item_fetches().await, 3);
}

#[tokio::test]
async fn duplicate_api_secret_titles_are_invalid() {
    let server = connect_mock().await;
    let mut items = list();
    let mut dup = items
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == API_ID)
        .unwrap()
        .clone();
    dup["id"] = json!("api2000000000000000000dup0");
    items.as_array_mut().unwrap().push(dup);
    mount_items(&server, &items).await;
    let err = backend(&server)
        .api_secret(&secret("github"))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, PolicyError::Invalid { item, field, .. } if item == "github" && field == "title"),
        "{err:?}"
    );
}

#[tokio::test]
async fn fake_backend_serves_api_secrets() {
    let fake = warden_broker::testkit::FakeBackend::new();
    let err = fake.api_secret(&secret("github")).await.unwrap_err();
    assert!(matches!(err, PolicyError::UnknownSecret(_)), "{err:?}");

    let policy = warden_broker::testkit::FakeBackend::example_api_secret();
    fake.set_api_secret(policy.clone(), CREDENTIAL);
    let got = fake.api_secret(&secret("github")).await.unwrap();
    assert_eq!(got.destination_digest(), policy.destination_digest());
    assert_eq!(full_grant(&got), full_grant(&policy));
    let (with_value, value) = fake.api_secret_with_value(&secret("github")).await.unwrap();
    assert_eq!(full_grant(&with_value), full_grant(&policy));
    assert_eq!(value.expose(), CREDENTIAL);

    // Rotation replaces the value.
    fake.set_api_secret(policy, "rotated-credential-value");
    let (_, value) = fake.api_secret_with_value(&secret("github")).await.unwrap();
    assert_eq!(value.expose(), "rotated-credential-value");
}
