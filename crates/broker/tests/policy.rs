//! Policy from 1Password Connect, against a wiremock Connect server.

use secrecy::SecretString;
use serde_json::{Value, json};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use url::Url;
use warden_broker::policy::{
    ApiSecretPolicy, OnePasswordConnect, PolicyError, SecretBackend, SshMode, ValueFormat,
};
use warden_broker_proto::{SecretName, TargetName, UnixUser, Window};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "eyJ-test-connect-token-do-not-leak";
const VAULT_ID: &str = "vault0000000000000000000a1";

const VAULTS: &str = include_str!("fixtures/vaults.json");
const ITEMS: &str = include_str!("fixtures/items.json");
const ITEM_PI: &str = include_str!("fixtures/item-pi.json");
const ITEM_NAS: &str = include_str!("fixtures/item-nas.json");
const ITEM_NOUSERS: &str = include_str!("fixtures/item-nousers.json");
const ITEM_BADMODE: &str = include_str!("fixtures/item-badmode.json");
const ITEM_CA: &str = include_str!("fixtures/item-ca.json");
// Throwaway keys generated only for these tests; they protect nothing.
const THROWAWAY_RSA: &str = include_str!("fixtures/throwaway-test-only-rsa.key");
const THROWAWAY_ENCRYPTED: &str =
    include_str!("fixtures/throwaway-test-only-ed25519-encrypted.key");
const THROWAWAY_ECDSA: &str = include_str!("fixtures/throwaway-test-only-ecdsa.key");

fn target(name: &str) -> TargetName {
    TargetName::try_from(name.to_owned()).unwrap()
}

fn host_key_line() -> String {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap()
}

/// Fill the `{{HOST_KEY}}` / `{{PRIVATE_KEY}}` placeholders, JSON-escaping.
fn fill(template: &str, placeholder: &str, value: &str) -> Value {
    let escaped = serde_json::to_string(value).unwrap();
    let escaped = &escaped[1..escaped.len() - 1];
    serde_json::from_str(&template.replace(placeholder, escaped)).unwrap()
}

fn ed25519_openssh() -> String {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .unwrap()
        .to_openssh(LineEnding::LF)
        .unwrap()
        .to_string()
}

async fn connect_mock() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/vaults"))
        .and(query_param("filter", r#"name eq "Warden""#))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_string(VAULTS))
        .mount(&server)
        .await;
    server
}

async fn mount_items(server: &MockServer, list: &Value) {
    Mock::given(method("GET"))
        .and(path(format!("/v1/vaults/{VAULT_ID}/items")))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(list))
        .mount(server)
        .await;
}

async fn mount_item(server: &MockServer, id: &str, body: &Value) {
    Mock::given(method("GET"))
        .and(path(format!("/v1/vaults/{VAULT_ID}/items/{id}")))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

fn backend(server: &MockServer) -> OnePasswordConnect {
    OnePasswordConnect::new(
        Url::parse(&server.uri()).unwrap(),
        SecretString::from(TOKEN.to_owned()),
        "Warden".to_owned(),
    )
}

fn list() -> Value {
    serde_json::from_str(ITEMS).unwrap()
}

async fn with_targets() -> MockServer {
    let server = connect_mock().await;
    mount_items(&server, &list()).await;
    let key = host_key_line();
    for (id, body) in [
        ("pi00000000000000000000000a", ITEM_PI),
        ("nas0000000000000000000000b", ITEM_NAS),
        ("nousers000000000000000000c", ITEM_NOUSERS),
        ("badmode00000000000000000d0", ITEM_BADMODE),
    ] {
        mount_item(&server, id, &fill(body, "{{HOST_KEY}}", &key)).await;
    }
    server
}

/// A list with only CA summaries, given their ids.
fn ca_list(ids: &[&str]) -> Value {
    Value::Array(
        ids.iter()
            .map(|id| {
                json!({
                    "id": id, "title": format!("ca-{id}"), "category": "SSH_KEY",
                    "vault": {"id": VAULT_ID}, "tags": ["warden:ssh-ca"]
                })
            })
            .collect(),
    )
}

fn ca_item(id: &str, private_key: &str) -> Value {
    let mut item = fill(ITEM_CA, "{{PRIVATE_KEY}}", private_key);
    item["id"] = json!(id);
    item["title"] = json!(format!("ca-{id}"));
    item
}

async fn ca_with(key_text: &str) -> Result<warden_broker::policy::CaKey, PolicyError> {
    let server = connect_mock().await;
    mount_items(&server, &ca_list(&["ca1"])).await;
    mount_item(&server, "ca1", &ca_item("ca1", key_text)).await;
    backend(&server).ssh_ca().await
}

#[tokio::test]
async fn parses_valid_cert_target() {
    let server = with_targets().await;
    let t = backend(&server).ssh_target(&target("pi")).await.unwrap();
    assert_eq!(t.name, target("pi"));
    assert_eq!(t.host, "192.0.2.10");
    assert_eq!(t.port, 22);
    assert_eq!(t.mode, SshMode::Cert);
    assert_eq!(
        t.users,
        vec![
            UnixUser::try_from("alice".to_owned()).unwrap(),
            UnixUser::try_from("admin".to_owned()).unwrap()
        ]
    );
    assert_eq!(t.max_window, Window::H1);
    assert_eq!(t.host_keys.len(), 1);
}

#[tokio::test]
async fn parses_host_port() {
    let server = with_targets().await;
    let t = backend(&server).ssh_target(&target("nas")).await.unwrap();
    assert_eq!(t.host, "nas.lan");
    assert_eq!(t.port, 2222);
    assert_eq!(t.mode, SshMode::Relay);
}

#[tokio::test]
async fn missing_users_field_is_invalid_with_names() {
    let server = with_targets().await;
    let err = backend(&server)
        .ssh_target(&target("nousers"))
        .await
        .unwrap_err();
    match &err {
        PolicyError::Invalid { item, field, .. } => {
            assert_eq!(item, "nousers");
            assert_eq!(field, "users");
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
    let text = err.to_string();
    assert!(text.contains("nousers") && text.contains("users"), "{text}");
}

#[tokio::test]
async fn bad_mode_is_invalid() {
    let server = with_targets().await;
    let err = backend(&server)
        .ssh_target(&target("badmode"))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, PolicyError::Invalid { item, field, .. } if item == "badmode" && field == "mode"),
        "{err:?}"
    );
}

#[tokio::test]
async fn unknown_target_not_found() {
    let server = with_targets().await;
    let err = backend(&server)
        .ssh_target(&target("ghost"))
        .await
        .unwrap_err();
    assert!(matches!(err, PolicyError::NotFound(_)), "{err:?}");
}

#[tokio::test]
async fn untagged_item_is_not_a_target() {
    // The fixture list holds an untagged LOGIN item that is also titled "pi";
    // only the tagged SERVER item may be returned.
    let server = with_targets().await;
    let t = backend(&server).ssh_target(&target("pi")).await.unwrap();
    assert_eq!(t.port, 22);
}

#[tokio::test]
async fn invalid_host_key_is_invalid() {
    let server = connect_mock().await;
    mount_items(&server, &list()).await;
    mount_item(
        &server,
        "pi00000000000000000000000a",
        &fill(ITEM_PI, "{{HOST_KEY}}", "not a key"),
    )
    .await;
    let err = backend(&server)
        .ssh_target(&target("pi"))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, PolicyError::Invalid { field, .. } if field == "host_keys"),
        "{err:?}"
    );
}

#[tokio::test]
async fn host_keys_accept_rsa_and_ecdsa_public_keys() {
    let rsa_pub = PrivateKey::from_openssh(THROWAWAY_RSA)
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap();
    let ecdsa_pub = PrivateKey::from_openssh(THROWAWAY_ECDSA)
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap();
    let server = connect_mock().await;
    mount_items(&server, &list()).await;
    mount_item(
        &server,
        "pi00000000000000000000000a",
        &fill(
            ITEM_PI,
            "{{HOST_KEY}}",
            &format!("{rsa_pub}\n\n{ecdsa_pub}\n"),
        ),
    )
    .await;
    let t = backend(&server).ssh_target(&target("pi")).await.unwrap();
    assert_eq!(t.host_keys.len(), 2);
}

#[tokio::test]
async fn ca_requires_exactly_one_item() {
    let none = connect_mock().await;
    mount_items(&none, &ca_list(&[])).await;
    let err = backend(&none).ssh_ca().await.unwrap_err();
    assert!(matches!(err, PolicyError::Ca(_)), "{err:?}");

    let two = connect_mock().await;
    mount_items(&two, &ca_list(&["ca1", "ca2"])).await;
    let err = backend(&two).ssh_ca().await.unwrap_err();
    assert!(matches!(err, PolicyError::Ca(_)), "{err:?}");

    let one = connect_mock().await;
    mount_items(&one, &ca_list(&["ca1"])).await;
    mount_item(&one, "ca1", &ca_item("ca1", &ed25519_openssh())).await;
    assert!(backend(&one).ssh_ca().await.is_ok());
}

#[tokio::test]
async fn ca_accepts_openssh_and_pkcs8_ed25519() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let openssh = key.to_openssh(LineEnding::LF).unwrap().to_string();
    let ca = ca_with(&openssh).await.unwrap();
    assert_eq!(ca.public_key(), key.public_key());

    let keypair = key.key_data().ed25519().unwrap();
    let signing = ed25519_dalek::SigningKey::from_bytes(&keypair.private.to_bytes());
    let pkcs8 = ed25519_dalek::pkcs8::EncodePrivateKey::to_pkcs8_pem(
        &signing,
        ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF,
    )
    .unwrap();
    let ca = ca_with(&pkcs8).await.unwrap();
    assert_eq!(ca.public_key(), key.public_key());
}

#[tokio::test]
async fn ca_rejects_non_ed25519_key() {
    for (name, text) in [("rsa", THROWAWAY_RSA), ("ecdsa", THROWAWAY_ECDSA)] {
        let err = ca_with(text).await.unwrap_err();
        match &err {
            PolicyError::Ca(msg) => {
                assert!(msg.contains("ca-ca1"), "{name}: {msg}");
                assert!(msg.contains("Ed25519"), "{name}: {msg}");
            }
            other => panic!("{name}: expected Ca, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn ca_rejects_garbage_and_missing_private_key() {
    let err = ca_with("not a key").await.unwrap_err();
    assert!(
        matches!(&err, PolicyError::Ca(m) if m.contains("ca-ca1")),
        "{err:?}"
    );

    let server = connect_mock().await;
    mount_items(&server, &ca_list(&["ca1"])).await;
    let mut item = ca_item("ca1", "x");
    item["fields"] = json!([]);
    mount_item(&server, "ca1", &item).await;
    let err = backend(&server).ssh_ca().await.unwrap_err();
    assert!(
        matches!(&err, PolicyError::Ca(m) if m.contains("ca-ca1")),
        "{err:?}"
    );
}

#[tokio::test]
async fn ca_debug_is_redacted() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let ca = ca_with(&key.to_openssh(LineEnding::LF).unwrap())
        .await
        .unwrap();
    assert_eq!(format!("{ca:?}"), "CaKey(<redacted>)");
}

#[tokio::test]
async fn connect_500_is_unavailable() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500).set_body_string(format!("boom {TOKEN}")))
        .mount(&server)
        .await;
    let err = backend(&server)
        .ssh_target(&target("pi"))
        .await
        .unwrap_err();
    assert!(matches!(&err, PolicyError::Unavailable(_)), "{err:?}");
    assert!(!err.to_string().contains(TOKEN), "token leaked: {err}");
}

#[tokio::test]
async fn connection_refused_is_unavailable_without_token() {
    // A port that was just free and has no listener. (A dropped MockServer
    // would not do: wiremock pools servers, so another test may answer.)
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let backend = OnePasswordConnect::new(
        Url::parse(&format!("http://{addr}")).unwrap(),
        SecretString::from(TOKEN.to_owned()),
        "Warden".to_owned(),
    );
    let err = backend.ssh_target(&target("pi")).await.unwrap_err();
    assert!(matches!(&err, PolicyError::Unavailable(_)), "{err:?}");
    assert!(!err.to_string().contains(TOKEN));
}

#[tokio::test]
async fn unknown_vault_is_unavailable() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/vaults"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    let err = backend(&server)
        .ssh_target(&target("pi"))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, PolicyError::Unavailable(m) if m.contains("Warden")),
        "{err:?}"
    );
}

#[tokio::test]
async fn sends_bearer_token() {
    // The mocks only match when the Authorization header carries the token;
    // an unmatched request would be a 404 and surface as Unavailable.
    let server = with_targets().await;
    backend(&server).ssh_target(&target("pi")).await.unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 3, "vault lookup, item list, item fetch");
    for r in requests {
        assert_eq!(
            r.headers.get("authorization").unwrap().to_str().unwrap(),
            format!("Bearer {TOKEN}")
        );
    }
}

#[tokio::test]
async fn vault_id_is_cached_but_items_are_fresh() {
    let server = with_targets().await;
    let b = backend(&server);
    b.ssh_target(&target("pi")).await.unwrap();
    b.ssh_target(&target("pi")).await.unwrap();
    let requests = server.received_requests().await.unwrap();
    let vault_lookups = requests
        .iter()
        .filter(|r| r.url.path() == "/v1/vaults")
        .count();
    assert_eq!(vault_lookups, 1);
    assert_eq!(requests.len(), 5);
}

#[tokio::test]
async fn duplicate_target_titles_are_invalid() {
    let server = connect_mock().await;
    let mut items = list();
    let mut dup = items[0].clone();
    dup["id"] = json!("pi2000000000000000000000dup");
    items.as_array_mut().unwrap().push(dup);
    mount_items(&server, &items).await;
    let err = backend(&server)
        .ssh_target(&target("pi"))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, PolicyError::Invalid { item, field, .. } if item == "pi" && field == "title"),
        "{err:?}"
    );
}

#[tokio::test]
async fn duplicate_required_label_is_invalid() {
    let server = connect_mock().await;
    mount_items(&server, &list()).await;
    let mut item = fill(ITEM_PI, "{{HOST_KEY}}", &host_key_line());
    item["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "dup", "type": "STRING", "label": "users", "value": "root"}));
    mount_item(&server, "pi00000000000000000000000a", &item).await;
    let err = backend(&server)
        .ssh_target(&target("pi"))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, PolicyError::Invalid { item, field, .. } if item == "pi" && field == "users"),
        "{err:?}"
    );
}

#[tokio::test]
async fn encrypted_ca_key_is_rejected() {
    let err = ca_with(THROWAWAY_ENCRYPTED).await.unwrap_err();
    assert!(
        matches!(&err, PolicyError::Ca(m) if m.contains("ca-ca1")),
        "{err:?}"
    );
}

#[tokio::test]
async fn ca_decode_error_does_not_echo_values() {
    let server = connect_mock().await;
    mount_items(&server, &ca_list(&["ca1"])).await;
    let mut item = ca_item("ca1", "x");
    // serde's own message for this shape would quote the string.
    item["fields"] = json!("TOP-SECRET-MARKER");
    mount_item(&server, "ca1", &item).await;
    let err = backend(&server).ssh_ca().await.unwrap_err();
    assert!(matches!(err, PolicyError::Ca(_)), "{err:?}");
    assert!(!err.to_string().contains("TOP-SECRET-MARKER"), "{err}");
}

#[tokio::test]
async fn undecodable_target_item_does_not_echo_its_content() {
    let server = connect_mock().await;
    mount_items(&server, &list()).await;
    // A field list that is a string: serde would quote it in its error.
    mount_item(
        &server,
        "pi00000000000000000000000a",
        &json!({"title": "pi", "fields": "s3cr3t-field-value"}),
    )
    .await;
    let err = backend(&server)
        .ssh_target(&target("pi"))
        .await
        .unwrap_err();
    assert!(matches!(&err, PolicyError::Unavailable(_)), "{err:?}");
    assert!(!err.to_string().contains("s3cr3t"), "value echoed: {err}");
}

// --- API secrets -------------------------------------------------------------

const ITEM_API: &str = include_str!("fixtures/item-api.json");
// A throwaway self-signed CA certificate; its key was discarded.
const THROWAWAY_CA_PEM: &str = include_str!("fixtures/throwaway-test-only-ca.pem");
const API_ID: &str = "api00000000000000000000g00";
const CREDENTIAL: &str = "test-credential-0123456789abcdef";

fn secret(name: &str) -> SecretName {
    SecretName::try_from(name.to_owned()).unwrap()
}

/// The `github` API item with its credential filled in.
fn api_item() -> Value {
    fill(ITEM_API, "{{CREDENTIAL}}", CREDENTIAL)
}

/// Set (or with `None`, remove) the field labelled `label`.
fn set_field(item: &mut Value, label: &str, value: Option<&str>) {
    let fields = item["fields"].as_array_mut().unwrap();
    fields.retain(|f| f["label"] != label);
    if let Some(value) = value {
        fields.push(json!({
            "id": format!("f-{label}"), "type": "STRING", "label": label, "value": value
        }));
    }
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
        other => panic!("expected Invalid for {want_field}, got {other:?}"),
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

    let g = p.grant();
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
    assert_eq!(with_value.grant(), policy.grant());
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
    assert_eq!(p.grant().methods, vec!["GET", "POST"]);

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
    let shown = format!("{policy:?} {:?}", policy.grant());
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
    assert_eq!(got.grant(), policy.grant());
    let (with_value, value) = fake.api_secret_with_value(&secret("github")).await.unwrap();
    assert_eq!(with_value.grant(), policy.grant());
    assert_eq!(value.expose(), CREDENTIAL);

    // Rotation replaces the value.
    fake.set_api_secret(policy, "rotated-credential-value");
    let (_, value) = fake.api_secret_with_value(&secret("github")).await.unwrap();
    assert_eq!(value.expose(), "rotated-credential-value");
}
