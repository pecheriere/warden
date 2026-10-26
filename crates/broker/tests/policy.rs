//! Policy from 1Password Connect, against a wiremock Connect server.

use secrecy::SecretString;
use serde_json::{Value, json};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use url::Url;
use warden_broker::policy::{OnePasswordConnect, PolicyError, SecretBackend, SshMode};
use warden_broker_proto::{TargetName, UnixUser, Window};
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
    let server = MockServer::start().await;
    let backend = backend(&server);
    drop(server);
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
