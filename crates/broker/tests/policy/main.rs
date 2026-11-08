//! Policy from 1Password Connect, against a wiremock Connect server.

use secrecy::SecretString;
use serde_json::{Value, json};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use url::Url;
use warden_broker::policy::OnePasswordConnect;
use warden_broker_proto::TargetName;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

mod api;
mod ca;
mod connect;
mod relay;
mod targets;

const TOKEN: &str = "eyJ-test-connect-token-do-not-leak";
const VAULT_ID: &str = "vault0000000000000000000a1";

const VAULTS: &str = include_str!("../fixtures/vaults.json");
const ITEMS: &str = include_str!("../fixtures/items.json");
const ITEM_PI: &str = include_str!("../fixtures/item-pi.json");
const ITEM_NAS: &str = include_str!("../fixtures/item-nas.json");
const ITEM_NOUSERS: &str = include_str!("../fixtures/item-nousers.json");
const ITEM_BADMODE: &str = include_str!("../fixtures/item-badmode.json");
const ITEM_CA: &str = include_str!("../fixtures/item-ca.json");
// Throwaway keys generated only for these tests; they protect nothing.
const THROWAWAY_RSA: &str = include_str!("../fixtures/throwaway-test-only-rsa.key");
const THROWAWAY_ENCRYPTED: &str =
    include_str!("../fixtures/throwaway-test-only-ed25519-encrypted.key");
const THROWAWAY_ECDSA: &str = include_str!("../fixtures/throwaway-test-only-ecdsa.key");
const THROWAWAY_RSA_PKCS8: &str = include_str!("../fixtures/throwaway-test-only-rsa-pkcs8.key");
const THROWAWAY_ECDSA_PKCS8: &str = include_str!("../fixtures/throwaway-test-only-ecdsa-pkcs8.key");

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
