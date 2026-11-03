//! What 1Password Connect must not be able to do to the broker, and what the
//! broker must not ask it: names and ids that would change a query or a path are
//! refused rather than sent, and an item with no host key is no target.

use secrecy::SecretString;
use serde_json::{Value, json};
use url::Url;
use warden_broker::policy::{OnePasswordConnect, PolicyError, SecretBackend};
use warden_broker_proto::TargetName;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VAULT_ID: &str = "vault0000000000000000000a1";
const ITEM_ID: &str = "pi00000000000000000000000a";
const ITEMS: &str = include_str!("fixtures/items.json");
const ITEM_PI: &str = include_str!("fixtures/item-pi.json");

fn backend(server: &MockServer, vault: &str) -> OnePasswordConnect {
    OnePasswordConnect::new(
        Url::parse(&server.uri()).unwrap(),
        SecretString::from("test-connect-token".to_owned()),
        vault.to_owned(),
    )
}

fn pi() -> TargetName {
    TargetName::try_from("pi".to_owned()).unwrap()
}

async fn answer(server: &MockServer, at: String, body: Value) {
    Mock::given(method("GET"))
        .and(path(at))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn serve_vaults(server: &MockServer, id: &str) {
    let vaults = json!([{"id": id, "name": "Warden"}]);
    answer(server, "/v1/vaults".to_owned(), vaults).await;
}

fn assert_unavailable(result: Result<impl std::fmt::Debug, PolicyError>, want: &str) {
    match result {
        Err(PolicyError::Unavailable(message)) => assert!(message.contains(want), "{message}"),
        other => panic!("expected unavailable, got {other:?}"),
    }
}

/// The vault's name goes into a filter expression, where a quote would end it.
#[tokio::test]
async fn a_vault_name_that_would_change_the_filter_is_never_sent() {
    let server = MockServer::start().await;
    let result = backend(&server, r#"Warden" or name pr or name eq "x"#)
        .ssh_target(&pi())
        .await;
    assert_unavailable(result, "unsupported characters");
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

/// Ids from Connect become part of later URLs, so one that would change the
/// path stops there.
#[tokio::test]
async fn a_vault_id_that_would_change_the_path_is_never_followed() {
    let server = MockServer::start().await;
    serve_vaults(&server, "../../v1/other").await;
    let result = backend(&server, "Warden").ssh_target(&pi()).await;
    assert_unavailable(result, "malformed id");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn an_item_id_that_would_change_the_path_is_never_followed() {
    let server = MockServer::start().await;
    serve_vaults(&server, VAULT_ID).await;
    let mut items: Value = serde_json::from_str(ITEMS).unwrap();
    items[0]["id"] = json!("../other");
    answer(&server, format!("/v1/vaults/{VAULT_ID}/items"), items).await;
    let result = backend(&server, "Warden").ssh_target(&pi()).await;
    assert_unavailable(result, "malformed id");
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

/// With nothing to pin there is no way to tell the target from an impostor.
#[tokio::test]
async fn a_target_with_no_host_keys_listed_is_invalid() {
    let server = MockServer::start().await;
    serve_vaults(&server, VAULT_ID).await;
    let items: Value = serde_json::from_str(ITEMS).unwrap();
    answer(&server, format!("/v1/vaults/{VAULT_ID}/items"), items).await;
    let item: Value = serde_json::from_str(&ITEM_PI.replace("{{HOST_KEY}}", r"  \n  \n")).unwrap();
    answer(
        &server,
        format!("/v1/vaults/{VAULT_ID}/items/{ITEM_ID}"),
        item,
    )
    .await;
    let err = backend(&server, "Warden")
        .ssh_target(&pi())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, PolicyError::Invalid { field, .. } if field == "host_keys"),
        "{err:?}"
    );
}
