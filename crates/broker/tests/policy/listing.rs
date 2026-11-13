//! Listing every target and API secret, and release presence, against a wiremock Connect server.

use std::sync::Arc;

use serde_json::{Value, json};
use warden_broker::policy::{Listing, PolicyError, SecretBackend};
use warden_broker::testkit::TestBroker;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::{
    ITEM_BADMODE, ITEM_NAS, ITEM_NOUSERS, ITEM_PI, VAULT_ID, backend, connect_mock, fill,
    host_key_line, mount_item, mount_items, set_field,
};

const ITEM_API: &str = include_str!("../fixtures/item-api.json");
const CREDENTIAL: &str = "test-credential-0123456789abcdef";

fn summary(id: &str, title: &str, tag: &str) -> Value {
    json!({
        "id": id, "title": title, "vault": {"id": VAULT_ID}, "tags": [tag]
    })
}

fn target_summary(id: &str, title: &str) -> Value {
    summary(id, title, "warden:ssh-target")
}

fn api_summary(id: &str, title: &str) -> Value {
    summary(id, title, "warden:api-secret")
}

fn names<T>(items: &[T], name: impl Fn(&T) -> &str) -> Vec<String> {
    items.iter().map(|i| name(i).to_owned()).collect()
}

/// Item-body fetches: every request below `/items/`, which the list does not make.
async fn body_fetches(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().contains("/items/"))
        .count()
}

/// Requests for the vault's item list, which every listing makes once.
async fn item_lists(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with("/items"))
        .count()
}

/// Mount the valid `pi` and `nas` target items under summaries listed in `extra` order.
async fn with_target_summaries(summaries: Vec<Value>) -> MockServer {
    let server = connect_mock().await;
    mount_items(&server, &Value::Array(summaries)).await;
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

#[tokio::test]
async fn listing_returns_valid_items_in_name_order() {
    let server = with_target_summaries(vec![
        target_summary("pi00000000000000000000000a", "pi"),
        target_summary("nas0000000000000000000000b", "nas"),
    ])
    .await;
    let targets = backend(&server).list_ssh_targets().await.unwrap();
    assert_eq!(names(&targets, |t| t.name.as_str()), ["nas", "pi"]);
    assert_eq!(targets[1].host, "192.0.2.10");
}

#[tokio::test]
async fn listing_returns_api_secrets_in_name_order() {
    let server = connect_mock().await;
    mount_items(
        &server,
        &Value::Array(vec![
            api_summary("api00000000000000000000g00", "github"),
            api_summary("api00000000000000000000g01", "alpha"),
        ]),
    )
    .await;
    let body = fill(ITEM_API, "{{CREDENTIAL}}", CREDENTIAL);
    mount_item(&server, "api00000000000000000000g00", &body).await;
    mount_item(&server, "api00000000000000000000g01", &body).await;
    let secrets = backend(&server).list_api_secrets().await.unwrap();
    assert_eq!(names(&secrets, |s| s.name.as_str()), ["alpha", "github"]);
    assert!(!format!("{secrets:?}").contains(CREDENTIAL));
}

#[tokio::test]
async fn listing_skips_unusable_items() {
    let server = with_target_summaries(vec![
        target_summary("pi00000000000000000000000a", "pi"),
        target_summary("nousers000000000000000000c", "nousers"),
        target_summary("badmode00000000000000000d0", "badmode"),
        target_summary("bad0000000000000000000000e", "Not A Name!"),
        target_summary("dup0000000000000000000000f", "dup"),
        target_summary("dup0000000000000000000000g", "dup"),
    ])
    .await;
    let targets = backend(&server).list_ssh_targets().await.unwrap();
    assert_eq!(names(&targets, |t| t.name.as_str()), ["pi"]);
}

#[tokio::test]
async fn listing_skips_unusable_api_secrets() {
    let server = connect_mock().await;
    mount_items(
        &server,
        &Value::Array(vec![
            api_summary("api00000000000000000000g00", "github"),
            api_summary("api00000000000000000000g01", "nowebsite"),
            api_summary("bad0000000000000000000000e", "Not A Name!"),
        ]),
    )
    .await;
    mount_item(
        &server,
        "api00000000000000000000g00",
        &fill(ITEM_API, "{{CREDENTIAL}}", CREDENTIAL),
    )
    .await;
    let mut broken = fill(ITEM_API, "{{CREDENTIAL}}", CREDENTIAL);
    broken["urls"] = json!([]);
    mount_item(&server, "api00000000000000000000g01", &broken).await;
    let secrets = backend(&server).list_api_secrets().await.unwrap();
    assert_eq!(names(&secrets, |s| s.name.as_str()), ["github"]);
}

#[tokio::test]
async fn listing_keeps_hidden_and_invalid_items() {
    let server = connect_mock().await;
    mount_items(
        &server,
        &Value::Array(vec![
            target_summary("pi00000000000000000000000a", "pi"),
            target_summary("nas0000000000000000000000b", "nas"),
        ]),
    )
    .await;
    let key = host_key_line();
    let mut hidden = fill(ITEM_PI, "{{HOST_KEY}}", &key);
    set_field(&mut hidden, "list", Some("hidden"));
    mount_item(&server, "pi00000000000000000000000a", &hidden).await;
    let mut invalid = fill(ITEM_NAS, "{{HOST_KEY}}", &key);
    set_field(&mut invalid, "list", Some("sometimes"));
    mount_item(&server, "nas0000000000000000000000b", &invalid).await;
    let targets = backend(&server).list_ssh_targets().await.unwrap();
    assert_eq!(names(&targets, |t| t.name.as_str()), ["nas", "pi"]);
    assert_eq!(targets[0].listing, Listing::Invalid);
    assert_eq!(targets[1].listing, Listing::Hidden);
}

#[tokio::test]
async fn listing_unavailable_when_connect_down() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let b = backend(&server);
    assert!(matches!(
        b.list_ssh_targets().await,
        Err(PolicyError::Unavailable(_))
    ));
    assert!(matches!(
        b.list_api_secrets().await,
        Err(PolicyError::Unavailable(_))
    ));
    assert!(matches!(
        b.has_release_signing().await,
        Err(PolicyError::Unavailable(_))
    ));
    assert!(matches!(
        b.has_release_app().await,
        Err(PolicyError::Unavailable(_))
    ));
}

#[tokio::test]
async fn release_presence_reads_no_key() {
    let server = connect_mock().await;
    mount_items(
        &server,
        &Value::Array(vec![
            summary("rs1", "signing", "warden:release-signing"),
            summary("ra1", "app", "warden:github-release-app"),
        ]),
    )
    .await;
    let b = backend(&server);
    assert!(b.has_release_signing().await.unwrap());
    assert!(b.has_release_app().await.unwrap());
    assert_eq!(body_fetches(&server).await, 0);
}

#[tokio::test]
async fn release_presence_is_false_without_items() {
    let server = connect_mock().await;
    mount_items(&server, &Value::Array(vec![])).await;
    let b = backend(&server);
    assert!(!b.has_release_signing().await.unwrap());
    assert!(!b.has_release_app().await.unwrap());
}

#[tokio::test]
async fn listing_reads_the_item_list_once() {
    let server = with_target_summaries(vec![
        target_summary("pi00000000000000000000000a", "pi"),
        target_summary("nas0000000000000000000000b", "nas"),
        target_summary("nousers000000000000000000c", "nousers"),
        target_summary("dup0000000000000000000000f", "dup"),
        target_summary("dup0000000000000000000000g", "dup"),
        api_summary("api00000000000000000000g00", "github"),
        api_summary("api00000000000000000000g01", "alpha"),
    ])
    .await;
    let body = fill(ITEM_API, "{{CREDENTIAL}}", CREDENTIAL);
    mount_item(&server, "api00000000000000000000g00", &body).await;
    mount_item(&server, "api00000000000000000000g01", &body).await;
    let b = backend(&server);

    let targets = b.list_ssh_targets().await.unwrap();
    assert_eq!(names(&targets, |t| t.name.as_str()), ["nas", "pi"]);
    assert_eq!(item_lists(&server).await, 1);
    // One body read per uniquely titled item; the duplicates are not read.
    assert_eq!(body_fetches(&server).await, 3);

    let secrets = b.list_api_secrets().await.unwrap();
    assert_eq!(names(&secrets, |s| s.name.as_str()), ["alpha", "github"]);
    assert_eq!(item_lists(&server).await, 2);
    assert_eq!(body_fetches(&server).await, 5);
}

#[tokio::test]
async fn offers_name_no_vault_or_item_id() {
    let server = with_target_summaries(vec![
        target_summary("pi00000000000000000000000a", "pi"),
        target_summary("nas0000000000000000000000b", "nas"),
        api_summary("api00000000000000000000g00", "github"),
    ])
    .await;
    mount_item(
        &server,
        "api00000000000000000000g00",
        &fill(ITEM_API, "{{CREDENTIAL}}", CREDENTIAL),
    )
    .await;
    let broker = TestBroker::with_secret_backend(Arc::new(backend(&server))).await;
    let key = broker.add_agent("bot").await;

    let resp = broker.api_get(&key, "/v1/offers").await;

    assert_eq!(resp.status, 200, "{}", resp.body);
    let offers = resp.json();
    assert_eq!(offers["ssh_targets"].as_array().unwrap().len(), 2);
    assert_eq!(offers["api_secrets"].as_array().unwrap().len(), 1);
    for id in [
        VAULT_ID,
        "pi00000000000000000000000a",
        "nas0000000000000000000000b",
        "api00000000000000000000g00",
    ] {
        assert!(
            !resp.body.contains(id),
            "the answer names {id}: {}",
            resp.body
        );
    }
    assert!(!resp.body.contains(CREDENTIAL));
}
