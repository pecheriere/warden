//! The release signing and release App items, against a wiremock Connect server.

use serde_json::{Value, json};
use warden_broker::policy::{PolicyError, SecretBackend};
use warden_broker::testkit::github_app::{APP_ID, RSA2048_PKCS8};
use warden_broker_proto::release::RepoName;
use wiremock::MockServer;

use crate::{VAULT_ID, backend, connect_mock, ed25519_openssh, mount_item, mount_items};

fn repo(name: &str) -> RepoName {
    RepoName::try_from(name.to_owned()).unwrap()
}

fn summaries(tag: &str, ids: &[&str]) -> Value {
    Value::Array(
        ids.iter()
            .map(|id| {
                json!({
                    "id": id, "title": format!("item-{id}"), "category": "API_CREDENTIAL",
                    "vault": {"id": VAULT_ID}, "tags": [tag]
                })
            })
            .collect(),
    )
}

fn field(label: &str, value: &str) -> Value {
    json!({"id": format!("x{}", label.len()), "type": "CONCEALED", "label": label, "value": value})
}

fn signing_item(id: &str, repository: &str, private: &str) -> Value {
    json!({
        "id": id, "title": format!("item-{id}"), "vault": {"id": VAULT_ID},
        "tags": ["warden:release-signing"],
        "fields": [
            field("private_key", private),
            field("repository", repository),
            field("tagger_name", "Release Bot"),
            field("tagger_email", "release@example.com"),
        ]
    })
}

async fn with_signing_items(items: &[(&str, &str, String)]) -> MockServer {
    let server = connect_mock().await;
    let ids: Vec<&str> = items.iter().map(|(id, _, _)| *id).collect();
    mount_items(&server, &summaries("warden:release-signing", &ids)).await;
    for (id, repository, private) in items {
        mount_item(&server, id, &signing_item(id, repository, private)).await;
    }
    server
}

#[tokio::test]
async fn release_signing_loads_the_repository_that_matches() {
    let server = with_signing_items(&[
        ("rs1", "example-owner/one", ed25519_openssh()),
        ("rs2", "example-owner/two", ed25519_openssh()),
    ])
    .await;
    let key = backend(&server)
        .release_signing(&repo("Example-Owner/TWO"))
        .await
        .unwrap();
    assert_eq!(key.repository().as_str(), "example-owner/two");
    assert!(!key.publish());
}

#[tokio::test]
async fn one_bad_item_fails_every_repository() {
    let server = with_signing_items(&[
        ("rs1", "example-owner/one", ed25519_openssh()),
        ("rs2", "not a repository", ed25519_openssh()),
    ])
    .await;
    for name in ["example-owner/one", "example-owner/other"] {
        let err = backend(&server)
            .release_signing(&repo(name))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, PolicyError::ReleaseKey(r) if r.contains("repository")),
            "{err:?}"
        );
    }
}

#[tokio::test]
async fn a_shared_key_fails_every_repository() {
    let shared = ed25519_openssh();
    let server = with_signing_items(&[
        ("rs1", "example-owner/one", shared.clone()),
        ("rs2", "example-owner/two", shared),
    ])
    .await;
    let err = backend(&server)
        .release_signing(&repo("example-owner/one"))
        .await
        .unwrap_err();
    assert!(matches!(err, PolicyError::ReleaseKey(_)), "{err:?}");
}

#[tokio::test]
async fn unknown_repository_is_not_configured() {
    let server = with_signing_items(&[("rs1", "example-owner/one", ed25519_openssh())]).await;
    let err = backend(&server)
        .release_signing(&repo("example-owner/unknown"))
        .await
        .unwrap_err();
    assert!(matches!(err, PolicyError::NoReleaseKey), "{err:?}");
}

#[tokio::test]
async fn release_app_loads() {
    let server = connect_mock().await;
    mount_items(&server, &summaries("warden:github-release-app", &["ra1"])).await;
    mount_item(
        &server,
        "ra1",
        &json!({
            "id": "ra1", "title": "release-app", "vault": {"id": VAULT_ID},
            "tags": ["warden:github-release-app"],
            "fields": [
                field("app_id", APP_ID),
                field("private_key", std::str::from_utf8(RSA2048_PKCS8).unwrap()),
            ]
        }),
    )
    .await;
    let app = backend(&server).release_app().await.unwrap();
    assert_eq!(app.app_id(), APP_ID);
}

#[tokio::test]
async fn no_release_app_is_not_configured() {
    let server = connect_mock().await;
    mount_items(&server, &summaries("warden:github-release-app", &[])).await;
    let err = backend(&server).release_app().await.unwrap_err();
    assert!(matches!(err, PolicyError::NoReleaseApp), "{err:?}");
}

#[tokio::test]
async fn two_release_apps_fail() {
    let server = connect_mock().await;
    mount_items(
        &server,
        &summaries("warden:github-release-app", &["ra1", "ra2"]),
    )
    .await;
    let err = backend(&server).release_app().await.unwrap_err();
    assert!(
        matches!(&err, PolicyError::ReleaseApp(r) if r.contains("exactly one")),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_release_key_that_is_the_commit_signing_key_fails() {
    let shared = ed25519_openssh();
    let server = connect_mock().await;
    let mut list = summaries("warden:release-signing", &["rs1"]);
    list.as_array_mut().unwrap().extend(
        summaries("warden:commit-signing", &["cs1"])
            .as_array()
            .unwrap()
            .clone(),
    );
    mount_items(&server, &list).await;
    mount_item(
        &server,
        "rs1",
        &signing_item("rs1", "example-owner/one", &shared),
    )
    .await;
    mount_item(
        &server,
        "cs1",
        &json!({
            "id": "cs1", "title": "commit-signing", "vault": {"id": VAULT_ID},
            "tags": ["warden:commit-signing"],
            "fields": [{"id": "private_key", "type": "CONCEALED", "label": "private key", "value": shared}]
        }),
    )
    .await;
    let err = backend(&server)
        .release_signing(&repo("example-owner/one"))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, PolicyError::ReleaseKey(r) if r.contains("commit signing key")),
        "{err:?}"
    );
}
