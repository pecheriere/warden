//! The SSH CA item.

use serde_json::{Value, json};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use warden_broker::policy::{PolicyError, SecretBackend};

use crate::{
    ITEM_CA, THROWAWAY_ECDSA, THROWAWAY_ENCRYPTED, THROWAWAY_RSA, VAULT_ID, backend, connect_mock,
    ed25519_openssh, fill, mount_item, mount_items,
};

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
