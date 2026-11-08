//! Relay target items and their onward credentials.

use serde_json::{Value, json};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use warden_broker::policy::{PolicyError, RelayCredential, SecretBackend, SshMode, SshTarget};
use wiremock::MockServer;
use zeroize::Zeroizing;

use crate::{
    ITEM_NAS, ITEM_PI, THROWAWAY_ECDSA, THROWAWAY_ECDSA_PKCS8, THROWAWAY_ENCRYPTED, THROWAWAY_RSA,
    THROWAWAY_RSA_PKCS8, VAULT_ID, backend, connect_mock, ed25519_openssh, fill, host_key_line,
    list, mount_item, mount_items, set_field, target,
};

const NAS_ID: &str = "nas0000000000000000000000b";
const PI_ID: &str = "pi00000000000000000000000a";
// The throwaway password in the `nas` fixture.
const NAS_PASSWORD: &str = "throwaway-test-password";

/// The `nas` relay item (password credential) with a fresh host key.
fn nas_item() -> Value {
    fill(ITEM_NAS, "{{HOST_KEY}}", &host_key_line())
}

/// Mount the item list and `item` under `id`.
async fn item_server(id: &str, item: &Value) -> MockServer {
    let server = connect_mock().await;
    mount_items(&server, &list()).await;
    mount_item(&server, id, item).await;
    server
}

async fn relay_with(item: &Value) -> Result<(SshTarget, RelayCredential), PolicyError> {
    let server = item_server(NAS_ID, item).await;
    backend(&server)
        .relay_target_with_credential(&target("nas"))
        .await
}

/// The `nas` item with `private_key` set to `key` and no password.
fn nas_with_key(key: &str) -> Value {
    let mut item = nas_item();
    set_field(&mut item, "password", None);
    set_field(&mut item, "private_key", Some(key));
    item
}

#[track_caller]
fn assert_invalid_target(err: &PolicyError, want_item: &str, want_field: &str, secret: &str) {
    match err {
        PolicyError::Invalid {
            item,
            field,
            reason,
        } => {
            assert_eq!(item, want_item);
            assert_eq!(field, want_field, "reason: {reason}");
            assert!(!reason.contains(secret), "credential echoed: {reason}");
        }
        other => panic!("expected Invalid {want_field}, got {other:?}"),
    }
    assert!(
        !err.to_string().contains(secret),
        "credential echoed: {err}"
    );
}

#[tokio::test]
async fn relay_item_needs_exactly_one_credential() {
    // Neither: unusable, through either lookup.
    let mut none = nas_item();
    set_field(&mut none, "password", None);
    let err = relay_with(&none).await.unwrap_err();
    assert_invalid_target(&err, "nas", "password", NAS_PASSWORD);
    let server = item_server(NAS_ID, &none).await;
    let err = backend(&server)
        .ssh_target(&target("nas"))
        .await
        .unwrap_err();
    assert_invalid_target(&err, "nas", "password", NAS_PASSWORD);

    // A blank credential counts as absent.
    let mut blank = nas_item();
    set_field(&mut blank, "password", Some(""));
    set_field(&mut blank, "private_key", Some("  \n"));
    let err = relay_with(&blank).await.unwrap_err();
    assert_invalid_target(&err, "nas", "password", NAS_PASSWORD);

    // Both: unusable.
    let mut both = nas_item();
    set_field(&mut both, "private_key", Some(&ed25519_openssh()));
    let err = relay_with(&both).await.unwrap_err();
    assert_invalid_target(&err, "nas", "private_key", NAS_PASSWORD);

    // A cert target must not hold an onward credential at all.
    for (label, value) in [
        ("password", NAS_PASSWORD.to_owned()),
        ("private_key", ed25519_openssh()),
    ] {
        let mut pi = fill(ITEM_PI, "{{HOST_KEY}}", &host_key_line());
        set_field(&mut pi, label, Some(&value));
        let server = item_server(PI_ID, &pi).await;
        let err = backend(&server)
            .ssh_target(&target("pi"))
            .await
            .unwrap_err();
        assert_invalid_target(&err, "pi", label, &value);
    }

    // A cert target has no relay credential to hand out.
    let pi = fill(ITEM_PI, "{{HOST_KEY}}", &host_key_line());
    let server = item_server(PI_ID, &pi).await;
    let err = backend(&server)
        .relay_target_with_credential(&target("pi"))
        .await
        .unwrap_err();
    assert_invalid_target(&err, "pi", "mode", NAS_PASSWORD);

    // Exactly one: the policy alone carries no credential.
    let server = item_server(NAS_ID, &nas_item()).await;
    let t = backend(&server).ssh_target(&target("nas")).await.unwrap();
    assert_eq!(t.mode, SshMode::Relay);
    assert!(!format!("{t:?}").contains(NAS_PASSWORD));
}

#[tokio::test]
async fn relay_key_and_password_parse() {
    // A password is used verbatim, surrounding spaces included.
    let (t, cred) = relay_with(&nas_item()).await.unwrap();
    assert_eq!(t.mode, SshMode::Relay);
    assert_eq!(t.host, "nas.lan");
    assert!(matches!(&cred, RelayCredential::Password(p) if p.as_str() == NAS_PASSWORD));
    let mut spaced = nas_item();
    set_field(&mut spaced, "password", Some(" pass phrase "));
    let (_, cred) = relay_with(&spaced).await.unwrap();
    assert!(matches!(&cred, RelayCredential::Password(p) if p.as_str() == " pass phrase "));

    // A key is returned in OpenSSH format.
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let (_, cred) = relay_with(&nas_with_key(&key.to_openssh(LineEnding::LF).unwrap()))
        .await
        .unwrap();
    let RelayCredential::Key(openssh) = &cred else {
        panic!("expected a key, got {cred:?}");
    };
    let parsed = PrivateKey::from_openssh(openssh.as_str()).unwrap();
    assert_eq!(parsed.public_key().key_data(), key.public_key().key_data());
}

#[tokio::test]
async fn relay_ed25519_key_accepted() {
    // OpenSSH or PKCS#8, normalised to OpenSSH.
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let pkcs8 = {
        let pair = key.key_data().ed25519().unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&pair.private.to_bytes());
        ed25519_dalek::pkcs8::EncodePrivateKey::to_pkcs8_pem(
            &signing,
            ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF,
        )
        .unwrap()
        .to_string()
    };
    let openssh = key.to_openssh(LineEnding::LF).unwrap().to_string();
    for text in [openssh, pkcs8] {
        let (_, cred) = relay_with(&nas_with_key(&text)).await.unwrap();
        let RelayCredential::Key(normalised) = &cred else {
            panic!("expected a key, got {cred:?}");
        };
        assert!(normalised.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        let parsed = PrivateKey::from_openssh(normalised.as_str()).unwrap();
        assert_eq!(parsed.public_key().key_data(), key.public_key().key_data());
    }

    // Still refused: passphrase-protected, PKCS#1, garbage.
    for (text, why) in [
        (THROWAWAY_ENCRYPTED, "passphrase-protected"),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nTOP-SECRET-MARKER\n-----END RSA PRIVATE KEY-----",
            "not a readable",
        ),
        ("TOP-SECRET-MARKER not a key", "not a readable"),
        (
            "-----BEGIN OPENSSH PRIVATE KEY-----\nTOP-SECRET-MARKER\n-----END OPENSSH PRIVATE KEY-----",
            "not a readable",
        ),
    ] {
        let err = relay_with(&nas_with_key(text)).await.unwrap_err();
        assert_invalid_target(&err, "nas", "private_key", "TOP-SECRET-MARKER");
        let shown = err.to_string();
        assert!(shown.contains(why), "{shown}");
        assert!(!shown.contains("PRIVATE KEY"), "{shown}");
    }
}

#[tokio::test]
async fn relay_rsa_and_ecdsa_keys_rejected() {
    // warden performs no RSA or NIST-curve private-key operation: these key
    // types are refused from their container's type information.
    for (name, text) in [
        ("rsa openssh", THROWAWAY_RSA),
        ("rsa pkcs8", THROWAWAY_RSA_PKCS8),
        ("ecdsa openssh", THROWAWAY_ECDSA),
        ("ecdsa pkcs8", THROWAWAY_ECDSA_PKCS8),
    ] {
        let err = relay_with(&nas_with_key(text)).await.unwrap_err();
        match &err {
            PolicyError::Invalid {
                item,
                field,
                reason,
            } => {
                assert_eq!(item, "nas", "{name}");
                assert_eq!(field, "private_key", "{name}");
                assert_eq!(
                    reason,
                    "relay keys must be Ed25519; use a password for targets that need another key type",
                    "{name}"
                );
            }
            other => panic!("{name}: expected Invalid, got {other:?}"),
        }
        // Through the policy-only lookup too.
        let server = item_server(NAS_ID, &nas_with_key(text)).await;
        let err = backend(&server)
            .ssh_target(&target("nas"))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, PolicyError::Invalid { field, .. } if field == "private_key"),
            "{name}: {err:?}"
        );
    }
}

#[tokio::test]
async fn relay_credential_debug_redacted() {
    let (t, cred) = relay_with(&nas_item()).await.unwrap();
    assert_eq!(format!("{cred:?}"), "RelayCredential::Password(<redacted>)");
    assert!(!format!("{t:?}").contains(NAS_PASSWORD));

    let key = ed25519_openssh();
    let (_, cred) = relay_with(&nas_with_key(&key)).await.unwrap();
    assert_eq!(format!("{cred:?}"), "RelayCredential::Key(<redacted>)");
}

#[tokio::test]
async fn relay_credential_decode_error_does_not_echo() {
    // The password has the wrong JSON type: serde's own message would quote it.
    let mut item = nas_item();
    item["fields"] = json!([
        { "id": "password", "label": "password", "value": ["TOP-SECRET-MARKER"] }
    ]);
    let err = relay_with(&item).await.unwrap_err();
    assert!(matches!(err, PolicyError::Unavailable(_)), "{err:?}");
    assert!(!err.to_string().contains("TOP-SECRET-MARKER"), "{err}");

    let mut item = nas_item();
    item["fields"] = json!("TOP-SECRET-MARKER");
    let server = item_server(NAS_ID, &item).await;
    let b = backend(&server);
    let err = b
        .relay_target_with_credential(&target("nas"))
        .await
        .unwrap_err();
    assert!(matches!(err, PolicyError::Unavailable(_)), "{err:?}");
    assert!(!err.to_string().contains("TOP-SECRET-MARKER"), "{err}");
    let err = b.ssh_target(&target("nas")).await.unwrap_err();
    assert!(!err.to_string().contains("TOP-SECRET-MARKER"), "{err}");
}

#[tokio::test]
async fn relay_target_and_credential_come_from_one_read() {
    let server = item_server(NAS_ID, &nas_item()).await;
    backend(&server)
        .relay_target_with_credential(&target("nas"))
        .await
        .unwrap();
    let item_fetches = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == format!("/v1/vaults/{VAULT_ID}/items/{NAS_ID}"))
        .count();
    assert_eq!(item_fetches, 1);
}

#[tokio::test]
async fn fake_backend_serves_relay_targets() {
    use warden_broker::testkit::FakeBackend;
    let fake = FakeBackend::new();
    // A cert target has no relay credential.
    let err = fake
        .relay_target_with_credential(&target("pi"))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, PolicyError::Invalid { field, .. } if field == "mode"),
        "{err:?}"
    );

    let nas = FakeBackend::relay_target();
    assert_eq!(nas.mode, SshMode::Relay);
    fake.set_relay_target(
        nas.clone(),
        RelayCredential::Password(Zeroizing::new(NAS_PASSWORD.to_owned())),
    );
    assert_eq!(
        fake.ssh_target(&target("nas"))
            .await
            .unwrap()
            .destination_digest(),
        nas.destination_digest()
    );
    let (t, cred) = fake
        .relay_target_with_credential(&target("nas"))
        .await
        .unwrap();
    assert_eq!(t.destination_digest(), nas.destination_digest());
    assert!(matches!(&cred, RelayCredential::Password(p) if p.as_str() == NAS_PASSWORD));

    // A relay target without a credential is unusable, as in 1Password.
    fake.set_target(nas);
    let err = fake
        .relay_target_with_credential(&target("nas"))
        .await
        .unwrap_err();
    assert!(matches!(err, PolicyError::Invalid { .. }), "{err:?}");
}

#[test]
fn ssh_destination_digest_binds_the_mode() {
    use warden_broker::testkit::FakeBackend;
    let cert = FakeBackend::pi_target();
    let mut relay = cert.clone();
    relay.mode = SshMode::Relay;
    // Same host, port and host keys: only the mode differs.
    assert_ne!(cert.destination_digest(), relay.destination_digest());
    assert_eq!(
        relay.destination_digest(),
        relay.clone().destination_digest()
    );
}
