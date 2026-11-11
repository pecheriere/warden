use serde_json::{Value, json};

use super::{ReleaseAppKey, parse_item};
use crate::policy::onepassword::SecretField;
use crate::testkit::github_app::{APP_ID, RSA1024_PKCS8, RSA2048_ENCRYPTED, RSA2048_PKCS8};

fn pem(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap()
}

fn fields(values: &[(&str, &str)]) -> Vec<SecretField> {
    let list: Vec<Value> = values
        .iter()
        .enumerate()
        .map(|(i, (label, value))| json!({"id": format!("f{i}"), "label": label, "value": value}))
        .collect();
    serde_json::from_value(Value::Array(list)).unwrap()
}

#[test]
fn loads_and_signs() {
    let key = parse_item(
        "release-app",
        &fields(&[("app_id", APP_ID), ("private_key", pem(RSA2048_PKCS8))]),
    )
    .unwrap();
    assert_eq!(key.app_id(), APP_ID);
    assert_eq!(key.sign_rs256(b"message").unwrap().len(), 256);
    assert_eq!(key.digest().len(), 64);
    assert!(!format!("{key:?}").contains("PRIVATE"));
}

#[test]
fn digest_follows_the_app_not_the_key() {
    let a = ReleaseAppKey::new("1".to_owned(), pem(RSA2048_PKCS8)).unwrap();
    let b = ReleaseAppKey::new("2".to_owned(), pem(RSA2048_PKCS8)).unwrap();
    assert_ne!(a.digest(), b.digest());
}

#[test]
fn refuses_unusable_items_without_quoting() {
    let secret = "SENTINEL-VALUE-7731";
    let good = pem(RSA2048_PKCS8);
    let cases = [
        fields(&[("private_key", good)]),
        fields(&[("app_id", APP_ID)]),
        fields(&[("app_id", APP_ID), ("private_key", secret)]),
        fields(&[("app_id", APP_ID), ("private_key", pem(RSA1024_PKCS8))]),
        fields(&[("app_id", APP_ID), ("private_key", pem(RSA2048_ENCRYPTED))]),
        fields(&[("app_id", "bad id"), ("private_key", good)]),
        fields(&[("app_id", APP_ID), ("app_id", "2"), ("private_key", good)]),
    ];
    for case in cases {
        let err = parse_item("release-app", &case).unwrap_err();
        assert!(err.contains("release-app"), "{err}");
        assert!(!err.contains(secret) && !err.contains("BEGIN"), "{err}");
    }
}
