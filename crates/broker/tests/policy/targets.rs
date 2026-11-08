//! SSH target items in certificate mode.

use serde_json::json;
use ssh_key::PrivateKey;
use warden_broker::policy::{PolicyError, SecretBackend, SshMode};
use warden_broker_proto::{UnixUser, Window};

use crate::{
    ITEM_PI, THROWAWAY_ECDSA, THROWAWAY_RSA, backend, connect_mock, fill, host_key_line, list,
    mount_item, mount_items, target, with_targets,
};

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
