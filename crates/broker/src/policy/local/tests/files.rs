//! Fresh reads of the policy and secret files, their permissions and paths.

use std::fs;

use super::{API_ENTRY, Setup, assert_invalid, cert_entry, chmod, secret};
use crate::policy::{PolicyError, SecretBackend};

/// The parser's message can quote the file, where a secret may have been pasted.
#[tokio::test]
async fn an_unusable_policy_file_is_refused_without_quoting_it() {
    let pasted = "[api_secrets.home-api]\ncredential = \"api-credential-do-not-leak\"\n";
    let repeated = format!("{API_ENTRY}{API_ENTRY}");
    let wrong_type = "[targets.web-01]\nmode = \"api-credential-do-not-leak\"\nusers = \"x\"\n";
    let unknown = "credentials = \"api-credential-do-not-leak\"\n";
    let broken = "api-credential-do-not-leak = ";
    for bad in [pasted, repeated.as_str(), wrong_type, unknown, broken] {
        let setup = Setup::new(bad);
        let error = setup
            .backend
            .api_secret(&secret("home-api"))
            .await
            .unwrap_err();
        assert!(matches!(error, PolicyError::Unavailable(_)), "{error}");
        Setup::assert_no_secret(&format!("{error} {error:?}"));
        assert!(error.to_string().contains("at line"), "{error}");
    }
}

/// "Always reads fresh data": no restart, no cache.
#[tokio::test]
async fn an_edit_applies_at_once() {
    let setup = Setup::new(API_ENTRY);
    let name = secret("home-api");
    let before = setup.backend.api_secret(&name).await.unwrap();

    let moved = API_ENTRY.replace("home.example.com", "other.example.com");
    setup.write_policy(&moved);
    let after = setup.backend.api_secret(&name).await.unwrap();
    assert_ne!(before.destination_digest(), after.destination_digest());

    setup.secret("home-api", "a-rotated-credential-value");
    let (_, value) = setup.backend.api_secret_with_value(&name).await.unwrap();
    assert_eq!(value.expose(), "a-rotated-credential-value");

    setup.write_policy(&cert_entry());
    assert!(matches!(
        setup.backend.api_secret(&name).await,
        Err(PolicyError::UnknownSecret(_))
    ));
}

#[tokio::test]
async fn removing_a_secret_file_stops_it_at_once() {
    let setup = Setup::new(API_ENTRY);
    let name = secret("home-api");
    assert!(setup.backend.api_secret(&name).await.is_ok());
    fs::remove_file(setup.secret_path("home-api")).unwrap();
    let error = setup.backend.api_secret(&name).await.unwrap_err();
    assert_invalid(&error, "home-api", "credential_file");
}

#[tokio::test]
async fn loosened_permissions_are_refused_at_once() {
    let setup = Setup::new(API_ENTRY);
    let name = secret("home-api");
    chmod(&setup.secret_path("home-api"), 0o640);
    let error = setup.backend.api_secret(&name).await.unwrap_err();
    assert_invalid(&error, "home-api", "credential_file");
    assert!(error.to_string().contains("group or others"), "{error}");
    assert!(setup.backend.api_secret_with_value(&name).await.is_err());
    chmod(&setup.secret_path("home-api"), 0o600);

    chmod(&setup.settings.policy_file, 0o664);
    let error = setup.backend.api_secret(&name).await.unwrap_err();
    assert!(matches!(error, PolicyError::Unavailable(_)), "{error}");
}

#[tokio::test]
async fn a_credential_cannot_point_outside_the_secrets_directory() {
    for path in ["../policy.toml", "/etc/passwd", ".hidden", ".."] {
        let entry = API_ENTRY.replace(
            "credential_file = \"home-api\"",
            &format!("credential_file = \"{path}\""),
        );
        let setup = Setup::new(&entry);
        let error = setup
            .backend
            .api_secret(&secret("home-api"))
            .await
            .unwrap_err();
        assert_invalid(&error, "home-api", "credential_file");
    }
}
