//! Target and API secret entries, checked by the validators shared with 1Password items.

use http::Method;
use warden_broker_proto::Window;

use super::{
    API_ENTRY, CREDENTIAL, PASSWORD, Setup, assert_invalid, cert_entry, ed25519_pem, host_key,
    secret, target,
};
use crate::policy::{PolicyError, RelayCredential, SecretBackend, SshMode};

#[tokio::test]
async fn reads_a_certificate_target() {
    let setup = Setup::new(&cert_entry());
    let found = setup.backend.ssh_target(&target("web-01")).await.unwrap();
    assert_eq!(found.host, "web-01.example.com");
    assert_eq!(found.port, 2222);
    assert_eq!(found.mode, SshMode::Cert);
    assert_eq!(found.users.len(), 2);
    assert_eq!(found.max_window, Window::H1);
    assert_eq!(found.host_keys.len(), 1);
}

#[tokio::test]
async fn reads_an_api_secret_and_its_value_without_a_line_ending() {
    let setup = Setup::new(API_ENTRY);
    let name = secret("home-api");
    let (policy, value) = setup.backend.api_secret_with_value(&name).await.unwrap();
    assert_eq!(value.expose(), CREDENTIAL);
    assert_eq!(policy.path_prefix, "/api/");
    assert_eq!(policy.methods, [Method::GET, Method::POST]);
    assert_eq!(
        policy.origin.ascii_serialization(),
        "https://home.example.com"
    );
    let same = setup.backend.api_secret(&name).await.unwrap();
    assert_eq!(same.destination_digest(), policy.destination_digest());
}

#[tokio::test]
async fn api_defaults_match_a_1password_item() {
    let setup = Setup::new(
        r#"
[api_secrets.home-api]
website = "https://home.example.com"
credential_file = "home-api"
max_window = "15m"
"#,
    );
    let policy = setup.backend.api_secret(&secret("home-api")).await.unwrap();
    assert_eq!(policy.methods, [Method::GET]);
    assert_eq!(policy.path_prefix, "/");
    assert_eq!(policy.header, http::header::AUTHORIZATION);
}

fn relay_entry(credential: &str) -> String {
    format!(
        r#"
[targets.switch-01]
address = "switch-01.example.com"
mode = "relay"
users = ["admin"]
max_window = "1h"
host_keys = ["{}"]
{credential}
"#,
        host_key()
    )
}

#[tokio::test]
async fn relay_targets_take_a_password_verbatim_or_a_key() {
    let setup = Setup::new(&relay_entry(r#"password_file = "switch-password""#));
    setup.secret("switch-password", &format!("{PASSWORD}\n"));
    let name = target("switch-01");
    let (found, credential) = setup
        .backend
        .relay_target_with_credential(&name)
        .await
        .unwrap();
    assert_eq!(found.mode, SshMode::Relay);
    let RelayCredential::Password(password) = credential else {
        panic!("expected a password");
    };
    assert_eq!(password.as_str(), PASSWORD);

    setup.write_policy(&relay_entry(r#"private_key_file = "switch-key""#));
    setup.secret("switch-key", &ed25519_pem());
    let (_, credential) = setup
        .backend
        .relay_target_with_credential(&name)
        .await
        .unwrap();
    assert!(matches!(credential, RelayCredential::Key(_)));
}

#[tokio::test]
async fn relay_credentials_follow_the_same_rules_as_a_1password_item() {
    let setup = Setup::new(&relay_entry(""));
    setup.secret("one", "a-password\n");
    setup.secret("two", &ed25519_pem());
    let name = target("switch-01");

    let error = setup.backend.ssh_target(&name).await.unwrap_err();
    assert_invalid(&error, "switch-01", "password");

    setup.write_policy(&relay_entry(
        "password_file = \"one\"\nprivate_key_file = \"two\"",
    ));
    let error = setup.backend.ssh_target(&name).await.unwrap_err();
    assert_invalid(&error, "switch-01", "private_key");

    // A credential is never left on a target that does not use it.
    let cert = cert_entry() + "password_file = \"one\"\n";
    setup.write_policy(&cert);
    let error = setup
        .backend
        .ssh_target(&target("web-01"))
        .await
        .unwrap_err();
    assert_invalid(&error, "web-01", "password");

    // Only Ed25519 keys.
    setup.write_policy(&relay_entry(r#"private_key_file = "rsa""#));
    setup.secret(
        "rsa",
        include_str!("../../../../tests/fixtures/throwaway-test-only-rsa.key"),
    );
    let error = setup.backend.ssh_target(&name).await.unwrap_err();
    assert_invalid(&error, "switch-01", "private_key");
    Setup::assert_no_secret(&format!("{error} {error:?}"));

    // A cert target's relay-only call is refused.
    setup.write_policy(&cert_entry());
    let error = setup
        .backend
        .relay_target_with_credential(&target("web-01"))
        .await
        .unwrap_err();
    assert_invalid(&error, "web-01", "mode");
}

#[tokio::test]
async fn invalid_fields_are_refused_by_the_shared_validators() {
    let key = host_key();
    let cases = [
        ("address", "address = \"-oProxyCommand=x\""),
        ("mode", "mode = \"open\""),
        ("users", "users = []"),
        ("users", "users = [\"Not A User\"]"),
        ("max_window", "max_window = \"5h\""),
        ("host_keys", "host_keys = []"),
        ("host_keys", "host_keys = [\"not a key\"]"),
    ];
    for (field, line) in cases {
        let kept = [
            ("address", "address = \"web-01.example.com\""),
            ("mode", "mode = \"cert\""),
            ("users", "users = [\"deploy\"]"),
            ("max_window", "max_window = \"1h\""),
        ]
        .into_iter()
        .filter(|(name, _)| *name != field)
        .map(|(_, kept)| kept)
        .collect::<Vec<_>>()
        .join("\n");
        let keys = if field == "host_keys" {
            String::new()
        } else {
            format!("host_keys = [\"{key}\"]")
        };
        let setup = Setup::new(&format!("[targets.web-01]\n{kept}\n{keys}\n{line}\n"));
        let error = setup
            .backend
            .ssh_target(&target("web-01"))
            .await
            .unwrap_err();
        assert_invalid(&error, "web-01", field);
    }
}

#[tokio::test]
async fn missing_required_fields_never_take_a_default() {
    for field in ["address", "mode", "users", "max_window", "host_keys"] {
        let full = cert_entry();
        let without: Vec<&str> = full.lines().filter(|l| !l.starts_with(field)).collect();
        let setup = Setup::new(&without.join("\n"));
        let error = setup
            .backend
            .ssh_target(&target("web-01"))
            .await
            .unwrap_err();
        assert_invalid(&error, "web-01", field);
    }
    for (field, reported) in [
        ("website", "website"),
        ("credential_file", "credential_file"),
        ("max_window", "max_window"),
    ] {
        let without: Vec<&str> = API_ENTRY
            .lines()
            .filter(|l| !l.starts_with(field))
            .collect();
        let setup = Setup::new(&without.join("\n"));
        let error = setup
            .backend
            .api_secret(&secret("home-api"))
            .await
            .unwrap_err();
        assert_invalid(&error, "home-api", reported);
    }
}

/// `path_prefix = ""` must not quietly mean the widest prefix.
#[tokio::test]
async fn a_blank_optional_setting_is_refused_rather_than_defaulted() {
    for (field, line) in [
        ("path_prefix", "path_prefix = \" \""),
        ("header", "header = \"\""),
        ("format", "format = \"\""),
        ("ca_pem", "ca_pem = \"\""),
        ("methods", "methods = []"),
    ] {
        let entry = format!(
            "[api_secrets.home-api]\nwebsite = \"https://home.example.com\"\n\
             credential_file = \"home-api\"\nmax_window = \"30m\"\n{line}\n"
        );
        let setup = Setup::new(&entry);
        let error = setup
            .backend
            .api_secret(&secret("home-api"))
            .await
            .unwrap_err();
        assert_invalid(&error, "home-api", field);
    }
}

#[tokio::test]
async fn api_fields_are_refused_by_the_shared_validators() {
    for (field, line) in [
        ("website", "website = \"http://home.example.com\""),
        ("website", "website = \"https://home.example.com/path\""),
        ("header", "header = \"Host\""),
        ("format", "format = \"no placeholder\""),
        ("methods", "methods = [\"get\"]"),
        ("path_prefix", "path_prefix = \"/a/../b\""),
        ("ca_pem", "ca_pem = \"not pem\""),
    ] {
        let kept = if field == "website" {
            String::new()
        } else {
            "website = \"https://home.example.com\"\n".to_owned()
        };
        let entry = format!(
            "[api_secrets.home-api]\n{kept}credential_file = \"home-api\"\n\
             max_window = \"30m\"\n{line}\n"
        );
        let setup = Setup::new(&entry);
        let error = setup
            .backend
            .api_secret(&secret("home-api"))
            .await
            .unwrap_err();
        assert_invalid(&error, "home-api", field);
    }
}

#[tokio::test]
async fn a_weak_or_unprintable_credential_is_refused_without_echoing_it() {
    let setup = Setup::new(API_ENTRY);
    for bad in [
        "short",
        "has\na-second-line-in-it",
        "caf\u{e9}-credential-value",
    ] {
        setup.secret("home-api", bad);
        let error = setup
            .backend
            .api_secret(&secret("home-api"))
            .await
            .unwrap_err();
        assert_invalid(&error, "home-api", "credential");
        assert!(!error.to_string().contains(bad), "{error}");
    }
}

#[tokio::test]
async fn unknown_names_are_not_found() {
    let setup = Setup::new(API_ENTRY);
    assert!(matches!(
        setup.backend.ssh_target(&target("absent")).await,
        Err(PolicyError::NotFound(_))
    ));
    assert!(matches!(
        setup.backend.api_secret(&secret("absent")).await,
        Err(PolicyError::UnknownSecret(_))
    ));
}
