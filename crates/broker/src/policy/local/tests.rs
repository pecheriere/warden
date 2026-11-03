//! [`LocalBackend`] through the [`SecretBackend`] trait, on real files.

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use http::Method;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use tempfile::TempDir;
use warden_broker_proto::{SecretName, TargetName, Window};

use super::{END_MARKER, LocalBackend, LocalProbe, digest_line, parse_policy, seal_text};
use crate::audit::AuditLog;
use crate::config::LocalSettings;
use crate::policy::{CaProbe, PolicyError, RelayCredential, SecretBackend, SshMode};

const CREDENTIAL: &str = "api-credential-do-not-leak";
const PASSWORD: &str = " relay password do not leak ";

/// A policy file and a secrets directory, private and at their real paths.
struct Setup {
    _guard: TempDir,
    root: PathBuf,
    settings: LocalSettings,
    backend: LocalBackend,
}

fn host_key() -> String {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap()
}

fn ed25519_pem() -> String {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .unwrap()
        .to_openssh(LineEnding::LF)
        .unwrap()
        .to_string()
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}

fn cert_entry() -> String {
    format!(
        r#"
[targets.web-01]
address = "web-01.example.com:2222"
mode = "cert"
users = ["build-agent", "deploy"]
max_window = "1h"
host_keys = ["{}"]
"#,
        host_key()
    )
}

const API_ENTRY: &str = r#"
[api_secrets.home-api]
website = "https://home.example.com"
credential_file = "home-api"
max_window = "30m"
methods = ["GET", "POST"]
path_prefix = "/api/"
"#;

impl Setup {
    fn new(policy: &str) -> Self {
        let guard = tempfile::tempdir().unwrap();
        let root = guard.path().canonicalize().unwrap();
        chmod(&root, 0o700);
        let secrets = root.join("secrets");
        fs::create_dir(&secrets).unwrap();
        chmod(&secrets, 0o700);
        let settings = LocalSettings {
            policy_file: root.join("policy.toml"),
            secrets_dir: secrets,
        };
        let backend = LocalBackend::unaudited(&settings);
        let setup = Self {
            _guard: guard,
            root,
            settings,
            backend,
        };
        setup.write_policy(policy);
        setup.secret("home-api", &format!("{CREDENTIAL}\n"));
        setup
    }

    /// Write a complete policy file: `policy` and the end marker.
    fn write_policy(&self, policy: &str) {
        self.write_raw(seal(&format!("{policy}\n{END_MARKER}\n")).as_bytes());
    }

    fn write_raw(&self, bytes: &[u8]) {
        fs::write(&self.settings.policy_file, bytes).unwrap();
        chmod(&self.settings.policy_file, 0o600);
    }

    fn secret(&self, name: &str, content: &str) {
        let path = self.settings.secrets_dir.join(name);
        fs::write(&path, content).unwrap();
        chmod(&path, 0o600);
    }

    fn secret_path(&self, name: &str) -> PathBuf {
        self.settings.secrets_dir.join(name)
    }

    /// Everything the error shows, to look for secrets in.
    fn assert_no_secret(shown: &str) {
        for secret in [CREDENTIAL, PASSWORD, "PRIVATE KEY"] {
            assert!(!shown.contains(secret), "{shown}");
        }
    }
}

fn target(name: &str) -> TargetName {
    TargetName::try_from(name.to_owned()).unwrap()
}

fn secret(name: &str) -> SecretName {
    SecretName::try_from(name.to_owned()).unwrap()
}

fn assert_invalid(error: &PolicyError, wanted_item: &str, wanted_field: &str) {
    let PolicyError::Invalid { item, field, .. } = error else {
        panic!("expected Invalid, got {error}");
    };
    assert_eq!(
        (item.as_str(), field.as_str()),
        (wanted_item, wanted_field),
        "{error}"
    );
}

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
        include_str!("../../../tests/fixtures/throwaway-test-only-rsa.key"),
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

fn ca_policy() -> String {
    "[ca]\nprivate_key_file = \"ssh-ca\"\n".to_owned() + &cert_entry()
}

#[tokio::test]
async fn loads_the_ca_key() {
    let setup = Setup::new(&ca_policy());
    let pem = ed25519_pem();
    setup.secret("ssh-ca", &pem);
    let key = setup.backend.ssh_ca().await.unwrap();
    assert_eq!(
        key.public_key().to_openssh().unwrap(),
        PrivateKey::from_openssh(&pem)
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap()
    );
}

#[tokio::test]
async fn refuses_an_unusable_ca_key_without_echoing_it() {
    let setup = Setup::new(&ca_policy());
    for bad in [
        "not a key at all",
        include_str!("../../../tests/fixtures/throwaway-test-only-rsa.key"),
        include_str!("../../../tests/fixtures/throwaway-test-only-ed25519-encrypted.key"),
    ] {
        setup.secret("ssh-ca", bad);
        let error = setup.backend.ssh_ca().await.err().unwrap();
        assert!(matches!(error, PolicyError::Ca(_)), "{error}");
        Setup::assert_no_secret(&format!("{error} {error:?}"));
    }
}

#[tokio::test]
async fn no_ca_section_is_a_ca_error() {
    let setup = Setup::new(&cert_entry());
    let error = setup.backend.ssh_ca().await.err().unwrap();
    assert!(matches!(error, PolicyError::Ca(_)), "{error}");
}

fn commit_signing_policy() -> String {
    format!("[commit_signing]\nprivate_key_file = \"commit-signing\"\n{API_ENTRY}")
}

#[tokio::test]
async fn loads_the_commit_signing_key_and_none_is_no_key() {
    let setup = Setup::new(&commit_signing_policy());
    setup.secret("commit-signing", &ed25519_pem());
    assert!(setup.backend.commit_signing_key().await.is_ok());
    let probe = setup.backend.probe().await;
    assert!(probe.problems().is_empty(), "{probe:?}");

    let without = Setup::new(API_ENTRY);
    let error = without.backend.commit_signing_key().await.err().unwrap();
    assert!(matches!(error, PolicyError::NoCommitSigningKey), "{error}");
    assert_eq!(
        without.backend.probe().await.problems(),
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn the_ca_key_cannot_also_be_the_commit_signing_key() {
    let policy = format!(
        "[ca]\nprivate_key_file = \"ssh-ca\"\n{}",
        commit_signing_policy()
    );
    let setup = Setup::new(&policy);
    let pem = ed25519_pem();
    setup.secret("ssh-ca", &pem);
    setup.secret("commit-signing", &pem);
    let problems = setup.backend.probe().await.problems();
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("also the SSH CA key"), "{problems:?}");
    // Two keys are fine.
    setup.secret("commit-signing", &ed25519_pem());
    assert_eq!(setup.backend.probe().await.problems(), Vec::<String>::new());
}

#[tokio::test]
async fn a_ca_that_cannot_be_used_refuses_the_commit_signing_key() {
    let policy = format!(
        "[ca]\nprivate_key_file = \"ssh-ca\"\n{}",
        commit_signing_policy()
    );
    let setup = Setup::new(&policy);
    setup.secret("ssh-ca", "not a key at all");
    setup.secret("commit-signing", &ed25519_pem());
    let problems = setup.backend.probe().await.problems();
    assert!(
        problems.iter().any(|p| p.contains("SSH CA cannot be read")),
        "{problems:?}"
    );
}

#[tokio::test]
async fn refuses_an_unusable_commit_signing_key_without_echoing_it() {
    let setup = Setup::new(&commit_signing_policy());
    for bad in [
        "not a key at all",
        include_str!("../../../tests/fixtures/throwaway-test-only-rsa.key"),
        include_str!("../../../tests/fixtures/throwaway-test-only-ed25519-encrypted.key"),
    ] {
        setup.secret("commit-signing", bad);
        let error = setup.backend.commit_signing_key().await.err().unwrap();
        assert!(matches!(error, PolicyError::CommitSigningKey(_)), "{error}");
        Setup::assert_no_secret(&format!("{error} {error:?}"));
        // And a server does not start on it.
        assert_eq!(setup.backend.probe().await.problems().len(), 1);
    }
}

#[tokio::test]
async fn the_probe_passes_a_good_setup() {
    let setup = Setup::new(&(ca_policy() + API_ENTRY));
    setup.secret("ssh-ca", &ed25519_pem());
    let probe = setup.backend.probe().await;
    assert!(probe.problems().is_empty(), "{probe:?}");
    let LocalProbe::Read {
        targets,
        api_secrets,
        ca,
        ..
    } = probe
    else {
        panic!("expected Read");
    };
    assert_eq!((targets, api_secrets), (1, 1));
    assert!(matches!(ca, CaProbe::Loaded { .. }));
}

#[tokio::test]
async fn the_probe_lists_every_problem_and_never_a_secret() {
    let policy = format!(
        "{API_ENTRY}\n[api_secrets.Bad_Name]\ncredential_file = \"x\"\n\
         [targets.pi]\nmode = \"cert\"\n"
    );
    let setup = Setup::new(&policy);
    chmod(&setup.secret_path("home-api"), 0o644);
    let probe = setup.backend.probe().await;
    let problems = probe.problems();
    assert_eq!(problems.len(), 3, "{problems:?}");
    let shown = problems.join("\n");
    assert!(shown.contains("home-api"), "{shown}");
    assert!(shown.contains("Bad_Name"), "{shown}");
    assert!(shown.contains("\"pi\""), "{shown}");
    Setup::assert_no_secret(&shown);
}

#[tokio::test]
async fn the_probe_lists_a_target_with_an_unusable_name() {
    let setup = Setup::new("[targets.Bad_Name]\nmode = \"cert\"\n");
    let probe = setup.backend.probe().await;
    let problems = probe.problems();
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("Bad_Name"), "{problems:?}");
    assert!(problems[0].contains("target name"), "{problems:?}");
}

#[tokio::test]
async fn the_probe_tells_a_needed_ca_from_an_unneeded_one() {
    let needed = Setup::new(&cert_entry()).backend.probe().await;
    let LocalProbe::Read { ca, .. } = &needed else {
        panic!("expected Read");
    };
    assert_eq!(*ca, CaProbe::Missing { cert_targets: 1 });
    assert_eq!(needed.problems().len(), 1);

    let unneeded = Setup::new(API_ENTRY).backend.probe().await;
    let LocalProbe::Read { ca, .. } = &unneeded else {
        panic!("expected Read");
    };
    assert_eq!(*ca, CaProbe::NotNeeded);
    assert_eq!(unneeded.problems(), Vec::<String>::new());
}

#[tokio::test]
async fn open_refuses_and_audits_anything_invalid_and_never_a_secret() {
    let setup = Setup::new(API_ENTRY);
    chmod(&setup.secret_path("home-api"), 0o644);
    let audit_path = setup.root.join("audit.jsonl");
    let audit = Arc::new(AuditLog::open(&audit_path).await.unwrap());
    let error = LocalBackend::open(&setup.settings, audit.clone())
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("home-api"), "{error}");
    let log = fs::read_to_string(&audit_path).unwrap();
    assert!(log.contains("local secret backend"), "{log}");
    assert!(log.contains("home-api"), "{log}");
    Setup::assert_no_secret(&log);

    chmod(&setup.secret_path("home-api"), 0o600);
    assert!(LocalBackend::open(&setup.settings, audit).await.is_ok());
}

#[tokio::test]
async fn a_refused_request_is_audited_but_an_unknown_name_is_not() {
    let setup = Setup::new(API_ENTRY);
    let audit_path = setup.root.join("audit.jsonl");
    let audit = Arc::new(AuditLog::open(&audit_path).await.unwrap());
    let backend = LocalBackend::open(&setup.settings, audit).await.unwrap();

    assert!(backend.api_secret(&secret("absent")).await.is_err());
    assert_eq!(fs::read_to_string(&audit_path).unwrap(), "");

    chmod(&setup.secret_path("home-api"), 0o644);
    assert!(backend.api_secret(&secret("home-api")).await.is_err());
    let log = fs::read_to_string(&audit_path).unwrap();
    assert_eq!(log.lines().count(), 1, "{log}");
    assert!(log.contains("group or others"), "{log}");
    Setup::assert_no_secret(&log);
}

fn seal(draft: &str) -> String {
    seal_text(draft).unwrap().to_string()
}

/// Every setting that has a default, each narrowing it, and every kind of entry.
fn full_policy() -> String {
    seal(&format!(
        r#"# A comment with a non-ASCII character: café, and # [end_of_policy]
[ca]
private_key_file = "ssh-ca"

[targets.web-01]
address = "web-01.example.com"
mode = "cert"
users = ["deploy"]
max_window = "1h"
host_keys = ["{key}"]

[targets.switch-01]
address = "switch-01.example.com"
mode = "relay"
users = ["admin"]
max_window = "1h"
host_keys = ["{key}"]
password_file = "switch-password"

[api_secrets.home-api]
website = "https://home.example.com"
credential_file = "home-api"
max_window = "30m"
ca_pem = """
{ca}"""
format = "token {{{{secret}}}}"
header = "X-Api-Key"
methods = ["GET"]
path_prefix = "/api/"

{END_MARKER}
"#,
        key = host_key(),
        ca = include_str!("../../../tests/fixtures/throwaway-test-only-ca.pem"),
    ))
}

/// A file cut at any byte, however the cut came about, must not load: neither
/// narrower nor, above all, wider than the file it was cut from. Every byte
/// through the parser; the file system is far slower, so below at line ends.
#[test]
fn a_policy_cut_at_any_byte_does_not_parse() {
    let full = full_policy();
    assert!(parse_policy(&full).is_ok());
    let complete = full.trim_end().len();
    for cut in 0..complete {
        // A cut inside a character is refused earlier, as invalid UTF-8.
        if let Ok(text) = std::str::from_utf8(&full.as_bytes()[..cut]) {
            assert!(parse_policy(text).is_err(), "cut at byte {cut} loaded");
        }
    }
    for cut in complete..=full.len() {
        assert!(parse_policy(&full[..cut]).is_ok(), "{cut}");
    }
}

/// The same through the backend: nothing is served from a cut file, and a whole
/// one is served unchanged.
#[tokio::test]
async fn a_cut_policy_file_is_refused_at_every_line_and_inside_the_marker() {
    let setup = Setup::new("");
    setup.secret("ssh-ca", &ed25519_pem());
    setup.secret("switch-password", "a-password\n");
    let full = full_policy();
    setup.write_raw(full.as_bytes());
    let probe = setup.backend.probe().await;
    assert_eq!(probe.problems(), Vec::<String>::new());
    let name = secret("home-api");
    let whole = setup.backend.api_secret(&name).await.unwrap();

    let complete = full.trim_end().len();
    let line_ends = full
        .match_indices('\n')
        .map(|(at, _)| at)
        .filter(|at| *at < complete);
    let marker = full.rfind(END_MARKER).unwrap()..complete;
    let inside_the_character = full.find('\u{e9}').unwrap() + 1;
    for cut in line_ends.chain(marker).chain([0, inside_the_character]) {
        setup.write_raw(&full.as_bytes()[..cut]);
        let probe = setup.backend.probe().await;
        assert!(
            matches!(probe, LocalProbe::Unreadable(_)),
            "cut at byte {cut} loaded: {probe:?}"
        );
        assert!(setup.backend.api_secret(&name).await.is_err(), "{cut}");
        let target = target("web-01");
        assert!(setup.backend.ssh_target(&target).await.is_err(), "{cut}");
        assert!(setup.backend.ssh_ca().await.is_err(), "{cut}");
    }
    setup.write_raw(&full.as_bytes()[..complete]);
    let same = setup.backend.api_secret(&name).await.unwrap();
    assert_eq!(same.destination_digest(), whole.destination_digest());
    assert_eq!(same.path_prefix, "/api/");
}

/// The attack as first found: the last line of the entry narrows the prefix.
#[tokio::test]
async fn a_cut_can_never_widen_a_prefix_or_change_a_header() {
    let setup = Setup::new("");
    let entry = format!(
        "{}header = \"X-Api-Key\"\npath_prefix = \"/api/\"\n",
        API_ENTRY.replace("path_prefix = \"/api/\"\n", "")
    );
    for lines in 1..entry.lines().count() {
        let cut: Vec<&str> = entry.lines().take(lines).collect();
        setup.write_raw(cut.join("\n").as_bytes());
        assert!(
            setup.backend.api_secret(&secret("home-api")).await.is_err(),
            "{lines} lines"
        );
    }
}

/// A line reading like the marker inside a string is not the marker: a cut just
/// after it leaves the string open, sealed or not.
#[tokio::test]
async fn the_marker_inside_a_string_does_not_complete_a_cut_file() {
    let setup = Setup::new("");
    let text = format!(
        "[api_secrets.home-api]\nwebsite = \"https://home.example.com\"\n\
         credential_file = \"home-api\"\nmax_window = \"30m\"\n\
         format = \"\"\"\n{END_MARKER}\nx {{{{secret}}}}\"\"\"\n{END_MARKER}\n"
    );
    let cut = text.find(END_MARKER).unwrap() + END_MARKER.len();
    for cut_file in [text[..cut].to_owned(), seal(&text[..cut])] {
        setup.write_raw(cut_file.as_bytes());
        let probe = setup.backend.probe().await;
        assert!(matches!(probe, LocalProbe::Unreadable(_)), "{probe:?}");
    }
}

#[tokio::test]
async fn the_marker_must_be_the_last_line_and_empty() {
    let setup = Setup::new("");
    for bad in [
        format!("{END_MARKER}\n{API_ENTRY}"),
        format!("{API_ENTRY}\n{END_MARKER} # done\n"),
        format!("{API_ENTRY}\n{END_MARKER}\nx = 1\n"),
        format!("{API_ENTRY}\n{END_MARKER}\n{END_MARKER}\n"),
        format!("{API_ENTRY}\n[end_of_policy.more]\n{END_MARKER}\n"),
    ] {
        // With a digest that matches: the marker's rules hold by themselves.
        let digest = digest_line(&bad);
        setup.write_raw(format!("{bad}{digest}\n").as_bytes());
        let probe = setup.backend.probe().await;
        assert!(
            matches!(probe, LocalProbe::Unreadable(_)),
            "{bad}: {probe:?}"
        );
    }
}

/// Parsing runs on a blocking thread of the broker: a file at the size limit,
/// nested as deep as it can be, must be refused rather than crash the process.
#[tokio::test]
async fn deep_nesting_is_refused() {
    let setup = Setup::new("");
    for depth in [200_usize, 5_000, 500_000] {
        let brackets = format!("a = {}{}", "[".repeat(depth), "]".repeat(depth));
        setup.write_policy(&brackets);
        let probe = setup.backend.probe().await;
        assert!(matches!(probe, LocalProbe::Unreadable(_)), "{depth}");
    }
}
