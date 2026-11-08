//! [`LocalBackend`] through the [`SecretBackend`] trait, on real files.

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use tempfile::TempDir;
use warden_broker_proto::{SecretName, TargetName};

use super::{END_MARKER, LocalBackend, seal_text};
use crate::config::LocalSettings;
use crate::policy::PolicyError;

mod cut;
mod entries;
mod files;
mod keys;
mod probe;

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

fn ca_policy() -> String {
    "[ca]\nprivate_key_file = \"ssh-ca\"\n".to_owned() + &cert_entry()
}

fn seal(draft: &str) -> String {
    seal_text(draft).unwrap().to_string()
}
