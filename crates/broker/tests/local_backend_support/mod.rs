//! Helpers shared by the local backend's integration tests.

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use warden_broker::config::LocalSettings;
use warden_broker::policy::local::seal_text;
use warden_broker::testkit::HttpsUpstream;

pub const CREDENTIAL: &str = "local-backend-credential-do-not-leak";

/// The backend's files in a private directory, at their real paths.
pub struct Files {
    _guard: TempDir,
    pub root: PathBuf,
    pub settings: LocalSettings,
}

pub fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}

impl Files {
    pub fn new() -> Self {
        let guard = tempfile::tempdir().unwrap();
        let root = guard.path().canonicalize().unwrap();
        chmod(&root, 0o700);
        let secrets_dir = root.join("secrets");
        fs::create_dir(&secrets_dir).unwrap();
        chmod(&secrets_dir, 0o700);
        Self {
            _guard: guard,
            settings: LocalSettings {
                policy_file: root.join("policy.toml"),
                secrets_dir,
            },
            root,
        }
    }

    /// Write a complete policy file: `text` and the end marker.
    pub fn policy(&self, text: &str) {
        let sealed = seal_text(&format!("{text}\n[end_of_policy]\n")).unwrap();
        fs::write(&self.settings.policy_file, sealed.as_bytes()).unwrap();
        chmod(&self.settings.policy_file, 0o600);
    }

    pub fn secret(&self, name: &str, content: &str) {
        let path = self.secret_path(name);
        fs::write(&path, content).unwrap();
        chmod(&path, 0o600);
    }

    pub fn secret_path(&self, name: &str) -> PathBuf {
        self.settings.secrets_dir.join(name)
    }
}

/// `[api_secrets.svc]` for `upstream`, trusting its CA, with extra settings.
pub fn api_entry(upstream: &HttpsUpstream, extra: &str) -> String {
    format!(
        r#"
[api_secrets.svc]
website = "{origin}"
credential_file = "svc-token"
max_window = "1h"
ca_pem = """
{ca}"""
{extra}
"#,
        origin = upstream.origin(),
        ca = upstream.ca_pem(),
    )
}

/// What the backend wrote to the audit log.
pub fn backend_audit(files: &Files) -> String {
    fs::read_to_string(files.root.join("backend-audit.jsonl")).unwrap()
}
