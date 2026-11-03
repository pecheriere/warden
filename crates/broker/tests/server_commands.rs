//! The owner's `warden-server` commands that change who has access, the real
//! binary against its own database and audit log.

use std::path::PathBuf;
use std::process::{Command, Output};

use tempfile::TempDir;
use warden_broker::audit::verify;
use warden_broker::store;

const PUBLIC_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh0zJ+xlPfFH6uwtZmJ2O9GrkMxjqMwPQTsBVmbbBrE bot@host";

struct Server {
    dir: TempDir,
}

impl Server {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_warden-server"));
        command
            .args(args)
            .env("WARDEN_DB_PATH", self.path("db.sqlite"))
            .env("WARDEN_AUDIT_PATH", self.path("audit.log"))
            .env_remove("WARDEN_PUBLIC_URL");
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    fn succeeds(&self, args: &[&str]) -> Output {
        let output = self.run(args);
        assert!(output.status.success(), "{args:?}: {}", stderr(&output));
        output
    }

    fn enroll(&self) -> Output {
        self.command(&["enroll"])
            .env("WARDEN_PUBLIC_URL", "https://warden.example.ts.net")
            .output()
            .unwrap()
    }

    fn audit(&self) -> String {
        std::fs::read_to_string(self.path("audit.log")).unwrap_or_default()
    }

    /// The audit log's entries of `kind`, after checking its chain.
    fn audited(&self, kind: &str) -> usize {
        verify(&self.path("audit.log")).unwrap();
        self.audit()
            .lines()
            .filter(|line| line.contains(&format!(r#""type":"{kind}""#)))
            .count()
    }

    /// Enroll a stand-in passkey straight in the database; these commands only
    /// list and remove it, and never read its credential.
    async fn add_passkey(&self, id: &str) {
        let pool = store::open(&self.path("db.sqlite")).await.unwrap();
        sqlx::query(
            "INSERT INTO passkeys (id, label, credential, created_at) VALUES (?, 'phone', '{}', 1)",
        )
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn revoking_an_agent_is_on_record_when_the_log_works() {
    let server = Server::new();
    server.succeeds(&["agent", "add", "build-agent"]);
    server.succeeds(&["agent", "revoke", "build-agent"]);
    assert_eq!(server.audited("agent_revoked"), 1);
    let agents = stdout(&server.succeeds(&["agent", "list"]));
    assert!(agents.contains("revoked@"), "{agents}");
    let verified = server.succeeds(&["audit", "verify"]);
    assert!(
        !stderr(&verified).contains("waiting"),
        "{}",
        stderr(&verified)
    );
}

#[test]
fn setting_a_key_switches_the_agent_and_is_on_record() {
    let server = Server::new();
    server.succeeds(&["agent", "add", "build-agent"]);
    let set = server.succeeds(&["agent", "set-key", "build-agent", PUBLIC_KEY]);
    assert!(stderr(&set).contains("no longer works"), "{}", stderr(&set));
    assert_eq!(server.audited("agent_key_set"), 1);
    let agents = stdout(&server.succeeds(&["agent", "list"]));
    assert!(agents.contains("SHA256:"), "{agents}");
}

#[test]
fn a_bad_key_or_unknown_agent_changes_nothing() {
    let server = Server::new();
    server.succeeds(&["agent", "add", "build-agent"]);
    let before = stdout(&server.succeeds(&["agent", "list"]));
    let entries = server.audit();

    let bad = server.run(&["agent", "set-key", "build-agent", "not a key"]);
    assert!(!bad.status.success());
    assert!(
        stderr(&bad).contains("refusing the public key"),
        "{}",
        stderr(&bad)
    );

    let unknown = server.run(&["agent", "set-key", "no-such-agent", PUBLIC_KEY]);
    assert!(!unknown.status.success());
    assert!(
        stderr(&unknown).contains("no-such-agent"),
        "{}",
        stderr(&unknown)
    );

    assert_eq!(stdout(&server.succeeds(&["agent", "list"])), before);
    assert!(server.audit().starts_with(&entries));
    assert_eq!(server.audited("agent_key_set"), 0);
}

/// The audit log says that a code was made, and must never hold the code.
#[test]
fn an_enrollment_code_is_shown_once_and_not_recorded() {
    let server = Server::new();
    let output = server.enroll();
    assert!(output.status.success(), "{}", stderr(&output));
    let shown = stdout(&output);
    let code = shown
        .lines()
        .find_map(|line| line.strip_prefix("enrollment code: "))
        .unwrap_or_else(|| panic!("no code in {shown}"));
    assert!(
        shown.contains("https://warden.example.ts.net/enroll"),
        "{shown}"
    );
    assert_eq!(server.audited("enrollment_code_created"), 1);
    assert!(!server.audit().contains(code));
    assert!(!stderr(&output).contains(code));
}

#[test]
fn no_enrollment_code_without_a_public_url() {
    let server = Server::new();
    let output = server.run(&["enroll"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("WARDEN_PUBLIC_URL"),
        "{}",
        stderr(&output)
    );
    assert!(stdout(&output).is_empty(), "{}", stdout(&output));
    assert!(!server.audit().contains("enrollment_code_created"));
}

#[tokio::test]
async fn removing_a_passkey_ends_it_and_is_on_record() {
    let server = Server::new();
    server.add_passkey("passkey-1").await;
    server.add_passkey("passkey-2").await;
    let listed = stdout(&server.succeeds(&["passkey", "list"]));
    assert!(listed.contains("passkey-1\tphone\tcreated@1"), "{listed}");

    server.succeeds(&["passkey", "remove", "passkey-1"]);
    let listed = stdout(&server.succeeds(&["passkey", "list"]));
    assert!(!listed.contains("passkey-1"), "{listed}");
    assert!(listed.contains("passkey-2"), "{listed}");
    assert_eq!(server.audited("passkey_removed"), 1);
}

#[tokio::test]
async fn removing_an_unknown_passkey_fails_and_records_nothing() {
    let server = Server::new();
    server.add_passkey("passkey-1").await;
    let output = server.run(&["passkey", "remove", "no-such-passkey"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("no-such-passkey"),
        "{}",
        stderr(&output)
    );
    assert_eq!(server.audited("passkey_removed"), 0);
}

/// The command opens the log before anything else, so it stops there. That a log
/// failing after this point also keeps the passkey is in `audit_gaps.rs`.
#[tokio::test]
async fn a_passkey_stays_when_the_audit_log_cannot_be_opened() {
    let server = Server::new();
    server.add_passkey("passkey-1").await;
    std::fs::write(server.path("audit.log"), "not an audit line\n").unwrap();
    let output = server.run(&["passkey", "remove", "passkey-1"]);
    assert!(!output.status.success());
    let listed = stdout(&server.succeeds(&["passkey", "list"]));
    assert!(listed.contains("passkey-1"), "{listed}");
}
