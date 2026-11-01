//! `warden-server agent add`, the real binary: a bearer key reaches stdout and
//! nothing else does, and the owner is told what to run on the agent machine.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;
use warden_broker::audience;

const PUBLIC_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh0zJ+xlPfFH6uwtZmJ2O9GrkMxjqMwPQTsBVmbbBrE bot@host";

const SERVER: &str = "https://warden-api.example.ts.net";

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

    fn audience_path(&self) -> PathBuf {
        self.path("audience")
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_warden-server"))
            .args(args)
            .env("WARDEN_DB_PATH", self.path("db.sqlite"))
            .env("WARDEN_AUDIT_PATH", self.path("audit.log"))
            .env("WARDEN_AUDIENCE_PATH", self.audience_path())
            .output()
            .unwrap()
    }

    /// The agents `agent list` shows.
    fn agents(&self) -> String {
        let list = self.run(&["agent", "list"]);
        assert!(list.status.success(), "{}", text(&list.stderr));
        text(&list.stdout)
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn create_audience(path: &Path) -> String {
    audience::load_or_create_blocking(path)
        .unwrap()
        .as_str()
        .to_owned()
}

/// Piped into a password manager, stdout must be the key and only the key,
/// and the key must appear nowhere else.
#[test]
fn bearer_key_goes_to_stdout_alone() {
    let server = Server::new();
    let out = server.run(&["agent", "add", "build-agent", "--server", SERVER]);
    assert!(out.status.success(), "{}", text(&out.stderr));

    let stdout = text(&out.stdout);
    let key = stdout.strip_suffix('\n').unwrap();
    assert!(key.starts_with("wdn_") && key.len() == 47, "{stdout}");
    assert!(!key.contains('\n'), "{stdout}");

    let stderr = text(&out.stderr);
    assert!(!stderr.contains(key), "{stderr}");
    assert!(!stderr.contains("wdn_"), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "warden login --server {SERVER} --agent build-agent\n"
        )),
        "{stderr}"
    );
    assert!(stderr.contains("WARDEN_AGENT_KEY"), "{stderr}");
}

#[test]
fn bearer_without_server_shows_what_to_fill_in() {
    let server = Server::new();
    let out = server.run(&["agent", "add", "build-agent"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("warden login --server <agent-api-url> --agent build-agent\n"),
        "{stderr}"
    );
    assert!(stderr.contains("Replace <agent-api-url>"), "{stderr}");
}

#[test]
fn signing_agent_is_told_the_exact_command_with_the_audience() {
    let server = Server::new();
    let audience = create_audience(&server.audience_path());
    let out = server.run(&[
        "agent",
        "add",
        "build-agent",
        "--server",
        SERVER,
        "--public-key",
        PUBLIC_KEY,
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(out.stdout, [] as [u8; 0]);
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains(&format!(
            "warden login --server {SERVER} --agent build-agent --ssh-key \
             ~/.ssh/build-agent.pub --audience {audience}\n"
        )),
        "{stderr}"
    );
}

/// Before the server first starts there is no audience: the agent is still
/// added, the command leaves the pin out, and `agent add` does not create a
/// file that belongs to the server.
#[test]
fn signing_agent_without_an_audience_yet_is_added_without_the_pin() {
    let server = Server::new();
    let out = server.run(&[
        "agent",
        "add",
        "build-agent",
        "--server",
        SERVER,
        "--public-key",
        PUBLIC_KEY,
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("does not pin"), "{stderr}");
    assert!(
        stderr.contains("--ssh-key ~/.ssh/build-agent.pub\n"),
        "{stderr}"
    );
    assert!(!stderr.contains("--audience"), "{stderr}");
    assert!(!server.audience_path().exists());
    assert!(server.agents().contains("build-agent"));
}

/// A bad URL is refused before an agent exists, so no key is spent on it.
#[test]
fn bad_server_url_is_refused_before_the_agent_is_made() {
    let server = Server::new();
    let out = server.run(&[
        "agent",
        "add",
        "build-agent",
        "--server",
        "http://warden-api.example.ts.net",
    ]);
    assert!(!out.status.success());
    assert_eq!(out.stdout, [] as [u8; 0]);
    let stderr = text(&out.stderr);
    assert!(stderr.contains("https"), "{stderr}");
    assert!(!server.path("db.sqlite").exists());
}
