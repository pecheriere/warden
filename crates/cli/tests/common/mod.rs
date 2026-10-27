//! The harness shared by the end-to-end tests: the real `warden` binary in
//! a private, throwaway environment, driven against an in-process broker.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use tempfile::TempDir;
use warden_broker::testkit::TestBroker;
use warden_broker::testkit::sshd::current_user;
use warden_broker_proto::Window;

pub fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

pub fn write_private(path: &Path, contents: &str) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(contents.as_bytes()).unwrap();
}

/// Everything the CLI writes lives under one short temporary root.
pub struct Cli {
    pub root: TempDir,
    key: String,
}

/// State and temp dirs contain a space, like macOS `~/Library/Application Support`:
/// paths handed to ssh options must survive ssh's whitespace splitting.
pub const STATE_DIR: &str = "app state";
pub const TMP_DIR: &str = "my tmp";

impl Cli {
    pub fn new(server: &url::Url, agent: &str, key: String) -> Self {
        let root = tempfile::Builder::new()
            .prefix("wdn")
            .tempdir_in("/tmp")
            .unwrap();
        for sub in ["config/warden", STATE_DIR, TMP_DIR] {
            fs::create_dir_all(root.path().join(sub)).unwrap();
        }
        write_private(
            &root.path().join("config/warden/config.toml"),
            &format!("server = \"{server}\"\nagent = \"{agent}\"\n"),
        );
        Self { root, key }
    }

    pub fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_warden"));
        cmd.env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env("XDG_STATE_HOME", self.root.path().join(STATE_DIR))
            .env("TMPDIR", self.root.path().join(TMP_DIR))
            .env("WARDEN_AGENT_KEY", &self.key)
            .stdin(Stdio::null());
        cmd
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }

    /// Kill every per-grant agent the CLI left running.
    fn kill_agents(&self) {
        let grants = self.root.path().join(STATE_DIR).join("warden/grants");
        let Ok(entries) = fs::read_dir(grants) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(raw) = fs::read_to_string(entry.path().join("grant.json")) else {
                continue;
            };
            let record: serde_json::Value = serde_json::from_str(&raw).unwrap();
            let _ = Command::new("ssh-agent")
                .arg("-k")
                .env("SSH_AGENT_PID", record["pid"].to_string())
                .env("SSH_AUTH_SOCK", record["socket"].as_str().unwrap())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }

    /// Every file under the CLI's directories containing `needle`.
    pub fn files_containing(&self, needle: &str) -> Vec<PathBuf> {
        fn walk(dir: &Path, needle: &[u8], hits: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                let kind = entry.file_type().unwrap();
                if kind.is_dir() {
                    walk(&path, needle, hits);
                } else if kind.is_file() {
                    let bytes = fs::read(&path).unwrap();
                    if bytes.windows(needle.len()).any(|w| w == needle) {
                        hits.push(path);
                    }
                }
            }
        }
        let mut hits = Vec::new();
        walk(self.root.path(), needle.as_bytes(), &mut hits);
        hits
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        self.kill_agents();
    }
}

/// Start `warden request ssh <target> --user <current user> …` in the
/// background.
pub fn spawn_request(cli: &Cli, target: &str) -> Child {
    let user = current_user();
    cli.command()
        .args([
            "request",
            "ssh",
            target,
            "--user",
            &user,
            "--for",
            "15m",
            "--goal",
            "run the e2e test",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Approve the request behind `token` as the owner.
pub async fn approve(broker: &TestBroker, token: &str) {
    let approved = broker.approve(token, Window::M15).await;
    assert!(approved.status.is_success(), "{}", approved.body);
}

/// Wait for a `warden request` to succeed; return the grant id it printed
/// and its stderr.
pub async fn approved_grant(child: Child) -> (String, String) {
    let out = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("fingerprint ") && stderr.contains("waiting for approval"),
        "{stderr}"
    );
    let rest = stdout
        .strip_prefix("approved: grant ")
        .unwrap_or_else(|| panic!("unexpected stdout: {stdout}"));
    let (grant, until) = rest.split_once(" until ").unwrap();
    assert!(!until.trim().is_empty());
    (grant.to_owned(), stderr)
}
