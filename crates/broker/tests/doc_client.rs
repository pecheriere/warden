//! The worked POSIX shell client of `docs/agent-protocol.md` (section 8),
//! run as published against a real broker, signing through a real
//! `ssh-agent`: the document's client must keep working.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ssh_key::{Algorithm, EcdsaCurve, LineEnding};
use tokio::process::{Child, Command};
use warden_broker::testkit::{CapturingNotifier, TestBroker};
use warden_broker_proto::Window;

const DOC: &str = include_str!("../../../docs/agent-protocol.md");

/// The `warden-call` script, exactly as the document shows it.
fn warden_call() -> &'static str {
    const OPENING: &str = "```sh\n#!/bin/sh\n# warden-call METHOD TARGET [BODY_FILE]\n";
    let start = DOC.find(OPENING).expect("section 8 shows warden-call") + "```sh\n".len();
    let len = DOC[start..].find("\n```\n").expect("the block is closed") + 1;
    &DOC[start..start + len]
}

/// Whether `tool` can be run; `false` only if it is not installed.
async fn installed(tool: &str) -> bool {
    match Command::new(tool)
        .arg("-?")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
    {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => panic!("{tool}: {e}"),
    }
}

/// An `ssh-agent` on a socket in `dir`, killed on drop.
struct SshAgent {
    socket: PathBuf,
    _child: Child,
}

impl SshAgent {
    async fn start(dir: &Path) -> Self {
        let socket = dir.join("agent.sock");
        let child = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("start ssh-agent");
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(socket.exists(), "ssh-agent did not create its socket");
        Self {
            socket,
            _child: child,
        }
    }

    /// Load the private key file `key`, then delete it, so that only the
    /// agent can sign (`ssh-keygen` would otherwise fall back to the file).
    async fn add(&self, key: &Path) {
        let out = Command::new("ssh-add")
            .arg(key)
            .env("SSH_AUTH_SOCK", &self.socket)
            .output()
            .await
            .expect("run ssh-add");
        assert!(
            out.status.success(),
            "ssh-add: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        std::fs::remove_file(key).unwrap();
    }
}

/// A shell session set up as the document's example session does.
struct Session {
    dir: PathBuf,
    env: Vec<(&'static str, String)>,
}

/// What one `warden-call` printed: the response body and the HTTP status.
struct Called {
    body: String,
    status: u16,
}

impl Called {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("{e}: {}", self.body))
    }
}

impl Session {
    async fn call(&self, args: &[&str]) -> Called {
        let out = Command::new("sh")
            .arg(self.dir.join("warden-call"))
            .args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .current_dir(&self.dir)
            .output()
            .await
            .expect("run warden-call");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(out.status.success(), "warden-call {args:?}: {stderr}");
        let status = stderr
            .lines()
            .find_map(|line| line.strip_prefix("HTTP "))
            .and_then(|code| code.trim().parse().ok())
            .unwrap_or_else(|| panic!("no HTTP status on stderr: {stderr}"));
        Called {
            body: String::from_utf8(out.stdout).unwrap(),
            status,
        }
    }
}

async fn run_session(algorithm: Algorithm) {
    let broker = TestBroker::new().await;
    // The script signs with the real clock.
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    broker.clock.set(i64::try_from(now.as_secs()).unwrap());
    let api = broker.spawn().await.api;
    let key = broker.add_signing_agent("build-bot", algorithm).await;

    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name);
    std::fs::write(path("warden-call"), warden_call()).unwrap();
    std::fs::write(
        path("signing-key"),
        key.to_openssh(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    std::fs::set_permissions(path("signing-key"), std::fs::Permissions::from_mode(0o600)).unwrap();
    let public = format!("{}\n", key.public_key().to_openssh().unwrap());
    std::fs::write(path("signing-key.pub"), public).unwrap();
    let agent = SshAgent::start(dir.path()).await;
    agent.add(&path("signing-key")).await;

    let url = api.as_str().trim_end_matches('/').to_owned();
    // The audience, read once at setup as the document's session does.
    let info = Command::new("curl")
        .args(["-sS", &format!("{url}/v1/info")])
        .output()
        .await
        .unwrap();
    let info: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    let audience = info["audience"].as_str().unwrap().to_owned();
    assert_eq!(audience, broker.state().audience.as_str());

    let session = Session {
        dir: dir.path().to_owned(),
        env: vec![
            ("WARDEN_URL", url),
            ("WARDEN_AGENT", "build-bot".to_owned()),
            (
                "WARDEN_PUBKEY",
                path("signing-key.pub").display().to_string(),
            ),
            ("WARDEN_AUDIENCE", audience),
            ("SSH_AUTH_SOCK", agent.socket.display().to_string()),
        ],
    };

    let grants = session.call(&["GET", "/v1/grants"]).await;
    assert_eq!(grants.status, 200, "{}", grants.body);
    assert_eq!(grants.json(), serde_json::json!([]));

    let body = serde_json::to_vec(&TestBroker::pi_request(
        "restart the backup job",
        Window::M30,
    ))
    .unwrap();
    std::fs::write(path("req.json"), body).unwrap();
    let created = session.call(&["POST", "/v1/requests", "req.json"]).await;
    assert_eq!(created.status, 201, "{}", created.body);
    let id = created.json()["id"].as_str().unwrap().to_owned();
    let token = CapturingNotifier::token(&broker.capture.next().await);

    let pending = session
        .call(&["GET", &format!("/v1/requests/{id}?wait=0")])
        .await;
    assert_eq!(pending.status, 200, "{}", pending.body);
    assert_eq!(pending.json()["status"], "pending");

    assert!(
        broker
            .approve(&token, Window::M15)
            .await
            .status
            .is_success()
    );
    let approved = session
        .call(&["GET", &format!("/v1/requests/{id}?wait=30")])
        .await;
    assert_eq!(approved.status, 200, "{}", approved.body);
    assert_eq!(approved.json()["status"], "approved");
    let grant = approved.json()["grant_id"].as_str().unwrap().to_owned();

    let revoked = session
        .call(&["POST", &format!("/v1/grants/{grant}/revoke")])
        .await;
    assert_eq!(revoked.status, 204, "{}", revoked.body);
    assert_eq!(revoked.body, "");
    let grants = session.call(&["GET", "/v1/grants"]).await;
    assert_eq!(grants.json(), serde_json::json!([]));
}

#[tokio::test]
async fn documented_shell_client_works() {
    for tool in ["ssh-keygen", "ssh-agent", "curl"] {
        if !installed(tool).await {
            eprintln!("{tool} not installed; skipping the shell client test");
            return;
        }
    }
    run_session(Algorithm::Ed25519).await;
    run_session(Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    })
    .await;
}
