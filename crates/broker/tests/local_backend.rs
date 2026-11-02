//! The whole flow against the local backend: an in-process broker reading real
//! files, and the real `warden-server` refusing to start or reporting through
//! doctor.

use std::fs::{self, Permissions};
use std::io::{BufRead as _, BufReader};
use std::net::TcpListener;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, Certificate, HashAlg, LineEnding, PrivateKey};
use tempfile::TempDir;
use warden_broker::audit::AuditLog;
use warden_broker::config::LocalSettings;
use warden_broker::policy::LocalBackend;
use warden_broker::store;
use warden_broker::testkit::{CapturingNotifier, HttpsUpstream, TestBroker, TestResponse};
use warden_broker_proto::{CreatedResponse, GrantAccess, Id, RequestStatus, Window};

const CREDENTIAL: &str = "local-backend-credential-do-not-leak";

/// The backend's files in a private directory, at their real paths.
struct Files {
    _guard: TempDir,
    root: PathBuf,
    settings: LocalSettings,
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}

impl Files {
    fn new() -> Self {
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
    fn policy(&self, text: &str) {
        fs::write(
            &self.settings.policy_file,
            format!("{text}\n[end_of_policy]\n"),
        )
        .unwrap();
        chmod(&self.settings.policy_file, 0o600);
    }

    fn secret(&self, name: &str, content: &str) {
        let path = self.secret_path(name);
        fs::write(&path, content).unwrap();
        chmod(&path, 0o600);
    }

    fn secret_path(&self, name: &str) -> PathBuf {
        self.settings.secrets_dir.join(name)
    }
}

fn host_key_line() -> String {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap()
}

/// `[api_secrets.svc]` for `upstream`, trusting its CA, with extra settings.
fn api_entry(upstream: &HttpsUpstream, extra: &str) -> String {
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

/// A broker reading `files`, opened as the server opens it, and an agent.
async fn broker_on(files: &Files) -> (TestBroker, String) {
    let audit = Arc::new(
        AuditLog::open(&files.root.join("backend-audit.jsonl"))
            .await
            .unwrap(),
    );
    let backend = LocalBackend::open(&files.settings, audit).await.unwrap();
    let broker = TestBroker::with_secret_backend(Arc::new(backend)).await;
    let key = broker.add_agent("bot").await;
    (broker, key)
}

/// What the backend wrote to the audit log.
fn backend_audit(files: &Files) -> String {
    fs::read_to_string(files.root.join("backend-audit.jsonl")).unwrap()
}

async fn approve_api(broker: &TestBroker, secret: &str) -> Id {
    let req = TestBroker::api_request(secret, "call the test api", Window::M30);
    let (created, token) = broker.create_request("bot", req).await;
    let done = broker.approve(&token, Window::M30).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    let agent = "bot".parse().unwrap();
    match broker
        .state()
        .requests
        .status(&agent, &created.id, std::time::Duration::ZERO)
        .await
        .unwrap()
    {
        RequestStatus::Approved(view) => view.grant_id,
        other => panic!("expected approved, got {other:?}"),
    }
}

async fn call(broker: &TestBroker, key: &str, grant: &Id, url: &str) -> TestResponse {
    broker
        .api_post_json(
            key,
            &format!("/v1/grants/{grant}/http"),
            &json!({"method": "GET", "url": url, "headers": []}),
        )
        .await
}

#[tokio::test]
async fn api_flow_request_approve_call_redact() {
    let upstream = HttpsUpstream::start().await;
    let files = Files::new();
    files.policy(&api_entry(&upstream, ""));
    files.secret("svc-token", &format!("{CREDENTIAL}\n"));
    let (broker, key) = broker_on(&files).await;
    let grant = approve_api(&broker, "svc").await;

    let answer = call(&broker, &key, &grant, &upstream.url("/echo")).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    let encoded = answer.json()["body_b64"].as_str().unwrap().to_owned();
    let echoed = String::from_utf8(STANDARD.decode(encoded).unwrap()).unwrap();
    assert!(echoed.contains("[REDACTED]"), "{echoed}");
    assert!(!echoed.contains(CREDENTIAL), "{echoed}");
    assert!(!answer.body.contains(CREDENTIAL), "{}", answer.body);

    let received = upstream.received();
    let sent = received.last().unwrap();
    assert_eq!(
        sent.headers["authorization"],
        format!("Bearer {CREDENTIAL}").as_str()
    );

    let audit = fs::read_to_string(broker.audit_path()).unwrap();
    assert!(audit.contains("proxy_call"), "{audit}");
    assert!(!audit.contains(CREDENTIAL), "{audit}");
}

#[tokio::test]
async fn ssh_flow_signs_with_the_local_ca() {
    let files = Files::new();
    let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    files.secret("ssh-ca", &ca.to_openssh(LineEnding::LF).unwrap());
    files.policy(&format!(
        r#"
[ca]
private_key_file = "ssh-ca"

[targets.pi]
address = "192.0.2.10"
mode = "cert"
users = ["alice"]
max_window = "1h"
host_keys = ["{}"]
"#,
        host_key_line()
    ));
    let (broker, key) = broker_on(&files).await;
    let request = TestBroker::pi_request("restart the backup job", Window::M30);
    let created = broker
        .api_post_json(
            &key,
            "/v1/requests",
            &serde_json::to_value(request).unwrap(),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let created: CreatedResponse = serde_json::from_str(&created.body).unwrap();
    let token = CapturingNotifier::token(&broker.capture.next().await);
    let done = broker.approve(&token, Window::M30).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);

    let status = broker
        .api_get(&key, &format!("/v1/requests/{}?wait=0", created.id))
        .await;
    let status: RequestStatus = serde_json::from_str(&status.body).unwrap();
    let RequestStatus::Approved(view) = status else {
        panic!("expected approved, got {status:?}");
    };
    let GrantAccess::Ssh(ssh) = &view.access else {
        panic!("expected an ssh grant");
    };
    let certificate = Certificate::from_openssh(&ssh.certificate).unwrap();
    assert_eq!(certificate.valid_principals(), ["warden:pi:alice"]);
    assert_eq!(
        certificate.signature_key().fingerprint(HashAlg::Sha256),
        ca.public_key().fingerprint(HashAlg::Sha256)
    );
}

/// A policy edit applies at once: a grant for the old destination stops
/// working without a restart, which is what revocation by edit relies on.
#[tokio::test]
async fn a_policy_edit_invalidates_a_grant_at_once() {
    let upstream = HttpsUpstream::start().await;
    let files = Files::new();
    files.policy(&api_entry(&upstream, ""));
    files.secret("svc-token", CREDENTIAL);
    let (broker, key) = broker_on(&files).await;
    let grant = approve_api(&broker, "svc").await;
    let url = upstream.url("/anything");
    assert_eq!(
        call(&broker, &key, &grant, &url).await.status,
        StatusCode::OK
    );

    files.policy(&api_entry(&upstream, "path_prefix = \"/narrower/\""));
    let sent_before = upstream.received().len();
    let refused = call(&broker, &key, &grant, &url).await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
    assert_eq!(upstream.received().len(), sent_before);

    // Removing the entry is revoking it.
    files.policy("");
    let gone = call(&broker, &key, &grant, &url).await;
    assert_eq!(gone.status, StatusCode::CONFLICT, "{}", gone.body);
    assert_eq!(upstream.received().len(), sent_before);
}

/// Each change that makes the files unsafe refuses the next call, sends
/// nothing to the upstream and is audited without a secret.
#[tokio::test]
async fn unsafe_files_refuse_the_call_and_are_audited() {
    let upstream = HttpsUpstream::start().await;
    let files = Files::new();
    files.policy(&api_entry(&upstream, ""));
    files.secret("svc-token", CREDENTIAL);
    let (broker, key) = broker_on(&files).await;
    let grant = approve_api(&broker, "svc").await;
    let url = upstream.url("/anything");
    let token = files.secret_path("svc-token");
    let sent_before = upstream.received().len();

    let refused = |expected: StatusCode, response: TestResponse| {
        assert_eq!(response.status, expected, "{}", response.body);
        assert!(!response.body.contains(CREDENTIAL), "{}", response.body);
    };

    chmod(&token, 0o640);
    refused(
        StatusCode::CONFLICT,
        call(&broker, &key, &grant, &url).await,
    );
    assert!(backend_audit(&files).contains("group or others"));
    chmod(&token, 0o600);

    let outside = files.root.join("outside");
    fs::write(&outside, CREDENTIAL).unwrap();
    chmod(&outside, 0o600);
    fs::remove_file(&token).unwrap();
    symlink(&outside, &token).unwrap();
    refused(
        StatusCode::CONFLICT,
        call(&broker, &key, &grant, &url).await,
    );
    assert!(backend_audit(&files).contains("symbolic link"));
    fs::remove_file(&token).unwrap();

    refused(
        StatusCode::CONFLICT,
        call(&broker, &key, &grant, &url).await,
    );
    assert!(backend_audit(&files).contains("does not exist"));
    files.secret("svc-token", CREDENTIAL);

    chmod(&files.settings.secrets_dir, 0o750);
    refused(
        StatusCode::CONFLICT,
        call(&broker, &key, &grant, &url).await,
    );
    chmod(&files.settings.secrets_dir, 0o700);

    chmod(&files.settings.policy_file, 0o666);
    refused(
        StatusCode::SERVICE_UNAVAILABLE,
        call(&broker, &key, &grant, &url).await,
    );
    assert!(backend_audit(&files).contains("written by group or others"));
    chmod(&files.settings.policy_file, 0o600);

    assert_eq!(upstream.received().len(), sent_before);
    assert!(!backend_audit(&files).contains(CREDENTIAL));
    assert_eq!(
        call(&broker, &key, &grant, &url).await.status,
        StatusCode::OK
    );
}

/// A request for something the policy cannot vouch for never reaches the owner.
#[tokio::test]
async fn an_unsafe_secret_refuses_the_request_before_any_notification() {
    let upstream = HttpsUpstream::start().await;
    let files = Files::new();
    files.policy(&api_entry(&upstream, ""));
    files.secret("svc-token", CREDENTIAL);
    let (broker, key) = broker_on(&files).await;
    chmod(&files.secret_path("svc-token"), 0o644);

    let request = TestBroker::api_request("svc", "call the test api", Window::M30);
    let answer = broker
        .api_post_json(
            &key,
            "/v1/requests",
            &serde_json::to_value(request).unwrap(),
        )
        .await;
    assert_ne!(answer.status, StatusCode::CREATED, "{}", answer.body);
    assert_eq!(broker.capture.rung().len(), 0);
    assert!(backend_audit(&files).contains("svc"));
}

/// The real binary, with its files in a temporary directory.
struct Server {
    files: Files,
    api: TcpListener,
    approval: TcpListener,
}

impl Server {
    async fn new() -> Self {
        let files = Files::new();
        store::open(&files.root.join("warden.db"))
            .await
            .unwrap()
            .close()
            .await;
        for file in ["audit.jsonl", "audience"] {
            let path = files.root.join(file);
            fs::write(&path, "").unwrap();
            chmod(&path, 0o600);
        }
        Self {
            files,
            api: TcpListener::bind("127.0.0.1:0").unwrap(),
            approval: TcpListener::bind("127.0.0.1:0").unwrap(),
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let path = |file: &str| self.files.root.join(file);
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_warden-server"));
        cmd.env_clear()
            .env("WARDEN_SECRET_BACKEND", "local")
            .env("WARDEN_LOCAL_POLICY_FILE", &self.files.settings.policy_file)
            .env("WARDEN_LOCAL_SECRETS_DIR", &self.files.settings.secrets_dir)
            .env("WARDEN_DB_PATH", path("warden.db"))
            .env("WARDEN_AUDIT_PATH", path("audit.jsonl"))
            .env("WARDEN_AUDIENCE_PATH", path("audience"))
            .env("WARDEN_PUBLIC_URL", "https://warden.example.ts.net")
            .env("WARDEN_OWNER_LOGIN", "owner@example.com")
            .env("WARDEN_NOTIFY", "ntfy")
            .env("WARDEN_NOTIFY_NTFY_URL", "https://ntfy.example.com/topic")
            .env(
                "WARDEN_API_LISTEN",
                self.api.local_addr().unwrap().to_string(),
            )
            .env(
                "WARDEN_APPROVAL_LISTEN",
                self.approval.local_addr().unwrap().to_string(),
            )
            .args(args)
            .stdin(Stdio::null());
        cmd
    }

    fn audit(&self) -> String {
        fs::read_to_string(self.files.root.join("audit.jsonl")).unwrap()
    }
}

fn line_of<'a>(stdout: &'a str, check: &str) -> &'a str {
    stdout
        .lines()
        .find(|l| l.split_whitespace().any(|word| word == check))
        .unwrap_or_else(|| panic!("no line for {check} in {stdout}"))
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

const API_ONLY: &str = r#"
[api_secrets.svc]
website = "https://api.example.com"
credential_file = "svc-token"
max_window = "1h"
"#;

#[tokio::test(flavor = "multi_thread")]
async fn the_server_refuses_to_start_on_loose_permissions_and_audits_it() {
    let server = Server::new().await;
    server.files.policy(API_ONLY);
    server.files.secret("svc-token", CREDENTIAL);
    chmod(&server.files.secret_path("svc-token"), 0o644);
    let output = server.command(&["serve"]).output().unwrap();
    assert!(!output.status.success());
    let shown = format!("{}{}", stdout(&output), stderr(&output));
    assert!(shown.contains("group or others"), "{shown}");
    assert!(!shown.contains(CREDENTIAL), "{shown}");
    let audit = server.audit();
    assert!(audit.contains("local secret backend"), "{audit}");
    assert!(!audit.contains(CREDENTIAL), "{audit}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_server_refuses_to_start_on_an_invalid_policy() {
    for (name, policy) in [
        ("missing file", None),
        ("syntax", Some("[targets")),
        (
            "pasted secret",
            Some("credential = \"local-backend-credential-do-not-leak\""),
        ),
        ("needs a CA", Some("[targets.pi]\nmode = \"relay\"\n")),
    ] {
        let server = Server::new().await;
        if let Some(policy) = policy {
            server.files.policy(policy);
        }
        let output = server.command(&["serve"]).output().unwrap();
        assert!(!output.status.success(), "{name}");
        let shown = format!("{}{}", stdout(&output), stderr(&output));
        assert!(!shown.contains(CREDENTIAL), "{name}: {shown}");
        assert!(!server.audit().contains(CREDENTIAL), "{name}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn doctor_passes_a_good_setup_and_says_what_is_lost() {
    let server = Server::new().await;
    server.files.policy(API_ONLY);
    server.files.secret("svc-token", CREDENTIAL);
    let output = server.command(&["doctor"]).output().unwrap();
    let text = stdout(&output);
    for check in ["config", "local.policy", "local.entries", "ssh-ca"] {
        assert!(line_of(&text, check).starts_with("pass"), "{text}");
    }
    assert!(
        line_of(&text, "local.host-boundary").starts_with("COULD NOT CHECK"),
        "{text}"
    );
    assert!(!text.contains("connect."), "{text}");
    assert!(!text.contains(CREDENTIAL), "{text}");
    assert_eq!(server.audit(), "", "doctor writes nothing to the audit log");
}

#[tokio::test(flavor = "multi_thread")]
async fn doctor_fails_loose_permissions_and_a_missing_policy() {
    let server = Server::new().await;
    server.files.policy(API_ONLY);
    server.files.secret("svc-token", CREDENTIAL);
    chmod(&server.files.secret_path("svc-token"), 0o644);
    let output = server.command(&["doctor"]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(
        line_of(&text, "local.entries").starts_with("FAIL"),
        "{text}"
    );
    assert!(text.contains("group or others"), "{text}");
    assert!(!text.contains(CREDENTIAL), "{text}");
    assert_eq!(server.audit(), "", "doctor audits no refusal");

    fs::remove_file(&server.files.settings.policy_file).unwrap();
    let output = server.command(&["doctor"]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(line_of(&text, "local.policy").starts_with("FAIL"), "{text}");
    assert!(
        line_of(&text, "local.entries").starts_with("COULD NOT CHECK"),
        "{text}"
    );
}

/// Runs `command` until it says it listens, stops it, and returns that line.
fn listening_line(mut command: Command) -> String {
    let mut child = command.stdout(Stdio::piped()).spawn().unwrap();
    let lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let line = lines
        .map(Result::unwrap)
        .find(|line| line.contains("warden-server listening"));
    child.kill().unwrap();
    child.wait().unwrap();
    line.expect("the server exited without listening")
}

/// The startup line of an existing 1Password setup stays what it was.
#[tokio::test(flavor = "multi_thread")]
async fn the_startup_line_names_the_vault_or_the_local_backend() {
    let server = Server::new().await;
    server.files.policy(API_ONLY);
    server.files.secret("svc-token", CREDENTIAL);
    // Doctor's fixture is an empty file; the server creates its own.
    fs::remove_file(server.files.root.join("audience")).unwrap();
    let mut local = server.command(&["serve"]);
    local
        .env("WARDEN_API_LISTEN", "127.0.0.1:0")
        .env("WARDEN_APPROVAL_LISTEN", "127.0.0.1:0");
    let line = listening_line(local);
    assert!(line.contains("secret_backend"), "{line}");
    assert!(!line.contains("vault="), "{line}");

    let mut connect = server.command(&["serve"]);
    connect
        .env_remove("WARDEN_SECRET_BACKEND")
        .env_remove("WARDEN_LOCAL_POLICY_FILE")
        .env_remove("WARDEN_LOCAL_SECRETS_DIR")
        .env("WARDEN_OP_CONNECT_URL", "http://192.0.2.1:8080")
        .env("WARDEN_OP_CONNECT_TOKEN", "connect-token-not-used")
        .env("WARDEN_API_LISTEN", "127.0.0.1:0")
        .env("WARDEN_APPROVAL_LISTEN", "127.0.0.1:0");
    let line = listening_line(connect);
    assert!(line.contains("vault=Warden"), "{line}");
    assert!(!line.contains("secret_backend"), "{line}");
}

/// A policy file cut short stops the real server, whatever it still parses as.
#[tokio::test(flavor = "multi_thread")]
async fn the_server_refuses_to_start_on_a_policy_cut_short() {
    let server = Server::new().await;
    server.files.secret("svc-token", CREDENTIAL);
    fs::write(&server.files.settings.policy_file, API_ONLY).unwrap();
    chmod(&server.files.settings.policy_file, 0o600);
    let output = server.command(&["serve"]).output().unwrap();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("cut short"), "{}", stderr(&output));
    assert!(server.audit().contains("cut short"), "{}", server.audit());
}

/// The weaker backend needs asking for: without the setting its files mean
/// nothing, and the server names what is wrong rather than falling back.
#[tokio::test(flavor = "multi_thread")]
async fn the_local_files_are_refused_without_the_explicit_setting() {
    let server = Server::new().await;
    server.files.policy(API_ONLY);
    server.files.secret("svc-token", CREDENTIAL);
    let mut command = server.command(&["serve"]);
    command.env_remove("WARDEN_SECRET_BACKEND");
    let output = command.output().unwrap();
    assert!(!output.status.success());
    let shown = stderr(&output);
    assert!(shown.contains("WARDEN_LOCAL_POLICY_FILE"), "{shown}");
}
