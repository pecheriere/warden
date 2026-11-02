//! The real `warden-server doctor` binary, against a wiremock Connect server
//! and files in a temporary directory.

use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::json;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use warden_broker::store;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "connect-token-do-not-leak-0123456789";
const VAULT_ID: &str = "vault0000000000000000000a1";

/// A deployment in a directory: the server's files, and sockets standing in
/// for its listeners.
struct Deployment {
    dir: tempfile::TempDir,
    api: TcpListener,
    approval: TcpListener,
    connect: MockServer,
}

impl Deployment {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        store::open(&dir.path().join("warden.db"))
            .await
            .unwrap()
            .close()
            .await;
        for file in ["audit.jsonl", "audience"] {
            let path = dir.path().join(file);
            fs::write(&path, "").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let connect = MockServer::start().await;
        let pem = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap()
            .to_string();
        let routes = [
            (
                "/v1/vaults".to_owned(),
                json!([{"id": VAULT_ID, "name": "Warden"}]),
            ),
            (
                format!("/v1/vaults/{VAULT_ID}/items"),
                json!([{"id": "ca1", "title": "warden-ssh-ca", "tags": ["warden:ssh-ca"]}]),
            ),
            (
                format!("/v1/vaults/{VAULT_ID}/items/ca1"),
                json!({"fields": [{"id": "private_key", "value": pem}]}),
            ),
        ];
        for (at, body) in routes {
            Mock::given(path(at))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&connect)
                .await;
        }
        Self {
            dir,
            api: TcpListener::bind("127.0.0.1:0").unwrap(),
            approval: TcpListener::bind("127.0.0.1:0").unwrap(),
            connect,
        }
    }

    fn path(&self, file: &str) -> String {
        self.dir.path().join(file).display().to_string()
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_warden-server"));
        cmd.env_clear()
            .env("WARDEN_DB_PATH", self.path("warden.db"))
            .env("WARDEN_AUDIT_PATH", self.path("audit.jsonl"))
            .env("WARDEN_AUDIENCE_PATH", self.path("audience"))
            .env("WARDEN_PUBLIC_URL", "https://warden.example.ts.net")
            .env("WARDEN_OWNER_LOGIN", "owner@example.com")
            .env("WARDEN_OP_CONNECT_URL", self.connect.uri())
            .env("WARDEN_OP_CONNECT_TOKEN", TOKEN)
            .env("WARDEN_NOTIFY", "ntfy")
            .env(
                "WARDEN_NOTIFY_NTFY_URL",
                format!("{}/topic", self.connect.uri()),
            )
            .env(
                "WARDEN_API_LISTEN",
                self.api.local_addr().unwrap().to_string(),
            )
            .env(
                "WARDEN_APPROVAL_LISTEN",
                self.approval.local_addr().unwrap().to_string(),
            )
            .stdin(Stdio::null());
        cmd
    }

    async fn enroll_a_passkey(&self) {
        let pool = store::open(&self.dir.path().join("warden.db"))
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO passkeys (id, label, credential, created_at) \
             VALUES ('a', 'phone', 'c', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
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

/// The content of the file `name` in `dir`.
fn content(dir: &Path, name: &str) -> Vec<u8> {
    fs::read(dir.join(name)).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_working_setup_exits_0_and_lists_what_only_the_owner_can_check() {
    let deployment = Deployment::new().await;
    deployment.enroll_a_passkey().await;
    let output = deployment.command().arg("doctor").output().unwrap();
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{text}");
    assert!(!text.contains("FAIL"), "{text}");
    assert!(text.contains("Not checked, so not passed: 4."), "{text}");
    assert!(text.contains("\n  tailscale.funnel-off: "), "{text}");
    for check in [
        "config",
        "connect.vault",
        "ssh-ca",
        "passkey",
        "listener.api",
    ] {
        assert!(line_of(&text, check).starts_with("pass"), "{text}");
    }
    for check in ["connect.token-read-only", "tailscale.funnel-off", "notify"] {
        assert!(
            line_of(&text, check).starts_with("COULD NOT CHECK"),
            "{text}"
        );
    }
    assert!(!text.contains(TOKEN), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn strict_exits_7_when_nothing_failed_but_something_was_not_checked() {
    let deployment = Deployment::new().await;
    deployment.enroll_a_passkey().await;
    let output = deployment
        .command()
        .args(["doctor", "--strict"])
        .output()
        .unwrap();
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(7), "{text}");
    assert!(!text.contains("FAIL"), "{text}");
    assert!(text.contains("Exit code 7."), "{text}");
    assert!(text.contains("\n  tailscale.funnel-off: "), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failure_exits_1_with_or_without_strict() {
    // No passkey is enrolled.
    let deployment = Deployment::new().await;
    for args in [&["doctor"][..], &["doctor", "--strict"][..]] {
        let output = deployment.command().args(args).output().unwrap();
        let text = stdout(&output);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {text}");
        assert!(line_of(&text, "passkey").starts_with("FAIL"), "{text}");
        assert!(text.contains("Exit code 1."), "{text}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn doctor_changes_no_data_and_sends_nothing_without_the_flag() {
    let deployment = Deployment::new().await;
    let dir = deployment.dir.path();
    let files = ["warden.db", "audit.jsonl", "audience"];
    let before = files.map(|name| content(dir, name));
    let output = deployment.command().arg("doctor").output().unwrap();
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(line_of(&text, "passkey").starts_with("FAIL"), "{text}");
    assert!(text.contains("sent no notification"), "{text}");
    assert_eq!(files.map(|name| content(dir, name)), before);
    let requests = deployment.connect.received_requests().await.unwrap();
    assert!(
        requests.iter().all(|r| r.method.as_str() == "GET"),
        "{requests:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_flag_sends_one_notification_and_the_output_says_so() {
    let deployment = Deployment::new().await;
    Mock::given(path("/topic"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&deployment.connect)
        .await;
    let dir = deployment.dir.path();
    let audit_before = content(dir, "audit.jsonl");
    let output = deployment
        .command()
        .args(["doctor", "--send-test-notification"])
        .output()
        .unwrap();
    let text = stdout(&output);
    assert!(line_of(&text, "notify.ntfy").starts_with("pass"), "{text}");
    assert!(
        text.contains("test notification through each channel: ntfy"),
        "{text}"
    );
    let requests = deployment.connect.received_requests().await.unwrap();
    let posts = requests
        .iter()
        .filter(|r| r.method.as_str() == "POST")
        .count();
    assert_eq!(posts, 1);
    assert_eq!(content(dir, "audit.jsonl"), audit_before);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_setting_exits_1_naming_it_without_creating_anything() {
    let deployment = Deployment::new().await;
    let db = deployment.dir.path().join("fresh.db");
    let output = deployment
        .command()
        .env("WARDEN_DB_PATH", &db)
        .env_remove("WARDEN_OWNER_LOGIN")
        .arg("doctor")
        .output()
        .unwrap();
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(text.contains("WARDEN_OWNER_LOGIN"), "{text}");
    assert!(!db.exists());
    assert!(!text.contains(TOKEN), "{text}");
}

/// Writes `content` to `name` in the deployment's directory, for the server's
/// user only, and returns its path.
fn secret_file(deployment: &Deployment, name: &str, content: &str) -> String {
    let file = deployment.path(name);
    fs::write(&file, content).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
    file
}

#[tokio::test(flavor = "multi_thread")]
async fn secrets_in_files_work_and_their_content_is_not_printed() {
    let deployment = Deployment::new().await;
    deployment.enroll_a_passkey().await;
    let topic_url = format!("{}/private-topic", deployment.connect.uri());
    let token_file = secret_file(&deployment, "token", &format!("{TOKEN}\n"));
    let topic_file = secret_file(&deployment, "topic", &format!("{topic_url}\n"));
    Mock::given(path("/private-topic"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&deployment.connect)
        .await;
    let output = deployment
        .command()
        .env_remove("WARDEN_OP_CONNECT_TOKEN")
        .env_remove("WARDEN_NOTIFY_NTFY_URL")
        .env("WARDEN_OP_CONNECT_TOKEN_FILE", &token_file)
        .env("WARDEN_NOTIFY_NTFY_URL_FILE", &topic_file)
        .args(["doctor", "--send-test-notification"])
        .output()
        .unwrap();
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{text}");
    for check in ["config", "connect.token", "notify.ntfy"] {
        assert!(line_of(&text, check).starts_with("pass"), "{text}");
    }
    let requests = deployment.connect.received_requests().await.unwrap();
    assert!(
        requests.iter().any(|r| r
            .headers
            .get("authorization")
            .is_some_and(|value| value.as_bytes() == format!("Bearer {TOKEN}").as_bytes())),
        "Connect did not receive the token from the file"
    );
    let printed = [&output.stdout[..], &output.stderr[..]].concat();
    let printed = String::from_utf8(printed).unwrap();
    // Fixed messages: on failure, printing the output would expose the leak.
    assert!(!printed.contains(TOKEN), "the output contains the token");
    assert!(
        !printed.contains(&topic_url),
        "the output contains the topic URL"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_secret_file_that_cannot_be_used_fails_config_naming_the_variable() {
    let deployment = Deployment::new().await;
    let world_readable = secret_file(&deployment, "open", TOKEN);
    fs::set_permissions(&world_readable, fs::Permissions::from_mode(0o644)).unwrap();
    let two_lines = secret_file(&deployment, "lines", &format!("{TOKEN}\n{TOKEN}\n"));
    let missing = deployment.path("missing-token-file");
    let cases = [
        (missing.as_str(), "entity not found"),
        (world_readable.as_str(), "accessible to other users"),
        (two_lines.as_str(), "single line"),
    ];
    for (file, reason) in cases {
        let output = deployment
            .command()
            .env_remove("WARDEN_OP_CONNECT_TOKEN")
            .env("WARDEN_OP_CONNECT_TOKEN_FILE", file)
            .arg("doctor")
            .output()
            .unwrap();
        let text = stdout(&output);
        assert_eq!(output.status.code(), Some(1), "{text}");
        let line = line_of(&text, "config");
        assert!(line.starts_with("FAIL"), "{text}");
        assert!(line.contains("WARDEN_OP_CONNECT_TOKEN_FILE"), "{text}");
        assert!(line.contains(reason), "{text}");
        assert!(
            line_of(&text, "connect").starts_with("COULD NOT CHECK"),
            "{text}"
        );
        assert!(
            !text.contains(TOKEN),
            "the report contains the file's content"
        );
        assert!(text.contains("the secret files"), "{text}");
    }
    assert_eq!(
        deployment.connect.received_requests().await.unwrap().len(),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_refused_from_a_file_names_the_file_variable() {
    let deployment = Deployment::new().await;
    deployment.connect.reset().await;
    Mock::given(path("/v1/vaults"))
        .respond_with(ResponseTemplate::new(401).set_body_string(TOKEN))
        .mount(&deployment.connect)
        .await;
    let token_file = secret_file(&deployment, "token", TOKEN);
    let output = deployment
        .command()
        .env_remove("WARDEN_OP_CONNECT_TOKEN")
        .env("WARDEN_OP_CONNECT_TOKEN_FILE", &token_file)
        .arg("doctor")
        .output()
        .unwrap();
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(text.contains("WARDEN_OP_CONNECT_TOKEN_FILE"), "{text}");
    assert!(!text.contains(TOKEN), "the report contains the token");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_token_fails_and_is_not_printed() {
    let deployment = Deployment::new().await;
    deployment.connect.reset().await;
    Mock::given(path("/v1/vaults"))
        .respond_with(ResponseTemplate::new(401).set_body_string(TOKEN))
        .mount(&deployment.connect)
        .await;
    let output = deployment.command().arg("doctor").output().unwrap();
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(1), "{text}");
    assert!(
        line_of(&text, "connect.token").starts_with("FAIL"),
        "{text}"
    );
    assert!(
        line_of(&text, "ssh-ca").starts_with("COULD NOT CHECK"),
        "{text}"
    );
    assert!(!text.contains(TOKEN), "{text}");
}
