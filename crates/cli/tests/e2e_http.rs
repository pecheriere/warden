//! End to end: the real `warden` binary against an in-process broker (behind a
//! stand-in for Tailscale Serve) that calls a local HTTPS upstream for it.
//! The secret lives only in the broker's backend: the CLI must never see it.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tempfile::TempDir;
use warden_broker::testkit::upstream::BINARY_BODY;
use warden_broker::testkit::{CapturingNotifier, HttpsUpstream, TestBroker};
use warden_broker_proto::Window;

const SECRET_NAME: &str = "svc";
const SECRET: &str = "s3cr3t-api-token-0123456789";

/// Everything the CLI writes lives under one short temporary root.
struct Cli {
    root: TempDir,
    key: String,
}

impl Cli {
    fn new(server: &url::Url, agent: &str, key: String) -> Self {
        let root = tempfile::Builder::new()
            .prefix("wdh")
            .tempdir_in("/tmp")
            .unwrap();
        for sub in ["config/warden", "state", "tmp"] {
            fs::create_dir_all(root.path().join(sub)).unwrap();
        }
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.path().join("config/warden/config.toml"))
            .unwrap();
        write!(f, "server = \"{server}\"\nagent = \"{agent}\"\n").unwrap();
        Self { root, key }
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_warden"));
        cmd.env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env("XDG_STATE_HOME", self.root.path().join("state"))
            .env("TMPDIR", self.root.path().join("tmp"))
            .env("WARDEN_AGENT_KEY", &self.key)
            .stdin(Stdio::null());
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }

    /// Every file under the CLI's directories containing `needle`.
    fn files_containing(&self, needle: &str) -> Vec<PathBuf> {
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

struct Setup {
    broker: TestBroker,
    upstream: HttpsUpstream,
    cli: Cli,
}

async fn setup() -> Setup {
    let broker = TestBroker::new().await;
    let upstream = HttpsUpstream::start().await;
    broker
        .backend
        .set_api_secret(upstream.policy(SECRET_NAME), SECRET);
    let urls = broker.spawn_behind_serve().await;
    let key = broker.add_agent("e2e").await;
    let cli = Cli::new(&urls.api, "e2e", key);
    Setup {
        broker,
        upstream,
        cli,
    }
}

fn spawn_request(cli: &Cli) -> Child {
    cli.command()
        .args([
            "request",
            "api",
            SECRET_NAME,
            "--for",
            "15m",
            "--goal",
            "call the e2e api",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Request api access, approve it as the owner, return the CLI's output.
async fn request_and_approve(s: &Setup) -> Output {
    let child = spawn_request(&s.cli);
    let token = CapturingNotifier::token(&s.broker.capture.next().await);
    let approved = s.broker.approve(&token, Window::M15).await;
    assert!(approved.status.is_success(), "{}", approved.body);
    tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_request_api_approve_and_call() {
    let s = setup().await;
    let req = request_and_approve(&s).await;
    assert_eq!(req.status.code(), Some(0), "stderr: {}", text(&req.stderr));
    let granted = text(&req.stdout);
    let Some((grant, _)) = granted
        .strip_prefix("approved: grant ")
        .and_then(|r| r.split_once(" until "))
    else {
        panic!("unexpected stdout: {granted}");
    };

    let call = s
        .cli
        .run(&["http", SECRET_NAME, "GET", &s.upstream.url("/hello"), "-i"]);
    assert_eq!(
        call.status.code(),
        Some(0),
        "stderr: {}",
        text(&call.stderr)
    );
    assert_eq!(text(&call.stdout), "hello from upstream");
    let head = text(&call.stderr);
    assert!(head.starts_with("HTTP 200"), "{head}");
    assert!(head.contains("content-type: text/plain"), "{head}");

    // The broker injected the secret; the agent never held it.
    let received = s.upstream.received();
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].headers["authorization"].to_str().unwrap(),
        format!("Bearer {SECRET}")
    );

    // A GET with a body and a header (a plain request is read-only, so a
    // write would be refused), and an echo that would carry the
    // secret back if the broker did not redact it.
    let post = s.cli.run(&[
        "http",
        SECRET_NAME,
        "GET",
        &s.upstream.url("/echo"),
        "-H",
        "X-Trace: abc:def",
        "-d",
        "payload",
    ]);
    assert_eq!(
        post.status.code(),
        Some(0),
        "stderr: {}",
        text(&post.stderr)
    );
    let echoed = text(&post.stdout);
    assert!(echoed.contains("body: payload"), "{echoed}");
    assert!(echoed.contains("[REDACTED]"), "{echoed}");
    assert_eq!(
        s.upstream.received()[1].headers["x-trace"]
            .to_str()
            .unwrap(),
        "abc:def"
    );

    let status = s.cli.run(&["status"]);
    assert_eq!(status.status.code(), Some(0));
    assert!(text(&status.stdout).contains(grant));

    // No secret, in any encoding, reached the agent's output or disk.
    let encodings = [SECRET.to_owned(), STANDARD.encode(SECRET)];
    for needle in &encodings {
        for out in [&req, &call, &post, &status] {
            assert!(!text(&out.stdout).contains(needle.as_str()));
            assert!(!text(&out.stderr).contains(needle.as_str()));
        }
        assert_eq!(s.cli.files_containing(needle), Vec::<PathBuf>::new());
    }
    assert!(!s.cli.files_containing("\"grant_id\"").is_empty());

    let revoke = s.cli.run(&["revoke", grant]);
    assert_eq!(revoke.status.code(), Some(0), "{}", text(&revoke.stderr));
    let after = s
        .cli
        .run(&["http", SECRET_NAME, "GET", &s.upstream.url("/hello")]);
    assert_eq!(after.status.code(), Some(5));
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_http_without_grant_exits_5() {
    let s = setup().await;
    let out = s
        .cli
        .run(&["http", SECRET_NAME, "GET", &s.upstream.url("/hello")]);
    assert_eq!(out.status.code(), Some(5));
    assert!(out.stdout.is_empty());
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("no active api grant for svc") && stderr.contains("warden request api"),
        "{stderr}"
    );
    assert!(s.upstream.received().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_http_fail_flag_exit_22() {
    let s = setup().await;
    let req = request_and_approve(&s).await;
    assert_eq!(req.status.code(), Some(0), "stderr: {}", text(&req.stderr));
    let url = s.upstream.url("/status/404");

    let plain = s.cli.run(&["http", SECRET_NAME, "GET", &url]);
    assert_eq!(plain.status.code(), Some(0));
    assert_eq!(text(&plain.stdout), "status 404");

    let failing = s.cli.run(&["http", SECRET_NAME, "GET", &url, "--fail"]);
    assert_eq!(failing.status.code(), Some(22));
    // The body is still written.
    assert_eq!(text(&failing.stdout), "status 404");
    assert!(text(&failing.stderr).contains("404"));

    let ok = s.cli.run(&[
        "http",
        SECRET_NAME,
        "GET",
        &s.upstream.url("/status/399"),
        "--fail",
    ]);
    assert_eq!(ok.status.code(), Some(0));
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_http_binary_body_is_written_raw() {
    let s = setup().await;
    let req = request_and_approve(&s).await;
    assert_eq!(req.status.code(), Some(0));
    let out = s
        .cli
        .run(&["http", SECRET_NAME, "GET", &s.upstream.url("/binary")]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout, BINARY_BODY);
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_http_body_from_stdin_and_local_limits() {
    let s = setup().await;
    let req = request_and_approve(&s).await;
    assert_eq!(req.status.code(), Some(0));
    let url = s.upstream.url("/echo");

    let mut child = s
        .cli
        .command()
        .args(["http", SECRET_NAME, "GET", &url, "--data-file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"from stdin")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("body: from stdin"));

    // Over 1 MiB is refused before anything is sent.
    let big = s.cli.root.path().join("big");
    fs::write(&big, vec![b'a'; 1024 * 1024 + 1]).unwrap();
    let before = s.upstream.received().len();
    let refused = s.cli.run(&[
        "http",
        SECRET_NAME,
        "POST",
        &url,
        "--data-file",
        big.to_str().unwrap(),
    ]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        text(&refused.stderr).contains("1 MiB"),
        "{}",
        text(&refused.stderr)
    );
    assert_eq!(s.upstream.received().len(), before);

    // Bad header syntax is refused locally.
    let bad = s
        .cli
        .run(&["http", SECRET_NAME, "GET", &url, "-H", ": no name"]);
    assert_ne!(bad.status.code(), Some(0));
    assert_eq!(s.upstream.received().len(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_http_broker_refusal_prints_message_and_exits_1() {
    let s = setup().await;
    let req = request_and_approve(&s).await;
    assert_eq!(req.status.code(), Some(0));
    // The policy allows GET and POST only.
    let out = s
        .cli
        .run(&["http", SECRET_NAME, "DELETE", &s.upstream.url("/hello")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert!(
        text(&out.stderr).contains("broker refused"),
        "{}",
        text(&out.stderr)
    );
    assert!(s.upstream.received().is_empty());
}
