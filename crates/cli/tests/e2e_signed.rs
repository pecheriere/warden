//! End to end with signed requests: the real `warden` binary, logged in
//! with `--ssh-key`, signs every call through a real `ssh-agent` that holds
//! the agent's key; the in-process broker verifies the signatures. The
//! broker is reached directly, without the stand-in for Tailscale Serve, so
//! no request carries the owner's `Tailscale-User-Login`, as from a tagged
//! agent host.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ssh_agent_lib::agent::Session as _;
use ssh_agent_lib::proto::{AddIdentity, PrivateCredential};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, PrivateKey};
use tempfile::TempDir;
use warden_broker::policy::{RelayCredential, SshMode, SshTarget};
use warden_broker::testkit::sshd::{Sshd, SshdLogin, current_user};
use warden_broker::testkit::{CapturingNotifier, HttpsUpstream, TestBroker};
use warden_broker_proto::{TargetName, UnixUser, Window};

const SECRET_NAME: &str = "svc";
const SECRET: &str = "s3cr3t-api-token-0123456789";
const TARGET: &str = "nas";
const AGENT: &str = "e2e";

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A throwaway `ssh-agent`, killed on drop.
struct TestAgent {
    child: Child,
    socket: PathBuf,
}

impl Drop for TestAgent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl TestAgent {
    fn start(dir: &Path) -> Self {
        let socket = dir.join("agent.sock");
        let child = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .env_remove("SSH_AUTH_SOCK")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("ssh-agent (OpenSSH) is needed for this test");
        let deadline = Instant::now() + Duration::from_secs(10);
        while std::os::unix::net::UnixStream::connect(&socket).is_err() {
            assert!(Instant::now() < deadline, "ssh-agent did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        Self { child, socket }
    }

    /// Load `key` over the socket: the private key is never in a file.
    async fn add(&self, key: &PrivateKey) {
        let stream = tokio::net::UnixStream::connect(&self.socket).await.unwrap();
        ssh_agent_lib::client::Client::new(stream)
            .add_identity(AddIdentity {
                credential: PrivateCredential::Key {
                    privkey: key.key_data().clone(),
                    comment: "warden e2e signing key".to_owned(),
                },
            })
            .await
            .unwrap();
    }
}

/// The CLI's private environment, with the signing key's ssh-agent at
/// `SSH_AUTH_SOCK` and no bearer key anywhere.
struct SignedCli {
    root: TempDir,
    agent: TestAgent,
    public_key: PathBuf,
}

impl SignedCli {
    /// A fresh environment whose ssh-agent holds `key`, with its public key
    /// written to `signing.pub`.
    async fn new(key: &PrivateKey) -> Self {
        let root = tempfile::Builder::new()
            .prefix("wds")
            .tempdir_in("/tmp")
            .unwrap();
        for sub in ["config", "state", "tmp"] {
            fs::create_dir_all(root.path().join(sub)).unwrap();
        }
        let agent = TestAgent::start(root.path());
        agent.add(key).await;
        let public_key = root.path().join("signing.pub");
        fs::write(
            &public_key,
            format!("{} e2e@host\n", key.public_key().to_openssh().unwrap()),
        )
        .unwrap();
        Self {
            root,
            agent,
            public_key,
        }
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_warden"));
        cmd.env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env("XDG_STATE_HOME", self.root.path().join("state"))
            .env("TMPDIR", self.root.path().join("tmp"))
            .env("SSH_AUTH_SOCK", &self.agent.socket)
            .env_remove("WARDEN_AGENT_KEY")
            .stdin(Stdio::null());
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }

    fn login(&self, server: &url::Url, extra: &[&str]) -> Output {
        let key = self.public_key.to_str().unwrap();
        self.run(
            &[
                &["login", "--server", server.as_str(), "--agent", AGENT],
                &["--ssh-key", key][..],
                extra,
            ]
            .concat(),
        )
    }

    fn config_path(&self) -> PathBuf {
        self.root.path().join("config/warden/config.toml")
    }

    fn config(&self) -> String {
        fs::read_to_string(self.config_path()).unwrap()
    }

    /// Kill every per-grant agent the CLI left running.
    fn kill_grant_agents(&self) {
        let Ok(entries) = fs::read_dir(self.root.path().join("state/warden/grants")) else {
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

    /// Whether any file the CLI wrote contains `needle`.
    fn wrote(&self, needle: &str) -> bool {
        fn walk(dir: &Path, needle: &[u8]) -> bool {
            fs::read_dir(dir).unwrap().flatten().any(|entry| {
                let kind = entry.file_type().unwrap();
                (kind.is_dir() && walk(&entry.path(), needle))
                    || (kind.is_file()
                        && fs::read(entry.path())
                            .unwrap()
                            .windows(needle.len())
                            .any(|w| w == needle))
            })
        }
        ["config", "state", "tmp"]
            .iter()
            .any(|sub| walk(&self.root.path().join(sub), needle.as_bytes()))
    }
}

impl Drop for SignedCli {
    fn drop(&mut self) {
        self.kill_grant_agents();
    }
}

/// Run `warden <args>` in the background, approve the request when the
/// doorbell rings, and return the CLI's output.
async fn request_and_approve(broker: &TestBroker, cli: &SignedCli, args: &[&str]) -> Output {
    let child = cli
        .command()
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let token = CapturingNotifier::token(&broker.capture.next().await);
    let approved = broker.approve(&token, Window::M15).await;
    assert!(approved.status.is_success(), "{}", approved.body);
    let out = tokio::task::spawn_blocking(move || child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
    out
}

/// A broker with an API secret on an HTTPS upstream and a relay target
/// `nas` in front of a throwaway `sshd`, served without the stand-in for
/// Tailscale Serve, and a key-signed agent `e2e` with a P-256 key (as a
/// Secure Enclave, TPM or PIV key would be).
struct Setup {
    broker: TestBroker,
    upstream: HttpsUpstream,
    sshd: Sshd,
    api: url::Url,
    key: PrivateKey,
}

async fn signed_setup() -> Setup {
    let (broker, _relay) = TestBroker::with_reachable_relay().await;
    // Signatures are checked against the broker's clock: the real time.
    broker.clock.set(now());
    let upstream = HttpsUpstream::start().await;
    broker
        .backend
        .set_api_secret(upstream.policy(SECRET_NAME), SECRET);
    let onward = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let sshd = Sshd::start(&SshdLogin::Key(onward.public_key().clone()));
    broker.backend.set_relay_target(
        SshTarget {
            name: TargetName::try_from(TARGET.to_owned()).unwrap(),
            host: "127.0.0.1".to_owned(),
            port: sshd.port(),
            mode: SshMode::Relay,
            users: vec![UnixUser::try_from(current_user()).unwrap()],
            max_window: Window::H1,
            host_keys: vec![sshd.host_key().clone()],
        },
        RelayCredential::Key(onward.to_openssh(LineEnding::LF).unwrap()),
    );
    // No stand-in for Tailscale Serve: no owner login on any request.
    let api = broker.spawn().await.api;
    let key = broker
        .add_signing_agent(
            AGENT,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        )
        .await;
    Setup {
        broker,
        upstream,
        sshd,
        api,
        key,
    }
}

/// Request API access, approve it, then make a GET and a POST whose body
/// comes from standard input, each signed.
async fn api_calls(s: &Setup, cli: &SignedCli) {
    let api = request_and_approve(
        &s.broker,
        cli,
        &[
            "request",
            "api",
            SECRET_NAME,
            "--methods",
            "GET,POST",
            "--for",
            "15m",
            "--goal",
            "call the e2e api with a signed agent",
        ],
    )
    .await;
    assert!(text(&api.stdout).starts_with("approved: grant "));
    let call = cli.run(&["http", SECRET_NAME, "GET", &s.upstream.url("/hello")]);
    assert_eq!(call.status.code(), Some(0), "{}", text(&call.stderr));
    assert_eq!(text(&call.stdout), "hello from upstream");
    let mut post = cli
        .command()
        .args(["http", SECRET_NAME, "POST", &s.upstream.url("/echo")])
        .args(["--data-file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    post.stdin
        .take()
        .unwrap()
        .write_all(b"streamed\npayload\n")
        .unwrap();
    let post = post.wait_with_output().unwrap();
    assert_eq!(post.status.code(), Some(0), "{}", text(&post.stderr));
    assert!(
        text(&post.stdout).contains("body: streamed\npayload\n"),
        "{}",
        text(&post.stdout)
    );
}

/// Request SSH access to `nas`, approve it, run a command through the
/// relay, then revoke the grant.
async fn ssh_session(s: &Setup, cli: &SignedCli) {
    let approved = request_and_approve(
        &s.broker,
        cli,
        &[
            "request",
            "ssh",
            TARGET,
            "--user",
            &current_user(),
            "--for",
            "15m",
            "--goal",
            "run the signed e2e test",
        ],
    )
    .await;
    let ssh = cli.run(&["ssh", TARGET, "--", "echo", "ok"]);
    assert_eq!(ssh.status.code(), Some(0), "{}", text(&ssh.stderr));
    assert_eq!(text(&ssh.stdout), "ok\n");

    let grant = text(&approved.stdout)
        .strip_prefix("approved: grant ")
        .and_then(|r| r.split_once(' '))
        .map(|(id, _)| id.to_owned())
        .unwrap();
    let status = cli.run(&["status"]);
    assert_eq!(status.status.code(), Some(0), "{}", text(&status.stderr));
    assert!(text(&status.stdout).contains(&grant));
    let revoke = cli.run(&["revoke", &grant]);
    assert_eq!(revoke.status.code(), Some(0), "{}", text(&revoke.stderr));
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_signed_login_request_approve_and_call() {
    let s = signed_setup().await;
    let cli = SignedCli::new(&s.key).await;

    let login = cli.login(
        &s.api,
        &["--ssh-agent-socket", cli.agent.socket.to_str().unwrap()],
    );
    assert_eq!(login.status.code(), Some(0), "{}", text(&login.stderr));
    let fingerprint = s.key.public_key().fingerprint(HashAlg::Sha256).to_string();
    let said = text(&login.stderr);
    assert!(said.contains(&fingerprint), "{said}");
    let audience = s.broker.state().audience.as_str().to_owned();
    let config = cli.config();
    assert!(
        config.contains(&format!("audience = \"{audience}\"")),
        "{config}"
    );
    assert!(config.contains("[ssh_key]"), "{config}");

    api_calls(&s, &cli).await;
    ssh_session(&s, &cli).await;

    // Nothing secret was written: no bearer key, no private key, no secret.
    assert!(!cli.wrote("wdn_"));
    assert!(!cli.wrote("PRIVATE KEY"));
    assert!(!cli.wrote(SECRET));
    drop(s.sshd);
}

/// A broker whose audience is not the one expected or pinned: the login
/// stops, and a call signed for the old audience says why it failed.
#[tokio::test(flavor = "multi_thread")]
async fn e2e_login_refuses_wrong_audience() {
    let broker = TestBroker::without_relay().await;
    broker.clock.set(now());
    let urls = broker.spawn().await;
    let key = broker.add_signing_agent(AGENT, Algorithm::Ed25519).await;
    let cli = SignedCli::new(&key).await;
    let audience = broker.state().audience.as_str().to_owned();
    let other = "0123456789abcdef0123456789abcdef";
    assert_ne!(audience, other);

    // The owner said another audience: not this broker.
    let wrong = cli.login(&urls.api, &["--audience", other]);
    assert_eq!(wrong.status.code(), Some(1));
    let said = text(&wrong.stderr);
    assert!(
        said.contains(&format!("reports audience {audience}, not {other}")),
        "{said}"
    );
    assert!(!cli.config_path().exists());

    // Pinned earlier for another broker at this URL.
    let pinned_other = format!(
        "server = \"{}\"\nagent = \"{AGENT}\"\n\n[ssh_key]\npublic_key = \"{}\"\naudience = \"{other}\"\n",
        urls.api,
        key.public_key().to_openssh().unwrap()
    );
    fs::create_dir_all(cli.config_path().parent().unwrap()).unwrap();
    fs::write(cli.config_path(), &pinned_other).unwrap();
    let repin = cli.login(&urls.api, &[]);
    assert_eq!(repin.status.code(), Some(1));
    let said = text(&repin.stderr);
    assert!(
        said.contains(&format!("but {other} was pinned before")),
        "{said}"
    );
    assert!(said.contains("--audience"), "{said}");
    assert_eq!(cli.config(), pinned_other);

    // A call signed for the pinned (wrong) audience is refused, and the CLI
    // says the audience changed.
    let status = cli.run(&["status"]);
    assert_eq!(status.status.code(), Some(1));
    let said = text(&status.stderr);
    assert!(said.contains("401"), "{said}");
    assert!(
        said.contains(&format!("audience is now {audience}, not {other}")),
        "{said}"
    );

    // The owner confirms the new audience: it is pinned and calls work.
    let confirmed = cli.login(&urls.api, &["--audience", &audience]);
    assert_eq!(
        confirmed.status.code(),
        Some(0),
        "{}",
        text(&confirmed.stderr)
    );
    assert!(cli.config().contains(&audience));
    let status = cli.run(&["status"]);
    assert_eq!(status.status.code(), Some(0), "{}", text(&status.stderr));
}

/// A key login that replaces a bearer-key login says, on macOS, how to
/// delete the old key from the Keychain (it deletes nothing itself); a key
/// login over a key login says nothing of the Keychain.
#[tokio::test(flavor = "multi_thread")]
async fn e2e_key_login_over_bearer_login_hints_keychain_cleanup() {
    let broker = TestBroker::without_relay().await;
    broker.clock.set(now());
    let urls = broker.spawn().await;
    let key = broker.add_signing_agent(AGENT, Algorithm::Ed25519).await;
    let cli = SignedCli::new(&key).await;
    fs::create_dir_all(cli.config_path().parent().unwrap()).unwrap();
    fs::write(
        cli.config_path(),
        format!("server = \"{}\"\nagent = \"{AGENT}\"\n", urls.api),
    )
    .unwrap();

    let login = cli.login(&urls.api, &[]);
    assert_eq!(login.status.code(), Some(0), "{}", text(&login.stderr));
    let said = text(&login.stderr);
    let hint = format!(
        "security delete-generic-password -s warden-broker -a '{}|{AGENT}'",
        urls.api
    );
    assert_eq!(said.contains(&hint), cfg!(target_os = "macos"), "{said}");
    assert!(cli.config().contains("[ssh_key]"));

    let again = cli.login(&urls.api, &[]);
    assert_eq!(again.status.code(), Some(0), "{}", text(&again.stderr));
    let said = text(&again.stderr);
    assert!(!said.contains("Keychain"), "{said}");
}

/// Key mode needs the broker at the root of its origin, an agent holding
/// the key, and the key enrolled.
#[tokio::test(flavor = "multi_thread")]
async fn e2e_signed_login_refusals() {
    let broker = TestBroker::without_relay().await;
    broker.clock.set(now());
    let urls = broker.spawn().await;
    let key = broker.add_signing_agent(AGENT, Algorithm::Ed25519).await;
    let cli = SignedCli::new(&key).await;

    let with_path = urls.api.join("api/").unwrap();
    let out = cli.login(&with_path, &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("must have no path"),
        "{}",
        text(&out.stderr)
    );

    // A key the agent does not hold.
    let stranger = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let stranger_pub = cli.root.path().join("stranger.pub");
    fs::write(&stranger_pub, stranger.public_key().to_openssh().unwrap()).unwrap();
    let out = cli.run(&[
        "login",
        "--server",
        urls.api.as_str(),
        "--agent",
        AGENT,
        "--ssh-key",
        stranger_pub.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    let said = text(&out.stderr);
    let fingerprint = stranger
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string();
    assert!(
        said.contains("does not hold the key") && said.contains(&fingerprint),
        "{said}"
    );

    // A key the agent holds but the broker does not know for this agent.
    let other = broker.add_signing_agent("other", Algorithm::Ed25519).await;
    cli.agent.add(&other).await;
    let other_pub = cli.root.path().join("other.pub");
    fs::write(&other_pub, other.public_key().to_openssh().unwrap()).unwrap();
    let out = cli.run(&[
        "login",
        "--server",
        urls.api.as_str(),
        "--agent",
        AGENT,
        "--ssh-key",
        other_pub.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    let said = text(&out.stderr);
    assert!(
        said.contains("did not accept a call signed by agent e2e"),
        "{said}"
    );
    assert!(said.contains("401"), "{said}");
    assert!(!cli.config_path().exists());
}
