//! End to end: the real `warden` binary against an in-process broker (behind a
//! stand-in for Tailscale Serve) and a throwaway, unprivileged `sshd` that
//! trusts the broker's CA and maps the target-scoped principal to the user,
//! as the documented host setup does.

use std::fs;
use std::io::Write as _;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use tempfile::TempDir;
use warden_broker::policy::{SshMode, SshTarget};
use warden_broker::testkit::{BaseUrls, CapturingNotifier, TestBroker};
use warden_broker_proto::{TargetName, UnixUser, Window};

const SSHD: &str = "/usr/sbin/sshd";
const TARGET: &str = "box";

/// A running `sshd` on a loopback port, killed on drop.
struct Sshd {
    child: Child,
    port: u16,
    _dir: TempDir,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn current_user() -> String {
    let out = Command::new("id").arg("-un").output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_private(path: &Path, contents: &str) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(contents.as_bytes()).unwrap();
}

/// Start `sshd` as the current user, trusting `ca_pub` for user certificates
/// whose principal is `warden:<host_target>:<user>` (`AuthorizedPrincipalsFile`).
/// Returns it with its host public key.
fn start_sshd(ca_pub: &str, host_target: &str) -> (Sshd, ssh_key::PublicKey) {
    assert!(
        Path::new(SSHD).exists(),
        "{SSHD} not found: the end-to-end test needs OpenSSH's sshd \
         (on Debian/Ubuntu: apt-get install openssh-server)"
    );
    // The host key is a server-side test fixture; it lives outside every
    // directory the CLI uses, which the on-disk scan covers.
    let dir = tempfile::Builder::new()
        .prefix("wsshd")
        .tempdir_in("/tmp")
        .unwrap();
    let host = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let host_key = dir.path().join("host_ed25519");
    write_private(&host_key, &host.to_openssh(LineEnding::LF).unwrap());
    let ca = dir.path().join("ca.pub");
    write_private(&ca, ca_pub);
    let principals = dir.path().join("principals");
    fs::create_dir(&principals).unwrap();
    let user = current_user();
    write_private(
        &principals.join(&user),
        &format!("warden:{host_target}:{user}\n"),
    );
    let mut config = format!(
        "HostKey {}\nTrustedUserCAKeys {}\nAuthorizedPrincipalsFile {}/%u\n\
         AuthorizedKeysFile none\n\
         PasswordAuthentication no\nKbdInteractiveAuthentication no\n\
         StrictModes no\nPidFile none\nListenAddress 127.0.0.1\n",
        host_key.display(),
        ca.display(),
        principals.display()
    );
    if cfg!(target_os = "linux") {
        config.push_str("UsePAM no\n");
    }
    let config_path = dir.path().join("sshd_config");
    write_private(&config_path, &config);

    let port = free_port();
    let child = Command::new(SSHD)
        .arg("-D")
        .arg("-e")
        .arg("-f")
        .arg(&config_path)
        .arg("-p")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot start {SSHD}: {e}"));
    let mut sshd = Sshd {
        child,
        port,
        _dir: dir,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err() {
        if let Some(status) = sshd.child.try_wait().unwrap() {
            panic!("sshd exited early with {status}");
        }
        assert!(Instant::now() < deadline, "sshd did not start listening");
        std::thread::sleep(Duration::from_millis(50));
    }
    (sshd, host.public_key().clone())
}

/// Everything the CLI writes lives under one short temporary root.
struct Cli {
    root: TempDir,
    key: String,
}

/// State and temp dirs contain a space, like macOS `~/Library/Application Support`:
/// paths handed to ssh options must survive ssh's whitespace splitting.
const STATE_DIR: &str = "app state";
const TMP_DIR: &str = "my tmp";

impl Cli {
    fn new(server: &url::Url, agent: &str, key: String) -> Self {
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

    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_warden"));
        cmd.env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env("XDG_STATE_HOME", self.root.path().join(STATE_DIR))
            .env("TMPDIR", self.root.path().join(TMP_DIR))
            .env("WARDEN_AGENT_KEY", &self.key)
            .stdin(Stdio::null());
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
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

impl Drop for Cli {
    fn drop(&mut self) {
        self.kill_agents();
    }
}

/// A broker whose `box` target is the throwaway `sshd` (set up as the host
/// of target `box`), with an agent `e2e` configured in a fresh CLI environment.
struct Setup {
    broker: TestBroker,
    sshd: Sshd,
    cli: Cli,
    urls: BaseUrls,
}

async fn setup() -> Setup {
    setup_with_host_target(TARGET).await
}

/// Like [`setup`], but the `sshd` behind target `box` is configured as the
/// host of `host_target`: it accepts only `warden:<host_target>:<user>`.
async fn setup_with_host_target(host_target: &str) -> Setup {
    let broker = TestBroker::new().await;
    // Certificates are checked by a real sshd against the real time.
    broker.clock.set(now());
    let ca_pub = broker.backend.ca_public_key().to_openssh().unwrap();
    let (sshd, host_key) = start_sshd(&ca_pub, host_target);
    broker.backend.set_target(SshTarget {
        name: TargetName::try_from(TARGET.to_owned()).unwrap(),
        host: "127.0.0.1".to_owned(),
        port: sshd.port,
        mode: SshMode::Cert,
        users: vec![UnixUser::try_from(current_user()).unwrap()],
        max_window: Window::H1,
        host_keys: vec![host_key],
    });
    let urls = broker.spawn_behind_serve().await;
    let key = broker.add_agent("e2e").await;
    let cli = Cli::new(&urls.api, "e2e", key);
    Setup {
        broker,
        sshd,
        cli,
        urls,
    }
}

/// Start `warden request ssh box …` in the background.
fn spawn_request(cli: &Cli) -> Child {
    let user = current_user();
    cli.command()
        .args([
            "request",
            "ssh",
            TARGET,
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
async fn approve(broker: &TestBroker, token: &str) {
    let approved = broker.approve(token, Window::M15).await;
    assert!(approved.status.is_success(), "{}", approved.body);
}

/// Wait for a `warden request` to succeed; return the grant id it printed
/// and its stderr.
async fn approved_grant(child: Child) -> (String, String) {
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

/// Run `warden request ssh box …`, approve it when the doorbell rings, and
/// return the grant id the CLI printed.
async fn request_and_approve(s: &Setup) -> String {
    let child = spawn_request(&s.cli);
    let token = CapturingNotifier::token(&s.broker.capture.next().await);
    approve(&s.broker, &token).await;
    approved_grant(child).await.0
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_request_approve_ssh_runs_command() {
    let s = setup().await;
    let grant = request_and_approve(&s).await;

    let ssh = s.cli.run(&["ssh", TARGET, "--", "echo", "ok"]);
    assert_eq!(
        ssh.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&ssh.stderr)
    );
    assert_eq!(String::from_utf8(ssh.stdout).unwrap(), "ok\n");

    let status = s.cli.run(&["status"]);
    assert_eq!(status.status.code(), Some(0));
    assert!(String::from_utf8(status.stdout).unwrap().contains(&grant));

    let revoke = s.cli.run(&["revoke", &grant]);
    assert_eq!(
        revoke.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&revoke.stderr)
    );

    let after = s.cli.run(&["ssh", TARGET, "--", "echo", "ok"]);
    assert_eq!(after.status.code(), Some(5));
    assert!(after.stdout.is_empty());
    let stderr = String::from_utf8(after.stderr).unwrap();
    assert!(stderr.contains("no active grant for box"), "{stderr}");
    drop(s.sshd);
}

#[tokio::test(flavor = "multi_thread")]
async fn cert_for_other_target_is_rejected() {
    // The host trusts the same CA but is configured for target `nas`; a
    // certificate approved for `box` must not log in there.
    let s = setup_with_host_target("nas").await;
    let _grant = request_and_approve(&s).await;
    let ssh = s.cli.run(&["ssh", TARGET, "--", "echo", "ok"]);
    assert_ne!(ssh.status.code(), Some(0));
    assert!(ssh.stdout.is_empty());
    let stderr = String::from_utf8(ssh.stderr).unwrap();
    assert!(stderr.contains("Permission denied"), "{stderr}");
    drop(s.sshd);
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_private_key_never_on_disk() {
    let s = setup().await;
    let _grant = request_and_approve(&s).await;
    let ssh = s.cli.run(&["ssh", TARGET, "--", "true"]);
    assert_eq!(
        ssh.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&ssh.stderr)
    );
    // The agent socket and grant metadata exist, so the scan covers the
    // directories the CLI actually wrote.
    assert!(!s.cli.files_containing("\"grant_id\"").is_empty());
    assert_eq!(s.cli.files_containing("PRIVATE KEY"), Vec::<PathBuf>::new());
    let mode = fs::metadata(s.cli.root.path().join(STATE_DIR).join("warden"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
}

#[tokio::test(flavor = "multi_thread")]
async fn poll_survives_server_restart_mid_wait() {
    let Setup {
        broker,
        sshd,
        cli,
        urls,
    } = setup().await;
    let child = spawn_request(&cli);
    let token = CapturingNotifier::token(&broker.capture.next().await);

    // The broker process goes away while the CLI is long-polling: its
    // listeners and the in-flight poll are dropped, and the port refuses
    // connections for a while before the broker comes back on it.
    let broker = broker.restart().await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    broker.spawn_behind_serve_at(&urls).await;
    approve(&broker, &token).await;

    let (grant, stderr) = approved_grant(child).await;
    assert!(stderr.contains("retrying"), "{stderr}");
    let ssh = cli.run(&["ssh", TARGET, "--", "echo", "ok"]);
    assert_eq!(
        String::from_utf8(ssh.stdout).unwrap(),
        "ok\n",
        "grant {grant}; stderr: {}",
        String::from_utf8_lossy(&ssh.stderr)
    );
    drop(sshd);
}
