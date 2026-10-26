//! End to end: the real `warden` binary against an in-process broker (behind a
//! stand-in for Tailscale Serve) and a throwaway, unprivileged `sshd` that
//! trusts the broker's CA and maps the target-scoped principal to the user,
//! as the documented host setup does.

mod common;

use std::fs;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use tempfile::TempDir;
use warden_broker::policy::{SshMode, SshTarget};
use warden_broker::testkit::sshd::current_user;
use warden_broker::testkit::{BaseUrls, CapturingNotifier, TestBroker};
use warden_broker_proto::{TargetName, UnixUser, Window};

use common::{Cli, STATE_DIR, approve, approved_grant, now, spawn_request, write_private};

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

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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

/// Run `warden request ssh box …`, approve it when the doorbell rings, and
/// return the grant id the CLI printed.
async fn request_and_approve(s: &Setup) -> String {
    let child = spawn_request(&s.cli, TARGET);
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
    let child = spawn_request(&cli, TARGET);
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
