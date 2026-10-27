//! End to end through the relay: the real `warden` binary against an
//! in-process broker (behind a stand-in for Tailscale Serve) whose SSH relay
//! listens on loopback, in front of a throwaway, unprivileged `sshd` that
//! knows nothing of warden and lets the current user log in only with the
//! credential the broker holds.

mod common;

use std::io::{BufRead as _, BufReader};
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use warden_broker::policy::{RelayCredential, SshMode, SshTarget};
use warden_broker::testkit::sshd::{Sshd, SshdLogin, current_user};
use warden_broker::testkit::{CapturingNotifier, TestBroker};
use warden_broker_proto::{TargetName, UnixUser, Window};

use common::{Cli, approve, approved_grant, now, spawn_request};

const TARGET: &str = "nas";

/// A broker whose relay target `nas` is `sshd`, logging in with
/// `credential`, and whose relay is reachable where its grants say; with an
/// agent `e2e` configured in a fresh CLI environment.
struct Setup {
    broker: TestBroker,
    sshd: Sshd,
    cli: Cli,
    relay: std::net::SocketAddr,
}

async fn setup(login: &SshdLogin, credential: RelayCredential) -> Setup {
    let (broker, relay) = TestBroker::with_reachable_relay().await;
    // The CLI checks grants against the real time.
    broker.clock.set(now());
    let sshd = Sshd::start(login);
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
        credential,
    );
    let urls = broker.spawn_behind_serve().await;
    let key = broker.add_agent("e2e").await;
    let cli = Cli::new(&urls.api, "e2e", key);
    Setup {
        broker,
        sshd,
        cli,
        relay,
    }
}

/// A key target: the onward login key is the credential.
async fn key_setup() -> (Setup, PrivateKey) {
    let onward = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let s = setup(
        &SshdLogin::Key(onward.public_key().clone()),
        RelayCredential::Key(onward.to_openssh(LineEnding::LF).unwrap()),
    )
    .await;
    (s, onward)
}

/// Run `warden request ssh nas …`, approve it when the doorbell rings, and
/// return the grant id the CLI printed.
async fn request_and_approve(s: &Setup) -> String {
    let child = spawn_request(&s.cli, TARGET);
    let token = CapturingNotifier::token(&s.broker.capture.next().await);
    approve(&s.broker, &token).await;
    approved_grant(child).await.0
}

/// `warden ssh nas -- echo ok` prints `ok`.
fn assert_echo_ok(cli: &Cli) {
    let ssh = cli.run(&["ssh", TARGET, "--", "echo", "ok"]);
    assert_eq!(
        ssh.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&ssh.stderr)
    );
    assert_eq!(String::from_utf8(ssh.stdout).unwrap(), "ok\n");
}

/// Neither the grant's private key, nor the onward credential (`secret`,
/// in every form it could be written), is anywhere the CLI writes.
fn assert_no_secret_on_disk(cli: &Cli, secrets: &[&str]) {
    // The agent socket and grant metadata exist, so the scan covers the
    // directories the CLI actually wrote.
    assert!(!cli.files_containing("\"grant_id\"").is_empty());
    assert_eq!(cli.files_containing("PRIVATE KEY"), Vec::<PathBuf>::new());
    for secret in secrets {
        assert_eq!(cli.files_containing(secret), Vec::<PathBuf>::new());
    }
}

/// The broker's audit events of type `kind`, oldest first.
fn audit_events(broker: &TestBroker, kind: &str) -> Vec<Value> {
    std::fs::read_to_string(broker.audit_path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["event"].clone())
        .filter(|e| e["type"] == kind)
        .collect()
}

/// Wait (at most 5 s) until the audit log holds an event of type `kind`.
async fn await_audit_events(broker: &TestBroker, kind: &str) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let found = audit_events(broker, kind);
        if !found.is_empty() || Instant::now() >= deadline {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_relay_request_approve_ssh_runs_command() {
    let (s, onward) = key_setup().await;
    let grant = request_and_approve(&s).await;

    assert_echo_ok(&s.cli);

    // The grant is recorded as relayed, and ssh pins exactly the relay's
    // host key at the relay's address.
    let dir = s
        .cli
        .root
        .path()
        .join(common::STATE_DIR)
        .join("warden/grants")
        .join(&grant);
    let record: Value =
        serde_json::from_slice(&std::fs::read(dir.join("grant.json")).unwrap()).unwrap();
    assert_eq!(record["route"], "relay");
    assert_eq!(record["host"], "127.0.0.1");
    assert_eq!(record["port"], s.relay.port());
    let relay_key = &s.broker.state().requests.relay().unwrap().host_key;
    let relay_key = relay_key.split(' ').take(2).collect::<Vec<_>>().join(" ");
    assert_eq!(
        std::fs::read_to_string(dir.join("known_hosts")).unwrap(),
        format!("[127.0.0.1]:{} {relay_key}\n", s.relay.port())
    );

    let onward_private = onward.to_openssh(LineEnding::LF).unwrap();
    let onward_body = onward_private.lines().nth(1).unwrap();
    assert_no_secret_on_disk(&s.cli, &[onward_body]);

    let started = audit_events(&s.broker, "relay_session_started");
    assert_eq!(started.len(), 1, "{started:?}");
    assert_eq!(started[0]["grant_id"], grant.as_str());

    let status = s.cli.run(&["status"]);
    assert_eq!(status.status.code(), Some(0));
    let status = String::from_utf8(status.stdout).unwrap();
    assert!(status.contains(&grant), "{status}");
    assert!(status.contains(" via relay 127.0.0.1:"), "{status}");
    drop(s.sshd);
}

/// The relay logs in to a password-only target; the password never reaches
/// the agent's machine.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn e2e_relay_password_target_runs_command() {
    let password = warden_broker::testkit::sshd::login_password();
    let s = setup(
        &SshdLogin::Password,
        RelayCredential::Password(password.clone()),
    )
    .await;
    let _grant = request_and_approve(&s).await;

    assert_echo_ok(&s.cli);
    assert_no_secret_on_disk(&s.cli, &[password.as_str()]);
    drop(s.sshd);
}

/// Wait until `child` exits, at most `limit`.
fn wait_exit(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn e2e_relay_revoke_ends_access() {
    let (s, _onward) = key_setup().await;
    let grant = request_and_approve(&s).await;

    // A live session: it prints a line, then waits far longer than the test.
    let mut session = s
        .cli
        .command()
        .args(["ssh", TARGET, "--", "echo started; exec sleep 120"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = session.stdout.take().unwrap();
    let first = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || {
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line).unwrap();
            line
        }),
    )
    .await
    .expect("the live session started")
    .unwrap();
    assert_eq!(first, "started\n");

    let revoke = s.cli.run(&["revoke", &grant]);
    assert_eq!(
        revoke.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&revoke.stderr)
    );

    // The relay cuts the live session within 5 s of the revocation.
    let ended = tokio::task::spawn_blocking(move || {
        let status = wait_exit(&mut session, Duration::from_secs(5));
        if status.is_none() {
            let _ = session.kill();
            let _ = session.wait();
        }
        status
    })
    .await
    .unwrap();
    let ended = ended.expect("the live session was not cut within 5 s of the revocation");
    assert!(!ended.success(), "{ended}");
    let ends = await_audit_events(&s.broker, "relay_session_ended").await;
    assert_eq!(ends.len(), 1, "{ends:?}");
    assert_eq!(ends[0]["grant_id"], grant.as_str());
    assert_eq!(ends[0]["reason"], "revoked");

    // And no new session starts.
    let after = s.cli.run(&["ssh", TARGET, "--", "echo", "ok"]);
    assert_eq!(after.status.code(), Some(5));
    assert!(after.stdout.is_empty());
    let stderr = String::from_utf8(after.stderr).unwrap();
    assert!(stderr.contains("no active grant for nas"), "{stderr}");
    assert_eq!(audit_events(&s.broker, "relay_session_started").len(), 1);
    drop(s.sshd);
}
