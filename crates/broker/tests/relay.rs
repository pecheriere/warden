//! The SSH relay end to end: real OpenSSH clients (and a russh client where
//! a test needs protocol-level control) log in to the broker's relay with
//! an approved ephemeral key, and the relay logs in to a throwaway,
//! unprivileged `sshd` target with the target item's credential.
//!
//! Password targets need the current user's real password (see
//! `testkit::sshd`), which only Linux CI provides: the password variants
//! are compiled on Linux only. Key targets run everywhere.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use russh::client::{self, AuthResult};
use russh::keys::PrivateKeyWithHashAlg;
use russh::{ChannelMsg, Disconnect, Sig};
use serde_json::Value;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use warden_broker::policy::{RelayCredential, SshMode, SshTarget};
use warden_broker::relay::RelayLimits;
use warden_broker::requests::Clock as _;
use warden_broker::testkit::TestBroker;
use warden_broker::testkit::sshd::{HostKeyType, Sshd, SshdLogin, current_user};
use warden_broker_proto::{
    Access, AgentName, CreateRequest, Goal, Id, TargetName, UnixUser, Window,
};
use zeroize::Zeroizing;

const TARGET: &str = "nas";

fn random_key() -> PrivateKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
}

fn openssh_private(key: &PrivateKey) -> Zeroizing<String> {
    key.to_openssh(LineEnding::LF).unwrap()
}

/// Target `nas` in relay mode, served by `sshd` for the current user.
fn nas(sshd: &Sshd) -> SshTarget {
    nas_pinned(sshd, sshd.host_key().clone())
}

fn nas_pinned(sshd: &Sshd, host_key: PublicKey) -> SshTarget {
    SshTarget {
        name: TargetName::try_from(TARGET.to_owned()).unwrap(),
        host: "127.0.0.1".to_owned(),
        port: sshd.port(),
        mode: SshMode::Relay,
        users: vec![UnixUser::try_from(current_user()).unwrap()],
        max_window: Window::H1,
        host_keys: vec![host_key],
    }
}

/// A broker whose relay target `nas` is an `sshd` logging in the current
/// user with a fresh key, and whose relay listens on loopback.
struct Setup {
    broker: TestBroker,
    sshd: Sshd,
    relay: SocketAddr,
    /// The relay target's onward login key (the credential).
    onward: PrivateKey,
}

async fn key_target() -> Setup {
    key_target_with(RelayLimits::default()).await
}

async fn key_target_with(limits: RelayLimits) -> Setup {
    let broker = TestBroker::new().await;
    let onward = random_key();
    let sshd = Sshd::start(&SshdLogin::Key(onward.public_key().clone()));
    broker
        .backend
        .set_relay_target(nas(&sshd), RelayCredential::Key(openssh_private(&onward)));
    let relay = broker.spawn_relay_with(limits).await;
    Setup {
        broker,
        sshd,
        relay,
        onward,
    }
}

#[cfg(target_os = "linux")]
async fn password_target() -> (TestBroker, Sshd, SocketAddr, Zeroizing<String>) {
    let broker = TestBroker::new().await;
    let password = warden_broker::testkit::sshd::login_password();
    let sshd = Sshd::start(&SshdLogin::Password);
    broker
        .backend
        .set_relay_target(nas(&sshd), RelayCredential::Password(password.clone()));
    let relay = broker.spawn_relay().await;
    (broker, sshd, relay, password)
}

/// An agent holding an approved relay grant for `nas`.
struct Agent {
    key: PrivateKey,
    grant_id: Id,
}

async fn approved_agent(broker: &TestBroker, name: &str) -> Agent {
    broker.add_agent(name).await;
    let key = random_key();
    let request = CreateRequest {
        goal: Goal::try_from("relay test".to_owned()).unwrap(),
        access: Access::Ssh {
            target: TargetName::try_from(TARGET.to_owned()).unwrap(),
            user: UnixUser::try_from(current_user()).unwrap(),
            public_key: key.public_key().to_openssh().unwrap(),
        },
        window: Window::M15,
    };
    let (_, token) = broker.create_request(name, request).await;
    let approved = broker.approve(&token, Window::M15).await;
    assert!(approved.status.is_success(), "{}", approved.body);
    let grants = broker
        .state()
        .requests
        .grants_for(&AgentName::try_from(name.to_owned()).unwrap())
        .await
        .unwrap();
    assert_eq!(grants.len(), 1);
    Agent {
        key,
        grant_id: grants[0].grant_id.clone(),
    }
}

/// The OpenSSH client, hardened like `warden ssh`: no config, only the
/// given key, the relay's host key pinned.
struct OpenSsh {
    dir: TempDir,
    relay: SocketAddr,
}

impl OpenSsh {
    fn new(broker: &TestBroker, relay: SocketAddr, key: &PrivateKey) -> Self {
        let dir = tempfile::Builder::new()
            .prefix("wrcli")
            .tempdir_in("/tmp")
            .unwrap();
        write_private(&dir.path().join("id"), &openssh_private(key));
        let host_key = &broker.state().requests.relay().unwrap().host_key;
        write_private(
            &dir.path().join("known_hosts"),
            &format!("[127.0.0.1]:{} {host_key}\n", relay.port()),
        );
        Self { dir, relay }
    }

    fn command(&self, user: &str, extra: &[&str], remote: &[&str]) -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new("ssh");
        cmd.arg("-F")
            .arg("/dev/null")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("IdentitiesOnly=yes")
            .arg("-o")
            .arg("IdentityAgent=none")
            .arg("-o")
            .arg(format!(
                "IdentityFile={}",
                self.dir.path().join("id").display()
            ))
            .arg("-o")
            .arg(format!(
                "UserKnownHostsFile={}",
                self.dir.path().join("known_hosts").display()
            ))
            .arg("-o")
            .arg("GlobalKnownHostsFile=/dev/null")
            .arg("-o")
            .arg("StrictHostKeyChecking=yes")
            .arg("-o")
            .arg("ConnectTimeout=10")
            .arg("-p")
            .arg(self.relay.port().to_string())
            .arg("-l")
            .arg(user)
            .args(extra)
            .arg("127.0.0.1")
            .arg("--")
            .args(remote)
            .kill_on_drop(true);
        cmd
    }

    async fn run_as(&self, user: &str, extra: &[&str], remote: &[&str], stdin: &[u8]) -> Output {
        let mut child = self
            .command(user, extra, remote)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Written while the output is read, so neither pipe can fill up and
        // stall the other.
        let mut input = child.stdin.take().unwrap();
        let stdin = stdin.to_vec();
        let writer = tokio::spawn(async move {
            // ssh may exit (and close its stdin) before reading it all.
            let _ = input.write_all(&stdin).await;
        });
        let out = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
            .await
            .expect("ssh finished")
            .unwrap();
        writer.await.unwrap();
        out
    }

    async fn run(&self, remote: &[&str]) -> Output {
        self.run_as(TARGET, &[], remote, b"").await
    }
}

fn write_private(path: &Path, contents: &str) {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(contents.as_bytes()).unwrap();
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Audit entries (their `event` objects), oldest first.
fn audit_events(broker: &TestBroker) -> Vec<Value> {
    std::fs::read_to_string(broker.audit_path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["event"].clone())
        .collect()
}

fn events_of(broker: &TestBroker, kind: &str) -> Vec<Value> {
    audit_events(broker)
        .into_iter()
        .filter(|e| e["type"] == kind)
        .collect()
}

/// Wait until the audit log holds `count` entries of `kind`.
async fn await_events(broker: &TestBroker, kind: &str, count: usize) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let found = events_of(broker, kind);
        if found.len() >= count {
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "{count} {kind} entries never appeared: {:?}",
            audit_events(broker)
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Number of connections `sshd` has seen.
fn sshd_connections(sshd: &Sshd) -> usize {
    sshd.log().matches("Connection from 127.0.0.1").count()
}

// --- russh client, for protocol-level checks -------------------------------

/// Accepts only the relay's host key.
struct Client {
    host_key: russh::keys::PublicKey,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(matches!(
            key,
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } if key.key_data() == self.host_key.key_data()
        ))
    }
}

fn russh_key(key: &PrivateKey) -> PrivateKeyWithHashAlg {
    let key = russh::keys::PrivateKey::from_openssh(openssh_private(key).as_str()).unwrap();
    PrivateKeyWithHashAlg::new(Arc::new(key), None)
}

struct Connected {
    handle: client::Handle<Client>,
}

/// Connect to the relay, without logging in yet.
async fn connect(broker: &TestBroker, relay: SocketAddr) -> Connected {
    let host_key =
        russh::keys::PublicKey::from_openssh(&broker.state().requests.relay().unwrap().host_key)
            .unwrap();
    let handle = client::connect(
        Arc::new(client::Config::default()),
        relay,
        Client { host_key },
    )
    .await
    .unwrap();
    Connected { handle }
}

/// Connect and log in to target `user` with `key`.
async fn login(broker: &TestBroker, relay: SocketAddr, user: &str, key: &PrivateKey) -> Connected {
    let mut c = connect(broker, relay).await;
    let auth = c
        .handle
        .authenticate_publickey(user, russh_key(key))
        .await
        .unwrap();
    assert!(matches!(auth, AuthResult::Success), "{auth:?}");
    c
}

/// What came back on a session channel until it closed.
#[derive(Debug, Default)]
struct Collected {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_status: Option<u32>,
    exit_signal: Option<Sig>,
}

async fn collect(channel: &mut russh::Channel<client::Msg>) -> Collected {
    let mut out = Collected::default();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while let Ok(Some(msg)) = tokio::time::timeout_at(deadline, channel.wait()).await {
        match msg {
            ChannelMsg::Data { data } => out.stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, ext: 1 } => out.stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => out.exit_status = Some(exit_status),
            ChannelMsg::ExitSignal { signal_name, .. } => out.exit_signal = Some(signal_name),
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    out
}

/// The next reply (success or failure) to a channel request.
async fn reply(channel: &mut russh::Channel<client::Msg>) -> bool {
    reply_keeping_stderr(channel, &mut Vec::new()).await
}

/// Like [`reply`], keeping stderr that arrives meanwhile in `stderr`.
async fn reply_keeping_stderr(
    channel: &mut russh::Channel<client::Msg>,
    stderr: &mut Vec<u8>,
) -> bool {
    loop {
        match tokio::time::timeout(Duration::from_secs(30), channel.wait())
            .await
            .expect("a reply")
        {
            Some(ChannelMsg::Success) => return true,
            Some(ChannelMsg::Failure) => return false,
            Some(ChannelMsg::ExtendedData { data, ext: 1 }) => stderr.extend_from_slice(&data),
            Some(_) => {}
            None => panic!("channel closed before replying"),
        }
    }
}

// --- tests ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn relay_works_with_key_target() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);

    let out = ssh.run(&["echo", "ok"]).await;
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "ok\n");

    // stdin reaches the target and its EOF ends `cat`; stderr comes back.
    let out = ssh
        .run_as(TARGET, &[], &["cat; echo done >&2"], b"hello relay\n")
        .await;
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "hello relay\n");
    assert!(text(&out.stderr).contains("done"), "{}", text(&out.stderr));

    // An interactive shell on a pty.
    let out = ssh
        .run_as(TARGET, &["-tt"], &[], b"echo shell-$((40+2)); exit 3\n")
        .await;
    assert!(
        text(&out.stdout).contains("shell-42"),
        "{}",
        text(&out.stdout)
    );
    assert_eq!(out.status.code(), Some(3), "stderr: {}", text(&out.stderr));

    // Only LANG, LC_* and TERM are passed on.
    let out = ssh
        .run_as(
            TARGET,
            &["-o", "SetEnv=LANG=C LC_TIME=C EVIL=1"],
            &["echo \"${LANG:-unset}/${LC_TIME:-unset}/${EVIL:-unset}\""],
            b"",
        )
        .await;
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "C/C/unset\n");
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn relay_shell_and_exec_work_with_password_target() {
    let (broker, sshd, relay, _password) = password_target().await;
    let agent = approved_agent(&broker, "bot").await;
    let ssh = OpenSsh::new(&broker, relay, &agent.key);

    let out = ssh.run(&["echo", "ok"]).await;
    assert_eq!(out.status.code(), Some(0), "stderr: {}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "ok\n");

    let out = ssh
        .run_as(TARGET, &["-tt"], &[], b"echo shell-$((40+2)); exit 4\n")
        .await;
    assert!(
        text(&out.stdout).contains("shell-42"),
        "{}",
        text(&out.stdout)
    );
    assert_eq!(out.status.code(), Some(4), "stderr: {}", text(&out.stderr));
    assert!(sshd.log().contains("Accepted password"), "{}", sshd.log());
}

#[tokio::test(flavor = "multi_thread")]
async fn window_change_and_signals_are_forwarded() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;

    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    assert!(reply(&mut channel).await);
    channel.exec(true, "sleep 2; stty size").await.unwrap();
    assert!(reply(&mut channel).await);
    channel.window_change(132, 50, 0, 0).await.unwrap();
    let out = collect(&mut channel).await;
    assert!(
        text(&out.stdout).contains("50 132"),
        "{}",
        text(&out.stdout)
    );

    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel
        .exec(true, "trap 'echo got-term; exit 9' TERM; sleep 20 & wait")
        .await
        .unwrap();
    assert!(reply(&mut channel).await);
    tokio::time::sleep(Duration::from_millis(500)).await;
    channel.signal(Sig::TERM).await.unwrap();
    let out = collect(&mut channel).await;
    assert!(text(&out.stdout).contains("got-term"), "{out:?}");
    assert_eq!(out.exit_status, Some(9), "{out:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_refuses_unbound_key_and_inactive_grant() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let refused = |out: &Output| {
        assert_eq!(out.status.code(), Some(255), "{}", text(&out.stderr));
        assert!(out.stdout.is_empty());
        assert!(
            text(&out.stderr).contains("Permission denied (publickey)"),
            "{}",
            text(&out.stderr)
        );
    };

    // A key nobody approved, the approved key for an unknown target, a
    // cert-mode target and a malformed name: all refused the same way.
    let stranger = random_key();
    let other = OpenSsh::new(&s.broker, s.relay, &stranger);
    refused(&other.run(&["true"]).await);
    for user in ["nosuch", "pi", "Not A Target"] {
        refused(&ssh.run_as(user, &[], &["true"], b"").await);
    }

    // The approved key works ...
    let out = ssh.run(&["echo", "ok"]).await;
    assert_eq!(text(&out.stdout), "ok\n", "{}", text(&out.stderr));

    // ... until its grant is revoked.
    s.broker
        .state()
        .requests
        .revoke_grant(&agent.grant_id, "test")
        .await
        .unwrap();
    refused(&ssh.run(&["true"]).await);

    // An expired grant is refused too.
    let late = approved_agent(&s.broker, "late").await;
    let late_ssh = OpenSsh::new(&s.broker, s.relay, &late.key);
    s.broker.clock.advance(15 * 60);
    refused(&late_ssh.run(&["true"]).await);

    // At most 3 attempts per connection: the 4th, with the right key,
    // never gets a chance.
    s.broker.clock.advance(-15 * 60);
    let mut c = connect(&s.broker, s.relay).await;
    for _ in 0..3 {
        let auth = c
            .handle
            .authenticate_publickey(TARGET, russh_key(&random_key()))
            .await
            .unwrap();
        assert!(!matches!(auth, AuthResult::Success));
    }
    let fourth = c
        .handle
        .authenticate_publickey(TARGET, russh_key(&late.key))
        .await;
    assert!(!matches!(fourth, Ok(AuthResult::Success)), "{fourth:?}");

    // Only the one accepted session ever reached the target.
    assert_eq!(sshd_connections(&s.sshd), 1, "{}", s.sshd.log());
    assert_eq!(events_of(&s.broker, "relay_session_started").len(), 1);
    // Refused logins are audited, without key material.
    let refusals = await_events(&s.broker, "relay_login_refused", 7).await;
    let users: Vec<&str> = refusals
        .iter()
        .map(|e| e["user"].as_str().unwrap())
        .collect();
    for user in [TARGET, "nosuch", "pi", "<invalid>"] {
        assert!(users.contains(&user), "{users:?}");
    }
    let log = std::fs::read_to_string(s.broker.audit_path()).unwrap();
    for key in [&stranger, &agent.key, &late.key] {
        let public = key.public_key().to_openssh().unwrap();
        let base64 = public.split(' ').nth(1).unwrap();
        assert!(!log.contains(base64), "public key in the audit log");
        let fingerprint = key
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        assert!(!log.contains(&fingerprint));
    }
    drop(c);
}

#[tokio::test(flavor = "multi_thread")]
async fn onward_host_key_mismatch_aborts_before_auth() {
    let s = key_target().await;
    // The target presents a key other than the pinned one: a
    // man-in-the-middle, or a re-imaged appliance.
    s.broker.backend.set_relay_target(
        nas_pinned(&s.sshd, random_key().public_key().clone()),
        RelayCredential::Key(openssh_private(&s.onward)),
    );
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let out = ssh.run(&["echo", "ok"]).await;
    assert_ne!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("warden relay: the target's host key does not match"),
        "{stderr}"
    );

    // The relay reached the target but never tried to log in.
    let log = s.sshd.log();
    assert_eq!(sshd_connections(&s.sshd), 1, "{log}");
    for auth in [
        "Accepted",
        "Failed",
        "Postponed",
        "Invalid user",
        "publickey",
    ] {
        assert!(!log.contains(auth), "{auth}: {log}");
    }
    let ended = await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(ended[0]["reason"], "host key mismatch");
    assert_eq!(ended[0]["grant_id"], agent.grant_id.as_str());
    assert_eq!(ended[0]["bytes_to_target"], 0);
}

/// A broker whose `nas` is an `sshd` with `host_keys`, of which `pin`
/// chooses the pinned ones, plus an approved agent's OpenSSH client.
async fn host_key_target(
    host_keys: &[HostKeyType],
    pin: impl FnOnce(&Sshd) -> Vec<PublicKey>,
) -> (Setup, OpenSsh) {
    let broker = TestBroker::new().await;
    let onward = random_key();
    let sshd = Sshd::start_with(&SshdLogin::Key(onward.public_key().clone()), host_keys);
    let mut target = nas(&sshd);
    target.host_keys = pin(&sshd);
    broker
        .backend
        .set_relay_target(target, RelayCredential::Key(openssh_private(&onward)));
    let relay = broker.spawn_relay().await;
    let agent = approved_agent(&broker, "bot").await;
    let ssh = OpenSsh::new(&broker, relay, &agent.key);
    let setup = Setup {
        broker,
        sshd,
        relay,
        onward,
    };
    (setup, ssh)
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_pins_ecdsa_when_target_also_has_ed25519() {
    // The target offers Ed25519 too, but only its ECDSA key is pinned: the
    // relay must ask for ECDSA rather than fail on the Ed25519 key.
    let (_s, ssh) = host_key_target(&[HostKeyType::Ed25519, HostKeyType::EcdsaP256], |sshd| {
        vec![sshd.host_keys()[1].clone()]
    })
    .await;
    let out = ssh.run(&["echo", "ok"]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "ok\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_verifies_rsa_host_key() {
    let (s, ssh) = host_key_target(&[HostKeyType::Rsa], |sshd| sshd.host_keys().to_vec()).await;
    let out = ssh.run(&["echo", "ok"]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "ok\n");
    let log = s.sshd.log();
    assert!(log.contains("Accepted publickey"), "{log}");
}

#[tokio::test(flavor = "multi_thread")]
async fn unpinned_algorithm_still_mismatch() {
    // A different ECDSA key, from another host.
    let other_ecdsa = Sshd::start_with(
        &SshdLogin::Key(random_key().public_key().clone()),
        &[HostKeyType::EcdsaP256],
    )
    .host_key()
    .clone();
    // Pinned while the target has Ed25519 and (another) ECDSA key ...
    let (s, ssh) = host_key_target(&[HostKeyType::Ed25519, HostKeyType::EcdsaP256], |_| {
        vec![other_ecdsa.clone()]
    })
    .await;
    // ... and while the target has only Ed25519 (no common algorithm).
    let (t, ssh2) = host_key_target(&[HostKeyType::Ed25519], |_| vec![other_ecdsa.clone()]).await;
    for (setup, client) in [(&s, &ssh), (&t, &ssh2)] {
        let out = client.run(&["true"]).await;
        assert_ne!(out.status.code(), Some(0));
        assert!(
            text(&out.stderr).contains("warden relay: the target's host key does not match"),
            "{}",
            text(&out.stderr)
        );
        let log = setup.sshd.log();
        for auth in ["Accepted", "Failed", "Postponed"] {
            assert!(!log.contains(auth), "{auth}: {log}");
        }
        let ended = await_events(&setup.broker, "relay_session_ended", 1).await;
        assert_eq!(ended[0]["reason"], "host key mismatch");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn onward_login_failure_is_reported_and_audited() {
    let s = key_target().await;
    // The item's key is not the one the target authorizes.
    s.broker.backend.set_relay_target(
        nas(&s.sshd),
        RelayCredential::Key(openssh_private(&random_key())),
    );
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let out = ssh.run(&["echo", "ok"]).await;
    assert_ne!(out.status.code(), Some(0));
    assert!(
        text(&out.stderr).contains("warden relay: the target refused the relay's login"),
        "{}",
        text(&out.stderr)
    );
    let ended = await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(ended[0]["reason"], "onward login refused");
}

#[tokio::test(flavor = "multi_thread")]
async fn session_refused_when_target_policy_changed() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);

    // The approved user is no longer allowed on the target.
    let mut changed = nas(&s.sshd);
    changed.users = vec![UnixUser::try_from("someone-else".to_owned()).unwrap()];
    s.broker
        .backend
        .set_relay_target(changed, RelayCredential::Key(openssh_private(&s.onward)));
    let out = ssh.run(&["true"]).await;
    assert_ne!(out.status.code(), Some(0));
    assert!(
        text(&out.stderr).contains("warden relay: this access is no longer valid"),
        "{}",
        text(&out.stderr)
    );

    // The target is no longer a relay target.
    let mut cert = nas(&s.sshd);
    cert.mode = SshMode::Cert;
    s.broker.backend.set_target(cert);
    let out = ssh.run(&["true"]).await;
    assert!(
        text(&out.stderr).contains("warden relay: this access is no longer valid"),
        "{}",
        text(&out.stderr)
    );

    let refused = await_events(&s.broker, "relay_session_refused", 2).await;
    assert_eq!(refused[0]["reason"], "user no longer allowed on the target");
    assert_eq!(refused[1]["reason"], "target is no longer a relay target");
    assert_eq!(sshd_connections(&s.sshd), 0, "{}", s.sshd.log());
    assert!(events_of(&s.broker, "relay_session_started").is_empty());
}

/// Replace target `nas` with `changed` after `agent` was approved, then
/// check that a session is refused before the relay connects anywhere,
/// on record as `target policy changed`.
async fn assert_refused_after_destination_change(s: &Setup, agent: &Agent, changed: SshTarget) {
    s.broker
        .backend
        .set_relay_target(changed, RelayCredential::Key(openssh_private(&s.onward)));
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let out = ssh.run(&["echo", "ok"]).await;
    assert_ne!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    assert!(
        text(&out.stderr).contains("warden relay: this access is no longer valid"),
        "{}",
        text(&out.stderr)
    );
    let refused = await_events(&s.broker, "relay_session_refused", 1).await;
    assert_eq!(refused[0]["reason"], "target policy changed");
    assert_eq!(refused[0]["grant_id"], agent.grant_id.as_str());
    assert!(events_of(&s.broker, "relay_session_started").is_empty());
    assert_eq!(sshd_connections(&s.sshd), 0, "{}", s.sshd.log());
}

#[tokio::test(flavor = "multi_thread")]
async fn session_refused_when_address_changed_after_approval() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    // Another name for the same sshd: the relay would reach it, but it is
    // not the address the owner approved.
    let mut moved = nas(&s.sshd);
    moved.host = "localhost".to_owned();
    assert_refused_after_destination_change(&s, &agent, moved).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn session_refused_when_host_keys_changed_after_approval() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    // The sshd's own key is still pinned, next to one the owner never saw.
    let mut repinned = nas(&s.sshd);
    repinned.host_keys.push(random_key().public_key().clone());
    assert_refused_after_destination_change(&s, &agent, repinned).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rotated_credential_alone_still_works() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    // The target's login key is rotated after approval: the destination
    // is unchanged, so the session runs with the new credential.
    let rotated = random_key();
    s.sshd.authorize_only(rotated.public_key());
    s.broker.backend.set_relay_target(
        nas(&s.sshd),
        RelayCredential::Key(openssh_private(&rotated)),
    );
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let out = ssh.run(&["echo", "rotated"]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "rotated\n");
    assert!(events_of(&s.broker, "relay_session_refused").is_empty());
    await_events(&s.broker, "relay_session_ended", 1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn forwarding_and_subsystems_refused() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;

    // -R: remote port forwarding.
    assert!(c.handle.tcpip_forward("127.0.0.1", 0).await.is_err());
    // -L: a direct-tcpip channel, here aimed at the target itself.
    let direct = c
        .handle
        .channel_open_direct_tcpip("127.0.0.1", u32::from(s.sshd.port()), "127.0.0.1", 40000)
        .await;
    assert!(direct.is_err());

    let mut channel = c.handle.channel_open_session().await.unwrap();
    // One session channel per connection.
    assert!(c.handle.channel_open_session().await.is_err());
    // sftp and any other subsystem, X11 and agent forwarding.
    let mut stderr = Vec::new();
    channel.request_subsystem(true, "sftp").await.unwrap();
    assert!(!reply_keeping_stderr(&mut channel, &mut stderr).await);
    channel
        .request_x11(true, false, "MIT-MAGIC-COOKIE-1", "00", 0)
        .await
        .unwrap();
    assert!(!reply_keeping_stderr(&mut channel, &mut stderr).await);
    channel.agent_forward(true).await.unwrap();
    assert!(!reply_keeping_stderr(&mut channel, &mut stderr).await);

    // The session itself is unaffected.
    channel.exec(true, "echo still-ok").await.unwrap();
    assert!(reply_keeping_stderr(&mut channel, &mut stderr).await);
    let out = collect(&mut channel).await;
    assert_eq!(text(&out.stdout), "still-ok\n");
    assert_eq!(out.exit_status, Some(0));
    stderr.extend_from_slice(&out.stderr);
    let stderr = text(&stderr);
    for notice in [
        "warden relay: port forwarding is not allowed",
        "warden relay: subsystems (such as sftp) are not allowed",
        "warden relay: X11 forwarding is not allowed",
        "warden relay: agent forwarding is not allowed",
    ] {
        assert!(stderr.contains(notice), "{notice}: {stderr}");
    }

    // The OpenSSH client reports a refused sftp subsystem.
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let mut cmd = ssh.command(TARGET, &["-s"], &["sftp"]);
    let out = cmd.stdin(Stdio::null()).output().await.unwrap();
    assert_ne!(out.status.code(), Some(0));
    assert!(
        text(&out.stderr).contains("subsystem request failed"),
        "{}",
        text(&out.stderr)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn exit_status_propagates() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let out = ssh.run(&["exit", "7"]).await;
    assert_eq!(out.status.code(), Some(7), "{}", text(&out.stderr));
    let ended = await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(ended[0]["exit_status"], 7);
    assert_eq!(ended[0]["reason"], "exited");

    // A command killed by a signal reports the signal.
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel.exec(true, "kill -TERM $$").await.unwrap();
    assert!(reply(&mut channel).await);
    let out = collect(&mut channel).await;
    assert!(matches!(out.exit_signal, Some(Sig::TERM)), "{out:?}");
    assert_eq!(out.exit_status, None, "{out:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn session_audited_start_before_bytes_and_end() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);

    // The target reads the audit log itself: the start entry is already
    // there, durably, when the command runs; the end entry is not.
    let audit = s.broker.audit_path().display().to_string();
    let out = ssh
        .run_as(
            TARGET,
            &[],
            &[&format!("cat >/dev/null; cat '{audit}'")],
            b"12345",
        )
        .await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let seen = text(&out.stdout);
    let started: Vec<Value> = seen
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap()["event"].clone())
        .filter(|e| e["type"] == "relay_session_started")
        .collect();
    assert_eq!(started.len(), 1, "{seen}");
    assert_eq!(started[0]["grant_id"], agent.grant_id.as_str());
    assert_eq!(started[0]["target"], TARGET);
    assert_eq!(started[0]["user"], current_user());
    assert_eq!(
        started[0]["command"],
        format!("cat >/dev/null; cat '{audit}'")
    );
    assert!(!seen.contains("relay_session_ended"), "{seen}");

    let ended = await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(ended[0]["grant_id"], agent.grant_id.as_str());
    assert_eq!(ended[0]["reason"], "exited");
    assert_eq!(ended[0]["exit_status"], 0);
    assert_eq!(ended[0]["bytes_to_target"], 5);
    assert_eq!(
        ended[0]["bytes_from_target"],
        u64::try_from(out.stdout.len() + out.stderr.len()).unwrap()
    );

    // A shell session is audited without a command, and a long command is
    // cut to 200 characters.
    let out = ssh.run_as(TARGET, &["-tt"], &[], b"exit 0\n").await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let long = format!("true {}", "x".repeat(300));
    let out = ssh.run(&[&long]).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let started = await_events(&s.broker, "relay_session_started", 3).await;
    assert!(started[1]["command"].is_null());
    let cut = started[2]["command"].as_str().unwrap();
    assert_eq!(cut.chars().count(), 201);
    assert!(cut.ends_with('…'));

    // If the start cannot be recorded, nothing reaches the target.
    let before = sshd_connections(&s.sshd);
    let holder = std::fs::File::open(s.broker.audit_path()).unwrap();
    holder.lock().unwrap();
    let out = ssh.run(&["echo", "unrecorded"]).await;
    holder.unlock().unwrap();
    assert_ne!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    assert!(
        text(&out.stderr).contains("warden relay: the session could not be recorded"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(sshd_connections(&s.sshd), before, "{}", s.sshd.log());
}

/// Everything logged through `tracing` (and `log`, which russh uses) by
/// this test binary, at every level.
fn captured_logs() -> Arc<Mutex<Vec<u8>>> {
    static LOGS: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = Arc::new(Mutex::new(Vec::new()));
        let sink = logs.clone();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || SharedWriter(sink.clone()))
            .try_init()
            .expect("install the capturing subscriber");
        logs
    })
    .clone()
}

struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Pieces of `credential` that must never appear anywhere: every line of
/// the key's body (or the password), and the key's private bytes in hex.
fn needles(credential: &RelayCredential) -> Vec<String> {
    match credential {
        RelayCredential::Key(text) => {
            let key = PrivateKey::from_openssh(text.as_str()).unwrap();
            let seed = key.key_data().ed25519().unwrap().private.to_bytes();
            let mut needles: Vec<String> = text
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .map(str::to_owned)
                .collect();
            needles.push(hex::encode(seed));
            needles.push(format!("{:?}", &seed[..]));
            needles
        }
        RelayCredential::Password(password) => vec![password.to_string()],
    }
}

fn assert_nowhere(credential: &RelayCredential, broker: &TestBroker, outputs: &[&Output]) {
    let logs = text(&captured_logs().lock().unwrap());
    assert!(
        logs.contains("relay: session"),
        "the capture saw the relay's logs"
    );
    // And the SSH library's own debug output, through the `log` bridge.
    assert!(logs.contains("russh"), "the capture saw russh's logs");
    let audit = std::fs::read_to_string(broker.audit_path()).unwrap();
    for needle in needles(credential) {
        assert!(!logs.contains(&needle), "credential in the logs");
        assert!(!audit.contains(&needle), "credential in the audit log");
        for out in outputs {
            assert!(!text(&out.stdout).contains(&needle));
            assert!(!text(&out.stderr).contains(&needle));
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_never_logged_or_audited() {
    captured_logs();
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let ok = ssh.run(&["echo", "ok"]).await;
    assert_eq!(text(&ok.stdout), "ok\n", "{}", text(&ok.stderr));

    // The failure paths too: a refused onward login and a host key mismatch.
    let wrong_key = random_key();
    s.broker.backend.set_relay_target(
        nas(&s.sshd),
        RelayCredential::Key(openssh_private(&wrong_key)),
    );
    let refused = ssh.run(&["true"]).await;
    // A host key mismatch needs a grant approved for the wrong pin: one
    // whose pin changed since approval is refused before connecting.
    s.broker.backend.set_relay_target(
        nas_pinned(&s.sshd, random_key().public_key().clone()),
        RelayCredential::Key(openssh_private(&s.onward)),
    );
    let mispinned = approved_agent(&s.broker, "other").await;
    let mismatch = OpenSsh::new(&s.broker, s.relay, &mispinned.key)
        .run(&["true"])
        .await;
    await_events(&s.broker, "relay_session_ended", 3).await;
    let right = RelayCredential::Key(openssh_private(&s.onward));
    let wrong = RelayCredential::Key(openssh_private(&wrong_key));
    assert_nowhere(&right, &s.broker, &[&ok, &refused, &mismatch]);
    assert_nowhere(&wrong, &s.broker, &[&ok, &refused, &mismatch]);
    // Debug output of the credential is redacted.
    assert!(!format!("{right:?}").contains(&needles(&right)[0]));
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn password_credential_never_logged_or_audited() {
    captured_logs();
    let (broker, _sshd, relay, password) = password_target().await;
    let agent = approved_agent(&broker, "bot").await;
    let ssh = OpenSsh::new(&broker, relay, &agent.key);
    let ok = ssh.run(&["echo", "ok"]).await;
    assert_eq!(text(&ok.stdout), "ok\n", "{}", text(&ok.stderr));
    await_events(&broker, "relay_session_ended", 1).await;
    assert_nowhere(&RelayCredential::Password(password), &broker, &[&ok]);
}

/// A session holding the relay open until its channel is dropped.
async fn hold_session(s: &Setup, key: &PrivateKey) -> (Connected, russh::Channel<client::Msg>) {
    let c = login(&s.broker, s.relay, TARGET, key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel.exec(true, "sleep 60").await.unwrap();
    assert!(reply(&mut channel).await);
    (c, channel)
}

fn too_many(out: &Output, what: &str) {
    assert_eq!(out.status.code(), Some(255), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains(what), "{}", text(&out.stderr));
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrency_limits_enforced() {
    let s = key_target_with(RelayLimits {
        max_sessions: 5,
        ..RelayLimits::default()
    })
    .await;
    let a = approved_agent(&s.broker, "a").await;
    let b = approved_agent(&s.broker, "b").await;

    // 4 sessions per grant.
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(hold_session(&s, &a.key).await);
    }
    let ssh_a = OpenSsh::new(&s.broker, s.relay, &a.key);
    too_many(
        &ssh_a.run(&["true"]).await,
        "warden relay: too many sessions for this grant",
    );

    // 5 overall (configured): b gets one, then none.
    held.push(hold_session(&s, &b.key).await);
    let ssh_b = OpenSsh::new(&s.broker, s.relay, &b.key);
    too_many(
        &ssh_b.run(&["true"]).await,
        "warden relay: too many relay sessions",
    );

    // Ending a session frees its place.
    let (c, channel) = held.remove(0);
    drop(channel);
    c.handle
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let out = ssh_b.run(&["echo", "ok"]).await;
        if out.status.success() {
            assert_eq!(text(&out.stdout), "ok\n");
            break;
        }
        assert!(Instant::now() < deadline, "{}", text(&out.stderr));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    drop(held);
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_connections_limited_and_timed_out() {
    let s = key_target_with(RelayLimits {
        max_unauthenticated_per_ip: 2,
        auth_timeout: Duration::from_secs(2),
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;

    // Two stalled connections take this address's pre-login places: one
    // says nothing, the other stops after the version exchange.
    let mut silent = Vec::new();
    for version in [None, Some(b"SSH-2.0-stalled\r\n")] {
        let mut conn = TcpStream::connect(s.relay).await.unwrap();
        let mut banner = [0_u8; 8];
        conn.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"SSH-2.0-");
        if let Some(version) = version {
            conn.write_all(version).await.unwrap();
        }
        silent.push(conn);
    }
    // A third is closed at once, without a banner.
    let mut third = TcpStream::connect(s.relay).await.unwrap();
    let mut buf = [0_u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(1), third.read(&mut buf))
        .await
        .expect("closed at once")
        .unwrap_or(0);
    assert_eq!(n, 0);

    // The stalled ones are cut off after the login timeout (2 s) and the
    // goodbye wait (5 s) ...
    for conn in &mut silent {
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(12), conn.read_to_end(&mut rest))
            .await
            .expect("closed after the login timeout")
            .ok();
    }
    // ... which frees their places.
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel.exec(true, "echo ok").await.unwrap();
    assert!(reply(&mut channel).await);
    assert_eq!(text(&collect(&mut channel).await.stdout), "ok\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_ends_live_sessions_audited() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let (_c, mut channel) = hold_session(&s, &agent.key).await;
    s.broker.stop_relay().await;
    let out = collect(&mut channel).await;
    assert_eq!(out.exit_status, None);
    let ended = await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(ended[0]["reason"], "relay shutting down");
    assert_each_start_ended(&s.broker).await;
}

/// A loopback port nothing listens on (yet).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Run `warden-server serve` with a minimal configuration (the relay's
/// public address only if `relay_public` is set); return it with its
/// relay listen port and host key path once its agent API answers.
async fn spawn_server(dir: &Path, relay_public: bool) -> (tokio::process::Child, u16, PathBuf) {
    let (api, approval, relay) = (free_port(), free_port(), free_port());
    let host_key = dir.join("relay_host_ed25519");
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_warden-server"));
    cmd.arg("serve")
        .env_clear()
        .env("WARDEN_DB_PATH", dir.join("warden.db"))
        .env("WARDEN_AUDIT_PATH", dir.join("audit.jsonl"))
        .env("WARDEN_PUBLIC_URL", "https://warden.example.ts.net")
        .env("WARDEN_OWNER_LOGIN", "alice@example.com")
        .env("WARDEN_OP_CONNECT_URL", "http://127.0.0.1:9")
        .env("WARDEN_OP_CONNECT_TOKEN", "unused")
        .env("WARDEN_NTFY_URL", "https://ntfy.invalid/warden")
        .env("WARDEN_API_LISTEN", format!("127.0.0.1:{api}"))
        .env("WARDEN_APPROVAL_LISTEN", format!("127.0.0.1:{approval}"))
        .env("WARDEN_RELAY_LISTEN", format!("127.0.0.1:{relay}"))
        .env("WARDEN_RELAY_HOST_KEY_PATH", &host_key)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if relay_public {
        cmd.env("WARDEN_RELAY_PUBLIC_ADDR", "relay.example.ts.net:2222");
    }
    let child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", api)).await.is_err() {
        assert!(Instant::now() < deadline, "warden-server did not start");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (child, relay, host_key)
}

async fn terminate(mut child: tokio::process::Child) {
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id().unwrap()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    let status = tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .expect("warden-server stopped")
        .unwrap();
    assert!(status.success(), "{status}");
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_runs_the_relay_only_when_configured() {
    let dir = tempfile::tempdir().unwrap();
    let (server, relay, host_key) = spawn_server(dir.path(), true).await;
    // The relay listener is bound just after the HTTP ones.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut conn = loop {
        match TcpStream::connect(("127.0.0.1", relay)).await {
            Ok(conn) => break conn,
            Err(e) => assert!(Instant::now() < deadline, "relay not listening: {e}"),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let mut banner = [0_u8; 16];
    conn.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"SSH-2.0-warden\r\n");
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&host_key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    terminate(server).await;
    // Stopping closed the relay's connections too.
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), conn.read_to_end(&mut rest))
        .await
        .expect("connection closed")
        .ok();

    let dir = tempfile::tempdir().unwrap();
    let (server, relay, host_key) = spawn_server(dir.path(), false).await;
    assert!(TcpStream::connect(("127.0.0.1", relay)).await.is_err());
    assert!(!host_key.exists());
    terminate(server).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_during_onward_setup_records_end() {
    let s = key_target().await;
    // The target accepts TCP connections but never speaks SSH, so the
    // relay is stuck connecting onward (for up to its 10 s timeout).
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut target = nas(&s.sshd);
    target.port = silent.local_addr().unwrap().port();
    s.broker
        .backend
        .set_relay_target(target, RelayCredential::Key(openssh_private(&s.onward)));
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let client = tokio::spawn(async move { ssh.run(&["true"]).await });
    let (_held, _) = silent.accept().await.unwrap();
    await_events(&s.broker, "relay_session_started", 1).await;

    let stopping = Instant::now();
    s.broker.stop_relay().await;
    // The stop returns only once the session's end is on record.
    let ended = events_of(&s.broker, "relay_session_ended");
    assert_eq!(ended.len(), 1, "{:?}", audit_events(&s.broker));
    assert_eq!(ended[0]["reason"], "relay shutting down");
    assert_eq!(ended[0]["grant_id"], agent.grant_id.as_str());
    assert!(
        stopping.elapsed() < Duration::from_secs(8),
        "{:?}",
        stopping.elapsed()
    );
    let out = client.await.unwrap();
    assert_ne!(out.status.code(), Some(0));
}

/// Log `agent` in, open its session channel and ask for `echo ok`; the
/// reply and everything after it are collected on a task. Returns the
/// connection, the task, and when the start was asked for.
async fn exec_in_background(
    s: &Setup,
    agent: &Agent,
) -> (
    Connected,
    tokio::task::JoinHandle<(bool, Vec<u8>, Collected)>,
    Instant,
) {
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel.exec(true, "echo ok").await.unwrap();
    let asked = Instant::now();
    let task = tokio::spawn(async move {
        let mut stderr = Vec::new();
        let replied = reply_keeping_stderr(&mut channel, &mut stderr).await;
        let out = collect(&mut channel).await;
        stderr.extend_from_slice(&out.stderr);
        (replied, stderr, out)
    });
    (c, task, asked)
}

/// The session was refused once for `reason`, on record, before anything
/// started or reached the target.
async fn assert_refused_once(s: &Setup, reason: &str) {
    let refused = await_events(&s.broker, "relay_session_refused", 1).await;
    // Give a duplicate a chance to show up.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let refused_now = events_of(&s.broker, "relay_session_refused");
    assert_eq!(refused_now.len(), 1, "{:?}", audit_events(&s.broker));
    assert_eq!(
        refused[0]["reason"],
        reason,
        "{:?}",
        audit_events(&s.broker)
    );
    assert!(events_of(&s.broker, "relay_session_started").is_empty());
    assert!(events_of(&s.broker, "relay_session_ended").is_empty());
    assert_eq!(sshd_connections(&s.sshd), 0, "{}", s.sshd.log());
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_during_slow_target_read_is_prompt() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    // The secret backend takes a minute to answer.
    s.broker
        .backend
        .set_relay_read_delay(Some(Duration::from_secs(60)));
    let (_c, client, _) = exec_in_background(&s, &agent).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let stopping = Instant::now();
    tokio::time::timeout(Duration::from_secs(5), s.broker.stop_relay())
        .await
        .expect("the relay stopped without waiting for the target read");
    assert!(
        stopping.elapsed() < Duration::from_secs(3),
        "{:?}",
        stopping.elapsed()
    );
    // Refused, not started: so no end either.
    assert_refused_once(&s, "relay shutting down").await;
    tokio::time::timeout(Duration::from_secs(5), client)
        .await
        .expect("the agent got an answer or was hung up on")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_during_slow_target_read_refuses() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    s.broker
        .backend
        .set_relay_read_delay(Some(Duration::from_secs(60)));
    let (_c, client, _) = exec_in_background(&s, &agent).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let revoking = Instant::now();
    s.broker
        .state()
        .requests
        .revoke_grant(&agent.grant_id, "owner")
        .await
        .unwrap();
    let (replied, stderr, out) = tokio::time::timeout(Duration::from_secs(3), client)
        .await
        .expect("refused without waiting for the target read")
        .unwrap();
    assert!(revoking.elapsed() < Duration::from_secs(3));
    assert!(replied);
    assert_eq!(out.exit_status, Some(255), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(
        text(&stderr).contains("warden relay: access revoked"),
        "{}",
        text(&stderr)
    );
    assert_refused_once(&s, "revoked").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_during_slow_grant_lookup_refuses() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    // Logged in, channel open: the next grant lookup is the session's.
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();

    // Every connection of the pool taken: a grant lookup now waits for one
    // (sqlx's 30 s acquire timeout), as on a hung disk. The grant is
    // revoked meanwhile through one of them, as by another process.
    let mut held = Vec::new();
    while let Ok(Ok(conn)) =
        tokio::time::timeout(Duration::from_millis(500), s.broker.state().pool.acquire()).await
    {
        held.push(conn);
    }
    let revoked = sqlx::query("UPDATE grants SET revoked_at = ? WHERE id = ?")
        .bind(s.broker.clock.now())
        .bind(agent.grant_id.as_str())
        .execute(&mut *held[0])
        .await
        .unwrap();
    assert_eq!(revoked.rows_affected(), 1);

    channel.exec(true, "echo ok").await.unwrap();
    let asked = Instant::now();
    let mut stderr = Vec::new();
    assert!(reply_keeping_stderr(&mut channel, &mut stderr).await);
    let out = collect(&mut channel).await;
    stderr.extend_from_slice(&out.stderr);
    // Bounded by the 1.5 s grant query timeout, not the pool's 30 s.
    assert!(
        asked.elapsed() < Duration::from_secs(4),
        "{:?}",
        asked.elapsed()
    );
    assert_eq!(out.exit_status, Some(255), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(
        text(&stderr).contains("warden relay: access cannot be checked right now"),
        "{}",
        text(&stderr)
    );
    assert_refused_once(&s, "grant lookup failed").await;
    drop(held);
}

#[tokio::test(flavor = "multi_thread")]
async fn login_grant_lookup_is_bounded() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let mut c = connect(&s.broker, s.relay).await;

    // Every connection of the pool taken: the login's grant lookup waits
    // for one (sqlx's 30 s acquire timeout), as on a hung disk.
    let mut held = Vec::new();
    while let Ok(Ok(conn)) =
        tokio::time::timeout(Duration::from_millis(500), s.broker.state().pool.acquire()).await
    {
        held.push(conn);
    }

    let asked = Instant::now();
    let auth = c
        .handle
        .authenticate_publickey(TARGET, russh_key(&agent.key))
        .await;
    // Refused once the 1.5 s lookup bound (plus the 1 s rejection delay)
    // is over, not hung up after the 10 s login timeout.
    assert!(
        matches!(auth, Ok(AuthResult::Failure { .. })),
        "{auth:?} after {:?}",
        asked.elapsed()
    );
    assert!(
        asked.elapsed() < Duration::from_secs(4),
        "{:?}",
        asked.elapsed()
    );
    c.handle
        .disconnect(Disconnect::ByApplication, "", "en")
        .await
        .unwrap();

    // Audited like any refused login, without key material.
    let refused = await_events(&s.broker, "relay_login_refused", 1).await;
    assert_eq!(refused[0]["user"], TARGET, "{refused:?}");
    assert_eq!(refused[0]["attempts"], 1, "{refused:?}");
    let log = std::fs::read_to_string(s.broker.audit_path()).unwrap();
    let public = agent.key.public_key().to_openssh().unwrap();
    assert!(!log.contains(public.split(' ').nth(1).unwrap()));
    assert!(
        !log.contains(
            &agent
                .key
                .public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string()
        )
    );

    // Once the database answers again, the same key logs in.
    drop(held);
    login(&s.broker, s.relay, TARGET, &agent.key).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_target_read_is_refused_after_its_bound() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    s.broker
        .backend
        .set_relay_read_delay(Some(Duration::from_secs(60)));
    let (_c, client, asked) = exec_in_background(&s, &agent).await;
    let (replied, stderr, out) = tokio::time::timeout(Duration::from_secs(15), client)
        .await
        .expect("refused once the target read took too long")
        .unwrap();
    // The read is given 10 s.
    let waited = asked.elapsed();
    assert!(
        waited >= Duration::from_millis(9500) && waited < Duration::from_secs(13),
        "{waited:?}"
    );
    assert!(replied);
    assert_eq!(out.exit_status, Some(255), "{out:?}");
    assert!(
        text(&stderr).contains("warden relay: the target's policy cannot be read right now"),
        "{}",
        text(&stderr)
    );
    assert_refused_once(&s, "target lookup failed").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn input_flood_before_start_disconnects() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let channel = c.handle.channel_open_session().await.unwrap();
    // Data before any shell or exec, past the 32-message allowance.
    for _ in 0..40 {
        if channel.data_bytes(&b"x"[..]).await.is_err() {
            break;
        }
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while !c.handle.is_closed() {
        assert!(Instant::now() < deadline, "the relay kept the connection");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let refused = await_events(&s.broker, "relay_session_refused", 1).await;
    assert_eq!(
        refused[0]["reason"],
        "too much input before the session started"
    );
    assert_eq!(refused[0]["grant_id"], agent.grant_id.as_str());
    assert_eq!(sshd_connections(&s.sshd), 0, "{}", s.sshd.log());

    // Bytes count too: one 70 KiB write is over the 64 KiB allowance.
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let channel = c.handle.channel_open_session().await.unwrap();
    let _ = channel.data_bytes(vec![b'y'; 70 * 1024]).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !c.handle.is_closed() {
        assert!(Instant::now() < deadline, "the relay kept the connection");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    await_events(&s.broker, "relay_session_refused", 2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn large_transfers_both_ways() {
    use sha2::{Digest as _, Sha256};
    const SIZE: usize = 16 * 1024 * 1024;
    // All eight log in at once, from one address.
    let s = key_target_with(RelayLimits {
        max_unauthenticated_per_ip: 10,
        ..RelayLimits::default()
    })
    .await;
    let agents = [
        approved_agent(&s.broker, "bot").await,
        approved_agent(&s.broker, "other").await,
    ];
    // Eight sessions at once (four per grant), each sending 16 MiB of
    // incompressible bytes up through `cat` and reading them back: both
    // directions of every session run against full windows and queues at
    // the same time, which is when the two connections could stall each
    // other.
    let mut transfers = Vec::new();
    for i in 0..8 {
        let ssh = OpenSsh::new(&s.broker, s.relay, &agents[i % 2].key);
        transfers.push(tokio::spawn(async move {
            let mut payload = vec![0_u8; SIZE];
            getrandom::fill(&mut payload).unwrap();
            let out = ssh.run_as(TARGET, &[], &["cat"], &payload).await;
            assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
            assert_eq!(out.stdout.len(), payload.len());
            assert_eq!(Sha256::digest(&out.stdout), Sha256::digest(&payload));
        }));
    }
    for transfer in transfers {
        if let Err(e) = transfer.await {
            panic!("{e}: {:?}", events_of(&s.broker, "relay_session_ended"));
        }
    }
    for ended in await_events(&s.broker, "relay_session_ended", 8).await {
        assert_eq!(ended["reason"], "exited");
        assert_eq!(ended["bytes_to_target"], SIZE);
        assert_eq!(ended["bytes_from_target"], SIZE);
    }
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_agent_gets_the_end_of_its_output() {
    const SIZE: usize = 1024 * 1024;
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    // Less than the client's window: the relay hands all of it over, with
    // the exit status and the close, and its session is over. The agent
    // takes its output only well after that, as over a slow link or with a
    // busy reader.
    let child = ssh
        .command(TARGET, &[], &["head", "-c", &SIZE.to_string(), "/dev/zero"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let ended = await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(ended[0]["reason"], "exited", "{ended:?}");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // It still gets every byte and the exit status, not a hang-up.
    let out = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
        .await
        .expect("ssh finished")
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(out.stdout.len(), SIZE);
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_that_stays_after_its_session_is_hung_up() {
    let s = key_target_with(RelayLimits {
        stall_timeout: Duration::from_secs(2),
        max_sessions_per_grant: 1,
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel.exec(true, "echo ok").await.unwrap();
    assert!(reply(&mut channel).await);
    let out = collect(&mut channel).await;
    assert_eq!(
        (text(&out.stdout).as_str(), out.exit_status),
        ("ok\n", Some(0))
    );
    let over = Instant::now();
    await_events(&s.broker, "relay_session_ended", 1).await;

    // The session is over but the agent stays: until it is hung up, it
    // keeps its place.
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    too_many(
        &ssh.run(&["true"]).await,
        "warden relay: too many sessions for this grant",
    );
    let deadline = over + Duration::from_secs(2 + 5);
    while !c.handle.is_closed() {
        assert!(Instant::now() < deadline, "the relay kept the connection");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(over.elapsed() >= Duration::from_millis(1500));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let out = ssh.run(&["echo", "ok"]).await;
        if out.status.success() {
            assert_eq!(text(&out.stdout), "ok\n");
            break;
        }
        assert!(Instant::now() < deadline, "{}", text(&out.stderr));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_each_start_ended(&s.broker).await;
}

/// An agent running `cat` on the target that feeds it input and never
/// reads the output, until its input stops being accepted (or 96 MiB).
/// Returns the ssh child, its unread stdout, and the MiB accepted.
async fn wedge(ssh: &OpenSsh) -> (tokio::process::Child, tokio::process::ChildStdout, usize) {
    let mut child = ssh
        .command(TARGET, &[], &["cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let chunk = vec![0_u8; 1 << 20];
    let mut accepted = 0;
    while accepted < 96 {
        match tokio::time::timeout(Duration::from_secs(1), input.write_all(&chunk)).await {
            Ok(Ok(())) => accepted += 1,
            _ => break,
        }
    }
    // Keep stdin open (as a stuck agent would) by leaking it into a task
    // that holds it until the child is gone.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(120)).await;
        drop(input);
    });
    (child, stdout, accepted)
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_disconnect_ends_wedged_session() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let (mut child, stdout, _) = wedge(&ssh).await;
    child.kill().await.unwrap();
    drop(stdout);
    let gone = Instant::now();
    let ended = tokio::time::timeout(
        Duration::from_secs(5),
        await_events(&s.broker, "relay_session_ended", 1),
    )
    .await
    .expect("the session ended within 5 s of the agent leaving");
    // While wedged, the agent's connection does not see the agent leave;
    // the wedge itself ends the session (it may have done so already).
    let reason = ended[0]["reason"].as_str().unwrap();
    assert!(
        reason == "client closed" || reason == "flow control: both directions held up",
        "{reason} after {:?}",
        gone.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_relay_completes_with_wedged_session() {
    // The wedge is left in place (no wedge timeout) for the stop to meet.
    let s = key_target_with(RelayLimits {
        wedge_timeout: Duration::from_secs(600),
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let (_child, _stdout, _) = wedge(&ssh).await;
    tokio::time::timeout(Duration::from_secs(10), s.broker.stop_relay())
        .await
        .expect("stop_relay finished within 10 s");
    let ended = events_of(&s.broker, "relay_session_ended");
    assert_eq!(ended.len(), 1, "{:?}", audit_events(&s.broker));
    assert_eq!(ended[0]["reason"], "relay shutting down");
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_not_reading_output_ends_session() {
    // The wedge watchdog is kept out of the way: this is the stall rule.
    let s = key_target_with(RelayLimits {
        stall_timeout: Duration::from_secs(3),
        wedge_timeout: Duration::from_secs(600),
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let started = Instant::now();
    let (mut child, _stdout, accepted) = wedge(&ssh).await;
    // The agent's input is held back by its window once the queues are
    // full: well short of the 96 MiB it tried to send. What it got rid of
    // sits in the relay's two queues (2 MiB each, plus a window), the SSH
    // windows and socket buffers on both connections, and `cat`.
    assert!(accepted < 32, "{accepted} MiB accepted");
    // The stuck output ends the session, while the agent is still there.
    let ended = tokio::time::timeout(
        Duration::from_secs(15),
        await_events(&s.broker, "relay_session_ended", 1),
    )
    .await
    .expect("the stalled session ended");
    assert_eq!(
        ended[0]["reason"],
        "flow control: output to the agent not drained",
        "after {:?}",
        started.elapsed()
    );
    // And the agent's connection is closed.
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("ssh exited")
        .unwrap();
    assert!(!status.success());
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pty_full_environment_and_window_changes_fit_before_start() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    assert!(reply(&mut channel).await);
    // The most variables the relay passes on (16), each answered.
    for i in 0..16 {
        channel
            .set_env(true, format!("LC_V{}", char::from(b'A' + i)), "C")
            .await
            .unwrap();
        assert!(reply(&mut channel).await, "variable {i}");
    }
    // A 17th is refused, but the session goes on.
    channel.set_env(true, "LANG", "C").await.unwrap();
    assert!(!reply(&mut channel).await);
    for cols in [90, 100, 110, 120, 132] {
        channel.window_change(cols, 40, 0, 0).await.unwrap();
    }
    channel.exec(true, "stty size").await.unwrap();
    assert!(reply(&mut channel).await);
    let out = collect(&mut channel).await;
    assert!(text(&out.stdout).contains("40 132"), "{out:?}");
    assert_eq!(out.exit_status, Some(0));
}

/// Every `relay_session_started` has exactly one `relay_session_ended`
/// for its grant (sessions of one grant end in any order), waiting a
/// little for ends still being written.
async fn assert_each_start_ended(broker: &TestBroker) {
    let tally = |kind| {
        let mut per_grant = std::collections::BTreeMap::<String, usize>::new();
        for event in events_of(broker, kind) {
            *per_grant
                .entry(event["grant_id"].as_str().unwrap().to_owned())
                .or_default() += 1;
        }
        per_grant
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let (started, ended) = (tally("relay_session_started"), tally("relay_session_ended"));
        for (grant, n) in &ended {
            assert!(
                started.get(grant).is_some_and(|s| n <= s),
                "more ends than starts for {grant}: {:?}",
                audit_events(broker)
            );
        }
        if started == ended {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "started {started:?}, ended {ended:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_started_session_has_exactly_one_end() {
    let s = key_target_with(RelayLimits {
        stall_timeout: Duration::from_secs(2),
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    // A command that exits, one killed by a signal, a session the agent
    // leaves mid-way, one that stalls, a refused onward login, a host key
    // mismatch, and one the relay stops in the middle of.
    ssh.run(&["echo", "ok"]).await;
    ssh.run(&["kill -TERM $$"]).await;
    let mut leaving = ssh
        .command(TARGET, &[], &["sleep", "30"])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    await_events(&s.broker, "relay_session_started", 3).await;
    leaving.kill().await.unwrap();
    let (mut stalled, _stdout, _) = wedge(&ssh).await;
    await_events(&s.broker, "relay_session_ended", 4).await;
    stalled.kill().await.unwrap();
    s.broker.backend.set_relay_target(
        nas(&s.sshd),
        RelayCredential::Key(openssh_private(&random_key())),
    );
    ssh.run(&["true"]).await;
    // A host key mismatch needs a grant approved for the wrong pin: one
    // whose pin changed since approval is refused before connecting.
    s.broker.backend.set_relay_target(
        nas_pinned(&s.sshd, random_key().public_key().clone()),
        RelayCredential::Key(openssh_private(&s.onward)),
    );
    let mispinned = approved_agent(&s.broker, "other").await;
    OpenSsh::new(&s.broker, s.relay, &mispinned.key)
        .run(&["true"])
        .await;
    // Back to the destination `bot` was approved for.
    s.broker.backend.set_relay_target(
        nas(&s.sshd),
        RelayCredential::Key(openssh_private(&s.onward)),
    );
    let mut held = ssh
        .command(TARGET, &[], &["sleep", "30"])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    await_events(&s.broker, "relay_session_started", 7).await;
    s.broker.stop_relay().await;
    let _ = held.kill().await;
    assert_each_start_ended(&s.broker).await;
    assert_eq!(events_of(&s.broker, "relay_session_ended").len(), 7);
}

// --- teardown on revocation, expiry and idleness ----------------------------

/// Connections to `sshd` (the relay's onward ones) not yet ended, by its
/// log: each is named by its client port.
fn sshd_open_connections(sshd: &Sshd) -> usize {
    let port_of = |line: &str| {
        let rest = &line[line.find(" port ")? + 6..];
        let digits = rest.split(|c: char| !c.is_ascii_digit()).next()?;
        digits.parse::<u16>().ok()
    };
    let (mut opened, mut closed) = (
        std::collections::BTreeSet::new(),
        std::collections::BTreeSet::new(),
    );
    for line in sshd.log().lines() {
        let set = if line.starts_with("Connection from ") {
            &mut opened
        } else if [
            "Connection closed by",
            "Connection reset by",
            "Disconnected from",
            "Closing connection to",
        ]
        .iter()
        .any(|ended| line.contains(ended))
        {
            &mut closed
        } else {
            continue;
        };
        if let Some(port) = port_of(line) {
            set.insert(port);
        }
    }
    opened.difference(&closed).count()
}

/// Wait, at most until `deadline`, for the relay to have closed the agent's
/// connection `c` and for `sshd` to be down to `still_open` connections.
async fn assert_both_sides_closed(s: &Setup, c: &Connected, still_open: usize, deadline: Instant) {
    loop {
        let (agent_gone, onward) = (c.handle.is_closed(), sshd_open_connections(&s.sshd));
        if agent_gone && onward == still_open {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "agent connection closed: {agent_gone}, onward connections open: {onward}\n{}",
            s.sshd.log()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Exactly one `relay_session_ended` (per started session), all with
/// `reason`; then the relay still stops promptly, adding no further end.
async fn assert_ended_once_then_stop(s: &Setup, sessions: usize, reason: &str) {
    let ended = await_events(&s.broker, "relay_session_ended", sessions).await;
    // Give a duplicate end a chance to show up.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let ended_now = events_of(&s.broker, "relay_session_ended");
    assert_eq!(ended_now.len(), sessions, "{:?}", audit_events(&s.broker));
    for end in &ended {
        assert_eq!(end["reason"], reason, "{:?}", audit_events(&s.broker));
        assert_eq!(end["exit_status"], Value::Null);
    }
    tokio::time::timeout(Duration::from_secs(3), s.broker.stop_relay())
        .await
        .expect("the relay stopped promptly");
    assert_eq!(
        events_of(&s.broker, "relay_session_ended").len(),
        sessions,
        "{:?}",
        audit_events(&s.broker)
    );
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_closes_live_session() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let (c, mut channel) = hold_session(&s, &agent.key).await;
    let revoked = Instant::now();
    s.broker
        .state()
        .requests
        .revoke_grant(&agent.grant_id, "owner")
        .await
        .unwrap();
    assert_both_sides_closed(&s, &c, 0, revoked + Duration::from_secs(5)).await;
    let out = collect(&mut channel).await;
    assert!(
        text(&out.stderr).contains("warden relay: access revoked"),
        "{out:?}"
    );
    assert_ended_once_then_stop(&s, 1, "revoked").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn expiry_closes_live_session() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let (c, _channel) = hold_session(&s, &agent.key).await;
    // Window 15 min: one second past it.
    s.broker.clock.advance(15 * 60 + 1);
    let expired = Instant::now();
    assert_both_sides_closed(&s, &c, 0, expired + Duration::from_secs(5)).await;
    assert_ended_once_then_stop(&s, 1, "expired").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_revoke_closes_sessions() {
    let s = key_target().await;
    let bot = approved_agent(&s.broker, "bot").await;
    let other = approved_agent(&s.broker, "other").await;
    let (first, _first_channel) = hold_session(&s, &bot.key).await;
    let (second, _second_channel) = hold_session(&s, &bot.key).await;
    let (kept, kept_channel) = hold_session(&s, &other.key).await;
    let revoked = Instant::now();
    s.broker
        .state()
        .requests
        .revoke_agent(&AgentName::try_from("bot".to_owned()).unwrap())
        .await
        .unwrap();
    let deadline = revoked + Duration::from_secs(5);
    assert_both_sides_closed(&s, &first, 1, deadline).await;
    assert_both_sides_closed(&s, &second, 1, deadline).await;
    let ended = await_events(&s.broker, "relay_session_ended", 2).await;
    for end in &ended {
        assert_eq!(end["grant_id"], bot.grant_id.as_str());
        assert_eq!(end["reason"], "revoked");
    }
    // The other agent's session goes on.
    assert!(!kept.handle.is_closed());
    kept_channel.data(&b"x"[..]).await.unwrap();
    assert_eq!(events_of(&s.broker, "relay_session_ended").len(), 2);
    tokio::time::timeout(Duration::from_secs(3), s.broker.stop_relay())
        .await
        .expect("the relay stopped promptly");
    let ended = events_of(&s.broker, "relay_session_ended");
    assert_eq!(ended.len(), 3, "{:?}", audit_events(&s.broker));
    assert_eq!(ended[2]["grant_id"], other.grant_id.as_str());
    assert_eq!(ended[2]["reason"], "relay shutting down");
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn db_revoke_from_another_process_closes_session() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let (c, _channel) = hold_session(&s, &agent.key).await;
    // What `warden-server agent revoke` does from its own process: the
    // database changes, and the running relay is not told.
    let state = s.broker.state();
    let revoked = Instant::now();
    warden_broker::requests::revoke_agent(
        &state.pool,
        &state.audit,
        &AgentName::try_from("bot".to_owned()).unwrap(),
        state.clock.now(),
    )
    .await
    .unwrap();
    assert_both_sides_closed(&s, &c, 0, revoked + Duration::from_secs(5)).await;
    assert_ended_once_then_stop(&s, 1, "revoked").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_session_times_out() {
    let s = key_target_with(RelayLimits {
        idle_timeout: Duration::from_secs(2),
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    // Output every half second for 4 s: never idle for 2 s, so it runs to
    // its end although it lasts longer than the idle timeout.
    let busy = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = busy.handle.channel_open_session().await.unwrap();
    channel
        .exec(
            true,
            "for i in 1 2 3 4 5 6 7 8; do echo $i; sleep 0.5; done",
        )
        .await
        .unwrap();
    assert!(reply(&mut channel).await);
    let out = collect(&mut channel).await;
    assert_eq!(out.exit_status, Some(0), "{out:?}");
    let ended = await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(ended[0]["reason"], "exited");

    // Silent for the idle timeout: ended, both sides closed.
    let (c, mut channel) = hold_session(&s, &agent.key).await;
    let quiet = Instant::now();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!c.handle.is_closed(), "ended before the idle timeout");
    assert_both_sides_closed(&s, &c, 0, quiet + Duration::from_secs(5)).await;
    let out = collect(&mut channel).await;
    assert!(text(&out.stderr).contains("idle"), "{out:?}");
    let ended = await_events(&s.broker, "relay_session_ended", 2).await;
    assert_eq!(ended[1]["reason"], "idle timeout");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(events_of(&s.broker, "relay_session_ended").len(), 2);
    tokio::time::timeout(Duration::from_secs(3), s.broker.stop_relay())
        .await
        .expect("the relay stopped promptly");
    assert_eq!(events_of(&s.broker, "relay_session_ended").len(), 2);
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unstarted_authenticated_connection_is_closed() {
    let s = key_target_with(RelayLimits {
        start_timeout: Duration::from_secs(2),
        max_sessions_per_grant: 1,
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    // Logged in, a session channel open, never started.
    let idle = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let _channel = idle.handle.channel_open_session().await.unwrap();
    let logged_in = Instant::now();
    let deadline = logged_in + Duration::from_secs(2 + 5);
    while !idle.handle.is_closed() {
        assert!(Instant::now() < deadline, "the connection was not closed");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(logged_in.elapsed() >= Duration::from_millis(1500));
    // Nothing started, so nothing is recorded; its place is free again.
    assert!(events_of(&s.broker, "relay_session_started").is_empty());
    assert!(events_of(&s.broker, "relay_session_ended").is_empty());
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel.exec(true, "echo ok").await.unwrap();
    assert!(reply(&mut channel).await);
    assert_eq!(text(&collect(&mut channel).await.stdout), "ok\n");
    tokio::time::timeout(Duration::from_secs(3), s.broker.stop_relay())
        .await
        .expect("the relay stopped promptly");
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn db_unreadable_fails_closed() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let (running, mut running_channel) = hold_session(&s, &agent.key).await;
    // Logged in before the outage, its session not started yet.
    let waiting = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut waiting_channel = waiting.handle.channel_open_session().await.unwrap();

    // Every query fails from now on.
    s.broker.state().pool.close().await;
    let lost = Instant::now();
    // Not before the state has been unreadable for 10 s ...
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert!(!running.handle.is_closed(), "ended before 10 s of failures");
    assert!(events_of(&s.broker, "relay_session_ended").is_empty());
    // ... then the session ends, both sides closed.
    assert_both_sides_closed(&s, &running, 0, lost + Duration::from_secs(15)).await;
    let out = collect(&mut running_channel).await;
    assert!(
        text(&out.stderr).contains("warden relay: access cannot be checked right now"),
        "{out:?}"
    );

    // A session cannot start meanwhile, on record.
    waiting_channel.exec(true, "echo ok").await.unwrap();
    let mut stderr = Vec::new();
    assert!(reply_keeping_stderr(&mut waiting_channel, &mut stderr).await);
    let out = collect(&mut waiting_channel).await;
    stderr.extend_from_slice(&out.stderr);
    assert!(out.stdout.is_empty(), "{out:?}");
    assert_eq!(out.exit_status, Some(255));
    assert!(
        text(&stderr).contains("warden relay: access cannot be checked right now"),
        "{}",
        text(&stderr)
    );
    let refused = await_events(&s.broker, "relay_session_refused", 1).await;
    assert_eq!(refused.len(), 1, "{:?}", audit_events(&s.broker));
    assert_eq!(refused[0]["reason"], "grant state unavailable");

    assert_ended_once_then_stop(&s, 1, "grant state unavailable").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hung_grant_query_still_fails_closed_and_expires() {
    let s = key_target().await;
    // `bot`'s grant ends 10 minutes before `other`'s.
    let expiring = approved_agent(&s.broker, "bot").await;
    s.broker.clock.advance(600);
    let other = approved_agent(&s.broker, "other").await;
    let (ending, _ending_channel) = hold_session(&s, &expiring.key).await;
    let (kept, _kept_channel) = hold_session(&s, &other.key).await;

    // Every connection of the pool taken: from now on a grant query waits
    // for one (sqlx's 30 s acquire timeout), as on a hung disk. The last
    // successful check was at most one tick (1 s) before this.
    let hung = Instant::now();
    let mut held = Vec::new();
    while let Ok(Ok(conn)) =
        tokio::time::timeout(Duration::from_millis(500), s.broker.state().pool.acquire()).await
    {
        held.push(conn);
    }
    assert!(!held.is_empty());

    // `bot`'s window ends: expiry needs no query, so it is not held up.
    s.broker.clock.advance(15 * 60 - 600 + 1);
    let expired = Instant::now();
    assert_both_sides_closed(&s, &ending, 1, expired + Duration::from_secs(5)).await;
    let ended = await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(ended[0]["grant_id"], expiring.grant_id.as_str());
    assert_eq!(ended[0]["reason"], "expired");

    // `other`'s session ends once no query has succeeded for 10 s: not
    // before 9 s after the queries started hanging.
    tokio::time::sleep_until((hung + Duration::from_millis(8900)).into()).await;
    assert!(!kept.handle.is_closed(), "failed closed too early");
    assert_eq!(events_of(&s.broker, "relay_session_ended").len(), 1);
    assert_both_sides_closed(&s, &kept, 0, hung + Duration::from_secs(14)).await;
    let ended = await_events(&s.broker, "relay_session_ended", 2).await;
    assert_eq!(ended[1]["grant_id"], other.grant_id.as_str());
    assert_eq!(ended[1]["reason"], "grant state unavailable");

    drop(held);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(events_of(&s.broker, "relay_session_ended").len(), 2);
    tokio::time::timeout(Duration::from_secs(3), s.broker.stop_relay())
        .await
        .expect("the relay stopped promptly");
    assert_eq!(events_of(&s.broker, "relay_session_ended").len(), 2);
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn connection_closed_once_its_session_is_over() {
    let s = key_target_with(RelayLimits {
        stall_timeout: Duration::from_secs(2),
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    // The start is refused (the grant was revoked after login) ...
    s.broker
        .state()
        .requests
        .revoke_grant(&agent.grant_id, "owner")
        .await
        .unwrap();
    channel.exec(true, "echo ok").await.unwrap();
    let mut stderr = Vec::new();
    assert!(reply_keeping_stderr(&mut channel, &mut stderr).await);
    let out = collect(&mut channel).await;
    assert_eq!(out.exit_status, Some(255), "{out:?}");
    let over = Instant::now();
    // ... and the agent keeps the connection: the relay hangs up once it
    // has had the stall timeout (2 s here) to leave.
    while !c.handle.is_closed() {
        assert!(
            over.elapsed() < Duration::from_secs(4),
            "the connection was not closed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        over.elapsed() >= Duration::from_millis(1500),
        "{:?}",
        over.elapsed()
    );
    assert_eq!(events_of(&s.broker, "relay_session_refused").len(), 1);
    assert!(events_of(&s.broker, "relay_session_started").is_empty());
    tokio::time::timeout(Duration::from_secs(3), s.broker.stop_relay())
        .await
        .expect("the relay stopped promptly");
}
