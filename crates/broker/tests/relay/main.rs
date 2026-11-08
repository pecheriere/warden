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
use std::path::Path;
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::client::{self, AuthResult};
use russh::keys::PrivateKeyWithHashAlg;
use russh::{ChannelMsg, Sig};
use serde_json::Value;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt as _;
use warden_broker::policy::{RelayCredential, SshMode, SshTarget};
use warden_broker::relay::RelayLimits;
use warden_broker::testkit::TestBroker;
use warden_broker::testkit::sshd::{Sshd, SshdLogin, current_user};
use warden_broker_proto::{
    Access, AgentName, CreateRequest, Goal, Id, TargetName, UnixUser, Window,
};
use zeroize::Zeroizing;

mod credentials;
mod flow;
mod limits;
mod serve;
mod session;
mod start;
mod target_checks;
mod teardown;

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
        session: None,
        link: None,
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
    await_events_within(broker, kind, count, Duration::from_secs(15)).await
}

/// Wait until the audit log holds `count` entries of `kind`, failing after
/// `limit`.
async fn await_events_within(
    broker: &TestBroker,
    kind: &str,
    count: usize,
    limit: Duration,
) -> Vec<Value> {
    let deadline = Instant::now() + limit;
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

    fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKeyOrCertificate,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        std::future::ready(Ok(matches!(
            key,
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } if key.key_data() == self.host_key.key_data()
        )))
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
