//! The target's credential never reaches the logs, the audit log or the
//! agent.

use std::process::Output;
use std::sync::{Arc, Mutex, OnceLock};

use ssh_key::PrivateKey;
use warden_broker::policy::RelayCredential;
use warden_broker::testkit::TestBroker;

#[cfg(target_os = "linux")]
use super::password_target;
use super::{
    OpenSsh, approved_agent, await_events, key_target, nas, nas_pinned, openssh_private,
    random_key, text,
};

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
