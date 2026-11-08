//! Unit tests for the SSH target digest and the redacted secret value.

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use warden_broker_proto::{TargetName, Window};

use zeroize::Zeroizing;

use super::{SecretValue, SshMode, SshTarget};

fn key() -> PublicKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .clone()
}

fn target(host: &str, port: u16, host_keys: Vec<PublicKey>) -> SshTarget {
    SshTarget {
        name: TargetName::try_from("pi".to_owned()).unwrap(),
        host: host.to_owned(),
        port,
        mode: SshMode::Cert,
        users: Vec::new(),
        max_window: Window::H1,
        host_keys,
    }
}

#[test]
fn destination_digest_ignores_key_order_and_comments() {
    let (a, b) = (key(), key());
    let base = target("pi.lan", 22, vec![a.clone(), b.clone()]);
    let mut commented = a.clone();
    commented.set_comment("root@pi");
    let reordered = target("pi.lan", 22, vec![b, commented]);
    assert_eq!(base.destination_digest(), reordered.destination_digest());
    assert_eq!(base.destination_digest().len(), 64);
}

#[test]
fn destination_digest_changes_with_host_port_or_keys() {
    let k = key();
    let base = target("pi.lan", 22, vec![k.clone()]).destination_digest();
    assert_ne!(
        base,
        target("pi.lan2", 22, vec![k.clone()]).destination_digest()
    );
    assert_ne!(
        base,
        target("pi.lan", 2222, vec![k.clone()]).destination_digest()
    );
    assert_ne!(base, target("pi.lan", 22, vec![key()]).destination_digest());
    assert_ne!(
        base,
        target("pi.lan", 22, vec![k, key()]).destination_digest()
    );
    // Length prefixes keep parts from running into each other.
    assert_ne!(
        target("a1", 22, Vec::new()).destination_digest(),
        target("a", 122, Vec::new()).destination_digest()
    );
}

#[test]
fn secret_value_debug_is_redacted() {
    let v = SecretValue::new(Zeroizing::new("hunter2-hunter2".to_owned()));
    assert_eq!(format!("{v:?}"), "SecretValue(<redacted>)");
    assert_eq!(v.expose(), "hunter2-hunter2");
}
