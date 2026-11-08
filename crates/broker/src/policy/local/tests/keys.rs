//! The SSH CA key and the commit signing key.

use ssh_key::PrivateKey;

use super::{API_ENTRY, Setup, ca_policy, cert_entry, ed25519_pem};
use crate::policy::{PolicyError, SecretBackend};

#[tokio::test]
async fn loads_the_ca_key() {
    let setup = Setup::new(&ca_policy());
    let pem = ed25519_pem();
    setup.secret("ssh-ca", &pem);
    let key = setup.backend.ssh_ca().await.unwrap();
    assert_eq!(
        key.public_key().to_openssh().unwrap(),
        PrivateKey::from_openssh(&pem)
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap()
    );
}

#[tokio::test]
async fn refuses_an_unusable_ca_key_without_echoing_it() {
    let setup = Setup::new(&ca_policy());
    for bad in [
        "not a key at all",
        include_str!("../../../../tests/fixtures/throwaway-test-only-rsa.key"),
        include_str!("../../../../tests/fixtures/throwaway-test-only-ed25519-encrypted.key"),
    ] {
        setup.secret("ssh-ca", bad);
        let error = setup.backend.ssh_ca().await.err().unwrap();
        assert!(matches!(error, PolicyError::Ca(_)), "{error}");
        Setup::assert_no_secret(&format!("{error} {error:?}"));
    }
}

#[tokio::test]
async fn no_ca_section_is_a_ca_error() {
    let setup = Setup::new(&cert_entry());
    let error = setup.backend.ssh_ca().await.err().unwrap();
    assert!(matches!(error, PolicyError::Ca(_)), "{error}");
}

fn commit_signing_policy() -> String {
    format!("[commit_signing]\nprivate_key_file = \"commit-signing\"\n{API_ENTRY}")
}

#[tokio::test]
async fn loads_the_commit_signing_key_and_none_is_no_key() {
    let setup = Setup::new(&commit_signing_policy());
    setup.secret("commit-signing", &ed25519_pem());
    assert!(setup.backend.commit_signing_key().await.is_ok());
    let probe = setup.backend.probe().await;
    assert!(probe.problems().is_empty(), "{probe:?}");

    let without = Setup::new(API_ENTRY);
    let error = without.backend.commit_signing_key().await.err().unwrap();
    assert!(matches!(error, PolicyError::NoCommitSigningKey), "{error}");
    assert_eq!(
        without.backend.probe().await.problems(),
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn the_ca_key_cannot_also_be_the_commit_signing_key() {
    let policy = format!(
        "[ca]\nprivate_key_file = \"ssh-ca\"\n{}",
        commit_signing_policy()
    );
    let setup = Setup::new(&policy);
    let pem = ed25519_pem();
    setup.secret("ssh-ca", &pem);
    setup.secret("commit-signing", &pem);
    let problems = setup.backend.probe().await.problems();
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("also the SSH CA key"), "{problems:?}");
    // Two keys are fine.
    setup.secret("commit-signing", &ed25519_pem());
    assert_eq!(setup.backend.probe().await.problems(), Vec::<String>::new());
}

#[tokio::test]
async fn a_ca_that_cannot_be_used_refuses_the_commit_signing_key() {
    let policy = format!(
        "[ca]\nprivate_key_file = \"ssh-ca\"\n{}",
        commit_signing_policy()
    );
    let setup = Setup::new(&policy);
    setup.secret("ssh-ca", "not a key at all");
    setup.secret("commit-signing", &ed25519_pem());
    let problems = setup.backend.probe().await.problems();
    assert!(
        problems.iter().any(|p| p.contains("SSH CA cannot be read")),
        "{problems:?}"
    );
}

#[tokio::test]
async fn refuses_an_unusable_commit_signing_key_without_echoing_it() {
    let setup = Setup::new(&commit_signing_policy());
    for bad in [
        "not a key at all",
        include_str!("../../../../tests/fixtures/throwaway-test-only-rsa.key"),
        include_str!("../../../../tests/fixtures/throwaway-test-only-ed25519-encrypted.key"),
    ] {
        setup.secret("commit-signing", bad);
        let error = setup.backend.commit_signing_key().await.err().unwrap();
        assert!(matches!(error, PolicyError::CommitSigningKey(_)), "{error}");
        Setup::assert_no_secret(&format!("{error} {error:?}"));
        // And a server does not start on it.
        assert_eq!(setup.backend.probe().await.problems().len(), 1);
    }
}
