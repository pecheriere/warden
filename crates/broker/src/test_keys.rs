//! Signing keys for tests, of both types agents may sign with.
//!
//! `ssh-key` 0.6 only generates and signs with P-256 keys through its `p256`
//! feature, which stays off because it needs crypto-bigint 0.5
//! (RUSTSEC-2026-0387). These helpers do both with the `p256` crate.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::process::{Command, Stdio};

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer as _;
use ssh_encoding::{Decode as _, Encode as _};
use ssh_key::private::{EcdsaKeypair, KeypairData};
use ssh_key::rand_core::{OsRng, RngCore as _};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, Mpint, PrivateKey, Signature, SshSig};

/// `ecdsa-sha2-nistp256`.
pub const P256: Algorithm = Algorithm::Ecdsa {
    curve: EcdsaCurve::NistP256,
};

/// A fresh key of `algorithm`, [`Algorithm::Ed25519`] or [`P256`].
///
/// # Panics
/// If the key cannot be made, or for any other algorithm.
#[must_use]
pub fn random_key(algorithm: Algorithm) -> PrivateKey {
    if algorithm != P256 {
        return PrivateKey::random(&mut OsRng, algorithm).expect("key generation");
    }
    let mut scalar = [0_u8; 32];
    let signing = loop {
        OsRng.fill_bytes(&mut scalar);
        // Almost every 32 bytes are a valid scalar; try again if not.
        if let Ok(signing) = SigningKey::from_slice(&scalar) {
            break signing;
        }
    };
    // `ssh-key` offers no constructor without its `p256` feature, but decodes
    // the OpenSSH form: curve, public point, private scalar.
    let mut encoded = Vec::new();
    "nistp256".encode(&mut encoded).expect("encode curve");
    signing
        .verifying_key()
        .to_sec1_bytes()
        .as_ref()
        .encode(&mut encoded)
        .expect("encode point");
    Mpint::from_positive_bytes(&scalar)
        .expect("scalar")
        .encode(&mut encoded)
        .expect("encode scalar");
    let keypair = EcdsaKeypair::decode(&mut encoded.as_slice()).expect("decode keypair");
    PrivateKey::new(KeypairData::Ecdsa(keypair), "").expect("private key")
}

/// An SSHSIG by `key`, [`Algorithm::Ed25519`] or [`P256`], over `message`.
///
/// # Panics
/// If it cannot be signed.
#[must_use]
pub fn sign(key: &PrivateKey, namespace: &str, hash: HashAlg, message: &[u8]) -> SshSig {
    let Some(EcdsaKeypair::NistP256 { private, .. }) = key.key_data().ecdsa() else {
        return key.sign(namespace, hash, message).expect("sign");
    };
    let signing = SigningKey::from_slice(private.as_slice()).expect("P-256 scalar");
    let signed = SshSig::signed_data(namespace, hash, message).expect("preimage");
    let signature: p256::ecdsa::Signature = signing.sign(&signed);
    let (r, s) = signature.split_bytes();
    let mut raw = Vec::new();
    for part in [r.as_slice(), s.as_slice()] {
        Mpint::from_positive_bytes(part)
            .expect("signature part")
            .encode(&mut raw)
            .expect("encode signature part");
    }
    SshSig::new(
        key.public_key().key_data().clone(),
        namespace,
        hash,
        Signature::new(P256, raw).expect("signature"),
    )
    .expect("SSHSIG")
}

/// Load `key` into the `ssh-agent` at `socket` with OpenSSH's `ssh-add`, from
/// a private temporary file.
///
/// # Panics
/// If `ssh-add` is missing or fails.
pub fn ssh_add(key: &PrivateKey, socket: &Path) {
    let dir = tempfile::tempdir().expect("temporary directory");
    let path = dir.path().join("key");
    write_private(key, &path);
    let status = Command::new("ssh-add")
        .arg("-q")
        .arg(&path)
        .env("SSH_AUTH_SOCK", socket)
        .stdin(Stdio::null())
        .status()
        .expect("ssh-add (OpenSSH) is needed for this test");
    assert!(status.success(), "ssh-add failed: {status}");
}

/// Write `key` to `path`, readable only by its owner. `ssh-add` refuses it
/// otherwise, and `ssh-key` only writes files with its `std` feature, which
/// stays off (see the workspace manifest).
fn write_private(key: &PrivateKey, path: &Path) {
    let text = key.to_openssh(LineEnding::LF).expect("encode key");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create key file")
        .write_all(text.as_bytes())
        .expect("write key file");
}
