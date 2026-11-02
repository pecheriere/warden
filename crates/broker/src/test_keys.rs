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
    loop {
        OsRng.fill_bytes(&mut scalar);
        if let Some(key) = p256_key(&scalar) {
            return key;
        }
    }
}

/// The P-256 key with private scalar `scalar`, or `None` if `scalar` cannot be
/// one here: almost every 32 bytes can. Those starting with a zero byte cannot,
/// because [`Mpint`] drops that byte and `ssh-key` decodes only full-length
/// scalars. Tests have no need of those keys, and leaving them out costs 1 key
/// in 256 a second try.
fn p256_key(scalar: &[u8; 32]) -> Option<PrivateKey> {
    if scalar[0] == 0 {
        return None;
    }
    let signing = SigningKey::from_slice(scalar).ok()?;
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
    Mpint::from_positive_bytes(scalar)
        .expect("scalar")
        .encode(&mut encoded)
        .expect("encode scalar");
    let keypair = EcdsaKeypair::decode(&mut encoded.as_slice()).expect("decode keypair");
    Some(PrivateKey::new(KeypairData::Ecdsa(keypair), "").expect("private key"))
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

#[cfg(test)]
mod tests {
    use super::{P256, p256_key};

    fn scalar_starting(first: u8) -> [u8; 32] {
        let mut scalar = [1_u8; 32];
        scalar[0] = first;
        scalar
    }

    #[test]
    fn a_scalar_starting_with_a_zero_byte_is_skipped_rather_than_a_panic() {
        assert!(p256_key(&scalar_starting(0)).is_none());
    }

    #[test]
    fn a_scalar_out_of_range_is_skipped() {
        assert!(p256_key(&[0xff; 32]).is_none());
    }

    #[test]
    fn scalars_with_the_top_bit_clear_or_set_make_a_key() {
        for first in [0x01, 0x7f, 0x80, 0xfe] {
            let key = p256_key(&scalar_starting(first)).expect("key");
            assert_eq!(key.algorithm(), P256);
        }
    }
}
