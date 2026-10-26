//! Access policy: which targets exist and the SSH CA key, sourced from a
//! secret backend (1Password Connect in production).

use std::fmt;

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey};
use warden_broker_proto::{TargetName, UnixUser, Window};

pub mod onepassword;

pub use onepassword::OnePasswordConnect;

/// How warden grants access to an SSH target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshMode {
    /// The target trusts the warden CA; warden signs a short-lived certificate.
    Cert,
    /// Warden relays the connection itself.
    Relay,
}

/// An SSH target as defined by its 1Password item.
#[derive(Debug, Clone)]
pub struct SshTarget {
    /// Target name (the item title).
    pub name: TargetName,
    /// Host name or IP address, without brackets or port.
    pub host: String,
    /// TCP port, 22 unless the address says otherwise.
    pub port: u16,
    /// Access mode.
    pub mode: SshMode,
    /// Unix users that may be requested.
    pub users: Vec<UnixUser>,
    /// Longest window that may be granted.
    pub max_window: Window,
    /// Public host keys of the target (any OpenSSH algorithm).
    pub host_keys: Vec<PublicKey>,
}

impl SshTarget {
    /// Lowercase hex SHA-256 over where this target sends a connection: host,
    /// port and the set of host keys (by SHA-256 key fingerprint, sorted, so
    /// key order and comments do not matter). Every part is length-prefixed,
    /// so distinct destinations cannot collide by concatenation.
    #[must_use]
    pub fn destination_digest(&self) -> String {
        let mut keys: Vec<String> = self
            .host_keys
            .iter()
            .map(|k| k.fingerprint(HashAlg::Sha256).to_string())
            .collect();
        keys.sort_unstable();
        keys.dedup();
        let port = self.port.to_string();
        let mut hasher = Sha256::new();
        for part in [self.host.as_str(), port.as_str()]
            .into_iter()
            .chain(keys.iter().map(String::as_str))
        {
            hasher.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

/// A policy lookup failed. Messages name the item and field but never carry
/// secret values.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// No target with that name exists.
    #[error("unknown target \"{0}\"")]
    NotFound(String),
    /// An item is present but a field is missing or malformed.
    #[error("item \"{item}\": field \"{field}\": {reason}")]
    Invalid {
        /// Item title.
        item: String,
        /// Field label.
        field: String,
        /// What is wrong.
        reason: String,
    },
    /// The SSH CA item is absent, ambiguous or unusable.
    #[error("SSH CA: {0}")]
    Ca(String),
    /// The secret backend could not be reached or answered with an error.
    #[error("secret backend unavailable: {0}")]
    Unavailable(String),
}

/// The SSH CA private key. Ed25519 only; never printed.
///
/// Zeroization is best effort. The parsed key is wiped by
/// `ssh_key::private::Ed25519PrivateKey`'s `Drop` impl (`PrivateKey` does not
/// implement `Zeroize`, so it cannot be wrapped in `Zeroizing`). While the key
/// is fetched, the HTTP body and the PEM field value are held in
/// `Zeroizing` buffers and wiped when `ssh_ca` returns. Accepted residual: the
/// copies inside reqwest/hyper receive buffers, `serde_json`'s unescape scratch
/// space, and the PEM/base64 decoders in `ssh-key`/`pkcs8` are not wiped.
pub struct CaKey(PrivateKey);

impl CaKey {
    /// Wrap a private key, rejecting anything but an unencrypted Ed25519 key.
    ///
    /// # Errors
    /// [`PolicyError::Ca`] if the key is encrypted or not Ed25519.
    pub fn new(key: PrivateKey) -> Result<Self, PolicyError> {
        if key.is_encrypted() {
            return Err(PolicyError::Ca(
                "the key is passphrase-protected; an unencrypted Ed25519 key is required".into(),
            ));
        }
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(PolicyError::Ca(format!(
                "the key is {}, but only Ed25519 keys are accepted",
                key.algorithm()
            )));
        }
        Ok(Self(key))
    }

    /// The private key, for signing certificates.
    #[must_use]
    pub fn private_key(&self) -> &PrivateKey {
        &self.0
    }

    /// The public half, for `TrustedUserCAKeys`.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        self.0.public_key()
    }
}

impl fmt::Debug for CaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CaKey(<redacted>)")
    }
}

/// Source of targets and the CA key. Always reads fresh data.
#[async_trait]
pub trait SecretBackend: Send + Sync + 'static {
    /// Look up an SSH target by name.
    ///
    /// # Errors
    /// [`PolicyError::NotFound`], [`PolicyError::Invalid`] or
    /// [`PolicyError::Unavailable`].
    async fn ssh_target(&self, name: &TargetName) -> Result<SshTarget, PolicyError>;

    /// Load the SSH CA key.
    ///
    /// # Errors
    /// [`PolicyError::Ca`] or [`PolicyError::Unavailable`].
    async fn ssh_ca(&self) -> Result<CaKey, PolicyError>;
}

#[cfg(test)]
mod tests {
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey, PublicKey};
    use warden_broker_proto::{TargetName, Window};

    use super::{SshMode, SshTarget};

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
}
