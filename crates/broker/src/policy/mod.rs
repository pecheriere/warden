//! Access policy: which SSH targets and API secrets exist, and the SSH CA
//! key, sourced from a secret backend: 1Password Connect, the recommended one,
//! or files on the broker's host ([`local`]), which is weaker.

use std::fmt;

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey};
use warden_broker_proto::{SecretName, TargetName, UnixUser, Window};
use zeroize::Zeroizing;

mod api;
mod commit_signing_key;
pub mod local;
pub mod onepassword;

pub use api::{ApiScope, ApiSecretPolicy, ValueFormat, is_reserved_header};
pub(crate) use api::{check_path_prefix, is_header_text, parse_method};
pub use commit_signing_key::{
    CA_UNREADABLE, CommitSigningKey, CommitSigningPolicy, CommitSigningProbe, SAME_AS_CA,
    check_separate_from_ca,
};
pub use local::{LocalBackend, LocalProbe};
pub use onepassword::{CaProbe, OnePasswordConnect, VaultProbe};

/// How warden grants access to an SSH target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshMode {
    /// The target trusts the warden CA; warden signs a short-lived certificate.
    Cert,
    /// Warden relays the connection itself.
    Relay,
}

impl SshMode {
    /// The item's spelling: `cert` or `relay`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cert => "cert",
            Self::Relay => "relay",
        }
    }
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
    /// Lowercase hex SHA-256 over where and how this target sends a
    /// connection: the mode (a certificate for the agent, or the broker's
    /// relay logging in with its own credential), host, port and the set of
    /// host keys (by SHA-256 key fingerprint, sorted, so key order and
    /// comments do not matter). Every part is length-prefixed, so distinct
    /// destinations cannot collide by concatenation.
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
        digest_parts(
            [self.mode.as_str(), self.host.as_str(), port.as_str()]
                .into_iter()
                .chain(keys.iter().map(String::as_str)),
        )
    }
}

/// Feed length-prefixed parts into a SHA-256 and return lowercase hex, so
/// distinct part lists cannot collide by concatenation.
fn digest_parts<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// An API secret value, wiped on drop and never printed.
pub struct SecretValue(Zeroizing<String>);

impl SecretValue {
    /// Wrap a secret value.
    #[must_use]
    pub fn new(value: Zeroizing<String>) -> Self {
        Self(value)
    }

    /// The secret, for building the outbound header.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

/// The credential warden logs in to a relay target with, from the target's
/// 1Password item. Never printed; wiped on drop.
///
/// Zeroization is best effort, as for [`CaKey`]: the key text and the
/// password live in `Zeroizing` buffers, and the HTTP body and field values
/// they were read from are wiped when the fetch returns. Accepted residual:
/// the copies inside reqwest/hyper receive buffers, `serde_json`'s unescape
/// scratch space, and the PEM/base64/DER decoders' intermediate buffers are
/// not wiped.
pub enum RelayCredential {
    /// An unencrypted Ed25519 private key, normalised to OpenSSH format
    /// whatever format (OpenSSH or PKCS#8) the item held it in.
    Key(Zeroizing<String>),
    /// A password, verbatim.
    Password(Zeroizing<String>),
}

impl fmt::Debug for RelayCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Key(_) => "RelayCredential::Key(<redacted>)",
            Self::Password(_) => "RelayCredential::Password(<redacted>)",
        })
    }
}

/// The error for asking a target that is not in relay mode for its relay
/// credential.
pub(crate) fn not_a_relay_target(item: &str) -> PolicyError {
    PolicyError::Invalid {
        item: item.to_owned(),
        field: "mode".to_owned(),
        reason: "is not \"relay\"; only relay targets have an onward credential".to_owned(),
    }
}

/// A policy lookup failed. Messages name the item and field but never carry
/// secret values.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// No target with that name exists.
    #[error("unknown target \"{0}\"")]
    NotFound(String),
    /// No API secret with that name exists.
    #[error("unknown API secret \"{0}\"")]
    UnknownSecret(String),
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
    /// No commit signing key is configured.
    #[error("no commit signing key is configured")]
    NoCommitSigningKey,
    /// The commit signing key is ambiguous or unusable. Never quotes the key.
    #[error("commit signing key: {0}")]
    CommitSigningKey(String),
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

/// Source of targets, API secrets and the CA key. Always reads fresh data.
#[async_trait]
pub trait SecretBackend: Send + Sync + 'static {
    /// Look up an SSH target by name. The whole item is validated, a relay
    /// target's credential included, but the credential is not returned.
    ///
    /// # Errors
    /// [`PolicyError::NotFound`], [`PolicyError::Invalid`] or
    /// [`PolicyError::Unavailable`].
    async fn ssh_target(&self, name: &TargetName) -> Result<SshTarget, PolicyError>;

    /// Look up a relay target and its onward credential in one read of its
    /// item, only when a relay session is about to start, so the credential
    /// always belongs to the policy it is used with. The item is validated
    /// exactly as by [`SecretBackend::ssh_target`].
    ///
    /// # Errors
    /// As [`SecretBackend::ssh_target`]; [`PolicyError::Invalid`] on field
    /// `mode` if the target is not a relay target.
    async fn relay_target_with_credential(
        &self,
        name: &TargetName,
    ) -> Result<(SshTarget, RelayCredential), PolicyError>;

    /// Load the SSH CA key.
    ///
    /// # Errors
    /// [`PolicyError::Ca`] or [`PolicyError::Unavailable`].
    async fn ssh_ca(&self) -> Result<CaKey, PolicyError>;

    /// Whether an SSH CA is configured at all, usable or not, without reading its key.
    ///
    /// # Errors
    /// [`PolicyError::Unavailable`].
    async fn has_ssh_ca(&self) -> Result<bool, PolicyError>;

    /// Load the commit signing key.
    ///
    /// # Errors
    /// [`PolicyError::NoCommitSigningKey`] if none is configured,
    /// [`PolicyError::CommitSigningKey`] or [`PolicyError::Unavailable`].
    async fn commit_signing_key(&self) -> Result<CommitSigningKey, PolicyError>;

    /// Whether a commit signing key is configured, without reading it: what an agent
    /// with no grant can cause.
    ///
    /// # Errors
    /// [`PolicyError::Unavailable`].
    async fn has_commit_signing_key(&self) -> Result<bool, PolicyError>;

    /// Look up an API secret's policy by name. The whole item is validated,
    /// the credential included, but its value is not returned.
    ///
    /// # Errors
    /// [`PolicyError::UnknownSecret`], [`PolicyError::Invalid`] or
    /// [`PolicyError::Unavailable`].
    async fn api_secret(&self, name: &SecretName) -> Result<ApiSecretPolicy, PolicyError>;

    /// Look up an API secret's policy and value in one read of its item,
    /// only when a call is about to be made, so the value always belongs to
    /// the policy it is checked against. The item is validated exactly as
    /// by [`SecretBackend::api_secret`].
    ///
    /// # Errors
    /// As [`SecretBackend::api_secret`].
    async fn api_secret_with_value(
        &self,
        name: &SecretName,
    ) -> Result<(ApiSecretPolicy, SecretValue), PolicyError>;
}

#[cfg(test)]
mod tests;
