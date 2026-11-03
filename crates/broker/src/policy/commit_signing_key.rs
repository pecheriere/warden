//! The commit signing key the broker holds, and what doctor says about it.

use std::fmt;

use sha2::{Digest as _, Sha256};
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey};
use warden_broker_proto::{CommitSigningGrant, Window};

use super::{CaKey, PolicyError, SecretBackend};

/// Why a commit signing key is refused while the SSH CA cannot be used. The CA's own
/// problem is in doctor's report, and is not repeated here.
pub const CA_UNREADABLE: &str = "the SSH CA cannot be read, so nothing says the commit signing \
                                 key is a different key; fix the CA first";

/// Why a key that is also the SSH CA key is refused.
pub const SAME_AS_CA: &str = "the commit signing key is also the SSH CA key; it must be a key of \
                              its own";

/// The commit signing private key: `ssh-ed25519` only, never printed.
///
/// Zeroization is best effort, as for [`super::CaKey`]: the parsed key is wiped by
/// its own `Drop`, and the backends hold the text it came from in `Zeroizing`
/// buffers. It is read from the backend for each signature and dropped straight
/// after.
pub struct CommitSigningKey(PrivateKey);

impl CommitSigningKey {
    /// Wrap a private key, rejecting anything but an unencrypted Ed25519 key.
    ///
    /// # Errors
    /// [`PolicyError::CommitSigningKey`] if the key is encrypted or not Ed25519.
    pub fn new(key: PrivateKey) -> Result<Self, PolicyError> {
        if key.is_encrypted() {
            return Err(PolicyError::CommitSigningKey(
                "the key is passphrase-protected; an unencrypted ssh-ed25519 key is required"
                    .into(),
            ));
        }
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(PolicyError::CommitSigningKey(format!(
                "the key is {}, but only ssh-ed25519 keys are accepted",
                key.algorithm()
            )));
        }
        Ok(Self(key))
    }

    /// Whether `other` is this key's public half. Comments do not count.
    #[must_use]
    pub fn is_same_key_as(&self, other: &PublicKey) -> bool {
        self.0.public_key().key_data() == other.key_data()
    }

    /// The private key, for signing.
    #[must_use]
    pub(crate) const fn private_key(&self) -> &PrivateKey {
        &self.0
    }

    /// The policy this key makes, with grants of at most `max_window`.
    ///
    /// # Errors
    /// [`PolicyError::CommitSigningKey`] if the public key cannot be encoded.
    pub fn policy(&self, max_window: Window) -> Result<CommitSigningPolicy, PolicyError> {
        let mut public = self.0.public_key().clone();
        // The comment is whatever the key file had, which may name a machine.
        public.set_comment("");
        let public_key = public
            .to_openssh()
            .map_err(|_| PolicyError::CommitSigningKey("cannot encode the public key".into()))?;
        Ok(CommitSigningPolicy {
            public_key,
            key_fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
            max_window,
        })
    }
}

impl fmt::Debug for CommitSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CommitSigningKey(<redacted>)")
    }
}

/// Refuse `key` if it is also `backend`'s SSH CA key. Only a broker with no CA at all
/// has nothing to compare with. A CA that is there but cannot be used (several items,
/// a malformed or encrypted key) could be this key, so it refuses too.
///
/// # Errors
/// [`PolicyError::CommitSigningKey`] with [`SAME_AS_CA`] or [`CA_UNREADABLE`], or
/// [`PolicyError::Unavailable`] if the backend cannot answer.
pub async fn check_separate_from_ca<B: SecretBackend + ?Sized>(
    backend: &B,
    key: &CommitSigningKey,
) -> Result<(), PolicyError> {
    if !backend.has_ssh_ca().await? {
        return Ok(());
    }
    compare_with_ca(key, backend.ssh_ca().await)
}

/// Whether `key` may be used given what reading the CA gave.
///
/// # Errors
/// As [`check_separate_from_ca`].
pub(super) fn compare_with_ca(
    key: &CommitSigningKey,
    ca: Result<CaKey, PolicyError>,
) -> Result<(), PolicyError> {
    match ca {
        Ok(ca) if key.is_same_key_as(ca.public_key()) => {
            Err(PolicyError::CommitSigningKey(SAME_AS_CA.to_owned()))
        }
        Ok(_) => Ok(()),
        Err(PolicyError::Ca(_)) => Err(PolicyError::CommitSigningKey(CA_UNREADABLE.to_owned())),
        Err(e) => Err(e),
    }
}

/// What a commit signing grant is for: the public half of the broker's key, and
/// the longest window the server allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitSigningPolicy {
    /// OpenSSH public key, without a comment.
    pub public_key: String,
    /// `SHA256:…` fingerprint.
    pub key_fingerprint: String,
    /// Longest window that may be granted.
    pub max_window: Window,
}

impl CommitSigningPolicy {
    /// Lowercase hex digest of what a grant is bound to: the key. Changing the key
    /// ends every grant made for the old one.
    #[must_use]
    pub fn destination_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"warden commit signing key\n");
        hasher.update(self.key_fingerprint.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// The grant details approving this policy gives.
    #[must_use]
    pub fn grant(&self) -> CommitSigningGrant {
        CommitSigningGrant {
            key_fingerprint: self.key_fingerprint.clone(),
            digest: self.destination_digest(),
        }
    }
}

/// What doctor found about the commit signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitSigningProbe {
    /// It loads. Holds its public key's fingerprint.
    Loaded {
        /// `SHA256:…` fingerprint.
        fingerprint: String,
    },
    /// None is configured, which is fine unless commit signing is wanted.
    NotConfigured,
    /// It is there but cannot be used. Holds the reason, never the key.
    Invalid(String),
    /// The backend could not say.
    Unknown(String),
}

impl CommitSigningProbe {
    /// The probe for the outcome of reading the key.
    #[must_use]
    pub fn of(read: Result<CommitSigningKey, PolicyError>) -> Self {
        match read {
            Ok(key) => Self::Loaded {
                fingerprint: key.0.public_key().fingerprint(HashAlg::Sha256).to_string(),
            },
            Err(PolicyError::NoCommitSigningKey) => Self::NotConfigured,
            Err(PolicyError::CommitSigningKey(reason)) => Self::Invalid(reason),
            Err(e) => Self::Unknown(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey};
    use warden_broker_proto::Window;

    use super::{CommitSigningKey, CommitSigningProbe};
    use crate::policy::PolicyError;

    fn ed25519() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
    }

    #[test]
    fn debug_never_shows_the_key() {
        let key = CommitSigningKey::new(ed25519()).unwrap();
        assert_eq!(format!("{key:?}"), "CommitSigningKey(<redacted>)");
    }

    #[test]
    fn the_digest_changes_with_the_key_and_not_the_limit() {
        let key = CommitSigningKey::new(ed25519()).unwrap();
        let (short, long) = (
            key.policy(Window::D7).unwrap(),
            key.policy(Window::D90).unwrap(),
        );
        assert_eq!(short.destination_digest(), long.destination_digest());
        let other = CommitSigningKey::new(ed25519()).unwrap();
        assert_ne!(
            short.destination_digest(),
            other.policy(Window::D7).unwrap().destination_digest()
        );
    }

    #[test]
    fn the_policy_drops_the_key_files_comment() {
        let mut key = ed25519();
        key.set_comment("root@a-private-machine");
        let policy = CommitSigningKey::new(key)
            .unwrap()
            .policy(Window::D30)
            .unwrap();
        assert!(!policy.public_key.contains("private-machine"));
    }

    #[test]
    fn the_probe_keeps_each_answer_apart() {
        assert!(matches!(
            CommitSigningProbe::of(CommitSigningKey::new(ed25519())),
            CommitSigningProbe::Loaded { .. }
        ));
        assert_eq!(
            CommitSigningProbe::of(Err(PolicyError::NoCommitSigningKey)),
            CommitSigningProbe::NotConfigured
        );
        assert_eq!(
            CommitSigningProbe::of(Err(PolicyError::CommitSigningKey("bad".to_owned()))),
            CommitSigningProbe::Invalid("bad".to_owned())
        );
        assert!(matches!(
            CommitSigningProbe::of(Err(PolicyError::Unavailable("out".to_owned()))),
            CommitSigningProbe::Unknown(_)
        ));
    }
}
