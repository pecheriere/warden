//! The GitHub App the broker mints agent tokens for, and what doctor says about it.
//!
//! The App's RSA private key signs the short JWT GitHub exchanges for an installation
//! token. It is only ever used through `aws-lc-rs`, and never printed.

use std::fmt;
use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeyPair;
use aws_lc_rs::signature::RSA_PKCS1_SHA256;
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject as _;
use sha2::{Digest as _, Sha256};
use warden_broker_proto::github_token::GrantScope;
use warden_broker_proto::{GithubTokenGrant, Window};
use zeroize::Zeroizing;

use super::PolicyError;
use super::onepassword::{SecretField, values_by_label};

/// The shortest RSA modulus accepted, in bytes (2048 bits): GitHub's own minimum.
const MIN_MODULUS_BYTES: usize = 256;

/// The longest App id accepted. GitHub's are short numbers or `Iv1.`-style client ids.
const MAX_APP_ID_CHARS: usize = 64;

/// Item fields, by label.
const APP_ID_FIELD: &str = "app_id";
const INSTALLATION_ID_FIELD: &str = "installation_id";
const PRIVATE_KEY_FIELD: &str = "private_key";
const LABELS: [&str; 3] = [APP_ID_FIELD, INSTALLATION_ID_FIELD, PRIVATE_KEY_FIELD];

/// Why an App id is refused. The release App's id follows the same rule.
const APP_ID_REASON: &str =
    "the App id must be 1 to 64 letters, digits, dots, dashes or underscores";

/// Check that `app_id` is 1 to 64 letters, digits, dots, dashes or underscores.
///
/// # Errors
/// A fixed reason; it never quotes the id.
pub(super) fn check_app_id(app_id: &str) -> Result<(), &'static str> {
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    if !app_id.is_empty() && app_id.chars().count() <= MAX_APP_ID_CHARS && app_id.chars().all(plain)
    {
        Ok(())
    } else {
        Err(APP_ID_REASON)
    }
}

fn app_error(reason: &str) -> PolicyError {
    PolicyError::GithubApp(reason.to_owned())
}

/// The GitHub App: its ids and RSA private key. The key is never printed.
///
/// Zeroization is best effort: `aws-lc-rs` wipes the key it parsed when the last
/// clone is dropped, the backends hold the PEM text in `Zeroizing` buffers, and the DER the PEM
/// decoder produces is wiped after parsing. Accepted residual: the copies inside the HTTP stack are not wiped.
#[derive(Clone)]
pub struct GithubAppKey {
    app_id: String,
    installation_id: u64,
    key: Arc<KeyPair>,
}

impl GithubAppKey {
    /// Load an App from its ids and an unencrypted RSA private key of at least 2048
    /// bits, as PKCS#1 (`RSA PRIVATE KEY`) or PKCS#8 (`PRIVATE KEY`) PEM.
    ///
    /// # Errors
    /// [`PolicyError::GithubApp`] with a fixed reason, if an id is not plain text or
    /// the key is not usable. It never quotes the key.
    pub fn new(app_id: String, installation_id: u64, pem: &[u8]) -> Result<Self, PolicyError> {
        check_app_id(&app_id).map_err(app_error)?;
        if installation_id == 0 {
            return Err(app_error("the installation id must not be 0"));
        }
        let pem = std::str::from_utf8(pem)
            .map_err(|_| app_error("the private key is not a readable PKCS#1 or PKCS#8 PEM key"))?;
        Ok(Self {
            app_id,
            installation_id,
            key: parse_rsa_key(pem).map_err(app_error)?,
        })
    }

    /// The App id, as GitHub's `iss` claim wants it.
    #[must_use]
    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    /// The installation tokens are minted for.
    #[must_use]
    pub const fn installation_id(&self) -> u64 {
        self.installation_id
    }

    /// An RSASSA-PKCS1-v1_5 signature of `message` with SHA-256 (JWT `RS256`).
    ///
    /// # Errors
    /// [`PolicyError::GithubApp`] if the signing library fails.
    pub fn sign_rs256(&self, message: &[u8]) -> Result<Vec<u8>, PolicyError> {
        let mut signature = vec![0_u8; self.key.public_modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message,
                &mut signature,
            )
            .map_err(|_| app_error("the App's private key could not sign"))?;
        Ok(signature)
    }

    /// The policy this App makes, with grants of at most `max_window`.
    #[must_use]
    pub fn policy(&self, max_window: Window) -> GithubTokenPolicy {
        GithubTokenPolicy {
            app_id: self.app_id.clone(),
            installation_id: self.installation_id,
            max_window,
        }
    }
}

impl fmt::Debug for GithubAppKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubAppKey")
            .field("app_id", &self.app_id)
            .field("installation_id", &self.installation_id)
            .finish_non_exhaustive()
    }
}

/// Decode one unencrypted RSA private key of at least 2048 bits from PEM, as the
/// GitHub App and the release App both hold it. The reason is fixed text and never
/// quotes the key.
pub(crate) fn parse_rsa_key(pem: &str) -> Result<Arc<KeyPair>, &'static str> {
    const NOT_RSA: &str =
        "the private key is not an RSA key of at least 2048 bits (PKCS#1 or PKCS#8)";
    if pem.contains("ENCRYPTED") {
        return Err("the private key is passphrase-protected; an unencrypted RSA key is required");
    }
    let der = Zeroizing::new(
        PrivateKeyDer::from_pem_slice(pem.as_bytes())
            .map_err(|_| "the private key is not a readable PKCS#1 or PKCS#8 PEM key")?,
    );
    let key = match &*der {
        PrivateKeyDer::Pkcs1(der) => KeyPair::from_der(der.secret_pkcs1_der()),
        PrivateKeyDer::Pkcs8(der) => KeyPair::from_pkcs8(der.secret_pkcs8_der()),
        _ => return Err(NOT_RSA),
    }
    .map_err(|_| NOT_RSA)?;
    if key.public_modulus_len() < MIN_MODULUS_BYTES {
        return Err(NOT_RSA);
    }
    Ok(Arc::new(key))
}

/// Read the GitHub App from the fields of its item, matched by label like every
/// other policy item (1Password gives fields added in its apps random ids). `title`
/// names the item in reasons; no reason quotes a field value.
///
/// # Errors
/// [`PolicyError::GithubApp`] naming the field that is missing, repeated or unusable.
pub(super) fn parse_item(title: &str, fields: &[SecretField]) -> Result<GithubAppKey, PolicyError> {
    let by_label = values_by_label(fields, &LABELS).map_err(|label| {
        PolicyError::GithubApp(format!(
            "item \"{title}\": field \"{label}\" appears more than once"
        ))
    })?;
    let field = |label: &str| -> Result<&str, PolicyError> {
        by_label
            .get(label)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                PolicyError::GithubApp(format!(
                    "item \"{title}\": field \"{label}\" is missing or empty"
                ))
            })
    };
    let in_item = |e: PolicyError| match e {
        PolicyError::GithubApp(reason) => {
            PolicyError::GithubApp(format!("item \"{title}\": {reason}"))
        }
        other => other,
    };
    let app_id = field(APP_ID_FIELD)?.to_owned();
    let installation_id = field(INSTALLATION_ID_FIELD)?
        .parse::<u64>()
        .ok()
        .filter(|id| *id != 0)
        .ok_or_else(|| {
            PolicyError::GithubApp(format!(
                "item \"{title}\": field \"{INSTALLATION_ID_FIELD}\" must be a positive number"
            ))
        })?;
    let pem = Zeroizing::new(field(PRIVATE_KEY_FIELD)?.as_bytes().to_vec());
    GithubAppKey::new(app_id, installation_id, &pem).map_err(|e| match e {
        PolicyError::GithubApp(reason) if reason.contains("private key") => in_item(
            PolicyError::GithubApp(format!("field \"{PRIVATE_KEY_FIELD}\": {reason}")),
        ),
        other => in_item(other),
    })
}

/// What a GitHub token grant is for: the App and installation tokens are minted
/// for, and the longest window the server allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubTokenPolicy {
    /// The App's id.
    pub app_id: String,
    /// The installation tokens are minted for.
    pub installation_id: u64,
    /// Longest window that may be granted.
    pub max_window: Window,
}

impl GithubTokenPolicy {
    /// Lowercase hex digest of what a grant is bound to: the App and installation.
    /// Changing either ends every grant made for the old one. The key itself is not
    /// part of it: rotating it keeps grants, because the App stays the same.
    #[must_use]
    pub fn destination_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"warden github-token v1\0");
        hasher.update(self.app_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.installation_id.to_string().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// The grant details approving this policy gives, for these repositories.
    #[must_use]
    pub fn grant(&self, repositories: GrantScope) -> GithubTokenGrant {
        GithubTokenGrant {
            app_id: self.app_id.clone(),
            installation_id: self.installation_id,
            digest: self.destination_digest(),
            repositories,
        }
    }
}

/// What doctor found about the GitHub App.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GithubAppProbe {
    /// It loads.
    Loaded {
        /// The App's id.
        app_id: String,
        /// The installation tokens are minted for.
        installation_id: u64,
    },
    /// None is configured, which is fine unless GitHub tokens are wanted.
    NotConfigured,
    /// It is there but cannot be used. Holds the reason, never the key.
    Invalid(String),
    /// The backend could not say.
    Unknown(String),
}

impl GithubAppProbe {
    /// The probe for the outcome of reading the App.
    #[must_use]
    pub fn of(read: Result<GithubAppKey, PolicyError>) -> Self {
        match read {
            Ok(key) => Self::Loaded {
                app_id: key.app_id,
                installation_id: key.installation_id,
            },
            Err(PolicyError::NoGithubApp) => Self::NotConfigured,
            Err(PolicyError::GithubApp(reason)) => Self::Invalid(reason),
            Err(e) => Self::Unknown(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
    use warden_broker_proto::Window;
    use warden_broker_proto::github_token::GrantScope;

    use super::{GithubAppKey, GithubAppProbe};
    use crate::policy::PolicyError;
    use crate::testkit::github_app::{
        APP_ID, EC_P256_PKCS8, ED25519_PKCS8, INSTALLATION_ID, RSA1024_PKCS8, RSA2048_ENCRYPTED,
        RSA2048_ENCRYPTED_PKCS1, RSA2048_PKCS1, RSA2048_PKCS8, RSA2048_PUBLIC_DER,
    };

    fn load(pem: &[u8]) -> Result<GithubAppKey, PolicyError> {
        GithubAppKey::new(APP_ID.to_owned(), INSTALLATION_ID, pem)
    }

    #[test]
    fn github_app_key_accepts_pkcs1_and_pkcs8() {
        for pem in [RSA2048_PKCS1, RSA2048_PKCS8] {
            let key = load(pem).unwrap();
            let signature = key.sign_rs256(b"header.payload").unwrap();
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, RSA2048_PUBLIC_DER)
                .verify(b"header.payload", &signature)
                .unwrap();
        }
    }

    #[test]
    fn github_app_key_rejects_ec_ed25519_encrypted_and_short_keys() {
        for (what, pem) in [
            ("ec", EC_P256_PKCS8),
            ("ed25519", ED25519_PKCS8),
            ("encrypted", RSA2048_ENCRYPTED),
            ("1024-bit", RSA1024_PKCS8),
            ("garbage", b"not a key".as_slice()),
        ] {
            let err = load(pem).unwrap_err();
            assert!(matches!(err, PolicyError::GithubApp(_)), "{what}: {err:?}");
        }
    }

    #[test]
    fn github_app_key_says_an_encrypted_key_is_passphrase_protected() {
        for (what, pem) in [
            ("pkcs8", RSA2048_ENCRYPTED),
            ("legacy pkcs1", RSA2048_ENCRYPTED_PKCS1),
        ] {
            let Err(PolicyError::GithubApp(reason)) = load(pem) else {
                panic!("{what}: not refused as a GitHub App error");
            };
            assert!(reason.contains("passphrase-protected"), "{what}: {reason}");
        }
    }

    #[test]
    fn github_app_rejects_ids_that_are_not_plain() {
        for bad in ["", "12 34", "12\"34", "12\n34", &"1".repeat(65)] {
            let err =
                GithubAppKey::new(bad.to_owned(), INSTALLATION_ID, RSA2048_PKCS8).unwrap_err();
            assert!(matches!(err, PolicyError::GithubApp(_)), "{bad:?}: {err:?}");
        }
    }

    #[test]
    fn github_app_debug_redacts() {
        let key = load(RSA2048_PKCS8).unwrap();
        let shown = format!("{key:?}");
        assert!(shown.contains(APP_ID), "{shown}");
        assert!(shown.contains(&INSTALLATION_ID.to_string()), "{shown}");
        assert!(!shown.contains("KeyPair"), "{shown}");
        assert!(!shown.to_lowercase().contains("key:"), "{shown}");
    }

    #[test]
    fn digest_changes_with_app_or_installation() {
        let base = load(RSA2048_PKCS8).unwrap().policy(Window::D30);
        let longer = load(RSA2048_PKCS8).unwrap().policy(Window::D7);
        assert_eq!(base.destination_digest(), longer.destination_digest());
        let other_app = GithubAppKey::new("654321".to_owned(), INSTALLATION_ID, RSA2048_PKCS8)
            .unwrap()
            .policy(Window::D30);
        let other_installation = GithubAppKey::new(APP_ID.to_owned(), 1, RSA2048_PKCS8)
            .unwrap()
            .policy(Window::D30);
        assert_ne!(base.destination_digest(), other_app.destination_digest());
        assert_ne!(
            base.destination_digest(),
            other_installation.destination_digest()
        );
        // "1" + "23" and "12" + "3" must not collide.
        let a = GithubAppKey::new("1".to_owned(), 23, RSA2048_PKCS8).unwrap();
        let b = GithubAppKey::new("12".to_owned(), 3, RSA2048_PKCS8).unwrap();
        assert_ne!(
            a.policy(Window::D30).destination_digest(),
            b.policy(Window::D30).destination_digest()
        );
        let grant = base.grant(GrantScope::Legacy);
        assert_eq!(grant.app_id, APP_ID);
        assert_eq!(grant.installation_id, INSTALLATION_ID);
        assert_eq!(grant.digest, base.destination_digest());
        assert_eq!(grant.digest.len(), 64);
    }

    #[test]
    fn the_probe_keeps_each_answer_apart() {
        assert_eq!(
            GithubAppProbe::of(load(RSA2048_PKCS8)),
            GithubAppProbe::Loaded {
                app_id: APP_ID.to_owned(),
                installation_id: INSTALLATION_ID
            }
        );
        assert_eq!(
            GithubAppProbe::of(Err(PolicyError::NoGithubApp)),
            GithubAppProbe::NotConfigured
        );
        assert_eq!(
            GithubAppProbe::of(Err(PolicyError::GithubApp("bad".to_owned()))),
            GithubAppProbe::Invalid("bad".to_owned())
        );
        assert!(matches!(
            GithubAppProbe::of(Err(PolicyError::Unavailable("out".to_owned()))),
            GithubAppProbe::Unknown(_)
        ));
    }
}
