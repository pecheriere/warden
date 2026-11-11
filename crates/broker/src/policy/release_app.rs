//! The release GitHub App: a second App, apart from the one agents' tokens come
//! from, that creates release tags and uploads release assets.
//!
//! It has no single installation: the broker finds the installation for the
//! repository when it is used. Its RSA private key is only ever used through
//! `aws-lc-rs`, and never printed.

use std::fmt;
use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeyPair;
use aws_lc_rs::signature::RSA_PKCS1_SHA256;
use sha2::{Digest as _, Sha256};

use super::PolicyError;
use super::github_app::{check_app_id, parse_rsa_key};
use super::onepassword::{SecretField, values_by_label};

const APP_ID_FIELD: &str = "app_id";
const PRIVATE_KEY_FIELD: &str = "private_key";
const LABELS: [&str; 2] = [APP_ID_FIELD, PRIVATE_KEY_FIELD];

/// The release App: its id and RSA private key. The key is never printed.
///
/// Zeroization is best effort, as for [`super::GithubAppKey`].
#[derive(Clone)]
pub struct ReleaseAppKey {
    app_id: String,
    key: Arc<KeyPair>,
}

impl ReleaseAppKey {
    /// Load an App from its id and an unencrypted RSA private key of at least 2048
    /// bits, as PKCS#1 or PKCS#8 PEM.
    ///
    /// # Errors
    /// A fixed reason, if the id is not plain text or the key is not usable. It
    /// never quotes the key.
    pub fn new(app_id: String, pem: &str) -> Result<Self, &'static str> {
        check_app_id(&app_id)?;
        Ok(Self {
            app_id,
            key: parse_rsa_key(pem)?,
        })
    }

    /// The App id, as GitHub's `iss` claim wants it.
    #[must_use]
    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    /// An RSASSA-PKCS1-v1_5 signature of `msg` with SHA-256 (JWT `RS256`).
    ///
    /// # Errors
    /// A fixed reason if the signing library fails.
    pub fn sign_rs256(&self, msg: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut signature = vec![0_u8; self.key.public_modulus_len()];
        self.key
            .sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), msg, &mut signature)
            .map_err(|_| "the release App's private key could not sign")?;
        Ok(signature)
    }

    /// Lowercase hex digest of what a release grant is bound to: the App. Changing
    /// the App ends every grant made for the old one; rotating its key keeps them.
    #[must_use]
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"warden release app v1\0");
        hasher.update(self.app_id.as_bytes());
        hex::encode(hasher.finalize())
    }
}

impl fmt::Debug for ReleaseAppKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleaseAppKey")
            .field("app_id", &self.app_id)
            .finish_non_exhaustive()
    }
}

/// Whether the release App loads, for doctor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseAppProbe {
    /// It loads.
    Loaded {
        /// The App's id.
        app_id: String,
    },
    /// None is configured, which is fine unless releases are wanted.
    NotConfigured,
    /// It is there but cannot be used. Holds the reason, never the key.
    Invalid(String),
    /// The backend could not say.
    Unknown(String),
}

impl ReleaseAppProbe {
    /// The probe for the outcome of reading the release App.
    #[must_use]
    pub fn of(read: Result<ReleaseAppKey, PolicyError>) -> Self {
        match read {
            Ok(key) => Self::Loaded { app_id: key.app_id },
            Err(PolicyError::NoReleaseApp) => Self::NotConfigured,
            Err(PolicyError::ReleaseApp(reason)) => Self::Invalid(reason),
            Err(e) => Self::Unknown(e.to_string()),
        }
    }
}

/// Read the release App from the fields of its item, matched by label. `title`
/// names the item in reasons; no reason quotes a field value.
///
/// # Errors
/// A reason naming the field that is missing, repeated or unusable.
pub fn parse_item(title: &str, fields: &[SecretField]) -> Result<ReleaseAppKey, String> {
    let values = values_by_label(fields, &LABELS)
        .map_err(|label| format!("item \"{title}\": field \"{label}\" appears more than once"))?;
    let required = |label: &str| {
        values
            .get(label)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("item \"{title}\": field \"{label}\" is missing or empty"))
    };
    let app_id = required(APP_ID_FIELD)?.to_owned();
    let pem = zeroize::Zeroizing::new(required(PRIVATE_KEY_FIELD)?.to_owned());
    // The id is checked here, so that after it passes a refusal from `new` can
    // only be about the key, whatever the wording of its reason.
    check_app_id(&app_id)
        .map_err(|reason| format!("item \"{title}\": field \"{APP_ID_FIELD}\": {reason}"))?;
    ReleaseAppKey::new(app_id, &pem)
        .map_err(|reason| format!("item \"{title}\": field \"{PRIVATE_KEY_FIELD}\": {reason}"))
}

#[cfg(test)]
mod tests;
