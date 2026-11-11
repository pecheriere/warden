//! The release signing keys the broker holds, one per releasing repository.
//!
//! Each key signs that repository's release tags, and its manifest where it has
//! one. A release key is kept apart from the commit signing key, from the SSH CA
//! key and from every other repository's key, so that no grant for one kind of
//! signature can produce one another kind of verifier trusts.

use std::fmt;

use sha2::{Digest as _, Sha256};
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey};
use warden_broker_proto::release::RepoName;

use super::onepassword::{SecretField, parse_private_key, values_by_label};
use super::{CommitSigningKey, PolicyError};

/// Item fields, by label.
const PRIVATE_KEY_FIELD: &str = "private_key";
const REPOSITORY_FIELD: &str = "repository";
const TAGGER_NAME_FIELD: &str = "tagger_name";
const TAGGER_EMAIL_FIELD: &str = "tagger_email";
const MANIFEST_FIELD: &str = "manifest";
const NAMESPACE_FIELD: &str = "manifest_namespace";
const PUBLISH_FIELD: &str = "publish";
const LABELS: [&str; 7] = [
    PRIVATE_KEY_FIELD,
    REPOSITORY_FIELD,
    TAGGER_NAME_FIELD,
    TAGGER_EMAIL_FIELD,
    MANIFEST_FIELD,
    NAMESPACE_FIELD,
    PUBLISH_FIELD,
];

/// Where the version goes in a manifest's file name.
const VERSION_PLACEHOLDER: &str = "{version}";
/// The longest tagger name, tagger email and manifest file name accepted.
const MAX_TAGGER_NAME_CHARS: usize = 100;
const MAX_TAGGER_EMAIL_CHARS: usize = 254;
const MAX_MANIFEST_NAME_CHARS: usize = 200;
const MAX_NAMESPACE_CHARS: usize = 64;

/// The manifest a repository signs: the name of the file and the `ssh-keygen -Y`
/// namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestSpec {
    pattern: String,
    namespace: String,
}

impl ManifestSpec {
    /// The manifest's file name for `version`.
    #[must_use]
    pub fn file_name(&self, version: &str) -> String {
        self.pattern.replace(VERSION_PLACEHOLDER, version)
    }

    /// The file name with `{version}` still in it.
    #[must_use]
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// The `ssh-keygen -Y` namespace the signature is made in.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

/// A repository's release signing key and what it signs. The key is never printed.
///
/// Zeroization is best effort, as for [`super::CommitSigningKey`]: the parsed key
/// is wiped by its own `Drop` and the backends hold the text it came from in
/// `Zeroizing` buffers.
#[derive(Clone)]
pub struct ReleaseSigningKey {
    repository: RepoName,
    key: PrivateKey,
    tagger_name: String,
    tagger_email: String,
    manifest: Option<ManifestSpec>,
    publish: bool,
}

impl ReleaseSigningKey {
    /// The only repository this key signs for.
    #[must_use]
    pub const fn repository(&self) -> &RepoName {
        &self.repository
    }

    /// The name on the tags this key signs.
    #[must_use]
    pub fn tagger_name(&self) -> &str {
        &self.tagger_name
    }

    /// The email on the tags this key signs.
    #[must_use]
    pub fn tagger_email(&self) -> &str {
        &self.tagger_email
    }

    /// The manifest the repository signs, if it has one.
    #[must_use]
    pub const fn manifest(&self) -> Option<&ManifestSpec> {
        self.manifest.as_ref()
    }

    /// Whether the broker publishes the draft release.
    #[must_use]
    pub const fn publish(&self) -> bool {
        self.publish
    }

    /// The public key's `SHA256:…` fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
    }

    /// Lowercase hex digest of what a release grant is bound to: the repository
    /// (lowercased), the key, the tagger, the manifest and whether the broker
    /// publishes. Changing any of them ends every grant made for the old item.
    #[must_use]
    pub fn destination_digest(&self) -> String {
        let mut hasher = Sha256::new();
        let mut part = |bytes: &[u8]| {
            hasher.update(bytes);
            hasher.update(b"\0");
        };
        part(b"warden release signing v1");
        part(self.repository.as_str().to_ascii_lowercase().as_bytes());
        part(self.fingerprint().as_bytes());
        part(self.tagger_name.as_bytes());
        part(self.tagger_email.as_bytes());
        match &self.manifest {
            Some(manifest) => {
                part(b"manifest");
                part(manifest.pattern.as_bytes());
                part(manifest.namespace.as_bytes());
            }
            None => part(b"no manifest"),
        }
        part(if self.publish {
            b"publish"
        } else {
            b"keep draft"
        });
        hex::encode(hasher.finalize())
    }
}

impl fmt::Debug for ReleaseSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleaseSigningKey")
            .field("repository", &self.repository)
            .field("key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A non-empty single line without control characters or the characters that end
/// a name or an email in a Git tag.
fn is_tag_text(text: &str, max_chars: usize) -> bool {
    !text.is_empty()
        && text.chars().count() <= max_chars
        && text == text.trim()
        && !text
            .chars()
            .any(|c| c.is_control() || matches!(c, '<' | '>'))
}

fn manifest_pattern_error(pattern: &str) -> Option<&'static str> {
    if pattern.matches(VERSION_PLACEHOLDER).count() != 1 {
        return Some("must contain {version} exactly once");
    }
    if pattern.contains(['/', '\\']) {
        return Some("must be a file name, without a path separator");
    }
    let sample = pattern.replace(VERSION_PLACEHOLDER, "0.0.0");
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-');
    if sample.chars().count() > MAX_MANIFEST_NAME_CHARS
        || sample == "."
        || sample == ".."
        || !sample.chars().all(plain)
    {
        return Some(
            "must be a file name of letters, digits, dots, underscores, plus signs and dashes around {version}",
        );
    }
    None
}

fn is_namespace(namespace: &str) -> bool {
    let bytes = namespace.as_bytes();
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    bytes.len() <= MAX_NAMESPACE_CHARS
        && bytes.first().is_some_and(|&b| alnum(b))
        && bytes.iter().all(|&b| alnum(b) || b == b'-')
}

/// Whether the release signing keys load, for doctor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseSigningProbe {
    /// Every item loads and they are all distinct. Holds the repositories, in the
    /// order the items were read; never a key or a fingerprint.
    Loaded {
        /// One `owner/name` per item.
        repositories: Vec<String>,
    },
    /// There are no release signing items, which is fine unless releases are wanted.
    NotConfigured,
    /// An item is unusable or the set is not distinct. Holds the reason, never a key.
    Invalid(String),
    /// The backend could not say.
    Unknown(String),
}

impl ReleaseSigningProbe {
    /// The probe for the outcome of reading every release signing key.
    #[must_use]
    pub fn of(read: Result<Vec<ReleaseSigningKey>, PolicyError>) -> Self {
        match read {
            Ok(keys) if keys.is_empty() => Self::NotConfigured,
            Ok(keys) => Self::Loaded {
                repositories: keys
                    .iter()
                    .map(|key| key.repository().as_str().to_owned())
                    .collect(),
            },
            Err(PolicyError::ReleaseKey(reason)) => Self::Invalid(reason),
            Err(e) => Self::Unknown(e.to_string()),
        }
    }
}

/// Read a release signing key from the fields of its item. `title` names the item
/// in reasons; no reason quotes a field value.
///
/// # Errors
/// A reason naming the field that is missing, repeated or unusable.
pub fn parse_item(title: &str, fields: &[SecretField]) -> Result<ReleaseSigningKey, String> {
    let values = values_by_label(fields, &LABELS)
        .map_err(|label| format!("item \"{title}\": field \"{label}\" appears more than once"))?;
    let bad = |label: &str, why: &str| format!("item \"{title}\": field \"{label}\" {why}");
    let required = |label: &str| {
        values
            .get(label)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| bad(label, "is missing or empty"))
    };
    let optional = |label: &str| {
        values
            .get(label)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
    };

    let repository = RepoName::try_from(required(REPOSITORY_FIELD)?.to_owned())
        .map_err(|_| bad(REPOSITORY_FIELD, "must be owner/name"))?;
    let key = parse_private_key(required(PRIVATE_KEY_FIELD)?).ok_or_else(|| {
        bad(
            PRIVATE_KEY_FIELD,
            "is not a readable OpenSSH or PKCS#8 Ed25519 key",
        )
    })?;
    if key.is_encrypted() {
        return Err(bad(
            PRIVATE_KEY_FIELD,
            "is passphrase-protected; an unencrypted ssh-ed25519 key is required",
        ));
    }
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(bad(
            PRIVATE_KEY_FIELD,
            "is not an ssh-ed25519 key; only ssh-ed25519 keys are accepted",
        ));
    }
    let tagger_name = required(TAGGER_NAME_FIELD)?;
    if !is_tag_text(tagger_name, MAX_TAGGER_NAME_CHARS) {
        return Err(bad(
            TAGGER_NAME_FIELD,
            "must be 1 to 100 characters on one line, without < or >",
        ));
    }
    let tagger_email = required(TAGGER_EMAIL_FIELD)?;
    if !is_tag_text(tagger_email, MAX_TAGGER_EMAIL_CHARS)
        || tagger_email.contains(char::is_whitespace)
        || !tagger_email.contains('@')
    {
        return Err(bad(
            TAGGER_EMAIL_FIELD,
            "must be an email address without spaces, < or >",
        ));
    }
    let manifest = match (optional(MANIFEST_FIELD), optional(NAMESPACE_FIELD)) {
        (None, None) => None,
        (None, Some(_)) => {
            return Err(bad(NAMESPACE_FIELD, "is set but \"manifest\" is not"));
        }
        (Some(_), None) => {
            return Err(bad(NAMESPACE_FIELD, "is required with \"manifest\""));
        }
        (Some(pattern), Some(namespace)) => {
            if let Some(why) = manifest_pattern_error(pattern) {
                return Err(bad(MANIFEST_FIELD, why));
            }
            if !is_namespace(namespace) {
                return Err(bad(NAMESPACE_FIELD, "must match ^[a-z0-9][a-z0-9-]{0,63}$"));
            }
            Some(ManifestSpec {
                pattern: pattern.to_owned(),
                namespace: namespace.to_owned(),
            })
        }
    };
    let publish = match optional(PUBLISH_FIELD) {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return Err(bad(PUBLISH_FIELD, "must be true or false")),
    };
    Ok(ReleaseSigningKey {
        repository,
        key,
        tagger_name: tagger_name.to_owned(),
        tagger_email: tagger_email.to_owned(),
        manifest,
        publish,
    })
}

/// Refuse a set of release keys that is not kept apart: two items for one
/// repository, one key in two items, or a key that is also the commit signing key
/// or the SSH CA key. Keys are compared by public key. `ca` is `None` only for a
/// broker with no SSH CA at all.
///
/// # Errors
/// A reason naming the repositories involved, never a key.
pub fn check_distinct(
    keys: &[ReleaseSigningKey],
    commit_signing: Option<&CommitSigningKey>,
    ca: Option<&PublicKey>,
) -> Result<(), String> {
    for (i, key) in keys.iter().enumerate() {
        let repo = key.repository.as_str();
        for other in &keys[i + 1..] {
            if key.repository.matches(&other.repository) {
                return Err(format!("more than one item is for repository {repo}"));
            }
            if key.key.public_key().key_data() == other.key.public_key().key_data() {
                return Err(format!(
                    "the release signing keys for {repo} and {} are the same key; each repository needs its own",
                    other.repository
                ));
            }
        }
        if commit_signing.is_some_and(|c| c.is_same_key_as(key.key.public_key())) {
            return Err(format!(
                "the release signing key for {repo} is also the commit signing key; it must be a key of its own"
            ));
        }
        if ca.is_some_and(|ca| ca.key_data() == key.key.public_key().key_data()) {
            return Err(format!(
                "the release signing key for {repo} is also the SSH CA key; it must be a key of its own"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
