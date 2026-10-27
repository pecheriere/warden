//! Access policy: which SSH targets and API secrets exist, and the SSH CA
//! key, sourced from a secret backend (1Password Connect in production).

use std::fmt;

use async_trait::async_trait;
use http::{HeaderName, Method};
use sha2::{Digest as _, Sha256};
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey};
use url::Origin;
use warden_broker_proto::{ApiGrant, SecretName, TargetName, UnixUser, Window};
use zeroize::Zeroizing;

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
        digest_parts(
            [self.host.as_str(), port.as_str()]
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

/// How the secret is written into the header: a fixed prefix and suffix
/// around the secret, parsed from a template holding exactly one
/// `{{secret}}`. Holds no secret itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueFormat {
    prefix: String,
    suffix: String,
}

impl ValueFormat {
    /// The placeholder the template must contain exactly once.
    pub const PLACEHOLDER: &'static str = "{{secret}}";

    /// Parse a template such as `Bearer {{secret}}`.
    ///
    /// # Errors
    /// A reason if the placeholder is absent or repeated, or if the text
    /// around it is not printable ASCII (it must be valid in a header value).
    pub fn parse(template: &str) -> Result<Self, &'static str> {
        let Some((prefix, suffix)) = template.split_once(Self::PLACEHOLDER) else {
            return Err("must contain {{secret}} exactly once");
        };
        if suffix.contains(Self::PLACEHOLDER) {
            return Err("must contain {{secret}} exactly once");
        }
        if !prefix.chars().chain(suffix.chars()).all(is_header_text) {
            return Err("text around {{secret}} must be printable ASCII");
        }
        Ok(Self {
            prefix: prefix.to_owned(),
            suffix: suffix.to_owned(),
        })
    }

    /// Text before the secret.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Text after the secret.
    #[must_use]
    pub fn suffix(&self) -> &str {
        &self.suffix
    }

    /// The header value for `secret`, in memory that is wiped on drop. The
    /// buffer is sized up front so no partial copy is left behind by a
    /// reallocation.
    #[must_use]
    pub fn render(&self, secret: &str) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(
            self.prefix.len() + secret.len() + self.suffix.len(),
        ));
        out.push_str(&self.prefix);
        out.push_str(secret);
        out.push_str(&self.suffix);
        out
    }
}

impl Default for ValueFormat {
    /// `Bearer {{secret}}`.
    fn default() -> Self {
        Self {
            prefix: "Bearer ".to_owned(),
            suffix: String::new(),
        }
    }
}

/// Printable ASCII, space included: safe inside an HTTP header value.
pub(crate) fn is_header_text(c: char) -> bool {
    (' '..='~').contains(&c)
}

/// Headers that frame or route a request, which must never carry the secret
/// (nor be set by an agent): `Host`, `Content-Length`, `Transfer-Encoding`,
/// `Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade` and `Proxy-*`.
#[must_use]
pub fn is_reserved_header(name: &HeaderName) -> bool {
    let name = name.as_str();
    matches!(
        name,
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "upgrade"
    ) || name.starts_with("proxy-")
}

/// An API secret as defined by its 1Password item: where the broker may send
/// it and how. The secret value itself is not part of it; see
/// [`SecretBackend::api_secret_with_value`].
#[derive(Debug, Clone)]
pub struct ApiSecretPolicy {
    /// Secret name (the item title).
    pub name: SecretName,
    /// The only origin calls may go to: a tuple origin with scheme `https`.
    pub origin: Origin,
    /// Header that carries the secret.
    pub header: HeaderName,
    /// How the secret is written into the header.
    pub format: ValueFormat,
    /// Allowed methods, in policy order, without duplicates.
    pub methods: Vec<Method>,
    /// Allowed path prefix, starting with `/`.
    pub path_prefix: String,
    /// PEM CA certificate(s) to trust instead of the system roots.
    pub ca_pem: Option<String>,
    /// Longest window that may be granted.
    pub max_window: Window,
}

impl ApiSecretPolicy {
    /// Lowercase hex SHA-256 over where and how the secret is sent: origin,
    /// path prefix, header, value format, pinned CA and the set of methods
    /// (sorted, so order does not matter). The secret value and the window
    /// are not part of it. Every part is length-prefixed.
    #[must_use]
    pub fn destination_digest(&self) -> String {
        let origin = self.origin.ascii_serialization();
        let mut methods: Vec<&str> = self.methods.iter().map(Method::as_str).collect();
        methods.sort_unstable();
        methods.dedup();
        let count = methods.len().to_string();
        let (ca_flag, ca_text) = match &self.ca_pem {
            Some(pem) => ("ca", pem.as_str()),
            None => ("no-ca", ""),
        };
        digest_parts(
            [
                origin.as_str(),
                self.path_prefix.as_str(),
                self.header.as_str(),
                self.format.prefix(),
                self.format.suffix(),
                ca_flag,
                ca_text,
                count.as_str(),
            ]
            .into_iter()
            .chain(methods),
        )
    }

    /// The grant details an approval of this policy hands to the agent:
    /// methods in sorted order (the order [`Self::destination_digest`]
    /// uses) and the destination digest, so two grants are equal exactly
    /// when they were made from the same destination.
    #[must_use]
    pub fn grant(&self) -> ApiGrant {
        let mut methods: Vec<String> = self.methods.iter().map(|m| m.as_str().to_owned()).collect();
        methods.sort_unstable();
        methods.dedup();
        ApiGrant {
            secret: self.name.clone(),
            origin: self.origin.ascii_serialization(),
            methods,
            path_prefix: self.path_prefix.clone(),
            header: self.header.as_str().to_owned(),
            digest: self.destination_digest(),
        }
    }
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
mod tests {
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey, PublicKey};
    use warden_broker_proto::{TargetName, Window};

    use http::{HeaderName, Method};
    use url::Url;
    use warden_broker_proto::SecretName;
    use zeroize::Zeroizing;

    use super::{ApiSecretPolicy, SecretValue, SshMode, SshTarget, ValueFormat};

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

    fn api(origin: &str, prefix: &str, methods: &[Method], header: &str) -> ApiSecretPolicy {
        ApiSecretPolicy {
            name: SecretName::try_from("github".to_owned()).unwrap(),
            origin: Url::parse(origin).unwrap().origin(),
            header: HeaderName::from_bytes(header.as_bytes()).unwrap(),
            format: ValueFormat::default(),
            methods: methods.to_vec(),
            path_prefix: prefix.to_owned(),
            ca_pem: None,
            max_window: Window::H1,
        }
    }

    #[test]
    fn digest_changes_with_origin_prefix_methods_header_not_with_value() {
        let get = [Method::GET];
        let base = api("https://api.example.com", "/v1/", &get, "authorization");
        let digest = base.destination_digest();
        assert_eq!(digest.len(), 64);

        // Where the secret goes, and how, is covered.
        for other in [
            api("https://api2.example.com", "/v1/", &get, "authorization"),
            api(
                "https://api.example.com:8443",
                "/v1/",
                &get,
                "authorization",
            ),
            api("https://api.example.com", "/v2/", &get, "authorization"),
            api("https://api.example.com", "/", &get, "authorization"),
            api(
                "https://api.example.com",
                "/v1/",
                &[Method::POST],
                "authorization",
            ),
            api(
                "https://api.example.com",
                "/v1/",
                &[Method::GET, Method::POST],
                "authorization",
            ),
            api("https://api.example.com", "/v1/", &get, "x-api-key"),
        ] {
            assert_ne!(digest, other.destination_digest(), "{other:?}");
        }
        let mut formatted = base.clone();
        formatted.format = ValueFormat::parse("token {{secret}}").unwrap();
        assert_ne!(digest, formatted.destination_digest());
        let mut pinned = base.clone();
        pinned.ca_pem = Some("-----BEGIN CERTIFICATE-----".to_owned());
        assert_ne!(digest, pinned.destination_digest());

        // Method order and the window are not; the value is not even part of
        // the policy, so rotating the credential keeps the digest.
        let both = api(
            "https://api.example.com",
            "/v1/",
            &[Method::GET, Method::POST],
            "authorization",
        );
        let reversed = api(
            "https://api.example.com",
            "/v1/",
            &[Method::POST, Method::GET],
            "authorization",
        );
        assert_eq!(both.destination_digest(), reversed.destination_digest());
        let mut longer = base.clone();
        longer.max_window = Window::H4;
        assert_eq!(digest, longer.destination_digest());
        assert_eq!(
            digest,
            api("https://api.example.com", "/v1/", &get, "Authorization").destination_digest()
        );
    }

    #[test]
    fn grant_sorts_methods_and_carries_digest() {
        let post_get = api(
            "https://api.example.com",
            "/v1/",
            &[Method::POST, Method::GET],
            "authorization",
        );
        let grant = post_get.grant();
        assert_eq!(grant.methods, ["GET", "POST"]);
        assert_eq!(grant.digest, post_get.destination_digest());

        // Equal grants exactly when the destination is the same: a change
        // the other grant fields do not show (format, CA) still differs.
        let mut get_post = post_get.clone();
        get_post.methods.reverse();
        assert_eq!(get_post.grant(), grant);
        let mut formatted = post_get.clone();
        formatted.format = ValueFormat::parse("token {{secret}}").unwrap();
        assert_ne!(formatted.grant(), grant);
        let mut pinned = post_get;
        pinned.ca_pem = Some("-----BEGIN CERTIFICATE-----".to_owned());
        assert_ne!(pinned.grant(), grant);
    }

    #[test]
    fn value_format_parse_and_render() {
        let f = ValueFormat::parse("Basic {{secret}}").unwrap();
        assert_eq!(f.render("abc").as_str(), "Basic abc");
        assert_eq!(ValueFormat::default().render("abc").as_str(), "Bearer abc");
        assert!(ValueFormat::parse("no placeholder").is_err());
        assert!(ValueFormat::parse("{{secret}}{{secret}}").is_err());
        assert!(ValueFormat::parse("x\r\n{{secret}}").is_err());
        assert!(ValueFormat::parse("{{secret}}\0").is_err());
    }

    #[test]
    fn secret_value_debug_is_redacted() {
        let v = SecretValue::new(Zeroizing::new("hunter2-hunter2".to_owned()));
        assert_eq!(format!("{v:?}"), "SecretValue(<redacted>)");
        assert_eq!(v.expose(), "hunter2-hunter2");
    }
}
