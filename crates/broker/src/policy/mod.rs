//! Access policy: which SSH targets and API secrets exist, and the SSH CA
//! key, sourced from a secret backend (1Password Connect in production).

use std::fmt;

use async_trait::async_trait;
use http::{HeaderName, Method};
use sha2::{Digest as _, Sha256};
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey};
use url::Origin;
use warden_broker_proto::{
    ApiGrant, READ_ONLY_METHODS, SecretName, TargetName, UnixUser, Window, under_prefix,
};
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

/// Most methods one request may name.
const MAX_REQUESTED_METHODS: usize = 8;

/// One uppercase method token (`GET`, `PATCH`, ...).
pub(crate) fn parse_method(token: &str) -> Option<Method> {
    // Uppercase ASCII letters are always a valid method token.
    Some(token)
        .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_uppercase()))
        .and_then(|t| Method::from_bytes(t.as_bytes()).ok())
}

/// Percent-encodings refused in a path, lowercase: `.`, `/`, `\` and `;`
/// (which servers may decode into dot segments, separators or parameters),
/// `%` (which a server decoding twice would turn into any of them), the
/// overlong UTF-8 lead bytes `%c0`/`%c1` (decoded by lax servers as `.` or
/// `/`) and IIS-style `%u` escapes.
const ENCODED_SEPARATORS: [&str; 8] = ["%2e", "%2f", "%5c", "%3b", "%25", "%c0", "%c1", "%u"];

/// The one validator for paths the broker compares: an item's or a request's
/// path prefix, and the path of a call. An absolute path without query,
/// fragment, empty or dot segments, `;` parameters, encoded separators or
/// characters that need quoting.
pub(crate) fn check_path_prefix(prefix: &str) -> Result<(), &'static str> {
    if !prefix.starts_with('/') {
        return Err("must start with /");
    }
    if !prefix
        .chars()
        .all(|c| c.is_ascii_graphic() && !matches!(c, '?' | '#' | '\\'))
    {
        return Err("must be printable ASCII without spaces, ?, # or \\");
    }
    if prefix.contains(';') {
        return Err("must not contain ;");
    }
    let lower = prefix.to_ascii_lowercase();
    if ENCODED_SEPARATORS.iter().any(|enc| lower.contains(enc)) {
        return Err("must not contain encoded separators");
    }
    // The leading "/" yields one empty first segment; a trailing "/" one
    // empty last segment. Any other empty segment is a "//".
    let segments: Vec<&str> = prefix.split('/').skip(1).collect();
    let (last, inner) = segments.split_last().unwrap_or((&"", &[]));
    if inner.iter().any(|s| s.is_empty()) {
        return Err("must not contain //");
    }
    if inner.iter().chain([last]).any(|s| matches!(*s, "." | "..")) {
        return Err("must not contain . or .. segments");
    }
    Ok(())
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

    /// The scope an API request asks for, resolved against this policy.
    ///
    /// Without `methods` it is the policy's read-only methods; with them,
    /// exactly those, each of which the policy must allow. Without
    /// `path_prefix` it is the policy's prefix; with one, it must be under
    /// the policy's. `CONNECT` and `TRACE` are never in a scope.
    ///
    /// # Errors
    /// A message for the agent when the request names nothing valid inside
    /// the policy. It never holds the secret value.
    pub fn scope(
        &self,
        methods: Option<&[String]>,
        path_prefix: Option<&str>,
    ) -> Result<ApiScope, String> {
        let name = &self.name;
        let mut chosen: Vec<Method> = match methods {
            None => self
                .methods
                .iter()
                .filter(|m| READ_ONLY_METHODS.contains(&m.as_str()))
                .cloned()
                .collect(),
            Some(list) => self.requested_methods(list)?,
        };
        chosen.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
        chosen.dedup();
        if chosen.is_empty() {
            return Err(format!(
                "secret {name} allows no read-only method; ask for methods explicitly"
            ));
        }
        let path_prefix = match path_prefix {
            None => self.path_prefix.clone(),
            Some(wanted) => {
                check_path_prefix(wanted)
                    .map_err(|reason| format!("secret {name}: path prefix {reason}"))?;
                if !under_prefix(wanted, &self.path_prefix) {
                    return Err(format!(
                        "secret {name}: path prefix must be under {}",
                        self.path_prefix
                    ));
                }
                wanted.to_owned()
            }
        };
        Ok(ApiScope {
            methods: chosen,
            path_prefix,
        })
    }

    /// Parse and check an explicit method list against this policy.
    fn requested_methods(&self, list: &[String]) -> Result<Vec<Method>, String> {
        let name = &self.name;
        if list.is_empty() || list.len() > MAX_REQUESTED_METHODS {
            return Err(format!(
                "secret {name}: methods must list 1 to {MAX_REQUESTED_METHODS} methods"
            ));
        }
        let mut parsed: Vec<Method> = Vec::with_capacity(list.len());
        for token in list {
            let method = parse_method(token).ok_or_else(|| {
                format!("secret {name}: methods must be uppercase method names, such as GET")
            })?;
            if parsed.contains(&method) {
                return Err(format!("secret {name}: methods must not repeat {method}"));
            }
            parsed.push(method);
        }
        for method in &parsed {
            if method == Method::CONNECT
                || method == Method::TRACE
                || !self.methods.contains(method)
            {
                return Err(format!("secret {name} does not allow {method}"));
            }
        }
        Ok(parsed)
    }

    /// This policy narrowed to `scope`: same destination, fewer methods and a
    /// deeper path prefix. Checking a call against it enforces the scope with
    /// every rule the policy already has.
    #[must_use]
    pub fn narrowed(&self, scope: &ApiScope) -> Self {
        Self {
            methods: scope.methods.clone(),
            path_prefix: scope.path_prefix.clone(),
            ..self.clone()
        }
    }

    /// The grant details an approval at `scope` hands to the agent: the
    /// scope's methods in sorted order (the order
    /// [`Self::destination_digest`] uses) and prefix, plus this policy's own
    /// destination digest (not the narrowed one), so a later edit of the item
    /// is still detected.
    #[must_use]
    pub fn grant_for(&self, scope: &ApiScope) -> ApiGrant {
        let mut methods: Vec<String> = scope
            .methods
            .iter()
            .map(|m| m.as_str().to_owned())
            .collect();
        methods.sort_unstable();
        methods.dedup();
        ApiGrant {
            secret: self.name.clone(),
            origin: self.origin.ascii_serialization(),
            methods,
            path_prefix: scope.path_prefix.clone(),
            header: self.header.as_str().to_owned(),
            digest: self.destination_digest(),
        }
    }

    /// The grant details of the whole policy, with no narrowing.
    #[must_use]
    pub fn grant(&self) -> ApiGrant {
        self.grant_for(&ApiScope {
            methods: self.methods.clone(),
            path_prefix: self.path_prefix.clone(),
        })
    }
}

/// What an API request asks for, resolved inside its policy: see
/// [`ApiSecretPolicy::scope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiScope {
    /// Methods the grant allows, sorted, without duplicates.
    pub methods: Vec<Method>,
    /// Path prefix the grant is limited to, starting with `/`.
    pub path_prefix: String,
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

    use super::{ApiScope, ApiSecretPolicy, SecretValue, SshMode, SshTarget, ValueFormat};

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

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn item(prefix: &str, methods: &[Method]) -> ApiSecretPolicy {
        api("https://api.example.com", prefix, methods, "authorization")
    }

    fn names(scope: &ApiScope) -> Vec<&str> {
        scope.methods.iter().map(Method::as_str).collect()
    }

    #[test]
    fn default_scope_is_read_only_subset() {
        let both = item(
            "/v1/",
            &[Method::POST, Method::HEAD, Method::GET, Method::DELETE],
        );
        let scope = both.scope(None, None).unwrap();
        assert_eq!(names(&scope), ["GET", "HEAD"]);
        assert_eq!(scope.path_prefix, "/v1/");

        let get = item("/", &[Method::GET, Method::POST]);
        assert_eq!(names(&get.scope(None, None).unwrap()), ["GET"]);
    }

    #[test]
    fn no_read_only_method_rejected() {
        let writes = item("/", &[Method::POST, Method::PUT]);
        assert_eq!(
            writes.scope(None, None).unwrap_err(),
            "secret github allows no read-only method; ask for methods explicitly"
        );
        // Asking explicitly works.
        let scope = writes.scope(Some(&strings(&["PUT"])), None).unwrap();
        assert_eq!(names(&scope), ["PUT"]);
    }

    #[test]
    fn explicit_methods_must_be_in_item() {
        let p = item("/", &[Method::GET, Method::POST]);
        let scope = p.scope(Some(&strings(&["POST", "GET"])), None).unwrap();
        assert_eq!(names(&scope), ["GET", "POST"]);
        assert_eq!(
            p.scope(Some(&strings(&["GET", "DELETE"])), None)
                .unwrap_err(),
            "secret github does not allow DELETE"
        );
        for bad in [
            strings(&[]),
            strings(&["GET", "GET"]),
            strings(&["get"]),
            strings(&["GET,POST"]),
            strings(&[""]),
            strings(&[" GET"]),
            strings(&["GET "]),
        ] {
            let err = p.scope(Some(&bad), None).unwrap_err();
            assert!(err.starts_with("secret github: methods "), "{bad:?}: {err}");
        }
    }

    #[test]
    fn method_count_limit_is_eight() {
        let nine = [
            "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "LINK", "UNLINK",
        ];
        let methods: Vec<Method> = nine
            .iter()
            .map(|m| Method::from_bytes(m.as_bytes()).unwrap())
            .collect();
        let p = item("/", &methods);
        let eight = strings(&nine[..8]);
        assert_eq!(p.scope(Some(&eight), None).unwrap().methods.len(), 8);
        assert_eq!(
            p.scope(Some(&strings(&nine)), None).unwrap_err(),
            "secret github: methods must list 1 to 8 methods"
        );
    }

    #[test]
    fn connect_trace_never_requestable() {
        let p = item("/", &[Method::GET, Method::CONNECT, Method::TRACE]);
        for denied in ["CONNECT", "TRACE"] {
            assert_eq!(
                p.scope(Some(&strings(&["GET", denied])), None).unwrap_err(),
                format!("secret github does not allow {denied}")
            );
        }
        // The default scope never picks them either.
        assert_eq!(names(&p.scope(None, None).unwrap()), ["GET"]);
    }

    #[test]
    fn requested_prefix_must_be_under_item_prefix() {
        let under = |item_prefix: &str, wanted: &str| {
            item(item_prefix, &[Method::GET]).scope(None, Some(wanted))
        };
        assert_eq!(under("/api", "/api/x").unwrap().path_prefix, "/api/x");
        assert_eq!(under("/api", "/api").unwrap().path_prefix, "/api");
        assert_eq!(under("/", "/anything/").unwrap().path_prefix, "/anything/");
        assert_eq!(
            item("/api/", &[Method::GET])
                .scope(None, None)
                .unwrap()
                .path_prefix,
            "/api/"
        );
        assert_eq!(
            under("/api", "/apiary").unwrap_err(),
            "secret github: path prefix must be under /api"
        );
        assert_eq!(
            under("/api/", "/api").unwrap_err(),
            "secret github: path prefix must be under /api/"
        );
        for bad in [
            "/api/../x",
            "/api/./x",
            "/api//x",
            "/api/%2e%2e/x",
            "/api/%2E/x",
            "/api/%2f",
            "/api/%5c",
            "/api/%5C",
            "/api/x;y",
            "/api/x?y",
            "api/x",
            "",
        ] {
            let err = under("/api/", bad).unwrap_err();
            assert!(
                err.starts_with("secret github: path prefix "),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn narrowed_and_grant_for_use_scope_and_item_digest() {
        let p = item("/v1/", &[Method::GET, Method::POST, Method::HEAD]);
        let scope = p.scope(None, Some("/v1/repos")).unwrap();
        let narrowed = p.narrowed(&scope);
        assert_eq!(narrowed.methods, scope.methods);
        assert_eq!(narrowed.path_prefix, "/v1/repos");
        assert_eq!(narrowed.origin, p.origin);
        assert_eq!(narrowed.header, p.header);
        assert_eq!(narrowed.name, p.name);

        let grant = p.grant_for(&scope);
        assert_eq!(grant.methods, ["GET", "HEAD"]);
        assert_eq!(grant.path_prefix, "/v1/repos");
        // The digest is the item's, not the narrowed policy's.
        assert_eq!(grant.digest, p.destination_digest());
        assert_ne!(grant.digest, narrowed.destination_digest());
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
