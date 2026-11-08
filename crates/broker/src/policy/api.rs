//! API secret policy: where and how a secret may be sent, the scope a request
//! resolves to inside it, and the method, path and header validators they use.

use std::fmt;

use http::{HeaderName, Method};
use url::Origin;
use warden_broker_proto::{ApiGrant, READ_ONLY_METHODS, SecretName, Window, under_prefix};
use zeroize::Zeroizing;

use super::digest_parts;

/// Most methods one request may name.
const MAX_REQUESTED_METHODS: usize = 8;

/// Longest path prefix one request may ask for, in bytes.
const MAX_REQUESTED_PATH_PREFIX: usize = 512;

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
/// [`SecretBackend::api_secret_with_value`](super::SecretBackend::api_secret_with_value).
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
                if wanted.len() > MAX_REQUESTED_PATH_PREFIX {
                    return Err(format!(
                        "secret {name}: path prefix is too long (at most {MAX_REQUESTED_PATH_PREFIX} bytes)"
                    ));
                }
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
}

/// What an API request asks for, resolved inside its policy: see
/// [`ApiSecretPolicy::scope`]. Only that and `TryFrom<&ApiGrant>` build one,
/// so a scope that came from a request is always inside its item's policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiScope {
    /// Methods the grant allows, sorted, without duplicates.
    methods: Vec<Method>,
    /// Path prefix the grant is limited to, starting with `/`.
    path_prefix: String,
}

impl ApiScope {
    /// Methods the grant allows, sorted, without duplicates.
    #[must_use]
    pub fn methods(&self) -> &[Method] {
        &self.methods
    }

    /// Path prefix the grant is limited to, starting with `/`.
    #[must_use]
    pub fn path_prefix(&self) -> &str {
        &self.path_prefix
    }

    fn method_names(&self) -> Vec<String> {
        self.methods.iter().map(|m| m.as_str().to_owned()).collect()
    }

    /// Whether the scope is non-empty and holds only `GET` and `HEAD`. An
    /// empty scope is not read-only: the label fails closed.
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        warden_broker_proto::is_read_only(&self.method_names())
    }

    /// What the owner is warned the scope can do: the methods other than
    /// `GET` and `HEAD`, in the scope's order, or `unverified scope` for an
    /// empty scope. Empty exactly when the scope is read-only.
    #[must_use]
    pub fn modifying_methods(&self) -> Vec<String> {
        warden_broker_proto::modifying_methods(&self.method_names())
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    /// How the owner is told what an API request is for: `api <secret>
    /// (read-only)` or `api <secret> (CAN MODIFY: POST, PUT)`. The
    /// notification, the audit summary and the approval page share it.
    #[must_use]
    pub fn subject(&self, secret: impl fmt::Display) -> String {
        if self.is_read_only() {
            format!("api {secret} (read-only)")
        } else {
            format!(
                "api {secret} (CAN MODIFY: {})",
                self.modifying_methods().join(", ")
            )
        }
    }
}

impl TryFrom<&ApiGrant> for ApiScope {
    type Error = String;

    /// The scope a stored grant limits calls to.
    ///
    /// # Errors
    /// A message when a method in the grant is not a valid method name; the
    /// broker only stores valid ones, so this means the record is damaged.
    fn try_from(grant: &ApiGrant) -> Result<Self, Self::Error> {
        let mut methods = grant
            .methods
            .iter()
            .map(|m| parse_method(m).ok_or_else(|| format!("grant method {m:?} is not valid")))
            .collect::<Result<Vec<_>, _>>()?;
        methods.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
        methods.dedup();
        Ok(Self {
            methods,
            path_prefix: grant.path_prefix.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
