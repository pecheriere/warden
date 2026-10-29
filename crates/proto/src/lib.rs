//! Shared wire types for the warden approval broker.
//!
//! Validated newtypes reject invalid input both through `TryFrom<String>` and
//! on deserialization.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_properties::{GeneralCategory, UnicodeGeneralCategory as _};

/// A value failed validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {what}: {reason}")]
pub struct ParseError {
    what: &'static str,
    reason: &'static str,
}

impl ParseError {
    const fn new(what: &'static str, reason: &'static str) -> Self {
        Self { what, reason }
    }
}

/// Implements the shared boilerplate of a validated string newtype.
macro_rules! string_newtype {
    ($name:ident) => {
        impl $name {
            /// The validated value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl FromStr for $name {
            type Err = ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::try_from(s.to_owned())
            }
        }
    };
}

pub mod signing;

/// 16 bytes of OS randomness as 32 lowercase hex characters.
///
/// # Panics
///
/// Panics if the operating system cannot provide randomness, which leaves no
/// safe way to continue.
fn random_hex16() -> String {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).expect("OS random number generator unavailable");
    hex::encode(bytes)
}

fn is_name(s: &str, first: impl Fn(u8) -> bool, rest: impl Fn(u8) -> bool) -> bool {
    let bytes = s.as_bytes();
    match bytes.split_first() {
        Some((&head, tail)) => bytes.len() <= 32 && first(head) && tail.iter().all(|&b| rest(b)),
        None => false,
    }
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Name of an agent: `^[a-z0-9][a-z0-9-]{0,31}$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AgentName(String);

impl TryFrom<String> for AgentName {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        if is_name(&value, alnum, |b| alnum(b) || b == b'-') {
            Ok(Self(value))
        } else {
            Err(ParseError::new(
                "agent name",
                "must match ^[a-z0-9][a-z0-9-]{0,31}$",
            ))
        }
    }
}
string_newtype!(AgentName);

/// Name of a target: `^[a-z0-9][a-z0-9-]{0,31}$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TargetName(String);

impl TryFrom<String> for TargetName {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        if is_name(&value, alnum, |b| alnum(b) || b == b'-') {
            Ok(Self(value))
        } else {
            Err(ParseError::new(
                "target name",
                "must match ^[a-z0-9][a-z0-9-]{0,31}$",
            ))
        }
    }
}
string_newtype!(TargetName);

/// Name of an API secret: `^[a-z0-9][a-z0-9-]{0,31}$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretName(String);

impl TryFrom<String> for SecretName {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
        if is_name(&value, alnum, |b| alnum(b) || b == b'-') {
            Ok(Self(value))
        } else {
            Err(ParseError::new(
                "secret name",
                "must match ^[a-z0-9][a-z0-9-]{0,31}$",
            ))
        }
    }
}
string_newtype!(SecretName);

/// Unix account name: `^[a-z_][a-z0-9_-]{0,31}$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UnixUser(String);

impl TryFrom<String> for UnixUser {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let head = |b: u8| b.is_ascii_lowercase() || b == b'_';
        let tail = |b: u8| head(b) || b.is_ascii_digit() || b == b'-';
        if is_name(&value, head, tail) {
            Ok(Self(value))
        } else {
            Err(ParseError::new(
                "unix user",
                "must match ^[a-z_][a-z0-9_-]{0,31}$",
            ))
        }
    }
}
string_newtype!(UnixUser);

/// Human-readable purpose of a request: 1 to 500 characters after trimming
/// Unicode whitespace, single line (no control characters), and free of
/// invisible format characters (general category Cf: bidi overrides and
/// isolates, zero-width characters, BOM, soft hyphen, tags, ...), which could
/// make the text the owner reads differ from what was sent. The stored value
/// is trimmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Goal(String);

impl TryFrom<String> for Goal {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let trimmed = value.trim();
        let chars = trimmed.chars().count();
        if chars == 0 || chars > 500 {
            return Err(ParseError::new("goal", "must be 1 to 500 characters"));
        }
        if trimmed.chars().any(char::is_control) {
            return Err(ParseError::new(
                "goal",
                "must not contain control characters",
            ));
        }
        if trimmed
            .chars()
            .any(|c| c.general_category() == GeneralCategory::Format)
        {
            return Err(ParseError::new(
                "goal",
                "must not contain invisible format characters",
            ));
        }
        Ok(Self(trimmed.to_owned()))
    }
}
string_newtype!(Goal);

/// Access window length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Window {
    /// 15 minutes.
    #[serde(rename = "15m")]
    M15,
    /// 30 minutes.
    #[serde(rename = "30m")]
    M30,
    /// 1 hour.
    #[serde(rename = "1h")]
    H1,
    /// 4 hours.
    #[serde(rename = "4h")]
    H4,
}

impl Window {
    /// Length of the window in seconds.
    #[must_use]
    pub const fn secs(self) -> u64 {
        match self {
            Self::M15 => 900,
            Self::M30 => 1800,
            Self::H1 => 3600,
            Self::H4 => 14400,
        }
    }
}

impl FromStr for Window {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "15m" => Ok(Self::M15),
            "30m" => Ok(Self::M30),
            "1h" => Ok(Self::H1),
            "4h" => Ok(Self::H4),
            _ => Err(ParseError::new("window", "must be one of 15m, 30m, 1h, 4h")),
        }
    }
}

/// What access is being requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Access {
    /// SSH certificate for a user on a target.
    Ssh {
        /// Target host to access.
        target: TargetName,
        /// Unix account to log in as.
        user: UnixUser,
        /// OpenSSH `ssh-ed25519` public key to certify. Not validated here to
        /// keep this crate dependency-light; the server must parse it as an
        /// OpenSSH `ssh-ed25519` public key before use.
        public_key: String,
    },
    /// Brokered HTTPS calls that use a stored API secret.
    Api {
        /// Name of the secret the broker injects on the agent's behalf.
        secret: SecretName,
        /// Methods the grant should allow: uppercase tokens, a subset of the
        /// item's. Absent means the read-only methods the item allows.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        methods: Option<Vec<String>>,
        /// Path prefix the grant should be limited to, under the item's.
        /// Absent means the item's prefix.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path_prefix: Option<String>,
    },
}

/// The methods that cannot modify anything on the server.
pub const READ_ONLY_METHODS: [&str; 2] = ["GET", "HEAD"];

/// Whether `methods` is non-empty and every method in it is one of
/// [`READ_ONLY_METHODS`]. An empty list is not read-only: fail closed.
#[must_use]
pub fn is_read_only(methods: &[String]) -> bool {
    !methods.is_empty()
        && methods
            .iter()
            .all(|m| READ_ONLY_METHODS.contains(&m.as_str()))
}

/// What a grant of `methods` is warned to be able to do: the methods other
/// than `GET` and `HEAD`, in order, or `unverified scope` for an empty list.
/// Empty exactly when `methods` is [`is_read_only`].
#[must_use]
pub fn modifying_methods(methods: &[String]) -> Vec<&str> {
    if methods.is_empty() {
        vec!["unverified scope"]
    } else {
        methods
            .iter()
            .map(String::as_str)
            .filter(|m| !READ_ONLY_METHODS.contains(m))
            .collect()
    }
}

/// `path` is `prefix` or below it, on a segment boundary: `/api` covers
/// `/api` and `/api/x` but not `/apiary`; `/api/` covers `/api/` and
/// `/api/x` but not `/api`.
#[must_use]
pub fn under_prefix(path: &str, prefix: &str) -> bool {
    match path.strip_prefix(prefix) {
        Some(rest) => prefix.ends_with('/') || rest.is_empty() || rest.starts_with('/'),
        None => false,
    }
}

/// Body of `POST` to create a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateRequest {
    /// Why access is needed.
    pub goal: Goal,
    /// What is being requested.
    pub access: Access,
    /// How long the access should last.
    pub window: Window,
}

/// Request or grant identifier: 32 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Id(String);

impl Id {
    /// A fresh identifier from 16 bytes of OS randomness.
    ///
    /// # Panics
    ///
    /// Panics if the operating system cannot provide randomness, which leaves
    /// no safe way to continue.
    #[must_use]
    pub fn random() -> Self {
        Self(random_hex16())
    }
}

impl TryFrom<String> for Id {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if is_lower_hex(&value, 32) {
            Ok(Self(value))
        } else {
            Err(ParseError::new("id", "must be 32 lowercase hex characters"))
        }
    }
}
string_newtype!(Id);

/// Short request digest shown to the approver: `xxxx-xxxx-xxxx`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Fingerprint(String);

impl TryFrom<String> for Fingerprint {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let ok = value.len() == 14
            && value.split('-').count() == 3
            && value.split('-').all(|group| is_lower_hex(group, 4));
        if ok {
            Ok(Self(value))
        } else {
            Err(ParseError::new(
                "fingerprint",
                "must look like xxxx-xxxx-xxxx",
            ))
        }
    }
}
string_newtype!(Fingerprint);

/// Fingerprint of a request as made by an agent: the first 6 bytes of the
/// SHA-256 of the JSON encoding of `(agent, req)`, hex, in groups of four.
///
/// # Panics
///
/// Never in practice: serializing these plain types to JSON cannot fail.
#[must_use]
pub fn fingerprint(agent: &AgentName, req: &CreateRequest) -> Fingerprint {
    let bytes = serde_json::to_vec(&(agent, req)).expect("wire types always serialize");
    let digest = Sha256::digest(bytes);
    let h = hex::encode(&digest[..6]);
    Fingerprint(format!("{}-{}-{}", &h[0..4], &h[4..8], &h[8..12]))
}

/// Response to creating a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedResponse {
    /// Request identifier.
    pub id: Id,
    /// Fingerprint the approver sees.
    pub fingerprint: Fingerprint,
}

/// Lifecycle state of a request as seen by the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum RequestStatus {
    /// Waiting for the owner.
    Pending,
    /// Approved; the grant is attached.
    Approved(GrantView),
    /// Denied by the owner.
    Denied,
    /// Expired without a decision.
    Expired,
    /// Withdrawn by the agent that made it, before any decision.
    Cancelled,
    /// Revoked after approval.
    Revoked,
    /// Failed, for example no notifier could deliver.
    Error {
        /// What went wrong.
        message: String,
    },
}

/// An approved grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantView {
    /// Grant identifier.
    pub grant_id: Id,
    /// Start of validity, Unix seconds.
    pub not_before: i64,
    /// End of validity, Unix seconds.
    pub not_after: i64,
    /// What the grant allows.
    pub access: GrantAccess,
}

/// Kind-specific details of an approved grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum GrantAccess {
    /// SSH certificate grant.
    Ssh(SshGrant),
    /// Brokered HTTPS API grant.
    Api(ApiGrant),
    /// SSH session relayed by the broker.
    Relay(RelayGrant),
}

/// SSH relay grant details: the agent connects to the broker's relay, which
/// logs in to the target with a credential that never leaves the broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayGrant {
    /// Target the relay opens the session to; also the user name to log in
    /// to the relay with.
    pub target: TargetName,
    /// Unix account the relay logs in to the target as.
    pub user: UnixUser,
    /// Host name or address of the broker's relay listener.
    pub relay_host: String,
    /// Port of the broker's relay listener.
    pub relay_port: u16,
    /// The relay's host public key, OpenSSH format, for pinning.
    pub relay_host_key: String,
    /// Lowercase hex digest of the approved destination (target address,
    /// port and pinned host keys): a session is refused once the target no
    /// longer matches it.
    pub digest: String,
}

/// Brokered API grant details. The secret value is never part of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiGrant {
    /// Secret the broker injects.
    pub secret: SecretName,
    /// Only origin the broker will call, `https://host[:port]`.
    pub origin: String,
    /// Allowed HTTP methods, uppercase, sorted.
    pub methods: Vec<String>,
    /// Allowed path prefix, starting with `/`.
    pub path_prefix: String,
    /// Header the broker sets to carry the secret.
    pub header: String,
    /// Lowercase hex digest of the approved policy (origin, prefix, header,
    /// value format, pinned CA, methods): a call is refused once the policy
    /// no longer matches it.
    pub digest: String,
}

/// Body of `POST /v1/grants/{id}/http`: a call for the broker to make.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyRequest {
    /// HTTP method.
    pub method: String,
    /// Absolute `https` URL.
    pub url: String,
    /// Request headers as name/value pairs.
    pub headers: Vec<(String, String)>,
    /// Request body, standard base64.
    pub body_b64: Option<String>,
}

/// The upstream response, with the secret redacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyResponse {
    /// Upstream status code.
    pub status: u16,
    /// Response headers as name/value pairs.
    pub headers: Vec<(String, String)>,
    /// Response body, standard base64.
    pub body_b64: String,
    /// Number of secret occurrences replaced with `[REDACTED]`.
    pub redactions: u32,
}

/// SSH certificate grant details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshGrant {
    /// OpenSSH certificate.
    pub certificate: String,
    /// Host to connect to.
    pub host: String,
    /// Port to connect to.
    pub port: u16,
    /// Unix account the certificate is valid for.
    pub user: UnixUser,
    /// Host public keys, `known_hosts` format.
    pub host_keys: Vec<String>,
}

/// Body of `GET /v1/info`: the signing protocols the broker accepts and
/// the audience a signed request must name. Clients pin the audience when
/// they log in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfoResponse {
    /// Accepted protocol identifiers, for example
    /// [`signing::PROTOCOL`].
    pub protocols: Vec<String>,
    /// The broker's audience.
    pub audience: signing::Audience,
}

/// Error body returned by the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    /// Human-readable message.
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> CreateRequest {
        CreateRequest {
            goal: Goal::try_from("deploy the thing".to_owned()).unwrap(),
            access: Access::Ssh {
                target: TargetName::try_from("pi".to_owned()).unwrap(),
                user: UnixUser::try_from("alice".to_owned()).unwrap(),
                public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample".to_owned(),
            },
            window: Window::M30,
        }
    }

    #[test]
    fn agent_name_rejects_uppercase_and_long() {
        assert!(AgentName::try_from("bot-1".to_owned()).is_ok());
        assert!(AgentName::try_from("Bot".to_owned()).is_err());
        assert!(AgentName::try_from("-a".to_owned()).is_err());
        assert!(AgentName::try_from(String::new()).is_err());
        assert!(AgentName::try_from("a".repeat(32)).is_ok());
        assert!(AgentName::try_from("a".repeat(33)).is_err());
        assert!(serde_json::from_str::<AgentName>("\"BAD\"").is_err());
        assert!(TargetName::try_from("A".to_owned()).is_err());
    }

    #[test]
    fn unix_user_rules() {
        assert!(UnixUser::try_from("_svc-1".to_owned()).is_ok());
        assert!(UnixUser::try_from("1abc".to_owned()).is_err());
        assert!(UnixUser::try_from("Root".to_owned()).is_err());
        assert!(serde_json::from_str::<UnixUser>("\"a b\"").is_err());
    }

    #[test]
    fn goal_rejects_empty_and_501_chars() {
        assert!(Goal::try_from(String::new()).is_err());
        assert!(Goal::try_from("   ".to_owned()).is_err());
        assert!(Goal::try_from("x".repeat(500)).is_ok());
        assert!(Goal::try_from("x".repeat(501)).is_err());
        assert!(Goal::try_from("é".repeat(500)).is_ok());
        assert!(Goal::try_from("a\nb".to_owned()).is_err());
        assert!(Goal::try_from("a\u{0}b".to_owned()).is_err());
        assert_eq!(Goal::try_from("  hi  ".to_owned()).unwrap().as_str(), "hi");
        assert!(serde_json::from_str::<Goal>("\"\"").is_err());
    }

    #[test]
    fn goal_rejects_bidi_overrides() {
        for c in [
            '\u{202A}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2069}',
        ] {
            assert!(
                Goal::try_from(format!("deploy {c}tset{c} now")).is_err(),
                "U+{:04X} accepted",
                u32::from(c)
            );
        }
    }

    #[test]
    fn goal_rejects_zero_width_and_other_format_chars() {
        for c in [
            '\u{200B}',
            '\u{200C}',
            '\u{200D}',
            '\u{200E}',
            '\u{200F}',
            '\u{FEFF}',
            '\u{00AD}',
            '\u{2060}',
            '\u{E0001}',
        ] {
            assert!(
                Goal::try_from(format!("de{c}ploy")).is_err(),
                "U+{:04X} accepted",
                u32::from(c)
            );
        }
        // Ordinary non-ASCII text is still fine.
        assert!(Goal::try_from("redémarrer le job 🚀 日本".to_owned()).is_ok());
    }

    #[test]
    fn goal_edge_format_chars_are_rejected_not_trimmed() {
        // Trimming removes only Unicode White_Space; a zero-width or BOM
        // character at either edge is not whitespace, so the goal is rejected
        // rather than silently trimmed.
        assert!(Goal::try_from("\u{200B}deploy".to_owned()).is_err());
        assert!(Goal::try_from("deploy\u{FEFF}".to_owned()).is_err());
        assert!(Goal::try_from(" \u{202E} deploy ".to_owned()).is_err());
        // Real whitespace at the edges is still trimmed.
        assert_eq!(
            Goal::try_from("\u{3000}deploy\u{00A0}".to_owned())
                .unwrap()
                .as_str(),
            "deploy"
        );
    }

    #[test]
    fn window_roundtrip_and_secs() {
        let w: Window = serde_json::from_str("\"30m\"").unwrap();
        assert_eq!(w, Window::M30);
        assert_eq!(w.secs(), 1800);
        assert_eq!(serde_json::to_string(&w).unwrap(), "\"30m\"");
        assert_eq!("15m".parse::<Window>().unwrap().secs(), 900);
        assert_eq!("1h".parse::<Window>().unwrap().secs(), 3600);
        assert_eq!("4h".parse::<Window>().unwrap().secs(), 14400);
        assert!("2h".parse::<Window>().is_err());
        assert!(serde_json::from_str::<Window>("\"2h\"").is_err());
        assert!(Window::M15 < Window::M30 && Window::H1 < Window::H4);
    }

    #[test]
    fn id_validation_and_random() {
        let id = Id::random();
        assert_eq!(id.as_str().len(), 32);
        assert!(
            id.as_str()
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_ne!(id, Id::random());
        assert!(Id::try_from("A".repeat(32)).is_err());
        assert!(Id::try_from("a".repeat(31)).is_err());
        assert!(serde_json::from_str::<Id>("\"zz\"").is_err());
    }

    #[test]
    fn fingerprint_is_stable() {
        let agent = AgentName::try_from("bot".to_owned()).unwrap();
        let fp = fingerprint(&agent, &sample_request());
        assert_eq!(fp.as_str(), "b65b-9812-eb72");
        assert_eq!(fp, fingerprint(&agent, &sample_request()));
        let mut other = sample_request();
        other.window = Window::H1;
        assert_ne!(fp, fingerprint(&agent, &other));
        assert!(serde_json::from_str::<Fingerprint>("\"nope\"").is_err());
    }

    #[test]
    fn status_serde_shape() {
        assert_eq!(
            serde_json::to_string(&RequestStatus::Denied).unwrap(),
            r#"{"status":"denied"}"#
        );
        assert_eq!(
            serde_json::to_string(&RequestStatus::Pending).unwrap(),
            r#"{"status":"pending"}"#
        );
        assert_eq!(
            serde_json::to_string(&RequestStatus::Cancelled).unwrap(),
            r#"{"status":"cancelled"}"#
        );
        let e = RequestStatus::Error {
            message: "boom".to_owned(),
        };
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"status":"error","message":"boom"}"#
        );
        let approved = RequestStatus::Approved(GrantView {
            grant_id: Id::random(),
            not_before: 1,
            not_after: 2,
            access: GrantAccess::Ssh(SshGrant {
                certificate: "cert".to_owned(),
                host: "pi".to_owned(),
                port: 22,
                user: UnixUser::try_from("alice".to_owned()).unwrap(),
                host_keys: vec!["k".to_owned()],
            }),
        });
        let json = serde_json::to_string(&approved).unwrap();
        assert!(json.starts_with(r#"{"status":"approved","grant_id":"#));
        assert_eq!(
            serde_json::from_str::<RequestStatus>(&json).unwrap(),
            approved
        );
    }

    #[test]
    fn api_access_serde_shape() {
        let access = Access::Api {
            secret: SecretName::try_from("github".to_owned()).unwrap(),
            methods: None,
            path_prefix: None,
        };
        assert_eq!(
            serde_json::to_string(&access).unwrap(),
            r#"{"kind":"api","secret":"github"}"#
        );
        assert_eq!(
            serde_json::from_str::<Access>(r#"{"kind":"api","secret":"github"}"#).unwrap(),
            access
        );
        assert!(serde_json::from_str::<Access>(r#"{"kind":"api","secret":"Bad"}"#).is_err());
    }

    #[test]
    fn api_request_serde_roundtrip_with_scope() {
        let access = Access::Api {
            secret: SecretName::try_from("github".to_owned()).unwrap(),
            methods: Some(vec!["GET".to_owned(), "POST".to_owned()]),
            path_prefix: Some("/v1/repos".to_owned()),
        };
        let json = serde_json::to_string(&access).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"api","secret":"github","methods":["GET","POST"],"path_prefix":"/v1/repos"}"#
        );
        assert_eq!(serde_json::from_str::<Access>(&json).unwrap(), access);
    }

    #[test]
    fn scope_fields_absent_keep_fingerprint() {
        // The request a 0.3 CLI sends (hash of its JSON checked by hand): the
        // new fields are absent from the encoding, so the fingerprint is the
        // one 0.3 computed.
        let agent = AgentName::try_from("bot".to_owned()).unwrap();
        let req = CreateRequest {
            goal: Goal::try_from("read the repos".to_owned()).unwrap(),
            access: serde_json::from_str(r#"{"kind":"api","secret":"github"}"#).unwrap(),
            window: Window::M15,
        };
        assert_eq!(
            serde_json::to_string(&req.access).unwrap(),
            r#"{"kind":"api","secret":"github"}"#
        );
        assert_eq!(fingerprint(&agent, &req).as_str(), "ae38-25c4-2428");
    }

    #[test]
    fn read_only_methods() {
        let m = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(is_read_only(&m(&["GET"])));
        assert!(is_read_only(&m(&["HEAD", "GET"])));
        assert!(!is_read_only(&m(&["GET", "POST"])));
        assert!(!is_read_only(&m(&["OPTIONS"])));
        assert!(!is_read_only(&m(&[])));
    }

    #[test]
    fn modifying_methods_names_what_is_not_read_only() {
        let m = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(modifying_methods(&m(&["GET", "HEAD"])).is_empty());
        assert_eq!(
            modifying_methods(&m(&["GET", "POST", "PUT"])),
            ["POST", "PUT"]
        );
        assert_eq!(modifying_methods(&m(&["OPTIONS"])), ["OPTIONS"]);
        assert_eq!(modifying_methods(&m(&[])), ["unverified scope"]);
    }

    #[test]
    fn under_prefix_is_segment_aware() {
        assert!(under_prefix("/api", "/api"));
        assert!(under_prefix("/api/x", "/api"));
        assert!(!under_prefix("/apiary", "/api"));
        assert!(under_prefix("/api/", "/api/"));
        assert!(under_prefix("/api/x", "/api/"));
        assert!(!under_prefix("/api", "/api/"));
        assert!(under_prefix("/anything", "/"));
    }

    #[test]
    fn grant_access_serde_tagged() {
        let api = GrantAccess::Api(ApiGrant {
            secret: SecretName::try_from("github".to_owned()).unwrap(),
            origin: "https://api.example.com".to_owned(),
            methods: vec!["GET".to_owned()],
            path_prefix: "/v1/".to_owned(),
            header: "Authorization".to_owned(),
            digest: "ab".repeat(32),
        });
        let json = serde_json::to_string(&api).unwrap();
        assert!(json.starts_with(r#"{"kind":"api","secret":"github""#));
        assert_eq!(serde_json::from_str::<GrantAccess>(&json).unwrap(), api);

        let ssh = GrantAccess::Ssh(SshGrant {
            certificate: "cert".to_owned(),
            host: "pi".to_owned(),
            port: 22,
            user: UnixUser::try_from("alice".to_owned()).unwrap(),
            host_keys: vec!["k".to_owned()],
        });
        let json = serde_json::to_string(&ssh).unwrap();
        assert!(json.starts_with(r#"{"kind":"ssh","certificate":"cert""#));
        assert_eq!(serde_json::from_str::<GrantAccess>(&json).unwrap(), ssh);

        let view = GrantView {
            grant_id: Id::random(),
            not_before: 1,
            not_after: 2,
            access: api,
        };
        let json = serde_json::to_string(&view).unwrap();
        assert!(json.contains(r#""access":{"kind":"api""#));
        assert_eq!(serde_json::from_str::<GrantView>(&json).unwrap(), view);
    }

    #[test]
    fn relay_grant_serde_tagged() {
        let relay = GrantAccess::Relay(RelayGrant {
            target: TargetName::try_from("nas".to_owned()).unwrap(),
            user: UnixUser::try_from("backup".to_owned()).unwrap(),
            relay_host: "warden.example.ts.net".to_owned(),
            relay_port: 2222,
            relay_host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample".to_owned(),
            digest: "cd".repeat(32),
        });
        let json = serde_json::to_string(&relay).unwrap();
        assert_eq!(
            json,
            format!(
                r#"{{"kind":"relay","target":"nas","user":"backup","relay_host":"warden.example.ts.net","relay_port":2222,"relay_host_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample","digest":"{}"}}"#,
                "cd".repeat(32)
            )
        );
        assert_eq!(serde_json::from_str::<GrantAccess>(&json).unwrap(), relay);
        // Names are validated on the way in.
        let bad = json.replace(r#""target":"nas""#, r#""target":"Bad Name""#);
        assert!(serde_json::from_str::<GrantAccess>(&bad).is_err());

        let view = GrantView {
            grant_id: Id::random(),
            not_before: 1,
            not_after: 2,
            access: relay,
        };
        let json = serde_json::to_string(&view).unwrap();
        assert!(json.contains(r#""access":{"kind":"relay","target":"nas""#));
        assert_eq!(serde_json::from_str::<GrantView>(&json).unwrap(), view);
    }

    #[test]
    fn secret_name_rules() {
        assert!(SecretName::try_from("github".to_owned()).is_ok());
        assert!(SecretName::try_from("a".repeat(32)).is_ok());
        assert!(SecretName::try_from("a".repeat(33)).is_err());
        assert!(SecretName::try_from("Git".to_owned()).is_err());
        assert!(SecretName::try_from("-a".to_owned()).is_err());
        assert!(SecretName::try_from(String::new()).is_err());
        assert!(serde_json::from_str::<SecretName>("\"A B\"").is_err());
    }

    #[test]
    fn ssh_fingerprint_unchanged() {
        let agent = AgentName::try_from("bot".to_owned()).unwrap();
        assert_eq!(
            fingerprint(&agent, &sample_request()).as_str(),
            "b65b-9812-eb72"
        );
        let json = serde_json::to_string(&sample_request().access).unwrap();
        assert_eq!(
            json,
            r#"{"kind":"ssh","target":"pi","user":"alice","public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"}"#
        );
    }

    #[test]
    fn proxy_request_roundtrip() {
        let req = ProxyRequest {
            method: "POST".to_owned(),
            url: "https://api.example.com/v1/x".to_owned(),
            headers: vec![("accept".to_owned(), "application/json".to_owned())],
            body_b64: Some("aGk=".to_owned()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(serde_json::from_str::<ProxyRequest>(&json).unwrap(), req);
        let res = ProxyResponse {
            status: 200,
            headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
            body_b64: "aGk=".to_owned(),
            redactions: 2,
        };
        let json = serde_json::to_string(&res).unwrap();
        assert_eq!(serde_json::from_str::<ProxyResponse>(&json).unwrap(), res);
    }

    #[test]
    fn info_response_wire_shape() {
        let json =
            r#"{"protocols":["warden-request-v1"],"audience":"40ad20029e94984d193159667b296d8a"}"#;
        let info: InfoResponse = serde_json::from_str(json).unwrap();
        assert_eq!(info.protocols, [signing::PROTOCOL]);
        assert_eq!(serde_json::to_string(&info).unwrap(), json);
        assert!(
            serde_json::from_str::<InfoResponse>(r#"{"protocols":[],"audience":"nope"}"#).is_err()
        );
    }

    #[test]
    fn create_request_wire_shape() {
        let json = serde_json::to_string(&sample_request()).unwrap();
        assert!(json.contains(r#""access":{"kind":"ssh","target":"pi""#));
        assert_eq!(
            serde_json::from_str::<CreateRequest>(&json).unwrap(),
            sample_request()
        );
    }
}
