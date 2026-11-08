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

pub mod commit_signing;
pub mod doctor;
mod grant;
mod names;
mod session;
pub mod signing;
mod window;
mod wordlist;
mod words;

pub use self::grant::{
    ApiGrant, GrantAccess, GrantView, ProxyRequest, ProxyResponse, RelayGrant, SshGrant,
};
pub use self::names::{AgentName, Goal, SecretName, TargetName, UnixUser};
pub use self::session::{SessionLabel, SessionLink};
pub use self::window::Window;
pub use commit_signing::CommitSigningGrant;

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

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Refuses control characters and invisible format characters (general category
/// Cf) in text that an agent writes for the owner to read.
fn check_free_text(what: &'static str, text: &str) -> Result<(), ParseError> {
    if text.chars().any(char::is_control) {
        return Err(ParseError::new(what, "must not contain control characters"));
    }
    if text
        .chars()
        .any(|c| c.general_category() == GeneralCategory::Format)
    {
        return Err(ParseError::new(
            what,
            "must not contain invisible format characters",
        ));
    }
    Ok(())
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
    /// Commit signing by the broker's key, in the agent's name.
    #[serde(rename = "commit_signing")]
    CommitSigning {},
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
    /// The name the session making the request states for itself: the agent's
    /// claim, not an identity. Part of the fingerprint when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionLabel>,
    /// A link to where the request came from, as the agent states it. Part of the
    /// fingerprint when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<SessionLink>,
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

/// Short request digest, `xxxx-xxxx-xxxx`: the form on the wire, in the
/// database and in the audit log. People read it as [`Fingerprint::words`],
/// which is the same 48 bits.
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

/// One of the agent's own requests still waiting for the owner, as listed by
/// `GET /v1/requests`. It has no approval link: that goes to the owner, and the
/// broker keeps only its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRequest {
    /// Request identifier.
    pub id: Id,
    /// Fingerprint the approver sees.
    pub fingerprint: Fingerprint,
    /// The goal, as sent.
    pub goal: Goal,
    /// The access, as sent.
    pub access: Access,
    /// The window, as sent.
    pub window: Window,
    /// The session label, as sent. Part of the fingerprint when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionLabel>,
    /// The link about the work, as sent. Part of the fingerprint when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<SessionLink>,
    /// When the request was made, Unix seconds.
    pub created_at: i64,
    /// When it expires unless decided first, Unix seconds.
    pub expires_at: i64,
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
mod tests;
