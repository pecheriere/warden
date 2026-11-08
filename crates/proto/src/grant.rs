//! Approved grants as the agent sees them, and the brokered HTTPS call made
//! under an API grant.

use serde::{Deserialize, Serialize};

use crate::{CommitSigningGrant, Id, SecretName, TargetName, UnixUser};

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
    /// Commit signing by the broker's key.
    #[serde(rename = "commit_signing")]
    CommitSigning(CommitSigningGrant),
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
