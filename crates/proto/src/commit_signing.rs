//! Wire types of commit signing: the broker holds the key and signs commits for
//! an agent that has an active commit signing grant. A signature means warden
//! signed the commit for that agent, not that anyone reviewed the change.

use serde::{Deserialize, Serialize};

/// The only SSHSIG namespace the broker signs in.
pub const NAMESPACE: &str = "git";

/// Largest commit the broker signs, in bytes, before base64.
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

/// What the broker says when the agent has no active commit signing grant: never
/// had one, or it ended or was revoked. The CLI recognises it to say how to ask.
pub const NO_ACTIVE_GRANT: &str = "no active commit signing grant for this agent";

/// What the broker says when a grant has used up its signatures for the day.
pub const DAILY_LIMIT: &str = "this grant has reached its limit of signatures for today; it \
                               starts again at 00:00 UTC, and warden tries once a day to notify \
                               the owner";

/// What the broker says when it holds no commit signing key.
pub const NOT_CONFIGURED: &str = "commit signing is not configured on this broker";

/// Commit signing grant details. The key itself is never part of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitSigningGrant {
    /// `SHA256:…` fingerprint of the key the owner approved.
    pub key_fingerprint: String,
    /// Lowercase hex digest of the approved key: signing is refused once the
    /// broker's key no longer matches it.
    pub digest: String,
}

/// Body of `POST /v1/commit-signing/sign`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignCommitRequest {
    /// SSHSIG namespace, as git asked for it.
    pub namespace: String,
    /// The exact bytes git wants signed, standard base64.
    pub payload_b64: String,
}

/// A signature the broker made and recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignCommitResponse {
    /// The armored SSH signature, as `ssh-keygen -Y sign` writes it.
    pub signature: String,
    /// The grant it was made under.
    pub grant_id: crate::Id,
    /// The id git gives the commit with this signature.
    pub commit: String,
}

/// Body of `GET /v1/commit-signing/key`: the public half of the broker's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitSigningKeyView {
    /// OpenSSH public key.
    pub public_key: String,
    /// `SHA256:…` fingerprint.
    pub fingerprint: String,
}
