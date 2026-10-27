//! Agents: creation, bearer-key verification, SSH public keys, listing and
//! revocation.
//!
//! An agent authenticates either with a bearer key (`wdn_` +
//! base64url(32 random bytes), of which only the lowercase hex SHA-256 is
//! stored) or by signing its requests with an SSH key whose public half the
//! owner registered ([`AgentPublicKey`]). Verifying signatures is the job of
//! the request-signing layer; this module only stores and validates the keys.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use sqlx::{Row as _, SqliteExecutor, SqlitePool};
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PublicKey};
use warden_broker_proto::AgentName;
use zeroize::Zeroizing;

use crate::audit::{AuditError, AuditEvent, AuditLog};

/// Prefix of every agent key.
const KEY_PREFIX: &str = "wdn_";

/// Random bytes in a key.
const KEY_BYTES: usize = 32;

/// Length of base64url without padding of [`KEY_BYTES`] bytes.
const KEY_ENCODED_LEN: usize = 43;

/// The published Ed25519 test key of the protocol document
/// (`crates/proto/tests/fixtures/signing-v1.json`), without its comment. Its
/// private half is in the repository, so enrolling it would let anyone sign
/// as the agent.
const PUBLISHED_ED25519_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFtEYSaZPFM5lYU6qb0mU18GImVC77EbHBHD9eXvkSjX";

/// The published P-256 test key of the protocol document, without its
/// comment. Its private half was discarded, but it is still a documented
/// example and not a key anyone should rely on.
const PUBLISHED_P256_KEY: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC+QqOP9eVCRD+mZKR9M9swQ1UATTw3+lcxT1Yj8H0huXEBHMc58PIqZfCWeiPzLR8jnMD8GKW77zKgpJ5a91W0=";

/// Why a public key line was refused at enrollment. Messages never echo the
/// line.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PublicKeyError {
    /// Not a single OpenSSH public key line.
    #[error("not an OpenSSH public key: expected one line such as 'ssh-ed25519 AAAA… comment'")]
    Malformed,
    /// A security key (`sk-*`).
    #[error(
        "security keys (sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com) are \
         refused: they need a touch for every signature, and every API call is signed"
    )]
    SecurityKey,
    /// An OpenSSH certificate.
    #[error(
        "certificates are refused: enroll the plain public key (ssh-ed25519 or ecdsa-sha2-nistp256)"
    )]
    Certificate,
    /// Any other key type, including RSA and other ECDSA curves.
    #[error("unsupported key type: only ssh-ed25519 and ecdsa-sha2-nistp256 keys are accepted")]
    Unsupported,
    /// The key is the published test key of the protocol document.
    #[error("this is the published test key from the protocol document; generate your own")]
    PublishedTestKey,
}

/// A validated agent signing key: an Ed25519 or ECDSA P-256 public key in
/// normalised OpenSSH form (comment dropped) with its `SHA256:…` fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPublicKey {
    openssh: String,
    fingerprint: String,
}

impl AgentPublicKey {
    /// Validate an OpenSSH public key line.
    ///
    /// # Errors
    ///
    /// [`PublicKeyError`] saying why the line is refused: malformed, a
    /// security key, a certificate, another key type (RSA, other curves), or
    /// a published test key.
    pub fn parse(line: &str) -> Result<Self, PublicKeyError> {
        let line = line.trim();
        if line.is_empty() || line.chars().any(char::is_control) {
            return Err(PublicKeyError::Malformed);
        }
        let algorithm = line.split_ascii_whitespace().next().unwrap_or_default();
        if algorithm.starts_with("sk-") {
            return Err(PublicKeyError::SecurityKey);
        }
        if algorithm.ends_with("-cert-v01@openssh.com") {
            return Err(PublicKeyError::Certificate);
        }
        let parsed = PublicKey::from_openssh(line).map_err(|_| PublicKeyError::Malformed)?;
        match parsed.algorithm() {
            Algorithm::Ed25519
            | Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            } => {}
            _ => return Err(PublicKeyError::Unsupported),
        }
        // `PublicKey::new` with an empty comment drops the comment.
        let normalised = PublicKey::new(parsed.key_data().clone(), "");
        let openssh = normalised
            .to_openssh()
            .map_err(|_| PublicKeyError::Malformed)?;
        if openssh == PUBLISHED_ED25519_KEY || openssh == PUBLISHED_P256_KEY {
            return Err(PublicKeyError::PublishedTestKey);
        }
        Ok(Self {
            fingerprint: normalised.fingerprint(HashAlg::Sha256).to_string(),
            openssh,
        })
    }

    /// The key as an OpenSSH line without a comment.
    #[must_use]
    pub fn openssh(&self) -> &str {
        &self.openssh
    }

    /// The key's fingerprint, `SHA256:…` (as `ssh-keygen -lf` prints it).
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// How an agent proves its identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    /// A `wdn_` bearer key.
    Bearer,
    /// Requests signed with a registered SSH key.
    SshKey,
}

impl AuthKind {
    /// The name stored in the database and shown by `agent list`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::SshKey => "ssh-key",
        }
    }

    fn from_stored(value: &str) -> Result<Self, AgentError> {
        match value {
            "bearer" => Ok(Self::Bearer),
            "ssh-key" => Ok(Self::SshKey),
            other => Err(AgentError::Db(sqlx::Error::Decode(
                format!("unknown auth kind {other:?}").into(),
            ))),
        }
    }
}

/// Failure of an agent key operation.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// An agent with this name exists already (revoked agents keep their name).
    #[error("agent already exists")]
    AlreadyExists,
    /// No agent matches.
    #[error("unknown agent")]
    Unknown,
    /// The agent's key has been revoked.
    #[error("agent key revoked")]
    Revoked,
    /// The public key is refused.
    #[error("{0}")]
    PublicKey(#[from] PublicKeyError),
    /// Another agent has registered this public key.
    #[error("this public key is already registered to another agent")]
    KeyInUse,
    /// Recording the key change failed, so the change was not made.
    #[error("the key change could not be audited, so it was not made: {0}")]
    Audit(#[from] AuditError),
    /// The database failed.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// The operating system could not provide randomness for a key.
    #[error("OS random number generator unavailable: {0}")]
    Random(#[source] getrandom::Error),
    /// Encoding a fresh key failed.
    #[error("agent key encoding failed: {0}")]
    Encoding(#[source] base64::EncodeSliceError),
    /// The agent was created but recording that failed, so it was revoked.
    #[error("agent creation could not be audited, so the agent was revoked: {0}")]
    Unaudited(#[source] AuditError),
    /// Recording the creation failed and revoking the agent failed as well.
    #[error(
        "agent creation could not be audited ({audit}) and revoking it failed ({revoke}); \
         revoke it manually"
    )]
    UnauditedNotRevoked {
        /// Why the audit append failed.
        audit: AuditError,
        /// Why the revocation failed.
        revoke: Box<AgentError>,
    },
}

/// A freshly generated agent key. Never printed by `Debug`.
pub struct AgentKey(SecretString);

impl AgentKey {
    /// A fresh key. Every intermediate buffer holding key material is
    /// zeroized, and the key text is built in a `String` of exactly its final
    /// length, so turning it into a [`SecretString`] does not reallocate and
    /// leave a copy behind.
    fn generate() -> Result<Self, AgentError> {
        let mut bytes = Zeroizing::new([0_u8; KEY_BYTES]);
        getrandom::fill(bytes.as_mut_slice()).map_err(AgentError::Random)?;
        let mut encoded = Zeroizing::new([0_u8; KEY_ENCODED_LEN]);
        let written = URL_SAFE_NO_PAD
            .encode_slice(bytes.as_slice(), encoded.as_mut_slice())
            .map_err(AgentError::Encoding)?;
        let mut key = String::with_capacity(KEY_PREFIX.len() + KEY_ENCODED_LEN);
        key.push_str(KEY_PREFIX);
        // base64url output is ASCII; each byte is pushed as its own char so no
        // temporary `str` copy is made.
        key.extend(encoded[..written].iter().copied().map(char::from));
        Ok(Self(SecretString::from(key)))
    }

    /// The key text; handle with care.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AgentKey(<redacted>)")
    }
}

/// Listing entry for an agent. Contains no key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInfo {
    /// Agent name.
    pub name: AgentName,
    /// Creation time, unix seconds.
    pub created_at: i64,
    /// Revocation time, unix seconds, if revoked.
    pub revoked_at: Option<i64>,
    /// How the agent authenticates.
    pub auth: AuthKind,
    /// The registered public key's fingerprint, for key-signed agents.
    pub fingerprint: Option<String>,
}

fn key_hash(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Create an agent and return its key. The key cannot be recovered later.
///
/// # Errors
///
/// [`AgentError::AlreadyExists`] if the name is taken, even by a revoked
/// agent; [`AgentError::Db`] on database failure; [`AgentError::Random`] if
/// no randomness is available.
pub async fn add(pool: &SqlitePool, name: &AgentName) -> Result<AgentKey, AgentError> {
    let key = AgentKey::generate()?;
    let result = sqlx::query(
        "INSERT INTO agents (name, auth_kind, key_hash, created_at) VALUES (?, 'bearer', ?, ?)",
    )
    .bind(name.as_str())
    .bind(key_hash(key.expose()))
    .bind(unix_now())
    .execute(pool)
    .await;
    match result {
        Ok(_) => Ok(key),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Err(AgentError::AlreadyExists),
        Err(e) => Err(e.into()),
    }
}

/// Create an agent, record [`AuditEvent::AgentAdded`], and return its key.
/// If the audit entry cannot be written, the agent is revoked at once so no
/// unaudited credential stays usable.
///
/// # Errors
/// Those of [`add`]; [`AgentError::Unaudited`] if the audit append failed
/// (the agent is revoked); [`AgentError::UnauditedNotRevoked`] if revoking it
/// failed too.
pub async fn add_audited(
    pool: &SqlitePool,
    audit: &AuditLog,
    name: &AgentName,
) -> Result<AgentKey, AgentError> {
    let key = add(pool, name).await?;
    let added = AuditEvent::AgentAdded {
        agent: name.clone(),
    };
    if let Err(audit_error) = audit.append(added).await {
        return Err(match revoke(pool, name, unix_now()).await {
            Ok(()) => AgentError::Unaudited(audit_error),
            Err(revoke_error) => AgentError::UnauditedNotRevoked {
                audit: audit_error,
                revoke: Box::new(revoke_error),
            },
        });
    }
    Ok(key)
}

fn key_conflict(error: sqlx::Error) -> AgentError {
    match error {
        sqlx::Error::Database(e) if e.is_unique_violation() => {
            if e.message().contains("key_fingerprint") {
                AgentError::KeyInUse
            } else {
                AgentError::AlreadyExists
            }
        }
        other => other.into(),
    }
}

/// Create a key-signed agent registered with `key`, recording
/// [`AuditEvent::AgentAdded`] and [`AuditEvent::AgentKeySet`]. The agent
/// exists only if both entries were written.
///
/// # Errors
///
/// [`AgentError::AlreadyExists`] if the name is taken, even by a revoked
/// agent; [`AgentError::KeyInUse`] if another agent has this key;
/// [`AgentError::Audit`] if the audit log could not be written (nothing is
/// created); [`AgentError::Db`] on database failure.
pub async fn add_key_audited(
    pool: &SqlitePool,
    audit: &AuditLog,
    name: &AgentName,
    key: &AgentPublicKey,
) -> Result<(), AgentError> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO agents (name, auth_kind, public_key, key_fingerprint, created_at) \
         VALUES (?, 'ssh-key', ?, ?, ?)",
    )
    .bind(name.as_str())
    .bind(key.openssh())
    .bind(key.fingerprint())
    .bind(unix_now())
    .execute(&mut *tx)
    .await
    .map_err(key_conflict)?;
    audit
        .append(AuditEvent::AgentAdded {
            agent: name.clone(),
        })
        .await?;
    audit
        .append(AuditEvent::AgentKeySet {
            agent: name.clone(),
            fingerprint: key.fingerprint().to_owned(),
        })
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Switch an existing agent to signing with `key`, recording
/// [`AuditEvent::AgentKeySet`]. Its bearer key (if it had one) is deleted,
/// so it stops working at once. The change is made only if the audit entry
/// was written.
///
/// # Errors
///
/// [`AgentError::Unknown`] if no such agent exists; [`AgentError::Revoked`]
/// if it is revoked; [`AgentError::KeyInUse`] if another agent has this key;
/// [`AgentError::Audit`] if the audit log could not be written (nothing is
/// changed); [`AgentError::Db`] on database failure.
pub async fn set_key_audited(
    pool: &SqlitePool,
    audit: &AuditLog,
    name: &AgentName,
    key: &AgentPublicKey,
) -> Result<(), AgentError> {
    let mut tx = pool.begin().await?;
    let revoked_at: Option<Option<i64>> =
        sqlx::query_scalar("SELECT revoked_at FROM agents WHERE name = ?")
            .bind(name.as_str())
            .fetch_optional(&mut *tx)
            .await?;
    match revoked_at {
        None => return Err(AgentError::Unknown),
        Some(Some(_)) => return Err(AgentError::Revoked),
        Some(None) => {}
    }
    sqlx::query(
        "UPDATE agents SET auth_kind = 'ssh-key', key_hash = NULL, public_key = ?, \
         key_fingerprint = ? WHERE name = ?",
    )
    .bind(key.openssh())
    .bind(key.fingerprint())
    .bind(name.as_str())
    .execute(&mut *tx)
    .await
    .map_err(key_conflict)?;
    audit
        .append(AuditEvent::AgentKeySet {
            agent: name.clone(),
            fingerprint: key.fingerprint().to_owned(),
        })
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Resolve a presented bearer key to its agent. Key-signed agents have no
/// bearer key and are never resolved here.
///
/// # Errors
///
/// [`AgentError::Unknown`] if no agent has this key, [`AgentError::Revoked`]
/// if its agent is revoked.
pub async fn authenticate(pool: &SqlitePool, presented: &str) -> Result<AgentName, AgentError> {
    let row = sqlx::query(
        "SELECT name, revoked_at FROM agents WHERE auth_kind = 'bearer' AND key_hash = ?",
    )
    .bind(key_hash(presented))
    .fetch_optional(pool)
    .await?
    .ok_or(AgentError::Unknown)?;
    let revoked_at: Option<i64> = row.try_get("revoked_at")?;
    if revoked_at.is_some() {
        return Err(AgentError::Revoked);
    }
    let name: String = row.try_get("name")?;
    AgentName::try_from(name).map_err(|e| AgentError::Db(sqlx::Error::Decode(Box::new(e))))
}

/// List all agents, oldest first.
///
/// # Errors
///
/// Fails on database error or a stored name that does not validate.
pub async fn list(pool: &SqlitePool) -> Result<Vec<AgentInfo>, AgentError> {
    let rows = sqlx::query(
        "SELECT name, created_at, revoked_at, auth_kind, key_fingerprint FROM agents \
         ORDER BY created_at, name",
    )
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|row| {
            let name: String = row.try_get("name")?;
            let auth: String = row.try_get("auth_kind")?;
            Ok(AgentInfo {
                name: AgentName::try_from(name)
                    .map_err(|e| AgentError::Db(sqlx::Error::Decode(Box::new(e))))?,
                created_at: row.try_get("created_at")?,
                revoked_at: row.try_get("revoked_at")?,
                auth: AuthKind::from_stored(&auth)?,
                fingerprint: row.try_get("key_fingerprint")?,
            })
        })
        .collect()
}

/// Mark an agent's key revoked at `now` (unix seconds). Revoking an already
/// revoked agent keeps the original revocation time. Runs on any executor so
/// the cascade to the agent's requests and grants
/// ([`crate::requests::revoke_agent`]) can share its transaction.
///
/// # Errors
///
/// [`AgentError::Unknown`] if no such agent exists.
pub async fn revoke<'e, E>(executor: E, name: &AgentName, now: i64) -> Result<(), AgentError>
where
    E: SqliteExecutor<'e>,
{
    let result =
        sqlx::query("UPDATE agents SET revoked_at = COALESCE(revoked_at, ?) WHERE name = ?")
            .bind(now)
            .bind(name.as_str())
            .execute(executor)
            .await?;
    if result.rows_affected() == 0 {
        return Err(AgentError::Unknown);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AgentKey, KEY_PREFIX, key_hash};

    #[test]
    fn generated_key_is_prefixed_base64url_of_32_bytes() {
        let key = AgentKey::generate().unwrap();
        let encoded = key.expose().strip_prefix(KEY_PREFIX).unwrap();
        assert_eq!(encoded.len(), 43);
        assert!(
            encoded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        let other = AgentKey::generate().unwrap();
        assert_ne!(key_hash(key.expose()), key_hash(other.expose()));
    }
}
