//! Agent API keys: creation, verification, listing and revocation.
//!
//! Keys are `wdn_` + base64url(32 random bytes). Only the lowercase hex
//! SHA-256 of a key is stored.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use sqlx::{Row as _, SqliteExecutor, SqlitePool};
use warden_broker_proto::AgentName;
use zeroize::Zeroizing;

use crate::audit::{AuditError, AuditEvent, AuditLog};

/// Prefix of every agent key.
const KEY_PREFIX: &str = "wdn_";

/// Random bytes in a key.
const KEY_BYTES: usize = 32;

/// Length of base64url without padding of [`KEY_BYTES`] bytes.
const KEY_ENCODED_LEN: usize = 43;

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
    let result = sqlx::query("INSERT INTO agents (name, key_hash, created_at) VALUES (?, ?, ?)")
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

/// Resolve a presented key to its agent.
///
/// # Errors
///
/// [`AgentError::Unknown`] if no agent has this key, [`AgentError::Revoked`]
/// if its agent is revoked.
pub async fn authenticate(pool: &SqlitePool, presented: &str) -> Result<AgentName, AgentError> {
    let row = sqlx::query("SELECT name, revoked_at FROM agents WHERE key_hash = ?")
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
    let rows =
        sqlx::query("SELECT name, created_at, revoked_at FROM agents ORDER BY created_at, name")
            .fetch_all(pool)
            .await?;
    rows.iter()
        .map(|row| {
            let name: String = row.try_get("name")?;
            Ok(AgentInfo {
                name: AgentName::try_from(name)
                    .map_err(|e| AgentError::Db(sqlx::Error::Decode(Box::new(e))))?,
                created_at: row.try_get("created_at")?,
                revoked_at: row.try_get("revoked_at")?,
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
