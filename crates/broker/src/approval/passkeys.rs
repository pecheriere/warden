//! Passkeys: enrollment with one-time codes, and approval ceremonies.
//!
//! webauthn-rs picks its own random challenge, so an approval is bound to
//! what the owner saw server-side: `begin` keeps the request (by token hash),
//! the chosen window and the request fingerprint next to the `WebAuthn` state,
//! keyed by a random ceremony id, for 120 s; `finish` verifies the assertion
//! against that state and hands back exactly what was stored. Ceremonies
//! live in memory only and are single use (removed on finish, success or
//! failure). User verification is required for registration and approval.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use sqlx::{Row as _, SqlitePool};
use url::Url;
use warden_broker_proto::{Fingerprint, Id, Window};
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Uuid, Webauthn,
    WebauthnBuilder, WebauthnError,
};

use crate::audit::{AuditError, AuditEvent, AuditLog};
use crate::requests::{Clock, audit_and_commit, begin};

/// How long a begun ceremony may be finished, in seconds.
pub const CEREMONY_TTL_SECS: i64 = 120;

/// How long an enrollment code stays valid, in seconds.
pub const ENROLLMENT_TTL_SECS: i64 = 600;

/// Characters in an enrollment code.
const CODE_LEN: usize = 12;

/// RFC 4648 base32 alphabet; 32 symbols, so `byte % 32` is uniform.
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Longest passkey label, in characters.
const LABEL_MAX: usize = 64;

/// Ceremonies kept at once; the owner never needs more than a few.
const MAX_CEREMONIES: usize = 64;

/// `WebAuthn` user handle of the owner. There is exactly one user, so it is a
/// constant; it identifies nothing beyond "the warden owner".
const OWNER_HANDLE: Uuid = Uuid::from_bytes(*b"warden-owner-key");

/// Why a passkey operation failed. Messages are safe to show the owner.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PasskeyError {
    /// The enrollment code is unknown, expired or already used.
    #[error("enrollment code is invalid, expired or already used")]
    BadCode,
    /// The label is empty, too long or has control characters.
    #[error("label must be 1 to 64 characters without control characters")]
    BadLabel,
    /// The ceremony is unknown (finished, expired or lost in a restart).
    #[error("this passkey prompt expired; tap again")]
    CeremonyExpired,
    /// The ceremony id belongs to the other kind of ceremony.
    #[error("this ceremony is not of the expected kind")]
    WrongCeremony,
    /// No passkey is enrolled, so nothing can approve.
    #[error("no passkey is enrolled; run `warden-server enroll` on the server")]
    NoPasskeys,
    /// The authenticator's response did not verify.
    #[error("passkey verification failed")]
    Verification(#[source] WebauthnError),
    /// The authenticator's signature counter did not increase: a possible
    /// cloned authenticator. Deliberately says no more than this.
    #[error("passkey refused: its signature counter went backwards")]
    CounterRegressed,
    /// The assertion was made with a credential that is not enrolled (any
    /// more).
    #[error("passkey verification failed: credential not enrolled")]
    UnknownCredential,
    /// This authenticator is already enrolled.
    #[error("this passkey is already enrolled")]
    AlreadyEnrolled,
    /// No such passkey.
    #[error("no such passkey")]
    NotFound,
    /// Too many ceremonies are in progress.
    #[error("too many passkey prompts in progress; try again in a minute")]
    Busy,
    /// The public URL cannot serve as a `WebAuthn` relying party.
    #[error("WebAuthn configuration rejected: {0}")]
    Config(#[source] WebauthnError),
    /// The database failed.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// The audit log could not record the change.
    #[error(transparent)]
    Audit(#[from] AuditError),
    /// A stored credential could not be encoded or decoded.
    #[error("stored passkey unreadable: {0}")]
    Encoding(#[from] serde_json::Error),
    /// A local resource (randomness, a lock) is unusable.
    #[error("internal error: {0}")]
    Internal(&'static str),
}

impl From<crate::requests::RequestError> for PasskeyError {
    fn from(e: crate::requests::RequestError) -> Self {
        use crate::requests::RequestError;
        match e {
            RequestError::Db(e) => Self::Db(e),
            RequestError::Audit(e) => Self::Audit(e),
            RequestError::Encoding(e) => Self::Encoding(e),
            _ => Self::Internal("recording the passkey change failed"),
        }
    }
}

/// What an approval ceremony is bound to, fixed when it begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalBinding {
    /// SHA-256 (hex) of the approval token: identifies the request.
    pub token_hash: String,
    /// The window the owner chose.
    pub window: Window,
    /// Fingerprint of the request the owner was shown.
    pub fingerprint: Fingerprint,
    /// [`crate::requests::Destination::digest`] of the destination
    /// the owner was shown.
    pub destination_digest: String,
    /// When the request expires, Unix seconds.
    pub request_expires_at: i64,
}

/// A verified approval: exactly what `begin` stored, and who signed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedCeremony {
    /// What the approval applies to.
    pub binding: ApprovalBinding,
    /// Id of the passkey that signed.
    pub passkey_id: String,
}

/// A stored passkey, as listed to the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyInfo {
    /// Passkey id.
    pub id: String,
    /// Owner-chosen label.
    pub label: String,
    /// Enrollment time, Unix seconds.
    pub created_at: i64,
}

enum Ceremony {
    Registration {
        label: String,
        state: PasskeyRegistration,
    },
    Approval {
        binding: ApprovalBinding,
        state: PasskeyAuthentication,
    },
}

struct Pending {
    ceremony: Ceremony,
    expires_at: i64,
}

/// Passkey enrollment and approval ceremonies.
pub struct Passkeys {
    webauthn: Webauthn,
    pool: SqlitePool,
    audit: Arc<AuditLog>,
    clock: Arc<dyn Clock>,
    ceremonies: Mutex<HashMap<Id, Pending>>,
}

impl Passkeys {
    /// The service for relying party `public_url` (its host is the RP id,
    /// its origin the only accepted origin).
    ///
    /// # Errors
    /// [`PasskeyError::Config`] if `public_url` has no domain or is otherwise
    /// unusable as a relying party.
    pub fn new(
        pool: SqlitePool,
        audit: Arc<AuditLog>,
        public_url: &Url,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PasskeyError> {
        let rp_id = public_url
            .domain()
            .ok_or(PasskeyError::Config(WebauthnError::Configuration))?;
        let origin = Url::parse(&public_url.origin().ascii_serialization())
            .map_err(|_| PasskeyError::Config(WebauthnError::Configuration))?;
        let ttl = Duration::from_secs(CEREMONY_TTL_SECS.unsigned_abs());
        let webauthn = WebauthnBuilder::new(rp_id, &origin)
            .and_then(|b| b.rp_name("warden").timeout(ttl).build())
            .map_err(PasskeyError::Config)?;
        Ok(Self {
            webauthn,
            pool,
            audit,
            clock,
            ceremonies: Mutex::new(HashMap::new()),
        })
    }

    /// Create a one-time enrollment code valid for 600 s from `now`: 12
    /// base32 characters, stored only as a SHA-256 hash.
    ///
    /// # Errors
    /// Randomness or storage failures.
    pub async fn create_enrollment_code(&self, now: i64) -> Result<String, PasskeyError> {
        let mut bytes = [0_u8; CODE_LEN];
        getrandom::fill(&mut bytes)
            .map_err(|_| PasskeyError::Internal("OS random number generator unavailable"))?;
        let code: String = bytes
            .iter()
            .map(|b| char::from(BASE32[usize::from(b % 32)]))
            .collect();
        let mut tx = begin(&self.pool).await?;
        sqlx::query("DELETE FROM enrollment_codes WHERE expires_at <= ?")
            .bind(now)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO enrollment_codes (code_hash, expires_at) VALUES (?, ?)")
            .bind(code_hash(&code))
            .bind(now + ENROLLMENT_TTL_SECS)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(code)
    }

    /// Spend enrollment `code` and start registering a passkey named `label`.
    ///
    /// # Errors
    /// [`PasskeyError::BadLabel`] (the code is not spent),
    /// [`PasskeyError::BadCode`], [`PasskeyError::Busy`], storage failures.
    pub async fn begin_registration(
        &self,
        code: &str,
        label: &str,
    ) -> Result<(Id, CreationChallengeResponse), PasskeyError> {
        let label = valid_label(label)?;
        let now = self.clock.now();
        self.ensure_room(now)?;
        let spent = sqlx::query(
            "UPDATE enrollment_codes SET used_at = ?1 \
             WHERE code_hash = ?2 AND used_at IS NULL AND expires_at > ?1",
        )
        .bind(now)
        .bind(code_hash(&normalize_code(code)))
        .execute(&self.pool)
        .await?;
        if spent.rows_affected() != 1 {
            return Err(PasskeyError::BadCode);
        }
        let exclude = self
            .stored()
            .await?
            .iter()
            .map(|(_, passkey)| passkey.cred_id().clone())
            .collect::<Vec<CredentialID>>();
        let (options, state) = self
            .webauthn
            .start_passkey_registration(OWNER_HANDLE, "warden", "warden owner", Some(exclude))
            .map_err(PasskeyError::Verification)?;
        let id = self.insert(Ceremony::Registration { label, state }, now)?;
        Ok((id, options))
    }

    /// Finish registration `ceremony` with the authenticator's response,
    /// store the passkey and audit it. Returns the new passkey's id.
    ///
    /// # Errors
    /// [`PasskeyError::CeremonyExpired`], [`PasskeyError::WrongCeremony`],
    /// [`PasskeyError::Verification`], [`PasskeyError::AlreadyEnrolled`],
    /// storage or audit failures.
    pub async fn finish_registration(
        &self,
        ceremony: &Id,
        cred: &RegisterPublicKeyCredential,
    ) -> Result<String, PasskeyError> {
        let Ceremony::Registration { label, state } = self.take(ceremony)? else {
            return Err(PasskeyError::WrongCeremony);
        };
        let passkey = self
            .webauthn
            .finish_passkey_registration(cred, &state)
            .map_err(PasskeyError::Verification)?;
        let id = Id::random().to_string();
        let mut tx = begin(&self.pool).await?;
        let existing = sqlx::query("SELECT credential FROM passkeys")
            .fetch_all(&mut *tx)
            .await?;
        for row in &existing {
            let stored: Passkey = serde_json::from_str(row.try_get("credential")?)?;
            if stored.cred_id() == passkey.cred_id() {
                return Err(PasskeyError::AlreadyEnrolled);
            }
        }
        let credential = serde_json::to_string(&passkey)?;
        // The counter column mirrors the one inside the credential from the
        // start (normally 0 at registration).
        sqlx::query(
            "INSERT INTO passkeys (id, label, credential, created_at, counter) \
             VALUES (?1, ?2, ?3, ?4, COALESCE(json_extract(?3, '$.cred.counter'), 0))",
        )
        .bind(&id)
        .bind(&label)
        .bind(credential)
        .bind(self.clock.now())
        .execute(&mut *tx)
        .await?;
        let enrolled = AuditEvent::PasskeyEnrolled {
            passkey_id: id.clone(),
        };
        audit_and_commit(
            &self.audit,
            tx,
            vec![enrolled],
            &format!("enrollment of passkey {id}"),
        )
        .await?;
        Ok(id)
    }

    /// Start an approval ceremony bound to `binding`.
    ///
    /// # Errors
    /// [`PasskeyError::NoPasskeys`], [`PasskeyError::Busy`], storage failures.
    pub async fn begin_approval(
        &self,
        binding: ApprovalBinding,
    ) -> Result<(Id, RequestChallengeResponse), PasskeyError> {
        let now = self.clock.now();
        self.ensure_room(now)?;
        let passkeys: Vec<Passkey> = self.stored().await?.into_iter().map(|(_, p)| p).collect();
        if passkeys.is_empty() {
            return Err(PasskeyError::NoPasskeys);
        }
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(PasskeyError::Verification)?;
        let id = self.insert(Ceremony::Approval { binding, state }, now)?;
        Ok((id, options))
    }

    /// Verify the assertion for approval `ceremony` and return exactly what
    /// `begin_approval` bound it to. The passkey's stored counter is raised, never
    /// lowered: an assertion whose counter is not above it is refused.
    ///
    /// # Errors
    /// [`PasskeyError::CeremonyExpired`], [`PasskeyError::WrongCeremony`],
    /// [`PasskeyError::Verification`], [`PasskeyError::UnknownCredential`],
    /// [`PasskeyError::CounterRegressed`], storage failures.
    pub async fn finish_approval(
        &self,
        ceremony: &Id,
        cred: &PublicKeyCredential,
    ) -> Result<ApprovedCeremony, PasskeyError> {
        let Ceremony::Approval { binding, state } = self.take(ceremony)? else {
            return Err(PasskeyError::WrongCeremony);
        };
        let result = self
            .webauthn
            .finish_passkey_authentication(cred, &state)
            .map_err(PasskeyError::Verification)?;
        // Required by the ceremony's policy already; checked again here
        // because approval must never rest on presence alone.
        if !result.user_verified() {
            return Err(PasskeyError::Verification(WebauthnError::UserNotVerified));
        }
        let (passkey_id, mut passkey) = self
            .stored()
            .await?
            .into_iter()
            .find(|(_, passkey)| passkey.cred_id() == result.cred_id())
            .ok_or(PasskeyError::UnknownCredential)?;
        // Backup flags may change without the counter moving; the counter
        // itself is guarded in `store_counter`, not by this in-memory copy.
        passkey.update_credential(&result);
        self.store_counter(
            &passkey_id,
            &serde_json::to_string(&passkey)?,
            result.counter(),
        )
        .await?;
        Ok(ApprovedCeremony {
            binding,
            passkey_id,
        })
    }

    /// Store `credential` and `counter` for passkey `passkey_id` only if
    /// `counter` is above the stored one (or both are 0, as for passkeys that
    /// never count), in one statement so that concurrent approvals cannot
    /// lower it. Any other counter is a possible cloned authenticator:
    /// audited, nothing stored, and the approval must not proceed.
    ///
    /// # Errors
    /// [`PasskeyError::CounterRegressed`], [`PasskeyError::UnknownCredential`]
    /// if the passkey was removed meanwhile, storage and audit failures.
    async fn store_counter(
        &self,
        passkey_id: &str,
        credential: &str,
        counter: u32,
    ) -> Result<(), PasskeyError> {
        let counter = i64::from(counter);
        let stored = sqlx::query(
            "UPDATE passkeys SET credential = ?1, counter = ?2 \
             WHERE id = ?3 AND (counter < ?2 OR (counter = 0 AND ?2 = 0))",
        )
        .bind(credential)
        .bind(counter)
        .bind(passkey_id)
        .execute(&self.pool)
        .await?;
        if stored.rows_affected() == 1 {
            return Ok(());
        }
        let exists = sqlx::query("SELECT 1 FROM passkeys WHERE id = ?")
            .bind(passkey_id)
            .fetch_optional(&self.pool)
            .await?
            .is_some();
        if !exists {
            return Err(PasskeyError::UnknownCredential);
        }
        self.audit
            .append(AuditEvent::PasskeyCounterRegressed {
                passkey_id: passkey_id.to_owned(),
            })
            .await
            .map_err(PasskeyError::Audit)?;
        Err(PasskeyError::CounterRegressed)
    }

    /// Every enrolled passkey with its id.
    async fn stored(&self) -> Result<Vec<(String, Passkey)>, PasskeyError> {
        sqlx::query("SELECT id, credential FROM passkeys ORDER BY created_at, id")
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(|row| {
                let credential: &str = row.try_get("credential")?;
                Ok((row.try_get("id")?, serde_json::from_str(credential)?))
            })
            .collect()
    }

    fn lock(&self) -> Result<MutexGuard<'_, HashMap<Id, Pending>>, PasskeyError> {
        self.ceremonies
            .lock()
            .map_err(|_| PasskeyError::Internal("ceremony table lock poisoned"))
    }

    /// Drop expired ceremonies and fail if no slot is free.
    fn ensure_room(&self, now: i64) -> Result<(), PasskeyError> {
        let mut map = self.lock()?;
        map.retain(|_, p| p.expires_at > now);
        if map.len() >= MAX_CEREMONIES {
            return Err(PasskeyError::Busy);
        }
        Ok(())
    }

    fn insert(&self, ceremony: Ceremony, now: i64) -> Result<Id, PasskeyError> {
        let mut map = self.lock()?;
        if map.len() >= MAX_CEREMONIES {
            return Err(PasskeyError::Busy);
        }
        let id = Id::random();
        map.insert(
            id.clone(),
            Pending {
                ceremony,
                expires_at: now + CEREMONY_TTL_SECS,
            },
        );
        Ok(id)
    }

    /// Remove ceremony `id` (it is single use) and return it if still live.
    fn take(&self, id: &Id) -> Result<Ceremony, PasskeyError> {
        let pending = self
            .lock()?
            .remove(id)
            .ok_or(PasskeyError::CeremonyExpired)?;
        if pending.expires_at <= self.clock.now() {
            return Err(PasskeyError::CeremonyExpired);
        }
        Ok(pending.ceremony)
    }
}

/// Every enrolled passkey, oldest first.
///
/// # Errors
/// Storage failures.
pub async fn list(pool: &SqlitePool) -> Result<Vec<PasskeyInfo>, PasskeyError> {
    sqlx::query("SELECT id, label, created_at FROM passkeys ORDER BY created_at, id")
        .fetch_all(pool)
        .await?
        .iter()
        .map(|row| {
            Ok(PasskeyInfo {
                id: row.try_get("id")?,
                label: row.try_get("label")?,
                created_at: row.try_get("created_at")?,
            })
        })
        .collect()
}

/// Remove passkey `id` and audit it.
///
/// # Errors
/// [`PasskeyError::NotFound`], storage or audit failures.
pub async fn remove(pool: &SqlitePool, audit: &AuditLog, id: &str) -> Result<(), PasskeyError> {
    let mut tx = begin(pool).await?;
    let deleted = sqlx::query("DELETE FROM passkeys WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(PasskeyError::NotFound);
    }
    let removed = AuditEvent::PasskeyRemoved {
        passkey_id: id.to_owned(),
    };
    audit_and_commit(
        audit,
        tx,
        vec![removed],
        &format!("removal of passkey {id}"),
    )
    .await?;
    Ok(())
}

/// Codes are compared case-insensitively, ignoring spaces and dashes.
fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn code_hash(code: &str) -> String {
    hex::encode(Sha256::digest(code.as_bytes()))
}

fn valid_label(label: &str) -> Result<String, PasskeyError> {
    let label = label.trim();
    let length = label.chars().count();
    if length == 0 || length > LABEL_MAX || label.chars().any(char::is_control) {
        return Err(PasskeyError::BadLabel);
    }
    Ok(label.to_owned())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sqlx::Row as _;
    use url::Url;

    use super::{PasskeyError, Passkeys, normalize_code, valid_label};
    use crate::audit::AuditLog;
    use crate::requests::SystemClock;

    /// A passkey service over a fresh database holding one row `p1` whose
    /// credential text is `"c0"` and whose counter is `counter`. `store_counter`
    /// treats the credential as opaque text, so no real passkey is needed.
    async fn service_with_passkey(
        dir: &tempfile::TempDir,
        counter: i64,
    ) -> (Passkeys, std::path::PathBuf) {
        let pool = crate::store::open(&dir.path().join("warden.db"))
            .await
            .unwrap();
        let audit_path = dir.path().join("audit.jsonl");
        let audit = Arc::new(AuditLog::open(&audit_path).await.unwrap());
        sqlx::query(
            "INSERT INTO passkeys (id, label, credential, created_at, counter) \
             VALUES ('p1', 'l', 'c0', 1, ?)",
        )
        .bind(counter)
        .execute(&pool)
        .await
        .unwrap();
        let url = Url::parse("https://warden.example.test/").unwrap();
        let service = Passkeys::new(pool, audit, &url, Arc::new(SystemClock)).unwrap();
        (service, audit_path)
    }

    async fn row(service: &Passkeys) -> (String, i64) {
        let row = sqlx::query("SELECT credential, counter FROM passkeys WHERE id = 'p1'")
            .fetch_one(&service.pool)
            .await
            .unwrap();
        (row.get("credential"), row.get("counter"))
    }

    #[tokio::test]
    async fn counter_not_lowered_by_late_finish() {
        let dir = tempfile::tempdir().unwrap();
        let (service, audit_path) = service_with_passkey(&dir, 0).await;
        // Two finishes verified against the same old credential; 5 lands
        // first, 3 arrives late.
        service.store_counter("p1", "c5", 5).await.unwrap();
        let late = service.store_counter("p1", "c3", 3).await;
        assert!(
            matches!(late, Err(PasskeyError::CounterRegressed)),
            "{late:?}"
        );
        assert_eq!(row(&service).await, ("c5".to_owned(), 5));
        // Replaying the stored counter is refused too.
        let replay = service.store_counter("p1", "c5b", 5).await;
        assert!(matches!(replay, Err(PasskeyError::CounterRegressed)));
        assert_eq!(row(&service).await, ("c5".to_owned(), 5));
        // A higher one still lands, and each refusal was audited.
        service.store_counter("p1", "c6", 6).await.unwrap();
        assert_eq!(row(&service).await, ("c6".to_owned(), 6));
        let log = std::fs::read_to_string(audit_path).unwrap();
        assert_eq!(log.matches("passkey_counter_regressed").count(), 2, "{log}");
    }

    #[tokio::test]
    async fn counter_regression_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (service, _) = service_with_passkey(&dir, 4).await;
        // A non-zero authenticator reporting 0 is a regression as well.
        for counter in [0, 3, 4] {
            let refused = service.store_counter("p1", "bad", counter).await;
            assert!(
                matches!(refused, Err(PasskeyError::CounterRegressed)),
                "{counter}: {refused:?}"
            );
        }
        assert_eq!(row(&service).await, ("c0".to_owned(), 4));
        // A passkey removed meanwhile is not mistaken for a clone.
        let gone = service.store_counter("nope", "x", 9).await;
        assert!(matches!(gone, Err(PasskeyError::UnknownCredential)));
    }

    #[tokio::test]
    async fn zero_counter_authenticators_still_work() {
        let dir = tempfile::tempdir().unwrap();
        let (service, audit_path) = service_with_passkey(&dir, 0).await;
        // Platform passkeys report 0 forever: accepted every time, with the
        // credential (backup flags) still stored.
        service.store_counter("p1", "c-a", 0).await.unwrap();
        service.store_counter("p1", "c-b", 0).await.unwrap();
        assert_eq!(row(&service).await, ("c-b".to_owned(), 0));
        // An authenticator that starts counting later is accepted.
        service.store_counter("p1", "c-c", 1).await.unwrap();
        assert_eq!(row(&service).await, ("c-c".to_owned(), 1));
        assert!(
            !std::fs::read_to_string(audit_path)
                .unwrap()
                .contains("passkey_counter_regressed")
        );
    }

    #[test]
    fn codes_ignore_case_spaces_and_dashes() {
        assert_eq!(normalize_code(" abcd-efgh ijkl\n"), "ABCDEFGHIJKL");
    }

    #[test]
    fn labels_are_trimmed_and_bounded() {
        assert_eq!(valid_label("  phone ").unwrap(), "phone");
        assert_eq!(valid_label(&"é".repeat(64)).unwrap().chars().count(), 64);
        for bad in ["", "  ", "a\u{7}b", "line\nbreak"] {
            assert!(
                matches!(valid_label(bad), Err(PasskeyError::BadLabel)),
                "{bad:?}"
            );
        }
        assert!(matches!(
            valid_label(&"é".repeat(65)),
            Err(PasskeyError::BadLabel)
        ));
    }
}
