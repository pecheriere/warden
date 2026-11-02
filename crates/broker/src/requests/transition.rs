//! How a state change is made: on its own task, in one write transaction,
//! with its audit entries written before the commit.

use sqlx::{Sqlite, SqlitePool, Transaction};

use super::{RequestError, Requests};
use crate::audit::{AuditError, AuditEvent, AuditLog};
use crate::notify::Doorbell;

/// Why [`audit_and_commit`] failed. Nothing took effect either way.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CommitError {
    /// An entry could not be written.
    #[error(transparent)]
    Audit(#[from] AuditError),
    /// The commit failed.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}

/// Record `events`, then commit `tx`.
///
/// The audit entries come first so no change ever lands unaudited. If a
/// later step fails after something was recorded (a further entry or the
/// commit), an `Error { context: "commit" }` entry states that `transition`
/// did not take effect.
pub(crate) async fn audit_and_commit(
    audit: &AuditLog,
    tx: Transaction<'static, Sqlite>,
    events: Vec<AuditEvent>,
    transition: &str,
) -> Result<(), CommitError> {
    let mut recorded = false;
    for event in events {
        if let Err(e) = audit.append(event).await {
            if recorded {
                record_not_committed(audit, transition, &e.to_string()).await;
            }
            return Err(e.into());
        }
        recorded = true;
    }
    if let Err(e) = tx.commit().await {
        record_not_committed(audit, transition, &e.to_string()).await;
        return Err(e.into());
    }
    Ok(())
}

/// Whether a revocation that took effect is on record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// Its entries were written, or there was nothing to record.
    Recorded,
    /// Access has stopped, but entries could not be written. The server log
    /// has them.
    Missing,
}

/// Commit a revocation `tx`, recording `events` if the audit log allows.
///
/// Stopping access matters more than recording it, so unlike
/// [`audit_and_commit`] this commits even if entries cannot be written (or
/// there is no log to write them to, `None`). The entries still come first, so
/// a revocation that is recorded reads as usual. Those not written go to the
/// server log at error level, and the caller must tell the owner about
/// [`AuditOutcome::Missing`]. A failed commit means access did not stop, and
/// is an error.
pub(crate) async fn commit_even_if_unaudited(
    audit: Option<&AuditLog>,
    tx: Transaction<'static, Sqlite>,
    events: Vec<AuditEvent>,
    transition: &str,
) -> Result<AuditOutcome, sqlx::Error> {
    let mut written = 0;
    if let Some(audit) = audit {
        for event in &events {
            if let Err(e) = audit.append(event.clone()).await {
                tracing::error!(transition, error = %e, "could not write the audit log");
                break;
            }
            written += 1;
        }
    }
    if let Err(e) = tx.commit().await {
        if let (Some(audit), true) = (audit, written > 0) {
            record_not_committed(audit, transition, &e.to_string()).await;
        }
        return Err(e);
    }
    let missing = &events[written..];
    if missing.is_empty() {
        return Ok(AuditOutcome::Recorded);
    }
    tracing::error!(
        transition,
        ?missing,
        "access was revoked but this is not in the audit log"
    );
    Ok(AuditOutcome::Missing)
}

impl Requests {
    /// Tell the owner that `what` took effect without its audit entries, in
    /// the background: a revocation need not wait for a notifier, and the agent
    /// that revoked its own grant may be the only one to know of it otherwise.
    pub(super) fn tell_owner_unaudited(&self, what: String) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut url = this.public_url.clone();
            if let Ok(mut path) = url.path_segments_mut() {
                path.pop_if_empty().push("grants");
            }
            let bell = Doorbell {
                title: "warden: revoked, but the audit log failed".to_owned(),
                message: format!(
                    "{what} took effect, but could not be recorded. Check the server's log and \
                     the disk that holds the audit log."
                ),
                url,
            };
            if let Err(e) = this.notifier.ring(&bell).await {
                tracing::error!(error = %e, "could not tell the owner of an unaudited revocation");
            }
        });
    }
}

async fn record_not_committed(audit: &AuditLog, transition: &str, cause: &str) {
    let event = AuditEvent::Error {
        context: "commit".to_owned(),
        message: format!("{transition} did not take effect: {cause}"),
    };
    if let Err(e) = audit.append(event).await {
        tracing::error!(transition, error = %e, "could not record an uncommitted transition");
    }
}

/// Run a state transition to completion on its own task, so dropping the
/// caller (for example a disconnected HTTP client) never stops it halfway.
pub(super) async fn detached<T>(
    work: impl Future<Output = Result<T, RequestError>> + Send + 'static,
) -> Result<T, RequestError>
where
    T: Send + 'static,
{
    tokio::spawn(work)
        .await
        .map_err(|_| RequestError::Internal("state transition task failed"))?
}

/// Start a write transaction that takes the write lock up front, so
/// concurrent writers queue on the busy timeout instead of failing.
pub(crate) async fn begin(pool: &SqlitePool) -> Result<Transaction<'static, Sqlite>, sqlx::Error> {
    pool.begin_with("BEGIN IMMEDIATE").await
}

#[cfg(test)]
mod tests {
    use warden_broker_proto::Id;

    use super::{
        AuditEvent, AuditLog, AuditOutcome, CommitError, audit_and_commit, begin,
        commit_even_if_unaudited,
    };
    use crate::store;

    #[tokio::test]
    async fn failed_commit_is_recorded_as_not_taking_effect() {
        let dir = tempfile::tempdir().unwrap();
        let pool = store::open(&dir.path().join("warden.db")).await.unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).await.unwrap();

        // A deferred foreign-key violation makes the commit itself fail.
        let mut tx = begin(&pool).await.unwrap();
        sqlx::query("PRAGMA defer_foreign_keys = ON")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO grants (id, request_id, agent, window_secs, not_before, not_after, view) \
             VALUES ('g', 'no-such-request', 'a', 900, 0, 900, '{}')",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        let id = Id::random();
        let result = audit_and_commit(
            &audit,
            tx,
            vec![AuditEvent::Denied { id: id.clone() }],
            &format!("denial of request {id}"),
        )
        .await;
        assert!(matches!(result, Err(CommitError::Db(_))), "{result:?}");

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[0].contains(r#""type":"denied""#));
        assert!(lines[1].contains(r#""context":"commit""#), "{text}");
        assert!(
            lines[1].contains(&format!("denial of request {id} did not take effect")),
            "{text}"
        );
        assert_eq!(crate::audit::verify(&path).unwrap(), 2);
        let grants: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM grants")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(grants, 0);
    }

    /// Insert a row in a transaction, as the change being made.
    async fn change(pool: &sqlx::SqlitePool) -> sqlx::Transaction<'static, sqlx::Sqlite> {
        let mut tx = begin(pool).await.unwrap();
        sqlx::query("INSERT INTO enrollment_codes (code_hash, expires_at) VALUES ('c', 1)")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx
    }

    async fn changes(pool: &sqlx::SqlitePool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM enrollment_codes")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_revocation_commits_when_its_entry_cannot_be_written() {
        let dir = tempfile::tempdir().unwrap();
        let pool = store::open(&dir.path().join("warden.db")).await.unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).await.unwrap();
        std::fs::write(&path, b"not an audit line\n").unwrap();

        let tx = change(&pool).await;
        let event = AuditEvent::Denied { id: Id::random() };
        let got = commit_even_if_unaudited(Some(&audit), tx, vec![event], "a revocation").await;
        assert_eq!(got.unwrap(), AuditOutcome::Missing);
        assert_eq!(changes(&pool).await, 1);
    }

    #[tokio::test]
    async fn a_revocation_commits_with_no_log_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let pool = store::open(&dir.path().join("warden.db")).await.unwrap();
        let tx = change(&pool).await;
        let event = AuditEvent::Denied { id: Id::random() };
        let got = commit_even_if_unaudited(None, tx, vec![event], "a revocation").await;
        assert_eq!(got.unwrap(), AuditOutcome::Missing);
        assert_eq!(changes(&pool).await, 1);
    }

    #[tokio::test]
    async fn a_recorded_revocation_is_written_before_it_commits() {
        let dir = tempfile::tempdir().unwrap();
        let pool = store::open(&dir.path().join("warden.db")).await.unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).await.unwrap();
        let tx = change(&pool).await;
        let event = AuditEvent::Denied { id: Id::random() };
        let got = commit_even_if_unaudited(Some(&audit), tx, vec![event], "a revocation").await;
        assert_eq!(got.unwrap(), AuditOutcome::Recorded);
        assert_eq!(crate::audit::verify(&path).unwrap(), 1);
        assert_eq!(changes(&pool).await, 1);
    }

    #[tokio::test]
    async fn a_revocation_that_cannot_commit_is_an_error_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let pool = store::open(&dir.path().join("warden.db")).await.unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).await.unwrap();
        // A deferred foreign-key violation makes the commit itself fail.
        let mut tx = begin(&pool).await.unwrap();
        sqlx::query("PRAGMA defer_foreign_keys = ON")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO grants (id, request_id, agent, window_secs, not_before, not_after, view) \
             VALUES ('g', 'no-such-request', 'a', 900, 0, 900, '{}')",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        let event = AuditEvent::Denied { id: Id::random() };
        let got = commit_even_if_unaudited(Some(&audit), tx, vec![event], "a revocation").await;
        assert!(got.is_err(), "{got:?}");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("a revocation did not take effect"), "{text}");
    }

    #[tokio::test]
    async fn entry_that_cannot_be_written_rolls_the_change_back() {
        let dir = tempfile::tempdir().unwrap();
        let pool = store::open(&dir.path().join("warden.db")).await.unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).await.unwrap();
        // An unreadable last line refuses every append.
        std::fs::write(&path, b"not an audit line\n").unwrap();

        let mut tx = begin(&pool).await.unwrap();
        sqlx::query("INSERT INTO enrollment_codes (code_hash, expires_at) VALUES ('c', 1)")
            .execute(&mut *tx)
            .await
            .unwrap();
        let result = audit_and_commit(
            &audit,
            tx,
            vec![AuditEvent::EnrollmentCodeCreated { expires_at: 1 }],
            "creation of a code",
        )
        .await;
        assert!(matches!(result, Err(CommitError::Audit(_))), "{result:?}");
        let codes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM enrollment_codes")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(codes, 0);
    }
}
