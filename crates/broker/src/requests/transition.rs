//! How a state change is made: on its own task, in one write transaction,
//! with its audit entries written before the commit.

use sqlx::{Sqlite, SqlitePool, Transaction};

use super::RequestError;
use crate::audit::{AuditError, AuditEvent, AuditLog};

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

    use super::{AuditEvent, AuditLog, CommitError, audit_and_commit, begin};
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
