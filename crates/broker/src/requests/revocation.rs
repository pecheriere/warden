//! Revocation does not wait for the audit log: stopping access matters more than
//! recording it.
//!
//! A revocation stores its audit entries in `unwritten_audit`, in the transaction
//! that revokes, and is then written to the log and removed from that table. So a
//! log that fails or stalls cannot stop a revocation, and an entry it could not
//! take is not lost: it waits in the database, and every sweep tries again. The
//! grants page warns the owner for as long as any is waiting. A crash after an
//! entry is written and before it is removed writes it twice, which overstates
//! nothing.

use std::sync::Arc;
use std::time::Duration;

use sqlx::{Row as _, Sqlite, SqlitePool, Transaction};
use tokio::sync::Mutex;

use super::{RequestError, Requests};
use crate::audit::{AuditEvent, AuditLog};
use crate::notify::Doorbell;

/// Longest a revocation waits for its entries to be written.
const WRITE_WAIT: Duration = Duration::from_secs(2);

/// An entry this many seconds after its revocation is noted as written late.
const LATE_SECS: i64 = 60;

/// Whether a revocation that took effect is on record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// Every entry has been written to the audit log.
    Recorded,
    /// Access has stopped, but entries are still waiting for the log.
    Missing,
}

/// The result of trying to write the waiting entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntriesWritten {
    /// Whether any is still waiting.
    pub outcome: AuditOutcome,
    /// Why the attempt failed, if it did. Never holds a secret.
    pub cause: Option<String>,
}

/// Store `events` and commit the revocation `tx` of `now`. This never touches the
/// audit log, so nothing about the log can delay or stop it.
///
/// # Errors
/// Storage failures, which mean the revocation did not happen.
pub(super) async fn commit_with_entries(
    mut tx: Transaction<'static, Sqlite>,
    events: Vec<AuditEvent>,
    now: i64,
) -> Result<(), RequestError> {
    for event in events {
        sqlx::query("INSERT INTO unwritten_audit (event, revoked_at) VALUES (?, ?)")
            .bind(serde_json::to_string(&event)?)
            .bind(now)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// The audit entries of revocations still waiting for the log, oldest first.
///
/// # Errors
/// Storage failures or an unreadable stored entry.
pub async fn unwritten_entries(pool: &SqlitePool) -> Result<Vec<AuditEvent>, RequestError> {
    sqlx::query("SELECT event FROM unwritten_audit ORDER BY id")
        .fetch_all(pool)
        .await?
        .iter()
        .map(|row| Ok(serde_json::from_str(row.try_get("event")?)?))
        .collect()
}

/// Write the waiting entries in order, each removed once it is in the log.
async fn write_waiting(pool: &SqlitePool, audit: &AuditLog, now: i64) -> Result<(), RequestError> {
    let rows = sqlx::query("SELECT id, event, revoked_at FROM unwritten_audit ORDER BY id")
        .fetch_all(pool)
        .await?;
    for row in &rows {
        let id: i64 = row.try_get("id")?;
        let revoked_at: i64 = row.try_get("revoked_at")?;
        let event: AuditEvent = serde_json::from_str(row.try_get("event")?)?;
        audit.append(event).await?;
        if now.saturating_sub(revoked_at) >= LATE_SECS {
            let note = AuditEvent::Error {
                context: "audit".to_owned(),
                message: format!(
                    "the entry above was written late: it took effect at {revoked_at}"
                ),
            };
            audit.append(note).await?;
        }
        sqlx::query("DELETE FROM unwritten_audit WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// Write the waiting entries, waiting for that at most [`WRITE_WAIT`]. A log that
/// has stalled finishes on its own task whenever it can; `gate` keeps two writers
/// in this process from writing an entry twice.
async fn write_bounded(
    pool: &SqlitePool,
    audit: &Arc<AuditLog>,
    gate: &Arc<Mutex<()>>,
    now: i64,
) -> EntriesWritten {
    let task = {
        let (pool, audit, gate) = (pool.clone(), Arc::clone(audit), Arc::clone(gate));
        tokio::spawn(async move {
            let _writing = gate.lock_owned().await;
            write_waiting(&pool, &audit, now).await
        })
    };
    let cause = match tokio::time::timeout(WRITE_WAIT, task).await {
        Ok(Ok(Ok(()))) => None,
        Ok(Ok(Err(e))) => Some(e.to_string()),
        Ok(Err(e)) => Some(e.to_string()),
        Err(_) => Some(format!(
            "the audit log did not answer within {} s",
            WRITE_WAIT.as_secs()
        )),
    };
    let outcome = match sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM unwritten_audit")
        .fetch_one(pool)
        .await
    {
        Ok(0) => AuditOutcome::Recorded,
        Ok(_) => AuditOutcome::Missing,
        Err(e) => {
            tracing::error!(error = %e, "could not read which audit entries are waiting");
            AuditOutcome::Missing
        }
    };
    EntriesWritten { outcome, cause }
}

/// Write the waiting entries from a process with no running [`Requests`], such
/// as `warden-server agent revoke`. Returns within a few seconds even if the log
/// has stalled; the caller reports what is left.
pub async fn write_entries(pool: &SqlitePool, audit: &Arc<AuditLog>, now: i64) -> EntriesWritten {
    write_bounded(pool, audit, &Arc::default(), now).await
}

impl Requests {
    /// Write the waiting entries, and report loudly if any must stay waiting.
    pub(super) async fn settle_entries(&self) -> AuditOutcome {
        let written = write_bounded(
            &self.pool,
            &self.audit,
            &self.entry_writer,
            self.clock.now(),
        )
        .await;
        if written.outcome == AuditOutcome::Missing {
            let waiting = unwritten_entries(&self.pool).await;
            tracing::error!(
                cause = written.cause.as_deref().unwrap_or("none reported"),
                ?waiting,
                "access was revoked but this is not in the audit log yet"
            );
        }
        written.outcome
    }

    /// Try again to write the entries still waiting, unless a write is under way.
    /// The sweep calls this, so an entry is written soon after the log recovers.
    pub async fn flush_revocation_entries(&self) {
        let is_writing = self.entry_writer.try_lock().is_err();
        if !is_writing {
            self.settle_entries().await;
        }
    }

    /// How many audit entries of revocations are waiting for the log; the grants
    /// page warns the owner while there are any.
    ///
    /// # Errors
    /// Storage failures.
    pub async fn unwritten_entry_count(&self) -> Result<i64, RequestError> {
        Ok(sqlx::query_scalar("SELECT COUNT(*) FROM unwritten_audit")
            .fetch_one(&self.pool)
            .await?)
    }

    /// Tell the owner that `what` took effect without its audit entries, in the
    /// background: a revocation need not wait for a notifier, and the agent that
    /// revoked its own grant may be the only one to know of it otherwise.
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
                    "{what} took effect, but is not in the audit log yet. Check the server's log \
                     and the disk that holds the audit log."
                ),
                url,
            };
            if let Err(e) = this.notifier.ring(&bell).await {
                tracing::error!(error = %e, "could not tell the owner of an unaudited revocation");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use warden_broker_proto::Id;

    use super::{
        AuditEvent, AuditLog, AuditOutcome, commit_with_entries, unwritten_entries, write_entries,
    };
    use crate::requests::begin;
    use crate::store;

    fn event() -> AuditEvent {
        AuditEvent::Denied { id: Id::random() }
    }

    /// A database, and an audit log with its path.
    async fn setup(
        dir: &tempfile::TempDir,
    ) -> (sqlx::SqlitePool, Arc<AuditLog>, std::path::PathBuf) {
        let pool = store::open(&dir.path().join("warden.db")).await.unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = Arc::new(AuditLog::open(&path).await.unwrap());
        (pool, audit, path)
    }

    async fn commit_one(pool: &sqlx::SqlitePool, now: i64) -> AuditEvent {
        let entry = event();
        let tx = begin(pool).await.unwrap();
        commit_with_entries(tx, vec![entry.clone()], now)
            .await
            .unwrap();
        entry
    }

    #[tokio::test]
    async fn an_entry_waits_in_the_database_until_it_is_in_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, audit, path) = setup(&dir).await;
        let entry = commit_one(&pool, 1000).await;
        assert_eq!(unwritten_entries(&pool).await.unwrap(), [entry]);
        assert_eq!(crate::audit::verify(&path).unwrap(), 0);

        let written = write_entries(&pool, &audit, 1000).await;
        assert_eq!(written.outcome, AuditOutcome::Recorded);
        assert_eq!(written.cause, None);
        assert_eq!(unwritten_entries(&pool).await.unwrap(), []);
        assert_eq!(crate::audit::verify(&path).unwrap(), 1);
    }

    #[tokio::test]
    async fn an_entry_the_log_refuses_stays_and_is_written_later_with_a_note() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, audit, path) = setup(&dir).await;
        std::fs::write(&path, b"not an audit line\n").unwrap();
        let entry = commit_one(&pool, 1000).await;

        let written = write_entries(&pool, &audit, 1000).await;
        assert_eq!(written.outcome, AuditOutcome::Missing);
        assert!(written.cause.is_some());
        assert_eq!(unwritten_entries(&pool).await.unwrap(), [entry]);

        std::fs::write(&path, b"").unwrap();
        let written = write_entries(&pool, &audit, 1060).await;
        assert_eq!(written.outcome, AuditOutcome::Recorded);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("written late: it took effect at 1000"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn an_entry_written_at_once_has_no_note() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, audit, path) = setup(&dir).await;
        commit_one(&pool, 1000).await;
        write_entries(&pool, &audit, 1059).await;
        assert!(!std::fs::read_to_string(&path).unwrap().contains("late"));
    }

    #[tokio::test]
    async fn a_stalled_log_does_not_hold_up_the_answer() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, audit, path) = setup(&dir).await;
        commit_one(&pool, 1000).await;
        // Another writer holds the lock, which an append waits on for 5 s: longer
        // than a revocation waits.
        let holder = std::fs::File::open(&path).unwrap();
        holder.lock().unwrap();
        let written = write_entries(&pool, &audit, 1000).await;
        assert_eq!(written.outcome, AuditOutcome::Missing);
        assert!(written.cause.unwrap().contains("did not answer"));
    }
}
