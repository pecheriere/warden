//! A change that ends access does not wait for the audit log: stopping access
//! matters more than recording it.
//!
//! Revoking, denying, cancelling and expiring store their audit entries in
//! `unwritten_audit`, in the transaction that makes the change, and the end of a
//! proxied call stopped because its grant ended is stored there too. The entries
//! are then written to the log and removed from that table. So the log cannot delay
//! the change, and an entry it could not take is not lost: it waits in the
//! database, and every sweep tries again. The grants page warns the owner for as
//! long as any is waiting. A writer claims a row before writing it, so two
//! processes do not both write it; a crash after an entry is written and before it
//! is removed writes it twice, which overstates nothing.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row as _, Sqlite, SqlitePool, Transaction};
use tokio::sync::Mutex;
use warden_broker_proto::Id;

use super::{Clock, RequestError, Requests};
use crate::audit::{AuditError, AuditEvent, AuditLog};
use crate::notify::Doorbell;

/// Longest a change waits for its entries to be written.
pub(super) const WRITE_WAIT: Duration = Duration::from_secs(2);

/// An entry written this many seconds after its change is noted as late.
const LATE_SECS: i64 = 60;

/// How long a claim on an entry lasts: after this its writer is taken to be gone.
const CLAIM_SECS: i64 = 300;

/// Whether a change that took effect is on record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// Every entry has been written to the audit log, or another process has
    /// claimed it to do so.
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

/// Store `events` and commit the change `tx` of `now`. This never touches the
/// audit log, so nothing about the log can delay or stop it.
///
/// # Errors
/// Storage failures, which mean the change did not happen.
pub(super) async fn commit_with_entries(
    mut tx: Transaction<'static, Sqlite>,
    events: Vec<AuditEvent>,
    now: i64,
) -> Result<(), RequestError> {
    for event in events {
        sqlx::query("INSERT INTO unwritten_audit (event, took_effect_at) VALUES (?, ?)")
            .bind(serde_json::to_string(&event)?)
            .bind(now)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// The audit entries still waiting for the log, oldest first.
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

/// How many audit entries are waiting in the database file `db`, read without
/// changing it. A database from before this table has none.
///
/// # Errors
/// Why the database could not be read.
pub async fn count_waiting_read_only(db: &Path) -> Result<i64, String> {
    let options = SqliteConnectOptions::new()
        .filename(db)
        .create_if_missing(false)
        .read_only(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(|e| e.to_string())?;
    let has_table: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'unwritten_audit'",
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| e.to_string())?;
    let count = if has_table.is_some() {
        sqlx::query_scalar("SELECT COUNT(*) FROM unwritten_audit")
            .fetch_one(&pool)
            .await
            .map_err(|e| e.to_string())
    } else {
        Ok(0)
    };
    pool.close().await;
    count
}

/// Write the waiting entries in order, each claimed first and removed once it is
/// in the log. The time is read after each write, which may take long. Returns the
/// last row it saw: one stored after that is for whoever stored it to report.
async fn write_waiting(
    pool: &SqlitePool,
    audit: &AuditLog,
    clock: &dyn Clock,
) -> Result<i64, RequestError> {
    let claim = Id::random();
    let mut last_seen = 0;
    let rows = sqlx::query("SELECT id, event, took_effect_at FROM unwritten_audit ORDER BY id")
        .fetch_all(pool)
        .await?;
    for row in &rows {
        let id: i64 = row.try_get("id")?;
        last_seen = id;
        let took_effect_at: i64 = row.try_get("took_effect_at")?;
        let event: AuditEvent = serde_json::from_str(row.try_get("event")?)?;
        let now = clock.now();
        let claimed = sqlx::query(
            "UPDATE unwritten_audit SET claim = ?1, claimed_at = ?2 \
             WHERE id = ?3 AND (claim IS NULL OR claimed_at <= ?4 OR claimed_at > ?2)",
        )
        .bind(claim.as_str())
        .bind(now)
        .bind(id)
        .bind(now.saturating_sub(CLAIM_SECS))
        .execute(pool)
        .await?;
        if claimed.rows_affected() == 0 {
            continue;
        }
        if let Err(e) = write_one(audit, event, took_effect_at, clock).await {
            sqlx::query("UPDATE unwritten_audit SET claim = NULL WHERE id = ?")
                .bind(id)
                .execute(pool)
                .await?;
            return Err(e.into());
        }
        sqlx::query("DELETE FROM unwritten_audit WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await?;
    }
    Ok(last_seen)
}

/// Write `event`, followed by a note when it is late: its own time is when it was
/// written, not when the change took effect. The note holds the entry, as another
/// writer's entry can come between the two.
async fn write_one(
    audit: &AuditLog,
    event: AuditEvent,
    took_effect_at: i64,
    clock: &dyn Clock,
) -> Result<(), AuditError> {
    let written = serde_json::to_string(&event)?;
    audit.append(event).await?;
    if clock.now().saturating_sub(took_effect_at) >= LATE_SECS {
        let note = AuditEvent::Error {
            context: "audit".to_owned(),
            message: format!(
                "this entry was written late, it took effect at {took_effect_at}: {written}"
            ),
        };
        audit.append(note).await?;
    }
    Ok(())
}

/// Write the waiting entries, waiting for that at most [`WRITE_WAIT`]. A log that
/// has stalled finishes on its own task whenever it can; `gate` keeps two writers
/// in this process from queueing up behind it.
async fn write_bounded(
    pool: &SqlitePool,
    audit: &Arc<AuditLog>,
    gate: &Arc<Mutex<()>>,
    clock: &Arc<dyn Clock>,
) -> EntriesWritten {
    let task = {
        let (pool, audit, gate) = (pool.clone(), Arc::clone(audit), Arc::clone(gate));
        let clock = Arc::clone(clock);
        tokio::spawn(async move {
            let _writing = gate.lock_owned().await;
            write_waiting(&pool, &audit, clock.as_ref()).await
        })
    };
    let (cause, last_seen) = match tokio::time::timeout(WRITE_WAIT, task).await {
        Ok(Ok(Ok(last_seen))) => (None, last_seen),
        Ok(Ok(Err(e))) => (Some(e.to_string()), i64::MAX),
        Ok(Err(e)) => (Some(e.to_string()), i64::MAX),
        Err(_) => (
            Some(format!(
                "the audit log did not answer within {} s",
                WRITE_WAIT.as_secs()
            )),
            i64::MAX,
        ),
    };
    // An entry another writer has claimed is that writer's to report, and so is
    // one stored since: a call that a revocation just stopped stores its end while
    // the revocation's own entry is being written, and that is no failure of the log.
    let unclaimed = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM unwritten_audit WHERE claim IS NULL AND id <= ?",
    )
    .bind(last_seen)
    .fetch_one(pool)
    .await;
    let outcome = match (&cause, unclaimed) {
        (None, Ok(0)) => AuditOutcome::Recorded,
        (_, Err(e)) => {
            tracing::error!(error = %e, "could not read which audit entries are waiting");
            AuditOutcome::Missing
        }
        _ => AuditOutcome::Missing,
    };
    EntriesWritten { outcome, cause }
}

/// Write the waiting entries from a process with no running [`Requests`], such
/// as `warden-server agent revoke`. Returns within a few seconds even if the log
/// has stalled; the caller reports what is left.
pub async fn write_entries(
    pool: &SqlitePool,
    audit: &Arc<AuditLog>,
    clock: &Arc<dyn Clock>,
) -> EntriesWritten {
    write_bounded(pool, audit, &Arc::default(), clock).await
}

impl Requests {
    /// Write the waiting entries, and report loudly if any must stay waiting.
    pub(super) async fn settle_entries(&self) -> AuditOutcome {
        let written = write_bounded(&self.pool, &self.audit, &self.entry_writer, &self.clock).await;
        if written.outcome == AuditOutcome::Missing {
            let waiting = unwritten_entries(&self.pool).await;
            tracing::error!(
                cause = written.cause.as_deref().unwrap_or("none reported"),
                ?waiting,
                "access was ended but this is not in the audit log yet"
            );
        }
        written.outcome
    }

    /// Record how a proxied call that was stopped ended. Access is gone already, so
    /// as for the change that ended it, the log cannot hold this up: the entry
    /// waits in the database if the log does not take it within 2 s. A
    /// call stopped because the database cannot be read may find it still cannot
    /// store the entry, and then goes straight to the log. The entry is lost only if
    /// both fail, which is logged.
    pub async fn record_stopped_call(&self, event: AuditEvent) {
        let stored = async {
            let row = serde_json::to_string(&event)?;
            sqlx::query("INSERT INTO unwritten_audit (event, took_effect_at) VALUES (?, ?)")
                .bind(row)
                .bind(self.clock.now())
                .execute(&self.pool)
                .await?;
            Ok::<_, RequestError>(())
        };
        match stored.await {
            Ok(()) => {
                self.settle_entries().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "could not store the end of a stopped call; writing it to the log");
                if let Err(e) = self.audit.append(event.clone()).await {
                    tracing::error!(error = %e, ?event, "the end of a stopped call is not on record");
                }
            }
        }
    }

    /// Try again to write the entries still waiting, unless a write is under way.
    /// The sweep calls this, so an entry is written soon after the log recovers,
    /// and soon after a start if a crash left some behind.
    pub async fn flush_waiting_entries(&self) {
        let is_writing = self.entry_writer.try_lock().is_err();
        if !is_writing {
            self.settle_entries().await;
        }
    }

    /// How many audit entries are waiting for the log; the grants page warns the
    /// owner while there are any.
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
    use std::sync::atomic::{AtomicI64, Ordering};

    use warden_broker_proto::Id;

    use super::{
        AuditEvent, AuditLog, AuditOutcome, Clock, commit_with_entries, count_waiting_read_only,
        unwritten_entries, write_entries,
    };
    use crate::requests::begin;
    use crate::store;

    /// A clock a test moves by hand.
    struct TestClock(AtomicI64);

    impl Clock for TestClock {
        fn now(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn clock_at(now: i64) -> (Arc<TestClock>, Arc<dyn Clock>) {
        let clock = Arc::new(TestClock(AtomicI64::new(now)));
        (Arc::clone(&clock), clock)
    }

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
        let db = dir.path().join("warden.db");
        assert_eq!(count_waiting_read_only(&db).await.unwrap(), 1);

        let (_, clock) = clock_at(1000);
        let written = write_entries(&pool, &audit, &clock).await;
        assert_eq!(written.outcome, AuditOutcome::Recorded);
        assert_eq!(written.cause, None);
        assert_eq!(unwritten_entries(&pool).await.unwrap(), []);
        assert_eq!(crate::audit::verify(&path).unwrap(), 1);
        assert_eq!(count_waiting_read_only(&db).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn an_entry_the_log_refuses_stays_and_is_written_later_with_a_note() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, audit, path) = setup(&dir).await;
        std::fs::write(&path, b"not an audit line\n").unwrap();
        let entry = commit_one(&pool, 1000).await;
        let named = serde_json::to_string(&serde_json::to_string(&entry).unwrap()).unwrap();

        let (time, clock) = clock_at(1000);
        let written = write_entries(&pool, &audit, &clock).await;
        assert_eq!(written.outcome, AuditOutcome::Missing);
        assert!(written.cause.is_some());
        assert_eq!(unwritten_entries(&pool).await.unwrap(), [entry]);

        std::fs::write(&path, b"").unwrap();
        time.0.store(1060, Ordering::SeqCst);
        let written = write_entries(&pool, &audit, &clock).await;
        assert_eq!(written.outcome, AuditOutcome::Recorded);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("written late, it took effect at 1000"),
            "{text}"
        );
        // The note holds the entry it is about.
        assert!(text.contains(named.trim_matches('"')), "{text}");
    }

    #[tokio::test]
    async fn an_entry_written_at_once_has_no_note() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, audit, path) = setup(&dir).await;
        commit_one(&pool, 1000).await;
        let (_, clock) = clock_at(1059);
        write_entries(&pool, &audit, &clock).await;
        assert!(!std::fs::read_to_string(&path).unwrap().contains("late"));
    }

    #[tokio::test]
    async fn an_entry_that_waited_on_a_stalled_write_is_noted_as_late() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, audit, path) = setup(&dir).await;
        commit_one(&pool, 1000).await;
        let holder = std::fs::File::open(&path).unwrap();
        holder.lock().unwrap();
        let (time, clock) = clock_at(1000);
        let written = write_entries(&pool, &audit, &clock).await;
        assert_eq!(written.outcome, AuditOutcome::Missing);

        // The write under way finishes an hour later, by this clock.
        time.0.store(4600, Ordering::SeqCst);
        drop(holder);
        while !unwritten_entries(&pool).await.unwrap().is_empty() {
            write_entries(&pool, &audit, &clock).await;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("written late, it took effect at 1000"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn two_processes_writing_at_once_write_each_entry_once() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, audit, path) = setup(&dir).await;
        // Separate handles and separate gates, as in two processes.
        let other = Arc::new(AuditLog::open(&path).await.unwrap());
        for _ in 0..40 {
            commit_one(&pool, 1000).await;
        }
        let (_, clock) = clock_at(1000);
        let (first, second) = tokio::join!(
            write_entries(&pool, &audit, &clock),
            write_entries(&pool, &other, &clock)
        );
        assert_eq!(first.cause, None);
        assert_eq!(second.cause, None);
        // Neither reports a failure because the other holds some entries.
        assert_eq!(first.outcome, AuditOutcome::Recorded);
        assert_eq!(second.outcome, AuditOutcome::Recorded);
        assert_eq!(crate::audit::verify(&path).unwrap(), 40);
    }

    #[tokio::test]
    async fn a_claim_left_by_a_crash_is_taken_over_only_after_it_lapses() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, audit, path) = setup(&dir).await;
        commit_one(&pool, 1000).await;
        sqlx::query("UPDATE unwritten_audit SET claim = 'gone', claimed_at = 1000")
            .execute(&pool)
            .await
            .unwrap();
        let (time, clock) = clock_at(1299);
        write_entries(&pool, &audit, &clock).await;
        assert_eq!(crate::audit::verify(&path).unwrap(), 0);
        time.0.store(1300, Ordering::SeqCst);
        let written = write_entries(&pool, &audit, &clock).await;
        assert_eq!(written.outcome, AuditOutcome::Recorded);
        // The entry, and the note that it is late.
        assert_eq!(crate::audit::verify(&path).unwrap(), 2);
    }

    #[tokio::test]
    async fn a_claim_stamped_ahead_of_the_clock_is_taken_over() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, audit, path) = setup(&dir).await;
        commit_one(&pool, 1000).await;
        sqlx::query("UPDATE unwritten_audit SET claim = 'gone', claimed_at = 5000")
            .execute(&pool)
            .await
            .unwrap();
        let (_, clock) = clock_at(1000);
        write_entries(&pool, &audit, &clock).await;
        assert_eq!(crate::audit::verify(&path).unwrap(), 1);
    }

    #[tokio::test]
    async fn a_stalled_log_does_not_hold_up_the_answer() {
        let dir = tempfile::tempdir().unwrap();
        let (pool, audit, path) = setup(&dir).await;
        commit_one(&pool, 1000).await;
        // Another writer holds the lock throughout, so the write cannot succeed,
        // whether it gives up first or this does.
        let holder = std::fs::File::open(&path).unwrap();
        holder.lock().unwrap();
        let (_, clock) = clock_at(1000);
        let written = write_entries(&pool, &audit, &clock).await;
        assert_eq!(written.outcome, AuditOutcome::Missing);
        assert!(written.cause.is_some());
    }
}
