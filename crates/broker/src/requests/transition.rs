//! How a state change is made: on its own task, and never with the audit log in
//! the middle of a database write. Writing the log can take as long as its disk
//! does, and a write transaction blocks every other writer, a revocation included.
//!
//! So a change that must not happen without its entry writes the entry first, with
//! [`record`], and only then opens its transaction. If it then cannot apply,
//! [`note_if_not_applied`] says so on the record. A change that ends access does not
//! wait for the log at all: see [`super::revocation`].

use std::fmt::Display;

use sqlx::{Sqlite, SqlitePool, Transaction};

use super::RequestError;
use crate::audit::{AuditError, AuditEvent, AuditLog};

/// Write `events`, which come before `transition` is applied. Call this with no
/// write transaction open. If a later entry fails, the record says `transition`
/// did not take effect.
///
/// # Errors
/// The audit failure: the caller must not apply the change.
pub(crate) async fn record(
    audit: &AuditLog,
    events: Vec<AuditEvent>,
    transition: &str,
) -> Result<(), AuditError> {
    let mut recorded = false;
    for event in events {
        if let Err(e) = audit.append(event).await {
            if recorded {
                record_not_committed(audit, transition, &e.to_string()).await;
            }
            return Err(e);
        }
        recorded = true;
    }
    Ok(())
}

/// Say on the record that `transition`, already recorded, did not take effect if
/// `applied` is an error. Call this with its transaction closed.
pub(crate) async fn note_if_not_applied<T, E: Display>(
    audit: &AuditLog,
    applied: &Result<T, E>,
    transition: &str,
) {
    if let Err(e) = applied {
        record_not_committed(audit, transition, &e.to_string()).await;
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

    use super::{AuditEvent, AuditLog, note_if_not_applied, record};

    fn denied(id: &Id) -> AuditEvent {
        AuditEvent::Denied { id: id.clone() }
    }

    #[tokio::test]
    async fn a_recorded_change_that_cannot_apply_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).await.unwrap();
        let id = Id::random();
        let transition = format!("denial of request {id}");
        record(&audit, vec![denied(&id)], &transition)
            .await
            .unwrap();
        let applied: Result<(), &str> = Err("the database refused it");
        note_if_not_applied(&audit, &applied, &transition).await;

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
    }

    #[tokio::test]
    async fn a_change_that_applied_adds_nothing_to_the_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).await.unwrap();
        let applied: Result<(), &str> = Ok(());
        note_if_not_applied(&audit, &applied, "a change").await;
        assert_eq!(crate::audit::verify(&path).unwrap(), 0);
    }

    #[tokio::test]
    async fn an_entry_that_cannot_be_written_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).await.unwrap();
        // An unreadable last line refuses every append.
        std::fs::write(&path, b"not an audit line\n").unwrap();
        let got = record(&audit, vec![denied(&Id::random())], "a change").await;
        assert!(got.is_err(), "{got:?}");
    }
}
