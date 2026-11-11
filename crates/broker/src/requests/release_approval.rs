//! What approving a release request needs from the store and from GitHub: the facts
//! the owner was shown, a second look at GitHub when the owner decides, the row that
//! tracks the grant's steps, and how far those have come.
//!
//! Nothing GitHub said is quoted in an error here either.

use sqlx::{Row as _, Sqlite, Transaction};
use warden_broker_proto::{Access, Id, Window};

use super::{PendingView, ReleaseFacts, RequestError, Requests};

/// What the owner is told when GitHub no longer says what the page showed. Fixed:
/// it quotes nothing from GitHub.
const CHANGED: &str = "the release changed on GitHub since this request was made; \
                       ask the agent to request it again";

/// Which of a release grant's steps have been claimed. A step is claimed once, just
/// before it is done, and a claim is never given back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseProgress {
    /// The tag step.
    pub tag: bool,
    /// The manifest step.
    pub manifest: bool,
    /// The publish step.
    pub publish: bool,
}

impl ReleaseProgress {
    /// Read from a row that selects the `release_steps` columns of a `LEFT JOIN`.
    pub(super) fn of(row: &sqlx::sqlite::SqliteRow) -> Result<Self, sqlx::Error> {
        let claimed = |column: &str| -> Result<bool, sqlx::Error> {
            Ok(row.try_get::<Option<i64>, _>(column)?.is_some())
        };
        Ok(Self {
            tag: claimed("tag_claimed_at")?,
            manifest: claimed("manifest_claimed_at")?,
            publish: claimed("publish_claimed_at")?,
        })
    }
}

/// Start tracking the steps of release grant `grant`, in the transaction that
/// stores the grant, so a grant never exists without its row.
pub(super) async fn insert_steps(
    tx: &mut Transaction<'static, Sqlite>,
    grant: &Id,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO release_steps (grant_id) VALUES (?)")
        .bind(grant.as_str())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

impl Requests {
    /// What GitHub said when release request `id` was made.
    ///
    /// # Errors
    /// [`RequestError::Corrupt`] when the request has no facts or they cannot be
    /// read; storage failures.
    pub(super) async fn release_facts(&self, id: &Id) -> Result<ReleaseFacts, RequestError> {
        let row = sqlx::query("SELECT facts FROM release_facts WHERE request_id = ?")
            .bind(id.as_str())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| RequestError::Corrupt("release request has no facts".to_owned()))?;
        let facts: String = row.try_get("facts")?;
        Ok(serde_json::from_str(&facts)?)
    }

    /// Ask GitHub again, as the owner decides, and refuse unless the tag and the
    /// commit's place on the default branch are what the page showed. The key and
    /// the App are read again too; whether they are still what the owner approved
    /// is for the caller to check against the destination digest.
    ///
    /// # Errors
    /// [`RequestError::Rejected`] with a fixed message when GitHub cannot be asked,
    /// answers anything unexpected, or no longer says what the owner was shown; the
    /// backend's errors.
    pub async fn recheck_release(&self, view: &PendingView) -> Result<(), RequestError> {
        let (Access::Release { .. }, Some(shown)) = (&view.request.access, &view.release) else {
            return Err(RequestError::Internal("not a release request"));
        };
        let slot = self
            .release_slot(Window::D1, &view.request.access, &view.agent)
            .await?;
        let now = self.check_release(&slot).await?;
        if now.tag_in_place != shown.tag_in_place
            || now.on_default_branch != shown.on_default_branch
        {
            return Err(RequestError::Rejected(CHANGED.to_owned()));
        }
        Ok(())
    }
}
