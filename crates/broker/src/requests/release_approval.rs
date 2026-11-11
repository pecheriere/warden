//! What approving a release request needs from the store and from GitHub: the facts
//! the owner was shown, a second look at GitHub when the owner decides, the row that
//! tracks the grant's steps, and how far those have come.
//!
//! Nothing GitHub said is quoted in an error here either.

use sqlx::{Row as _, Sqlite, Transaction};
use warden_broker_proto::release::{ReleaseGrant, ReleaseTag, RepoName};
use warden_broker_proto::{Access, AgentName, GrantAccess, GrantView, Id, Window};

use super::{PendingView, ReleaseFacts, RequestError, Requests, parse};
use crate::audit::AuditEvent;

/// Recorded as `by` for a release grant ended by approving the grant that replaces it.
const REPLACED: &str = "replaced by a new release grant";

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

/// End the other active release grants of `agent` that `kept`, the grant replacing
/// them, replaces, at `now`, in `tx`, which also stores it. They are selected here,
/// inside the transaction, so a grant stored since the audit entries were written is
/// ended too. Their requests are marked revoked, as revoking one on the owner's
/// screen does, and returned.
pub(super) async fn end_replaced(
    tx: &mut Transaction<'static, Sqlite>,
    agent: &AgentName,
    kept: &Id,
    new: &ReleaseGrant,
    now: i64,
) -> Result<Vec<Id>, RequestError> {
    let rows = sqlx::query(
        "SELECT id, request_id, view FROM grants \
         WHERE agent = ?1 AND id != ?2 AND revoked_at IS NULL AND not_after > ?3 \
         AND json_extract(view, '$.access.kind') = 'release'",
    )
    .bind(agent.as_str())
    .bind(kept.as_str())
    .bind(now)
    .fetch_all(&mut **tx)
    .await?;
    let mut requests = Vec::new();
    for row in &rows {
        if !replaces(row, new)? {
            continue;
        }
        let grant: Id = parse(row, "id")?;
        let request: Id = parse(row, "request_id")?;
        sqlx::query("UPDATE grants SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL")
            .bind(now)
            .bind(grant.as_str())
            .execute(&mut **tx)
            .await?;
        sqlx::query("UPDATE requests SET status = 'revoked' WHERE id = ? AND status = 'approved'")
            .bind(request.as_str())
            .execute(&mut **tx)
            .await?;
        requests.push(request);
    }
    Ok(requests)
}

/// Whether the release grant in `row` (with a `view`) is one `new` replaces.
fn replaces(row: &sqlx::sqlite::SqliteRow, new: &ReleaseGrant) -> Result<bool, RequestError> {
    let view: String = row.try_get("view")?;
    let view: GrantView = serde_json::from_str(&view)?;
    let GrantAccess::Release(grant) = view.access else {
        return Err(RequestError::Corrupt(
            "release grant changed kind".to_owned(),
        ));
    };
    Ok(same_release(&grant.repository, &grant.tag, new))
}

impl Requests {
    /// The entries for ending the active release grants of `agent` that a new grant
    /// of `access` for the same repository (matched ignoring ASCII case, as
    /// [`Requests::active_release`] does) and tag replaces. Written with the approval,
    /// before anything changes; [`end_replaced`] ends what is there when it commits.
    /// Empty for any other kind.
    pub(super) async fn release_replaced_events(
        &self,
        agent: &AgentName,
        access: &GrantAccess,
    ) -> Result<Vec<AuditEvent>, RequestError> {
        let GrantAccess::Release(new) = access else {
            return Ok(Vec::new());
        };
        let mut events = Vec::new();
        for row in self.active_rows(agent, "release").await? {
            if replaces(&row, new)? {
                events.push(AuditEvent::GrantRevoked {
                    grant_id: parse(&row, "id")?,
                    by: REPLACED.to_owned(),
                });
            }
        }
        Ok(events)
    }

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

fn same_release(repository: &RepoName, tag: &ReleaseTag, new: &ReleaseGrant) -> bool {
    repository.matches(&new.repository) && *tag == new.tag
}
