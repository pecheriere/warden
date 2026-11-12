//! Approving a GitHub token grant ends the agent's grants that cover one of the same
//! repositories, in the transaction that stores the new one, and no others. A grant
//! from before grants were scoped names no repository, so any approval ends it.

use sqlx::{Row as _, Sqlite, Transaction};
use warden_broker_proto::github_token::GrantScope;
use warden_broker_proto::{AgentName, GrantAccess, GrantView, Id};

use super::decide::same_ids;
use super::{ReplacedGrant, RequestError, Requests, parse};
use crate::audit::AuditEvent;

/// Recorded as `by` for a GitHub token grant ended by approving one that overlaps it.
const REPLACED: &str = "replaced";

/// The scope of the GitHub token grant stored as `view`.
fn scope_of(view: &str) -> Result<GrantScope, RequestError> {
    let view: GrantView = serde_json::from_str(view)?;
    match view.access {
        GrantAccess::GithubToken(grant) => Ok(grant.repositories),
        _ => Err(RequestError::Corrupt(
            "GitHub token grant changed kind".to_owned(),
        )),
    }
}

impl Requests {
    /// The agent's active GitHub token grants that cover one of the repositories of
    /// `new`; a legacy grant always does.
    pub(super) async fn overlapping_grants(
        &self,
        agent: &AgentName,
        new: &GrantScope,
    ) -> Result<Vec<ReplacedGrant>, RequestError> {
        let mut found = Vec::new();
        for row in self.active_rows(agent, "github_token").await? {
            let view: String = row.try_get("view")?;
            let scope = scope_of(&view)?;
            if scope.overlaps(new) {
                found.push(ReplacedGrant {
                    grant_id: parse(&row, "id")?,
                    scope,
                });
            }
        }
        Ok(found)
    }

    /// The entries for ending the active GitHub token grants of `agent` that the new
    /// grant `kept` of `access` overlaps, and their ids: one `grant_revoked` and one
    /// `github_token_grant_replaced` for each. Written with the approval, before
    /// anything changes; [`end_overlapping`] ends what is there when it commits, and
    /// refuses if that is not these. Empty for any other kind.
    pub(super) async fn github_replaced_events(
        &self,
        agent: &AgentName,
        kept: &Id,
        access: &GrantAccess,
    ) -> Result<(Vec<AuditEvent>, Vec<Id>), RequestError> {
        let GrantAccess::GithubToken(new) = access else {
            return Ok((Vec::new(), Vec::new()));
        };
        let mut events = Vec::new();
        let mut ids = Vec::new();
        for replaced in self.overlapping_grants(agent, &new.repositories).await? {
            events.push(AuditEvent::GrantRevoked {
                grant_id: replaced.grant_id.clone(),
                by: REPLACED.to_owned(),
            });
            events.push(AuditEvent::GithubTokenGrantReplaced {
                grant_id: replaced.grant_id.clone(),
                by_grant: kept.clone(),
                repository_ids: replaced.scope.overlapping_ids(&new.repositories),
            });
            ids.push(replaced.grant_id);
        }
        Ok((events, ids))
    }
}

/// End the other active GitHub token grants of `agent` that overlap `new`, in `tx`,
/// which also stores `kept`, the grant replacing them, and mark their requests
/// revoked. Returns those requests.
///
/// The grants are selected inside the write transaction, so a grant approved a moment
/// earlier is seen. They must be exactly `expected`, the ones the approval wrote its
/// entries for: anything else rolls the approval back rather than end a grant
/// unrecorded or leave one of the overlapping grants active.
///
/// # Errors
/// [`RequestError::ReplacedChanged`] when the grants to end are not `expected`; storage
/// failures.
pub(super) async fn end_overlapping(
    tx: &mut Transaction<'static, Sqlite>,
    agent: &AgentName,
    kept: &Id,
    new: &GrantScope,
    expected: &[Id],
    now: i64,
) -> Result<Vec<Id>, RequestError> {
    let rows = sqlx::query(
        "SELECT id, request_id, view FROM grants \
         WHERE agent = ?1 AND id != ?2 AND revoked_at IS NULL AND not_after > ?3 \
         AND json_extract(view, '$.access.kind') = 'github_token'",
    )
    .bind(agent.as_str())
    .bind(kept.as_str())
    .bind(now)
    .fetch_all(&mut **tx)
    .await?;
    let mut grants: Vec<(Id, Id)> = Vec::new();
    for row in &rows {
        let view: String = row.try_get("view")?;
        if scope_of(&view)?.overlaps(new) {
            grants.push((parse(row, "id")?, parse(row, "request_id")?));
        }
    }
    let found: Vec<Id> = grants.iter().map(|(id, _)| id.clone()).collect();
    if !same_ids(&found, expected) {
        return Err(RequestError::ReplacedChanged);
    }
    let mut requests = Vec::new();
    for (grant, request) in grants {
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
