//! Approving a GitHub token grant ends the agent's grants that cover one of the same
//! repositories with exactly the same extra permissions, in the transaction that stores
//! the new one, and no others: an agent holds at most one grant per repository and set
//! of extras. The owner's default is no part of the comparison, so changing it does not
//! keep an old grant alive past its renewal. A grant from before grants were scoped
//! names no repository, so any approval ends it, whatever its permissions.

use sqlx::{Row as _, Sqlite, Transaction};
use warden_broker_proto::github_permissions::PermissionSet;
use warden_broker_proto::github_token::GrantScope;
use warden_broker_proto::{AgentName, GrantAccess, Id};

use super::decide::same_ids;
use super::{
    ReplacedGrant, RequestError, Requests, github_extras_of, github_permissions_of, parse,
    stored_view,
};
use crate::audit::AuditEvent;

/// Recorded as `by` for a GitHub token grant ended by approving one that overlaps it.
const REPLACED: &str = "replaced";

/// What a stored GitHub token grant is compared by.
struct Held {
    scope: GrantScope,
    /// What its tokens have.
    permissions: PermissionSet,
    /// The extras it was approved with; `None` for none.
    extras: Option<PermissionSet>,
}

impl Held {
    /// Whether approving a grant of `new` with `extras` ends this one: it covers one of
    /// the same repositories and was approved with the same extras (none being none),
    /// or it is a legacy grant, which names no repository and is ended by any approval.
    fn replaced_by(&self, new: &GrantScope, extras: Option<&PermissionSet>) -> bool {
        self.scope.overlaps(new) && (self.scope.is_legacy() || self.extras.as_ref() == extras)
    }
}

/// The scope, permissions and extras of the GitHub token grant stored as `view`.
fn held_by(view: &str) -> Result<Held, RequestError> {
    let view = stored_view(view)?;
    match view.access {
        GrantAccess::GithubToken(grant) => Ok(Held {
            permissions: github_permissions_of(&grant)?,
            extras: github_extras_of(&grant)?,
            scope: grant.repositories,
        }),
        _ => Err(RequestError::Corrupt(
            "GitHub token grant changed kind".to_owned(),
        )),
    }
}

impl Requests {
    /// The agent's active GitHub token grants that cover one of the repositories of
    /// `new` and were approved with exactly `extras`; a legacy grant always qualifies,
    /// whatever it holds.
    pub(super) async fn overlapping_grants(
        &self,
        agent: &AgentName,
        new: &GrantScope,
        extras: Option<&PermissionSet>,
    ) -> Result<Vec<ReplacedGrant>, RequestError> {
        self.grants_covering(agent, |held| held.replaced_by(new, extras))
            .await
    }

    /// The agent's active GitHub token grants that cover one of the repositories of
    /// `new` and were approved with other extras than `extras`: the ones approving
    /// leaves live. Never a legacy grant, which any approval ends.
    pub(super) async fn other_live_grants(
        &self,
        agent: &AgentName,
        new: &GrantScope,
        extras: Option<&PermissionSet>,
    ) -> Result<Vec<ReplacedGrant>, RequestError> {
        self.grants_covering(agent, |held| {
            held.scope.overlaps(new) && !held.replaced_by(new, extras)
        })
        .await
    }

    /// The agent's active GitHub token grants that `keep` selects.
    async fn grants_covering(
        &self,
        agent: &AgentName,
        keep: impl Fn(&Held) -> bool,
    ) -> Result<Vec<ReplacedGrant>, RequestError> {
        let mut found = Vec::new();
        for row in self.active_rows(agent, "github_token").await? {
            let view: String = row.try_get("view")?;
            let held = held_by(&view)?;
            if keep(&held) {
                found.push(ReplacedGrant {
                    grant_id: parse(&row, "id")?,
                    scope: held.scope,
                    permissions: held.permissions,
                    not_after: row.try_get("not_after")?,
                });
            }
        }
        Ok(found)
    }

    /// The entries for ending the active GitHub token grants of `agent` that the new
    /// grant `kept` of `access` overlaps with the same extras, and their ids: one `grant_revoked` and one
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
        let extras = github_extras_of(new)?;
        for replaced in self
            .overlapping_grants(agent, &new.repositories, extras.as_ref())
            .await?
        {
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

/// End the other active GitHub token grants of `agent` that overlap `new` and hold
/// `extras`, in `tx`,
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
    extras: Option<&PermissionSet>,
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
        if held_by(&view)?.replaced_by(new, extras) {
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
