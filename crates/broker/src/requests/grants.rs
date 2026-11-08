//! Grants and history: the owner's and the relay's views of them, and
//! revoking a grant or an agent.

use sqlx::{Row as _, SqlitePool};
use warden_broker_proto::{
    Access, AgentName, CreateRequest, GrantAccess, GrantView, Id, TargetName,
};

use super::revocation::commit_with_entries;
use super::transition::detached;
use super::{
    ActiveGrant, AuditOutcome, GrantEnd, HistoryEntry, RelayGrantRecord, RequestError, Requests,
    begin, parse,
};
use crate::agents::{self, AgentError};
use crate::audit::AuditEvent;

/// Recorded as `by` for grants ended by revoking their agent.
const AGENT_REVOKE: &str = "agent revoke";

/// Active relay grants for a target (`?1` now, `?2` the target), with the
/// request that bound their key, longest lasting first. Grants are found by
/// `not_after` through its index, so a login check never scans the history.
pub(super) const ACTIVE_RELAY_GRANTS: &str = "\
    SELECT g.id, g.agent, g.not_after, g.view, r.body \
    FROM grants g JOIN requests r ON r.id = g.request_id \
    WHERE g.not_after > ?1 AND g.revoked_at IS NULL \
    AND json_extract(g.view, '$.access.kind') = 'relay' \
    AND json_extract(g.view, '$.access.target') = ?2 \
    ORDER BY g.not_after DESC, g.id";

/// Of the grants listed in `?2` (a JSON array of ids), those revoked or
/// past their window at `?1` (now), each with whether it was revoked.
/// Grants are found by primary key: the relay's periodic check costs one
/// lookup per grant with a live session.
pub(super) const ENDED_GRANTS: &str = "\
    SELECT id, revoked_at IS NOT NULL AS revoked FROM grants \
    WHERE id IN (SELECT value FROM json_each(?2)) \
    AND (revoked_at IS NOT NULL OR not_after <= ?1)";

impl Requests {
    /// Which of `grant_ids` are revoked or past their window now.
    ///
    /// # Errors
    /// Storage failures or unreadable stored rows.
    pub(crate) async fn ended_grants(
        &self,
        grant_ids: &[Id],
    ) -> Result<Vec<(Id, GrantEnd)>, RequestError> {
        let ids = serde_json::to_string(&grant_ids.iter().map(Id::as_str).collect::<Vec<_>>())?;
        sqlx::query(ENDED_GRANTS)
            .bind(self.clock.now())
            .bind(ids)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(|row| {
                let end = if row.try_get::<bool, _>("revoked")? {
                    GrantEnd::Revoked
                } else {
                    GrantEnd::Expired
                };
                Ok((parse(row, "id")?, end))
            })
            .collect()
    }

    /// End a grant now, whatever state the audit log is in: if its entry cannot
    /// be written, the owner is told and this returns [`AuditOutcome::Missing`].
    /// Revoking an already revoked grant changes nothing, and reports the same.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if no such grant exists; storage failures,
    /// which mean the grant was not revoked.
    pub async fn revoke_grant(
        &self,
        grant_id: &Id,
        by: &str,
    ) -> Result<AuditOutcome, RequestError> {
        let this = self.clone();
        let (grant_id, by) = (grant_id.clone(), by.to_owned());
        detached(async move { this.revoke_grant_now(&grant_id, &by).await }).await
    }

    async fn revoke_grant_now(
        &self,
        grant_id: &Id,
        by: &str,
    ) -> Result<AuditOutcome, RequestError> {
        let now = self.clock.now();
        let mut tx = begin(&self.pool).await?;
        let Some(row) = sqlx::query(
            "UPDATE grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL \
             RETURNING request_id",
        )
        .bind(now)
        .bind(grant_id.as_str())
        .fetch_optional(&mut *tx)
        .await?
        else {
            let exists = sqlx::query("SELECT 1 FROM grants WHERE id = ?")
                .bind(grant_id.as_str())
                .fetch_optional(&mut *tx)
                .await?;
            // Revoked already, perhaps by another process: its sessions and
            // calls end now rather than at their next check.
            drop(tx);
            exists.ok_or(RequestError::NotFound)?;
            self.sessions.revoke_grant(grant_id);
            self.proxy_calls.revoke_grant(grant_id);
            return Ok(self.settle_entries().await);
        };
        let request_id: Id = parse(&row, "request_id")?;
        sqlx::query("UPDATE requests SET status = 'revoked' WHERE id = ? AND status = 'approved'")
            .bind(request_id.as_str())
            .execute(&mut *tx)
            .await?;
        let revoked = AuditEvent::GrantRevoked {
            grant_id: grant_id.clone(),
            by: by.to_owned(),
        };
        commit_with_entries(tx, vec![revoked], now).await?;
        self.sessions.revoke_grant(grant_id);
        self.proxy_calls.revoke_grant(grant_id);
        let outcome = self.settle_entries().await;
        self.bus.publish(&request_id);
        if outcome == AuditOutcome::Missing {
            self.tell_owner_unaudited(format!("Revoking grant {grant_id}"));
        }
        Ok(outcome)
    }

    /// Revoke an agent and everything it holds, whatever state the audit log is
    /// in (the owner is told if its entries cannot be written); see
    /// [`revoke_agent`].
    ///
    /// # Errors
    /// [`RequestError::UnknownAgent`] or storage failures.
    pub async fn revoke_agent(&self, name: &AgentName) -> Result<AuditOutcome, RequestError> {
        let this = self.clone();
        let name = name.clone();
        detached(async move {
            let affected = revoke_agent(&this.pool, &name, this.clock.now()).await?;
            this.sessions.revoke_agent(&name);
            this.proxy_calls.revoke_agent(&name);
            let outcome = this.settle_entries().await;
            for id in &affected {
                this.bus.publish(id);
            }
            if outcome == AuditOutcome::Missing {
                this.tell_owner_unaudited(format!("Revoking agent {name}"));
            }
            Ok(outcome)
        })
        .await
    }

    /// The most recent `limit` requests, newest first, for the owner's
    /// read-only history.
    ///
    /// # Errors
    /// Storage failures or unreadable stored rows.
    pub async fn history(&self, limit: u32) -> Result<Vec<HistoryEntry>, RequestError> {
        let rows = sqlx::query(
            "SELECT r.id, r.agent, r.fingerprint, r.body, r.status, r.created_at, g.window_secs \
             FROM requests r LEFT JOIN grants g ON g.request_id = r.id \
             ORDER BY r.created_at DESC, r.rowid DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let body: String = row.try_get("body")?;
                Ok(HistoryEntry {
                    id: parse(row, "id")?,
                    agent: parse(row, "agent")?,
                    fingerprint: parse(row, "fingerprint")?,
                    request: serde_json::from_str(&body)?,
                    status: row.try_get("status")?,
                    created_at: row.try_get("created_at")?,
                    granted_secs: row.try_get("window_secs")?,
                })
            })
            .collect()
    }

    /// Grants that are neither revoked nor expired, soonest expiry first.
    ///
    /// # Errors
    /// Storage failures or unreadable stored rows.
    pub async fn active_grants(&self) -> Result<Vec<ActiveGrant>, RequestError> {
        let rows = sqlx::query(
            "SELECT g.id, g.agent, g.not_before, g.not_after, g.view, r.body, r.fingerprint \
             FROM grants g JOIN requests r ON r.id = g.request_id \
             WHERE g.revoked_at IS NULL AND g.not_after > ? ORDER BY g.not_after, g.id",
        )
        .bind(self.clock.now())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let body: String = row.try_get("body")?;
                let view: String = row.try_get("view")?;
                let view: GrantView = serde_json::from_str(&view)?;
                Ok(ActiveGrant {
                    grant_id: parse(row, "id")?,
                    agent: parse(row, "agent")?,
                    fingerprint: parse(row, "fingerprint")?,
                    request: serde_json::from_str(&body)?,
                    access: view.access,
                    not_before: row.try_get("not_before")?,
                    not_after: row.try_get("not_after")?,
                })
            })
            .collect()
    }

    /// The usable grants (neither revoked nor expired) of `agent`, soonest
    /// expiry first.
    ///
    /// # Errors
    /// Storage failures or unreadable stored rows.
    pub async fn grants_for(&self, agent: &AgentName) -> Result<Vec<GrantView>, RequestError> {
        let rows = sqlx::query(
            "SELECT view FROM grants WHERE agent = ? AND revoked_at IS NULL AND not_after > ? \
             ORDER BY not_after, id",
        )
        .bind(agent.as_str())
        .bind(self.clock.now())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let view: String = row.try_get("view")?;
                Ok(serde_json::from_str(&view)?)
            })
            .collect()
    }

    /// Grant `grant_id` of `agent` as approved, whatever its state, and
    /// whether it was revoked. Whether it expired is the caller's check
    /// against `not_after`.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if the grant does not exist or belongs to
    /// another agent; storage failures or an unreadable stored grant.
    pub async fn agent_grant(
        &self,
        agent: &AgentName,
        grant_id: &Id,
    ) -> Result<(GrantView, bool), RequestError> {
        let row = sqlx::query("SELECT view, revoked_at FROM grants WHERE id = ? AND agent = ?")
            .bind(grant_id.as_str())
            .bind(agent.as_str())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(RequestError::NotFound)?;
        let view: String = row.try_get("view")?;
        let revoked_at: Option<i64> = row.try_get("revoked_at")?;
        Ok((serde_json::from_str(&view)?, revoked_at.is_some()))
    }

    /// The active (neither revoked nor expired) relay grant for `target`
    /// whose approved request bound `public_key`, if there is one: the relay
    /// admits an agent offering that key for that target. Keys are compared
    /// by key data, so comments do not matter. If several match, the one
    /// lasting longest is returned.
    ///
    /// # Errors
    /// Storage failures or unreadable stored rows.
    pub async fn active_relay_grant(
        &self,
        target: &TargetName,
        public_key: &ssh_key::PublicKey,
    ) -> Result<Option<RelayGrantRecord>, RequestError> {
        let rows = sqlx::query(ACTIVE_RELAY_GRANTS)
            .bind(self.clock.now())
            .bind(target.as_str())
            .fetch_all(&self.pool)
            .await?;
        for row in &rows {
            let body: String = row.try_get("body")?;
            let request: CreateRequest = serde_json::from_str(&body)?;
            let Access::Ssh {
                public_key: bound, ..
            } = &request.access
            else {
                return Err(RequestError::Corrupt(
                    "relay grant for a non-SSH request".to_owned(),
                ));
            };
            let bound = ssh_key::PublicKey::from_openssh(bound)
                .map_err(|e| RequestError::Corrupt(format!("bound public key: {e}")))?;
            if bound.key_data() != public_key.key_data() {
                continue;
            }
            let view: String = row.try_get("view")?;
            let view: GrantView = serde_json::from_str(&view)?;
            let GrantAccess::Relay(grant) = view.access else {
                return Err(RequestError::Corrupt("relay grant changed kind".to_owned()));
            };
            if grant.target != *target {
                return Err(RequestError::Corrupt(
                    "relay grant changed target".to_owned(),
                ));
            }
            return Ok(Some(RelayGrantRecord {
                grant_id: parse(row, "id")?,
                agent: parse(row, "agent")?,
                target: grant.target,
                user: grant.user,
                destination_digest: grant.digest,
                not_after: row.try_get("not_after")?,
            }));
        }
        Ok(None)
    }

    /// End a grant on behalf of the agent that holds it, as
    /// [`Requests::revoke_grant`] does. Revoking an already revoked grant does
    /// nothing.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if the grant does not exist or belongs to
    /// another agent; storage failures.
    pub async fn revoke_agent_grant(
        &self,
        agent: &AgentName,
        grant_id: &Id,
    ) -> Result<AuditOutcome, RequestError> {
        sqlx::query("SELECT 1 FROM grants WHERE id = ? AND agent = ?")
            .bind(grant_id.as_str())
            .bind(agent.as_str())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(RequestError::NotFound)?;
        self.revoke_grant(grant_id, &format!("agent:{agent}")).await
    }
}

/// Revoke agent `name` at `now` in one transaction: its key stops working,
/// its pending requests end as revoked, and its active grants are revoked
/// (their requests too). Returns the ids of every affected request so a
/// running server can wake their long-polls.
///
/// This does not touch the audit log: the entries wait in the database, and the
/// caller then writes them with [`write_entries`](crate::requests::write_entries) and reports what it could not.
///
/// When this runs in another process (the `agent revoke` admin command), the
/// server's in-process [`StatusBus`](crate::requests::StatusBus) is not told; its long-polls see
/// `revoked` on their next re-read, within the 30 s wait cap, and its relay
/// ends the agent's sessions at its next grant check (every second).
///
/// # Errors
/// [`RequestError::UnknownAgent`] if no such agent exists; storage failures
/// (nothing changes then).
pub async fn revoke_agent(
    pool: &SqlitePool,
    name: &AgentName,
    now: i64,
) -> Result<Vec<Id>, RequestError> {
    let mut tx = begin(pool).await?;
    agents::revoke(&mut *tx, name, now)
        .await
        .map_err(|e| match e {
            AgentError::Unknown => RequestError::UnknownAgent(name.clone()),
            AgentError::Db(e) => RequestError::Db(e),
            other => RequestError::Agent(other),
        })?;
    let mut affected = sqlx::query(
        "UPDATE requests SET status = 'revoked', decided_at = ?1 \
         WHERE agent = ?2 AND status = 'pending' RETURNING id",
    )
    .bind(now)
    .bind(name.as_str())
    .fetch_all(&mut *tx)
    .await?
    .iter()
    .map(|row| parse(row, "id"))
    .collect::<Result<Vec<Id>, _>>()?;
    let grants = sqlx::query(
        "UPDATE grants SET revoked_at = ?1 \
         WHERE agent = ?2 AND revoked_at IS NULL AND not_after > ?1 \
         RETURNING id, request_id",
    )
    .bind(now)
    .bind(name.as_str())
    .fetch_all(&mut *tx)
    .await?
    .iter()
    .map(|row| Ok((parse(row, "id")?, parse(row, "request_id")?)))
    .collect::<Result<Vec<(Id, Id)>, RequestError>>()?;
    for (_, request_id) in &grants {
        sqlx::query("UPDATE requests SET status = 'revoked' WHERE id = ? AND status = 'approved'")
            .bind(request_id.as_str())
            .execute(&mut *tx)
            .await?;
    }
    let mut events = vec![AuditEvent::AgentRevoked {
        agent: name.clone(),
    }];
    for (grant_id, request_id) in grants {
        events.push(AuditEvent::GrantRevoked {
            grant_id,
            by: AGENT_REVOKE.to_owned(),
        });
        affected.push(request_id);
    }
    commit_with_entries(tx, events, now).await?;
    Ok(affected)
}
