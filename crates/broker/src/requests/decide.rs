//! A request's status and its decisions: the long-poll, denial, cancellation
//! and approval into a grant.

use std::time::Duration;

use sqlx::sqlite::SqliteRow;
use sqlx::{Row as _, Sqlite, Transaction};
use warden_broker_proto::{
    AgentName, CreateRequest, GrantAccess, GrantView, Id, RequestStatus, Window,
};

use super::bus::next_change;
use super::revocation::commit_with_entries;
use super::transition::detached;
use super::{
    AuditOutcome, PendingView, RequestError, Requests, Scope, begin, commit_signing,
    note_if_not_applied, parse, record, sha256_hex,
};
use crate::audit::AuditEvent;
use crate::ssh_ca;

/// Longest a status long-poll may wait.
const MAX_WAIT: Duration = Duration::from_secs(30);

impl Requests {
    /// The state of `agent`'s request `id`. While it is pending and `wait`
    /// is non-zero, wait (at most 30 s) for it to change.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if no such request belongs to `agent`;
    /// storage failures.
    pub async fn status(
        &self,
        agent: &AgentName,
        id: &Id,
        wait: Duration,
    ) -> Result<RequestStatus, RequestError> {
        // Subscribe before the first read so no change can slip between them.
        let mut rx = self.bus.subscribe();
        let deadline = tokio::time::Instant::now() + wait.min(MAX_WAIT);
        loop {
            let status = self.read_status(agent, id).await?;
            if status != RequestStatus::Pending || wait.is_zero() {
                return Ok(status);
            }
            match tokio::time::timeout_at(deadline, next_change(&mut rx, id)).await {
                Ok(true) => {}
                Ok(false) | Err(_) => return self.read_status(agent, id).await,
            }
        }
    }

    async fn read_status(&self, agent: &AgentName, id: &Id) -> Result<RequestStatus, RequestError> {
        let row = self.status_row(agent, id).await?;
        let status: String = row.try_get("status")?;
        let expires_at: i64 = row.try_get("expires_at")?;
        if status == "pending" && expires_at <= self.clock.now() {
            self.expire_due(Scope::Request(id.clone())).await?;
            return to_status(&self.status_row(agent, id).await?);
        }
        to_status(&row)
    }

    async fn status_row(&self, agent: &AgentName, id: &Id) -> Result<SqliteRow, RequestError> {
        sqlx::query(
            "SELECT r.status, r.error, r.expires_at, g.view FROM requests r \
             LEFT JOIN grants g ON g.request_id = r.id WHERE r.id = ? AND r.agent = ?",
        )
        .bind(id.as_str())
        .bind(agent.as_str())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(RequestError::NotFound)
    }

    /// The pending request behind an approval token, with the current
    /// policy of its target or secret.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if the token is unknown or its request is
    /// no longer pending; backend and storage failures.
    pub async fn pending_for_token(&self, token: &str) -> Result<PendingView, RequestError> {
        let row = sqlx::query(
            "SELECT id, agent, fingerprint, body, expires_at FROM requests \
             WHERE approval_token_hash = ? AND status = 'pending' AND expires_at > ?",
        )
        .bind(sha256_hex(token))
        .bind(self.clock.now())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(RequestError::NotFound)?;
        let body: String = row.try_get("body")?;
        let request: CreateRequest = serde_json::from_str(&body)?;
        let destination = self.destination(&request).await?;
        Ok(PendingView {
            id: parse(&row, "id")?,
            agent: parse(&row, "agent")?,
            fingerprint: parse(&row, "fingerprint")?,
            destination,
            expires_at: row.try_get("expires_at")?,
            request,
        })
    }

    /// Deny the pending request behind `token`, whatever state the audit log is
    /// in; [`AuditOutcome::Missing`] says it is not on record yet.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] for an unknown token,
    /// [`RequestError::AlreadyDecided`] if it is no longer pending.
    pub async fn deny(&self, token: &str) -> Result<AuditOutcome, RequestError> {
        let this = self.clone();
        let token = token.to_owned();
        detached(async move { this.deny_now(&token).await }).await
    }

    async fn deny_now(&self, token: &str) -> Result<AuditOutcome, RequestError> {
        let hash = sha256_hex(token);
        let now = self.clock.now();
        let mut tx = begin(&self.pool).await?;
        let Some(row) = sqlx::query(
            "UPDATE requests SET status = 'denied', decided_at = ?1 \
             WHERE approval_token_hash = ?2 AND status = 'pending' AND expires_at > ?1 \
             RETURNING id",
        )
        .bind(now)
        .bind(&hash)
        .fetch_optional(&mut *tx)
        .await?
        else {
            drop(tx);
            return Err(self.not_pending(&hash).await);
        };
        let id: Id = parse(&row, "id")?;
        self.finish_denial(tx, &id, now).await
    }

    /// Commit the denial of `id` made in `tx`, with its audit entry, and tell
    /// whoever waits on the request.
    pub(super) async fn finish_denial(
        &self,
        tx: Transaction<'static, Sqlite>,
        id: &Id,
        now: i64,
    ) -> Result<AuditOutcome, RequestError> {
        let denied = AuditEvent::Denied { id: id.clone() };
        commit_with_entries(tx, vec![denied], now).await?;
        let outcome = self.settle_entries().await;
        self.bus.publish(id);
        Ok(outcome)
    }

    /// Withdraw `agent`'s own pending request `id`. The request becomes
    /// `cancelled` and its approval link stops working; nothing else about
    /// it changes.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if no such request belongs to `agent`;
    /// [`RequestError::AlreadyDecided`] if it is no longer pending (decided,
    /// cancelled or past its expiry).
    pub async fn cancel(&self, agent: &AgentName, id: &Id) -> Result<(), RequestError> {
        let this = self.clone();
        let (agent, id) = (agent.clone(), id.clone());
        detached(async move { this.cancel_now(&agent, &id).await }).await
    }

    async fn cancel_now(&self, agent: &AgentName, id: &Id) -> Result<(), RequestError> {
        let now = self.clock.now();
        let mut tx = begin(&self.pool).await?;
        let cancelled = sqlx::query(
            "UPDATE requests SET status = 'cancelled', decided_at = ?1 \
             WHERE id = ?2 AND agent = ?3 AND status = 'pending' AND expires_at > ?1",
        )
        .bind(now)
        .bind(id.as_str())
        .bind(agent.as_str())
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if cancelled == 0 {
            drop(tx);
            // Existence is only revealed for the agent's own requests.
            return Err(match self.status_row(agent, id).await {
                Ok(_) => RequestError::AlreadyDecided,
                Err(e) => e,
            });
        }
        let event = AuditEvent::RequestCancelled {
            id: id.clone(),
            agent: agent.clone(),
        };
        commit_with_entries(tx, vec![event], now).await?;
        self.settle_entries().await;
        self.bus.publish(id);
        Ok(())
    }

    /// Whether the approval link `token` belongs to a request its agent
    /// cancelled.
    ///
    /// # Errors
    /// Storage failures.
    pub async fn is_cancelled(&self, token: &str) -> Result<bool, RequestError> {
        Ok(sqlx::query(
            "SELECT 1 FROM requests WHERE approval_token_hash = ? AND status = 'cancelled'",
        )
        .bind(sha256_hex(token))
        .fetch_optional(&self.pool)
        .await?
        .is_some())
    }

    /// Approve the pending request behind `token` with `grant`, atomically:
    /// either the request flips to approved, the grant is stored and both
    /// are audited (with `cert_issued` for a grant holding a certificate), or
    /// nothing changes and the request stays pending. A grant's certificate
    /// reaches the agent only through the stored grant, so a certificate that
    /// could not be audited never leaves the broker.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] for an unknown token;
    /// [`RequestError::AlreadyDecided`] if the request is no longer pending,
    /// has expired or its agent was revoked; [`RequestError::Audit`] if an
    /// entry could not be written.
    pub async fn mark_approved(
        &self,
        token: &str,
        window: Window,
        grant: GrantView,
        passkey_id: &str,
    ) -> Result<(), RequestError> {
        let this = self.clone();
        let (token, passkey_id) = (token.to_owned(), passkey_id.to_owned());
        detached(async move {
            this.mark_approved_now(&token, window, grant, &passkey_id)
                .await
        })
        .await
    }

    async fn mark_approved_now(
        &self,
        token: &str,
        window: Window,
        grant: GrantView,
        passkey_id: &str,
    ) -> Result<(), RequestError> {
        let hash = sha256_hex(token);
        let now = self.clock.now();
        let window_secs = u32::try_from(window.secs())
            .map_err(|_| RequestError::Internal("window length out of range"))?;
        // The grant must span exactly the approved window.
        if grant.not_after.checked_sub(grant.not_before) != Some(i64::from(window_secs)) {
            return Err(RequestError::Internal(
                "grant validity does not match the window",
            ));
        }
        let _change = self.recorded_change.lock().await;
        // Checked here so an approval that cannot apply writes nothing; the
        // update below checks again.
        let Some(row) = sqlx::query(
            "SELECT id, agent FROM requests \
             WHERE approval_token_hash = ?1 AND status = 'pending' AND expires_at > ?2 \
             AND EXISTS (SELECT 1 FROM agents \
                         WHERE agents.name = requests.agent AND agents.revoked_at IS NULL)",
        )
        .bind(&hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?
        else {
            return Err(self.not_pending(&hash).await);
        };
        let id: Id = parse(&row, "id")?;
        let agent: AgentName = parse(&row, "agent")?;
        let view = serde_json::to_string(&grant)?;
        let renews = matches!(grant.access, GrantAccess::CommitSigning(_));
        let mut events = vec![AuditEvent::Approved {
            id: id.clone(),
            grant_id: grant.grant_id.clone(),
            window_secs,
            passkey_id: passkey_id.to_owned(),
        }];
        if matches!(grant.access, GrantAccess::Ssh(_)) {
            events.push(AuditEvent::CertIssued {
                key_id: ssh_ca::key_id(&agent, &grant.grant_id),
                grant_id: grant.grant_id.clone(),
                not_after: grant.not_after,
            });
        }
        if renews {
            events.extend(self.renewal_events(&agent).await?);
        }
        let transition = format!("approval of request {id}");
        record(&self.audit, events, &transition).await?;
        let applied = async {
            let mut tx = begin(&self.pool).await?;
            // The time again: writing the log may have taken long. The token again
            // too: a link that was replaced approves nothing.
            let approved = sqlx::query(
                "UPDATE requests SET status = 'approved', decided_at = ?1 \
                 WHERE id = ?2 AND approval_token_hash = ?3 \
                 AND status = 'pending' AND expires_at > ?1 \
                 AND EXISTS (SELECT 1 FROM agents \
                             WHERE agents.name = requests.agent AND agents.revoked_at IS NULL)",
            )
            .bind(self.clock.now())
            .bind(id.as_str())
            .bind(&hash)
            .execute(&mut *tx)
            .await?;
            if approved.rows_affected() == 0 {
                return Err(RequestError::AlreadyDecided);
            }
            sqlx::query(
                "INSERT INTO grants \
                 (id, request_id, agent, window_secs, not_before, not_after, view) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(grant.grant_id.as_str())
            .bind(id.as_str())
            .bind(agent.as_str())
            .bind(window_secs)
            .bind(grant.not_before)
            .bind(grant.not_after)
            .bind(&view)
            .execute(&mut *tx)
            .await?;
            let renewed = if renews {
                commit_signing::end_renewed(&mut tx, &agent, &grant.grant_id, self.clock.now())
                    .await?
            } else {
                Vec::new()
            };
            tx.commit().await?;
            Ok(renewed)
        }
        .await;
        note_if_not_applied(&self.audit, &applied, &transition).await;
        for request in applied? {
            self.bus.publish(&request);
        }
        self.bus.publish(&id);
        Ok(())
    }

    /// Why a token matched no pending request.
    pub(super) async fn not_pending(&self, hash: &str) -> RequestError {
        match sqlx::query("SELECT 1 FROM requests WHERE approval_token_hash = ?")
            .bind(hash)
            .fetch_optional(&self.pool)
            .await
        {
            Ok(Some(_)) => RequestError::AlreadyDecided,
            Ok(None) => RequestError::NotFound,
            Err(e) => e.into(),
        }
    }
}

fn to_status(row: &SqliteRow) -> Result<RequestStatus, RequestError> {
    let status: String = row.try_get("status")?;
    Ok(match status.as_str() {
        "pending" => RequestStatus::Pending,
        "approved" => {
            let view: Option<String> = row.try_get("view")?;
            let view = view
                .ok_or_else(|| RequestError::Corrupt("approved request has no grant".to_owned()))?;
            RequestStatus::Approved(serde_json::from_str(&view)?)
        }
        "denied" => RequestStatus::Denied,
        "expired" => RequestStatus::Expired,
        "cancelled" => RequestStatus::Cancelled,
        "revoked" => RequestStatus::Revoked,
        "error" => RequestStatus::Error {
            message: row
                .try_get::<Option<String>, _>("error")?
                .unwrap_or_else(|| "request failed".to_owned()),
        },
        other => return Err(RequestError::Corrupt(format!("unknown status {other}"))),
    })
}
