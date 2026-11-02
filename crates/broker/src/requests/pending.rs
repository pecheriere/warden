//! What the owner's pending screen needs: the list of requests waiting for a
//! decision, a new approval link for one, and denying one by its id.

use sqlx::Row as _;
use url::Url;
use warden_broker_proto::{Access, AgentName, CreateRequest, Fingerprint, Id};

use super::transition::detached;
use super::{
    AuditOutcome, Destination, RequestError, Requests, approval_token, begin, note_if_not_applied,
    parse, record, sha256_hex,
};
use crate::audit::AuditEvent;

/// A request waiting for the owner's decision.
#[derive(Debug, Clone)]
pub struct PendingEntry {
    /// Request id.
    pub id: Id,
    /// Requesting agent.
    pub agent: AgentName,
    /// Fingerprint the agent also sees.
    pub fingerprint: Fingerprint,
    /// The request as made.
    pub request: CreateRequest,
    /// The current policy of what it asks for, or `None` if it could not be
    /// read. The owner can still deny the request, and its approval page says
    /// why it cannot be approved.
    pub destination: Option<Destination>,
    /// When the request expires, Unix seconds.
    pub expires_at: i64,
}

impl Requests {
    /// Every request still waiting for a decision, soonest expiry first. Their
    /// number is bounded by the agents' pending limit. One past its expiry that
    /// no sweep has reached yet is left out.
    ///
    /// # Errors
    /// Storage failures or unreadable stored rows. A policy that cannot be read
    /// is not an error: see [`PendingEntry::destination`].
    pub async fn pending_requests(&self) -> Result<Vec<PendingEntry>, RequestError> {
        let rows = sqlx::query(
            "SELECT id, agent, fingerprint, body, expires_at FROM requests \
             WHERE status = 'pending' AND expires_at > ? ORDER BY expires_at, rowid",
        )
        .bind(self.clock.now())
        .fetch_all(&self.pool)
        .await?;
        let mut entries = Vec::with_capacity(rows.len());
        // Once the backend is out, one wait for it is enough: the list must still
        // come up, for the owner to deny from.
        let mut backend_out = false;
        for row in &rows {
            let body: String = row.try_get("body")?;
            let request: CreateRequest = serde_json::from_str(&body)?;
            let destination = if backend_out {
                None
            } else {
                match self.destination(&request).await {
                    Ok(destination) => Some(destination),
                    Err(e) => {
                        backend_out = matches!(e, RequestError::Unavailable(_));
                        tracing::warn!(error = %e, "policy of a pending request unreadable");
                        None
                    }
                }
            };
            entries.push(PendingEntry {
                id: parse(row, "id")?,
                agent: parse(row, "agent")?,
                fingerprint: parse(row, "fingerprint")?,
                request,
                destination,
                expires_at: row.try_get("expires_at")?,
            });
        }
        Ok(entries)
    }

    /// The current policy of what `request` asks for.
    pub(super) async fn destination(
        &self,
        request: &CreateRequest,
    ) -> Result<Destination, RequestError> {
        Ok(match &request.access {
            Access::Ssh { target, .. } => Destination::Ssh(self.backend.ssh_target(target).await?),
            Access::Api { secret, .. } => Destination::Api(
                self.backend
                    .api_secret(secret)
                    .await
                    .map_err(RequestError::from_secret_lookup)?,
            ),
        })
    }

    /// Why `token` matches no pending request:
    /// [`RequestError::AlreadyDecided`] if its request has ended,
    /// [`RequestError::NotFound`] if no request holds it (it never existed or was
    /// replaced), or the storage failure.
    pub async fn why_not_pending(&self, token: &str) -> RequestError {
        self.not_pending(&sha256_hex(token)).await
    }

    /// Give pending request `id` a new approval link, which is returned, and
    /// make the one it had stop working. Only a hash of a token is kept, so this
    /// is the only way to show the owner a link again. Nothing is approved by
    /// this: the link leads to the passkey, like the first one.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if no request with that id is pending any more
    /// (decided, cancelled, past its expiry, or never there);
    /// [`RequestError::Audit`] if its entry could not be written, in which case
    /// the old link keeps working; storage failures.
    pub async fn replace_link(&self, id: &Id) -> Result<Url, RequestError> {
        let this = self.clone();
        let id = id.clone();
        detached(async move { this.replace_link_now(&id).await }).await
    }

    async fn replace_link_now(&self, id: &Id) -> Result<Url, RequestError> {
        let token = approval_token()?;
        let link = self.approval_link(&token)?;
        // An approval on the old link holds this while it checks and applies, so
        // it finishes first or finds the link gone.
        let _change = self.recorded_change.lock().await;
        // Checked here so a replacement that cannot apply writes nothing; the
        // update below checks again.
        sqlx::query(
            "SELECT 1 FROM requests WHERE id = ? AND status = 'pending' AND expires_at > ?",
        )
        .bind(id.as_str())
        .bind(self.clock.now())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(RequestError::NotFound)?;
        let transition = format!("replacement of the approval link of request {id}");
        let replaced = AuditEvent::ApprovalLinkReplaced { id: id.clone() };
        record(&self.audit, vec![replaced], &transition).await?;
        let applied: Result<(), RequestError> = async {
            let mut tx = begin(&self.pool).await?;
            // The time again: writing the log may have taken long.
            let updated = sqlx::query(
                "UPDATE requests SET approval_token_hash = ?1 \
                 WHERE id = ?2 AND status = 'pending' AND expires_at > ?3",
            )
            .bind(sha256_hex(&token))
            .bind(id.as_str())
            .bind(self.clock.now())
            .execute(&mut *tx)
            .await?;
            if updated.rows_affected() == 0 {
                return Err(RequestError::NotFound);
            }
            tx.commit().await?;
            Ok(())
        }
        .await;
        note_if_not_applied(&self.audit, &applied, &transition).await;
        applied?;
        Ok(link)
    }

    /// Deny pending request `id`, as [`Requests::deny`] does for a token: whatever
    /// state the audit log is in, with [`AuditOutcome::Missing`] saying it is not
    /// on record yet.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if no request with that id is pending any more;
    /// storage failures.
    pub async fn deny_pending(&self, id: &Id) -> Result<AuditOutcome, RequestError> {
        let this = self.clone();
        let id = id.clone();
        detached(async move {
            let now = this.clock.now();
            let mut tx = begin(&this.pool).await?;
            let denied = sqlx::query(
                "UPDATE requests SET status = 'denied', decided_at = ?1 \
                 WHERE id = ?2 AND status = 'pending' AND expires_at > ?1",
            )
            .bind(now)
            .bind(id.as_str())
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if denied == 0 {
                return Err(RequestError::NotFound);
            }
            this.finish_denial(tx, &id, now).await
        })
        .await
    }
}
