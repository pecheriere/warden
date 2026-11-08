//! Expiry of pending requests and the periodic sweep.

use std::time::Duration;

use warden_broker_proto::Id;

use super::revocation::commit_with_entries;
use super::transition::detached;
use super::{RequestError, Requests, Scope, begin, parse, revocation};
use crate::audit::AuditEvent;

impl Requests {
    /// Expire every pending request past its deadline.
    ///
    /// # Errors
    /// Storage or audit failures.
    pub async fn sweep_expired(&self) -> Result<u64, RequestError> {
        let expired = self.expire_due(Scope::All).await?;
        u64::try_from(expired.len()).map_err(|_| RequestError::Internal("count out of range"))
    }

    /// Forget the nonces of signed requests whose retention has ended (see
    /// [`crate::signed::NONCE_RETENTION_SECS`]).
    ///
    /// # Errors
    /// Storage failures.
    pub async fn sweep_nonces(&self) -> Result<u64, RequestError> {
        Ok(crate::signed::sweep_nonces(&self.pool, self.clock.now()).await?)
    }

    pub(super) async fn expire_due(&self, scope: Scope) -> Result<Vec<Id>, RequestError> {
        let this = self.clone();
        detached(async move { this.expire_due_now(&scope).await }).await
    }

    async fn expire_due_now(&self, scope: &Scope) -> Result<Vec<Id>, RequestError> {
        let now = self.clock.now();
        let mut tx = begin(&self.pool).await?;
        let query = match scope {
            Scope::All => sqlx::query(
                "UPDATE requests SET status = 'expired', decided_at = ?1 \
                 WHERE status = 'pending' AND expires_at <= ?1 RETURNING id",
            )
            .bind(now),
            Scope::Dedupe(key) => sqlx::query(
                "UPDATE requests SET status = 'expired', decided_at = ?1 \
                 WHERE status = 'pending' AND expires_at <= ?1 AND dedupe_key = ?2 RETURNING id",
            )
            .bind(now)
            .bind(key),
            Scope::Request(id) => sqlx::query(
                "UPDATE requests SET status = 'expired', decided_at = ?1 \
                 WHERE status = 'pending' AND expires_at <= ?1 AND id = ?2 RETURNING id",
            )
            .bind(now)
            .bind(id.as_str()),
        };
        let ids = query
            .fetch_all(&mut *tx)
            .await?
            .iter()
            .map(|row| parse(row, "id"))
            .collect::<Result<Vec<Id>, _>>()?;
        if ids.is_empty() {
            return Ok(ids);
        }
        let events = ids
            .iter()
            .map(|id| AuditEvent::Expired { id: id.clone() })
            .collect();
        commit_with_entries(tx, events, now).await?;
        self.settle_entries().await;
        for id in &ids {
            self.bus.publish(id);
        }
        Ok(ids)
    }
}

/// Expire due pending requests, forget expired nonces and record held-back
/// limit refusals every `every` until `shutdown` changes (or its sender is dropped). Failures are logged
/// and never end the loop.
pub async fn sweep_loop(
    requests: Requests,
    every: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                match requests.sweep_expired().await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(expired = n, "expired pending requests"),
                    Err(e) => tracing::error!(error = %e, "expiry sweep failed"),
                }
                if let Err(e) = requests.sweep_nonces().await {
                    tracing::error!(error = %e, "nonce sweep failed");
                }
                requests.flush_waiting_entries().await;
                // On its own task: it writes the log, which may have stalled, and
                // must not hold up expiry or the waiting entries.
                let flushing = requests.clone();
                drop(tokio::spawn(async move { flushing.flush_refusals(false).await }));
                // On its own task too: it waits for the notification channels.
                let noticing = requests.clone();
                drop(tokio::spawn(async move { noticing.notify_ending_commit_signing().await }));
            }
            // Any change, or the sender going away, means stop.
            _ = shutdown.changed() => {
                let flushed = requests.flush_refusals(true);
                if tokio::time::timeout(revocation::WRITE_WAIT, flushed).await.is_err() {
                    tracing::error!("the audit log did not take the refusal counts at shutdown");
                }
                return;
            }
        }
    }
}
