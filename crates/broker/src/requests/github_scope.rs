//! GitHub token grants are scoped to repositories. Those stored before that named
//! none, so nothing can be minted under them: they end when the broker starts.

use warden_broker_proto::Id;

use super::revocation::commit_with_entries;
use super::{RequestError, Requests, begin, parse};
use crate::audit::AuditEvent;

impl Requests {
    /// End every active GitHub token grant that names no repository (its request
    /// becomes `revoked`) and expire every pending GitHub token request that names
    /// none, writing one `github_unscoped_ended` entry for each. Returns how many.
    /// Run at startup, before the listeners; running it again ends nothing.
    ///
    /// # Errors
    /// Storage failures: the broker does not start, as it would otherwise serve
    /// grants that cannot be used.
    pub async fn end_unscoped_github(&self) -> Result<usize, RequestError> {
        let now = self.clock.now();
        let mut tx = begin(&self.pool).await?;
        let grants = sqlx::query(
            "UPDATE grants SET revoked_at = ?1 \
             WHERE revoked_at IS NULL AND not_after > ?1 \
             AND json_extract(view, '$.access.kind') = 'github_token' \
             AND COALESCE(json_array_length(view, '$.access.repositories'), 0) = 0 \
             RETURNING id, request_id",
        )
        .bind(now)
        .fetch_all(&mut *tx)
        .await?
        .iter()
        .map(|row| Ok((parse::<Id>(row, "id")?, parse::<Id>(row, "request_id")?)))
        .collect::<Result<Vec<_>, RequestError>>()?;
        let mut events = Vec::new();
        let mut changed = Vec::new();
        for (grant_id, request_id) in grants {
            sqlx::query(
                "UPDATE requests SET status = 'revoked' WHERE id = ? AND status = 'approved'",
            )
            .bind(request_id.as_str())
            .execute(&mut *tx)
            .await?;
            events.push(AuditEvent::GithubUnscopedEnded {
                request_id: request_id.clone(),
                grant_id: Some(grant_id),
            });
            changed.push(request_id);
        }
        let pending = sqlx::query(
            "UPDATE requests SET status = 'expired', decided_at = ?1 \
             WHERE status = 'pending' \
             AND json_extract(body, '$.access.kind') = 'github_token' \
             AND COALESCE(json_array_length(body, '$.access.repositories'), 0) = 0 \
             RETURNING id",
        )
        .bind(now)
        .fetch_all(&mut *tx)
        .await?;
        for row in &pending {
            let request_id: Id = parse(row, "id")?;
            events.push(AuditEvent::GithubUnscopedEnded {
                request_id: request_id.clone(),
                grant_id: None,
            });
            changed.push(request_id);
        }
        let ended = events.len();
        if ended == 0 {
            return Ok(0);
        }
        commit_with_entries(tx, events, now).await?;
        self.settle_entries().await;
        for id in &changed {
            self.bus.publish(id);
        }
        Ok(ended)
    }
}
