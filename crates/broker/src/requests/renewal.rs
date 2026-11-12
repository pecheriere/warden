//! Grants an agent holds one of at a time, commit signing and GitHub tokens:
//! approving a new one ends the one it replaces, in the same transaction, so that
//! revoking the grant on the owner's screen really does stop that agent's access.
//!
//! They last days, so the owner hears before one ends, and renews it from the grants
//! page with one passkey approval.

use sqlx::Row as _;
use sqlx::sqlite::SqliteRow;
use sqlx::{Sqlite, Transaction};
use url::Url;
use warden_broker_proto::{
    Access, AgentName, CreateRequest, GithubTokenAccess, Goal, GrantAccess, Id, Window,
};

use super::transition::detached;
use super::{Destination, RequestError, Requests, Scope, approval_token, begin, parse};
use crate::audit::AuditEvent;
use crate::notify::Doorbell;

/// Recorded as `by` for a grant ended by approving its replacement.
const RENEWED: &str = "renewed";

/// The owner hears at most this long before a grant ends, in seconds, and sooner
/// only for a grant so short that a quarter of it is less.
const NOTICE_SECS: i64 = 3 * 86_400;

/// Least time between tries to tell the owner about one grant, in seconds.
const NOTICE_RETRY_SECS: i64 = 3600;

/// Grants of every [`OneAtATime`] kind ending soon at `?1`, whose owner was not told
/// yet and was not tried since `?2`.
const ENDING_SOON: &str = "\
    SELECT id, agent, not_after, json_extract(view, '$.access.kind') AS kind FROM grants \
    WHERE not_after > ?1 AND revoked_at IS NULL \
    AND json_extract(view, '$.access.kind') IN ('commit_signing', 'github_token') \
    AND not_after - ?1 <= MIN(?3, window_secs / 4) \
    AND renewal_noticed_at IS NULL \
    AND (renewal_notice_tried_at IS NULL OR renewal_notice_tried_at <= ?2)";

/// A kind of grant an agent holds one of at a time, and that can be renewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OneAtATime {
    CommitSigning,
    GithubToken,
}

impl OneAtATime {
    /// The kind of `access`, or `None` for a kind an agent may hold any number of.
    const fn of(access: &GrantAccess) -> Option<Self> {
        match access {
            GrantAccess::CommitSigning(_) => Some(Self::CommitSigning),
            GrantAccess::GithubToken(_) => Some(Self::GithubToken),
            GrantAccess::Ssh(_)
            | GrantAccess::Relay(_)
            | GrantAccess::Api(_)
            | GrantAccess::Release(_) => None,
        }
    }

    /// The kind stored as `kind` in a grant's view, if it is one of these.
    fn stored(kind: &str) -> Option<Self> {
        match kind {
            "commit_signing" => Some(Self::CommitSigning),
            "github_token" => Some(Self::GithubToken),
            _ => None,
        }
    }

    /// How a grant's view stores this kind; also the end of its requests' dedupe slot.
    const fn kind(self) -> &'static str {
        match self {
            Self::CommitSigning => "commit_signing",
            Self::GithubToken => "github_token",
        }
    }

    /// What its requests are about in the audit log, as `create` writes it.
    const fn subject(self) -> &'static str {
        match self {
            Self::CommitSigning => "commit signing",
            Self::GithubToken => "github token",
        }
    }

    /// What the owner calls it, in notices and logs.
    const fn name(self) -> &'static str {
        match self {
            Self::CommitSigning => "commit signing",
            Self::GithubToken => "GitHub token",
        }
    }

    const fn windows(self) -> &'static [Window] {
        match self {
            Self::CommitSigning => &Window::COMMIT_SIGNING,
            Self::GithubToken => &Window::GITHUB_TOKEN,
        }
    }

    fn access(self) -> Access {
        match self {
            Self::CommitSigning => Access::CommitSigning {},
            Self::GithubToken => Access::GithubToken(GithubTokenAccess::default()),
        }
    }

    /// The doorbell telling the owner that `agent`'s grant ends in `left`. It names
    /// the agent and nothing it wrote.
    fn notice(self, agent: &AgentName, left: &str, url: Url) -> Doorbell {
        let without = match self {
            Self::CommitSigning => "this agent's commits fail once it ends",
            Self::GithubToken => {
                "this agent's next git or gh call to GitHub asks you again once it ends"
            }
        };
        Doorbell {
            title: format!("warden: {} for {agent} ends soon", self.name()),
            message: format!(
                "It ends in {left}. Renewing takes one passkey approval; without it, {without}."
            ),
            url,
        }
    }

    fn notified(self, grant_id: Id, channel: String) -> AuditEvent {
        match self {
            Self::CommitSigning => AuditEvent::CommitSigningRenewalNotified { grant_id, channel },
            Self::GithubToken => AuditEvent::GithubTokenRenewalNotified { grant_id, channel },
        }
    }
}

/// Whether the owner can renew a grant of `access`, and hears before it ends: the
/// kinds an agent holds one of at a time.
#[must_use]
pub(crate) const fn renewable(access: &GrantAccess) -> bool {
    OneAtATime::of(access).is_some()
}

/// The stored kind of the grants `access` replaces when approved, or `None` for a
/// kind an agent may hold any number of.
pub(super) fn replaced_kind(access: &GrantAccess) -> Option<&'static str> {
    OneAtATime::of(access).map(OneAtATime::kind)
}

/// End the other active grants of `kind` of `agent` at `now`, in `tx`, which also
/// stores `kept`, the grant replacing them. Returns their requests.
pub(super) async fn end_renewed(
    tx: &mut Transaction<'static, Sqlite>,
    agent: &AgentName,
    kept: &Id,
    kind: &str,
    now: i64,
) -> Result<Vec<Id>, RequestError> {
    let requests = sqlx::query(
        "UPDATE grants SET revoked_at = ?1 \
         WHERE agent = ?2 AND id != ?3 AND revoked_at IS NULL AND not_after > ?1 \
         AND json_extract(view, '$.access.kind') = ?4 \
         RETURNING request_id",
    )
    .bind(now)
    .bind(agent.as_str())
    .bind(kept.as_str())
    .bind(kind)
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(|row| parse(row, "request_id"))
    .collect::<Result<Vec<Id>, _>>()?;
    for request in &requests {
        sqlx::query("UPDATE requests SET status = 'revoked' WHERE id = ? AND status = 'approved'")
            .bind(request.as_str())
            .execute(&mut **tx)
            .await?;
    }
    Ok(requests)
}

impl Requests {
    /// `agent`'s active grants of `kind`, longest lasting first: not revoked and not
    /// past their end, as read by every use of a grant and every replacement of one.
    /// Rows of `id`, `not_after` and `view`.
    pub(super) async fn active_rows(
        &self,
        agent: &AgentName,
        kind: &str,
    ) -> Result<Vec<SqliteRow>, RequestError> {
        Ok(sqlx::query(
            "SELECT id, not_after, view FROM grants \
             WHERE agent = ?1 AND revoked_at IS NULL AND not_after > ?2 \
             AND json_extract(view, '$.access.kind') = ?3 \
             ORDER BY not_after DESC, id",
        )
        .bind(agent.as_str())
        .bind(self.clock.now())
        .bind(kind)
        .fetch_all(&self.pool)
        .await?)
    }

    /// The entries for ending the active grants of `kind` that a new grant of
    /// `agent` replaces. Written with the approval, before anything changes.
    pub(super) async fn renewal_events(
        &self,
        agent: &AgentName,
        kind: &str,
    ) -> Result<Vec<AuditEvent>, RequestError> {
        self.active_rows(agent, kind)
            .await?
            .iter()
            .map(|row| {
                Ok(AuditEvent::GrantRevoked {
                    grant_id: parse(row, "id")?,
                    by: RENEWED.to_owned(),
                })
            })
            .collect()
    }

    /// Start renewing grant `grant_id`, a commit signing or GitHub token grant, for
    /// the owner: a request of its agent for the same length, or as long as the server
    /// now allows, with an approval link the owner goes on to approve with a passkey.
    /// If that agent already has a request of that kind waiting, there can be only
    /// one, so this opens it instead, with the goal and window its agent gave: the
    /// approval page shows them, and the owner chooses the window there either way.
    /// Rings nobody, as the owner is the one asking. Returns the request and its link.
    /// Nothing is granted by this, and the grant keeps working until the approval.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if no such grant is active or it is of a kind that
    /// cannot be renewed, [`RequestError::Rejected`] if the broker no longer holds the
    /// key or App it needs, what [`Requests::create`] returns when a request cannot be
    /// made.
    pub async fn renew_grant(&self, grant_id: &Id) -> Result<(Id, Url), RequestError> {
        let row = sqlx::query(
            "SELECT agent, window_secs, json_extract(view, '$.access.kind') AS kind \
             FROM grants WHERE id = ?1 AND revoked_at IS NULL AND not_after > ?2",
        )
        .bind(grant_id.as_str())
        .bind(self.clock.now())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(RequestError::NotFound)?;
        let stored: Option<String> = row.try_get("kind")?;
        let kind = stored
            .as_deref()
            .and_then(OneAtATime::stored)
            .ok_or(RequestError::NotFound)?;
        let agent: AgentName = parse(&row, "agent")?;
        let secs: i64 = row.try_get("window_secs")?;
        let window = kind
            .windows()
            .iter()
            .copied()
            .find(|w| u64::try_from(secs).is_ok_and(|s| s == w.secs()))
            .ok_or_else(|| RequestError::Corrupt(format!("unknown {} window", kind.name())))?;
        // The key or App is read so that a broker that lost it says so here, on the
        // screen the owner is looking at, rather than on the approval page.
        let policy = match kind {
            OneAtATime::CommitSigning => {
                Destination::CommitSigning(self.approvable_commit_signing_policy().await?)
            }
            OneAtATime::GithubToken => Destination::GithubToken(self.github_token_policy().await?),
        };
        let window = window.min(policy.max_window());
        policy
            .check_window(window)
            .map_err(RequestError::Rejected)?;
        let goal = format!("Renew {}", kind.name());
        let req = CreateRequest {
            goal: Goal::try_from(goal)
                .map_err(|_| RequestError::Internal("the renewal goal is not valid"))?,
            access: kind.access(),
            window,
            session: None,
            link: None,
        };
        let this = self.clone();
        detached(async move { this.create_renewal(&agent, kind, req).await }).await
    }

    async fn create_renewal(
        &self,
        agent: &AgentName,
        kind: OneAtATime,
        req: CreateRequest,
    ) -> Result<(Id, Url), RequestError> {
        let dedupe_key = format!("{agent}|{}", kind.kind());
        self.expire_due(Scope::Dedupe(dedupe_key.clone())).await?;
        if let Some(existing) = self.pending_in_slot(&dedupe_key).await? {
            let link = self.replace_link(&existing.id).await?;
            return Ok((existing.id, link));
        }
        let token = approval_token()?;
        let link = self.approval_link(&token)?;
        let change = self.recorded_change.lock().await;
        let created = self
            .insert(agent, &req, kind.subject(), &dedupe_key, &token, None)
            .await;
        drop(change);
        if let Err(RequestError::Limited(refusal)) = &created {
            self.record_refusal(agent, *refusal).await;
        }
        Ok((created?.id, link))
    }

    /// Tell the owner about every commit signing and GitHub token grant about to end.
    /// A grant is told about once, and a failed try is repeated once an hour. The
    /// notice names the agent and nothing it wrote, and links to the grants page,
    /// where renewing takes one passkey approval. Failures are logged and never stop
    /// anything.
    pub async fn notify_ending_grants(&self) {
        let now = self.clock.now();
        let due = sqlx::query(ENDING_SOON)
            .bind(now)
            .bind(now - NOTICE_RETRY_SECS)
            .bind(NOTICE_SECS)
            .fetch_all(&self.pool)
            .await;
        let due = match due {
            Ok(due) => due,
            Err(e) => {
                tracing::error!(error = %e, "could not read which grants end soon");
                return;
            }
        };
        for row in &due {
            if let Err(e) = self.notify_ending(row, now).await {
                tracing::error!(error = %e, "could not tell the owner a grant ends soon");
            }
        }
    }

    async fn notify_ending(&self, row: &SqliteRow, now: i64) -> Result<(), RequestError> {
        let grant_id: Id = parse(row, "id")?;
        let agent: AgentName = parse(row, "agent")?;
        let not_after: i64 = row.try_get("not_after")?;
        let stored: String = row.try_get("kind")?;
        let kind = OneAtATime::stored(&stored).ok_or(RequestError::Internal(
            "a grant ending soon has another kind",
        ))?;
        // Claimed first, so that a sweep that overlaps this one does not ring too.
        let mut tx = begin(&self.pool).await?;
        let claimed = sqlx::query(
            "UPDATE grants SET renewal_notice_tried_at = ?1 WHERE id = ?2 \
             AND renewal_noticed_at IS NULL \
             AND (renewal_notice_tried_at IS NULL OR renewal_notice_tried_at <= ?3)",
        )
        .bind(now)
        .bind(grant_id.as_str())
        .bind(now - NOTICE_RETRY_SECS)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        if claimed == 0 {
            return Ok(());
        }
        let mut url = self.public_url.clone();
        url.path_segments_mut()
            .map_err(|()| RequestError::Internal("public URL cannot be a base"))?
            .pop_if_empty()
            .push("grants");
        let bell = kind.notice(&agent, &time_left(not_after - now), url);
        match self.notifier.ring(&bell).await {
            Ok(channel) => {
                sqlx::query("UPDATE grants SET renewal_noticed_at = ? WHERE id = ?")
                    .bind(now)
                    .bind(grant_id.as_str())
                    .execute(&self.pool)
                    .await?;
                self.audit
                    .append(kind.notified(grant_id, channel.to_owned()))
                    .await?;
            }
            Err(e) => {
                tracing::warn!(grant = %grant_id, error = %e, "renewal notice failed");
                self.audit
                    .append(AuditEvent::Error {
                        context: format!("{} renewal notice", kind.name()),
                        message: format!("grant {grant_id}: {e}"),
                    })
                    .await?;
            }
        }
        Ok(())
    }
}

/// `secs` for the owner: `3 days`, `1 day`, `5 hours`, `less than an hour`.
fn time_left(secs: i64) -> String {
    match secs {
        ..3600 => "less than an hour".to_owned(),
        3600..7200 => "1 hour".to_owned(),
        7200..86_400 => format!("{} hours", secs / 3600),
        86_400..172_800 => "1 day".to_owned(),
        _ => format!("{} days", secs / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::{ENDING_SOON, OneAtATime, time_left};

    #[test]
    fn time_left_reads_as_people_say_it() {
        assert_eq!(time_left(59), "less than an hour");
        assert_eq!(time_left(3600), "1 hour");
        assert_eq!(time_left(7200), "2 hours");
        assert_eq!(time_left(86_400), "1 day");
        assert_eq!(time_left(3 * 86_400), "3 days");
    }

    #[test]
    fn every_kind_held_one_at_a_time_is_told_about_and_read_back() {
        for kind in [OneAtATime::CommitSigning, OneAtATime::GithubToken] {
            assert!(
                ENDING_SOON.contains(&format!("'{}'", kind.kind())),
                "{kind:?}"
            );
            assert_eq!(OneAtATime::stored(kind.kind()), Some(kind));
        }
    }
}
