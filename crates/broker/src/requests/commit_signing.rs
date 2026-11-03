//! The commit signing grant's own lifecycle: finding an agent's active grant,
//! renewing, telling the owner before one ends, and recording refusals.
//!
//! An agent holds at most one: approving a new grant ends the one it replaces, in
//! the same transaction, so that revoking the grant on the owner's screen really
//! does stop that agent's signatures.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use sqlx::{Row as _, Sqlite, Transaction};
use url::Url;
use warden_broker_proto::{
    Access, AgentName, CommitSigningGrant, CreateRequest, Goal, GrantAccess, GrantView, Id, Window,
};

use super::transition::detached;
use super::{Destination, RequestError, Requests, Scope, approval_token, begin, parse};
use crate::audit::AuditEvent;
use crate::notify::Doorbell;
use crate::policy::{CommitSigningKey, CommitSigningPolicy, PolicyError, check_separate_from_ca};

/// Recorded as `by` for a grant ended by approving its replacement.
const RENEWED: &str = "renewed";

/// The owner hears at most this long before a grant ends, in seconds, and sooner
/// only for a grant so short that a quarter of it is less.
const NOTICE_SECS: i64 = 3 * 86_400;

/// Least time between tries to tell the owner about one grant, in seconds.
const NOTICE_RETRY_SECS: i64 = 3600;

/// Signatures per grant per UTC day, unless the server says otherwise. Far more than
/// rebases need, and small enough that a looping agent cannot fill the audit log's
/// disk in the life of a grant.
pub const SIGNATURES_PER_DAY: u32 = 5000;

/// Refusals recorded one by one per agent per minute; the rest are counted.
const REFUSALS_PER_MINUTE: u32 = 30;

/// An agent's active commit signing grants (`?1`, at `?2`), longest lasting first.
const ACTIVE_FOR_AGENT: &str = "\
    SELECT id, not_after, view FROM grants \
    WHERE agent = ?1 AND revoked_at IS NULL AND not_after > ?2 \
    AND json_extract(view, '$.access.kind') = 'commit_signing' \
    ORDER BY not_after DESC, id";

/// Commit signing grants ending soon at `?1`, whose owner was not told yet and was
/// not tried since `?2`.
const ENDING_SOON: &str = "\
    SELECT id, agent, not_after FROM grants \
    WHERE not_after > ?1 AND revoked_at IS NULL \
    AND json_extract(view, '$.access.kind') = 'commit_signing' \
    AND not_after - ?1 <= MIN(?3, window_secs / 4) \
    AND renewal_noticed_at IS NULL \
    AND (renewal_notice_tried_at IS NULL OR renewal_notice_tried_at <= ?2)";

/// A usable commit signing grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveCommitSigning {
    /// The grant.
    pub grant_id: Id,
    /// What was approved.
    pub grant: CommitSigningGrant,
}

/// One agent's refusals in the current minute.
#[derive(Debug, Default)]
struct RefusalMinute {
    started_at: i64,
    written: u32,
    held: u64,
}

/// The refusals to sign of every agent. Enrolled agents are the only callers that
/// get this far, so this holds an entry per enrolled agent at most. In memory: a
/// restart can at worst lose the count of a minute.
#[derive(Debug, Default)]
pub(super) struct SigningRefusals {
    agents: Mutex<HashMap<AgentName, RefusalMinute>>,
}

impl SigningRefusals {
    fn lock(&self) -> MutexGuard<'_, HashMap<AgentName, RefusalMinute>> {
        // Every update is a few steps that cannot panic, and at worst this
        // miscounts: the refusal itself has already been decided.
        self.agents.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Count a refusal of `agent` at `now`. Whether to record it in full; if not,
    /// it is held for a [`AuditEvent::CommitSigningRefusalsHeld`] entry.
    fn note(&self, agent: &AgentName, now: i64) -> bool {
        let mut agents = self.lock();
        let minute = agents.entry(agent.clone()).or_default();
        // A clock set back starts a new minute too.
        if now < minute.started_at || now - minute.started_at >= 60 {
            minute.started_at = now;
            minute.written = 0;
        }
        if minute.written < REFUSALS_PER_MINUTE {
            minute.written += 1;
            true
        } else {
            minute.held = minute.held.saturating_add(1);
            false
        }
    }

    /// Take every count held back.
    fn take_held(&self) -> Vec<(AgentName, u64)> {
        self.lock()
            .iter_mut()
            .filter(|(_, minute)| minute.held > 0)
            .map(|(agent, minute)| (agent.clone(), std::mem::take(&mut minute.held)))
            .collect()
    }

    /// Put back `count`, which could not be written.
    fn restore(&self, agent: &AgentName, count: u64) {
        let mut agents = self.lock();
        let minute = agents.entry(agent.clone()).or_default();
        minute.held = minute.held.saturating_add(count);
    }
}

/// Whether a commit signing grant may have `window`, under the server's `max`.
pub(super) fn check_window(window: Window, max: Window) -> Result<(), String> {
    if !window.is_commit_signing() {
        return Err("a commit signing grant lasts 1d, 7d, 30d or 90d".to_owned());
    }
    super::check_window(window, max, "commit signing")
}

/// End the other active commit signing grants of `agent` at `now`, in `tx`, which
/// also stores `kept`, the grant replacing them. Returns their requests.
pub(super) async fn end_renewed(
    tx: &mut Transaction<'static, Sqlite>,
    agent: &AgentName,
    kept: &Id,
    now: i64,
) -> Result<Vec<Id>, RequestError> {
    let requests = sqlx::query(
        "UPDATE grants SET revoked_at = ?1 \
         WHERE agent = ?2 AND id != ?3 AND revoked_at IS NULL AND not_after > ?1 \
         AND json_extract(view, '$.access.kind') = 'commit_signing' \
         RETURNING request_id",
    )
    .bind(now)
    .bind(agent.as_str())
    .bind(kept.as_str())
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
    /// Allow commit signing grants of up to `max`, instead of the default 30 days.
    #[must_use]
    pub const fn with_commit_signing_max(mut self, max: Window) -> Self {
        self.commit_signing_max = max;
        self
    }

    /// Allow each commit signing grant `limit` signatures per UTC day, instead of
    /// [`SIGNATURES_PER_DAY`].
    #[must_use]
    pub const fn with_commit_signing_per_day(mut self, limit: u32) -> Self {
        self.commit_signing_per_day = limit;
        self
    }

    /// Take one of `grant`'s signatures for today, or say there are none left. In one
    /// statement, so that concurrent calls cannot pass the limit, and in the database,
    /// so that a restart does not reset it.
    ///
    /// # Errors
    /// Storage failures: the caller refuses.
    pub(crate) async fn take_signature(&self, grant: &Id) -> Result<bool, RequestError> {
        let taken = sqlx::query(
            "UPDATE grants SET signing_day = ?1, signing_count = \
             CASE WHEN signing_day = ?1 THEN signing_count + 1 ELSE 1 END \
             WHERE id = ?2 AND (signing_day IS NOT ?1 OR signing_count < ?3)",
        )
        .bind(self.clock.now().div_euclid(86_400))
        .bind(grant.as_str())
        .bind(self.commit_signing_per_day)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(taken > 0)
    }

    /// Record that `grant` of `agent` reached its limit and tell the owner, once a day
    /// per grant, without holding up the refusal. One try: a failure is logged and
    /// recorded, and the refusals keep being recorded either way.
    pub(crate) async fn signature_limit_reached(&self, agent: &AgentName, grant: &Id) {
        let claimed = sqlx::query(
            "UPDATE grants SET signing_limit_noticed_day = ?1 \
             WHERE id = ?2 AND signing_limit_noticed_day IS NOT ?1",
        )
        .bind(self.clock.now().div_euclid(86_400))
        .bind(grant.as_str())
        .execute(&self.pool)
        .await;
        match claimed {
            Ok(done) if done.rows_affected() == 0 => return,
            Ok(_) => {}
            Err(e) => {
                tracing::error!(grant = %grant, error = %e, "could not record a signing limit");
                return;
            }
        }
        let reached = AuditEvent::CommitSigningLimitReached {
            grant_id: grant.clone(),
            agent: agent.clone(),
            limit: self.commit_signing_per_day,
        };
        if let Err(e) = self.audit.append(reached).await {
            tracing::error!(grant = %grant, error = %e, "could not audit a signing limit");
        }
        let this = self.clone();
        let (agent, grant) = (agent.clone(), grant.clone());
        tokio::spawn(async move { this.notify_signature_limit(&agent, &grant).await });
    }

    async fn notify_signature_limit(&self, agent: &AgentName, grant: &Id) {
        let mut url = self.public_url.clone();
        let Ok(mut path) = url.path_segments_mut() else {
            tracing::error!("public URL cannot be a base; not sending a signing limit notice");
            return;
        };
        path.pop_if_empty().push("grants");
        drop(path);
        let bell = Doorbell {
            title: format!("warden: {agent} reached its commit signing limit"),
            message: format!(
                "It made {} signatures today, so its commits fail until 00:00 UTC. If you do not \
                 expect this many, revoke its grant.",
                self.commit_signing_per_day
            ),
            url,
        };
        let event = match self.notifier.ring(&bell).await {
            Ok(channel) => AuditEvent::CommitSigningLimitNotified {
                grant_id: grant.clone(),
                channel: channel.to_owned(),
            },
            Err(e) => {
                tracing::warn!(grant = %grant, error = %e, "signing limit notice failed");
                AuditEvent::Error {
                    context: "commit signing limit notice".to_owned(),
                    message: format!("grant {grant}: {e}"),
                }
            }
        };
        if let Err(e) = self.audit.append(event).await {
            tracing::error!(grant = %grant, error = %e, "could not audit a signing limit notice");
        }
    }

    /// The commit signing policy `key` makes on this server.
    ///
    /// # Errors
    /// [`PolicyError::CommitSigningKey`] if its public half cannot be encoded.
    pub fn commit_signing_policy_of(
        &self,
        key: &CommitSigningKey,
    ) -> Result<CommitSigningPolicy, PolicyError> {
        key.policy(self.commit_signing_max)
    }

    /// The commit signing policy as it is now.
    ///
    /// # Errors
    /// [`RequestError::Rejected`] if no key is configured,
    /// [`RequestError::Unavailable`] if it cannot be read.
    pub async fn commit_signing_policy(&self) -> Result<CommitSigningPolicy, RequestError> {
        let key = self.backend.commit_signing_key().await?;
        Ok(key.policy(self.commit_signing_max)?)
    }

    /// The commit signing policy, if a grant may be approved under it: not if the key
    /// is also the SSH CA key. A grant is bound to the key it was approved for, so
    /// this is checked for as long as any grant can come to use a key.
    ///
    /// # Errors
    /// [`RequestError::Rejected`] if there is no key or it is the CA key, and
    /// [`RequestError::Unavailable`] if either key cannot be read.
    pub(super) async fn approvable_commit_signing_policy(
        &self,
    ) -> Result<CommitSigningPolicy, RequestError> {
        let key = self.backend.commit_signing_key().await?;
        match check_separate_from_ca(self.backend.as_ref(), &key).await {
            Err(PolicyError::CommitSigningKey(reason)) => Err(RequestError::Rejected(reason)),
            Err(e) => Err(e.into()),
            Ok(()) => Ok(key.policy(self.commit_signing_max)?),
        }
    }

    /// The longest commit signing grant the server allows.
    #[must_use]
    pub const fn commit_signing_max(&self) -> Window {
        self.commit_signing_max
    }

    /// The commit signing grant `agent` may sign with now, if any. Read for every
    /// signature, so that a revocation or the end of the window stops the next one.
    ///
    /// # Errors
    /// Storage failures or an unreadable stored grant: the caller refuses.
    pub async fn active_commit_signing(
        &self,
        agent: &AgentName,
    ) -> Result<Option<ActiveCommitSigning>, RequestError> {
        let row = sqlx::query(ACTIVE_FOR_AGENT)
            .bind(agent.as_str())
            .bind(self.clock.now())
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let view: String = row.try_get("view")?;
        let view: GrantView = serde_json::from_str(&view)?;
        let GrantAccess::CommitSigning(grant) = view.access else {
            return Err(RequestError::Corrupt(
                "commit signing grant changed kind".to_owned(),
            ));
        };
        Ok(Some(ActiveCommitSigning {
            grant_id: parse(&row, "id")?,
            grant,
        }))
    }

    /// The entries for ending the grants a new commit signing grant of `agent`
    /// replaces. Written with the approval, before anything changes.
    pub(super) async fn renewal_events(
        &self,
        agent: &AgentName,
    ) -> Result<Vec<AuditEvent>, RequestError> {
        sqlx::query(ACTIVE_FOR_AGENT)
            .bind(agent.as_str())
            .bind(self.clock.now())
            .fetch_all(&self.pool)
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

    /// Start renewing commit signing grant `grant_id`, for the owner: a request of its
    /// agent for the same length, or as long as the server now allows, with an approval
    /// link the owner goes on to approve with a passkey. If that agent already has a
    /// commit signing request waiting, there can be only one, so this opens it instead,
    /// with the goal and window its agent gave: the approval page shows them, and the
    /// owner chooses the window there either way. Rings nobody, as the owner is the one
    /// asking. Returns the request and its link. Nothing is granted by this, and the
    /// grant keeps working until the approval.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if no such commit signing grant is active, what
    /// [`Requests::create`] returns when a request cannot be made.
    pub async fn renew_commit_signing(&self, grant_id: &Id) -> Result<(Id, Url), RequestError> {
        let row = sqlx::query(
            "SELECT agent, window_secs FROM grants \
             WHERE id = ?1 AND revoked_at IS NULL AND not_after > ?2 \
             AND json_extract(view, '$.access.kind') = 'commit_signing'",
        )
        .bind(grant_id.as_str())
        .bind(self.clock.now())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(RequestError::NotFound)?;
        let agent: AgentName = parse(&row, "agent")?;
        let secs: i64 = row.try_get("window_secs")?;
        let window = Window::COMMIT_SIGNING
            .into_iter()
            .find(|w| u64::try_from(secs).is_ok_and(|s| s == w.secs()))
            .ok_or_else(|| RequestError::Corrupt("unknown commit signing window".to_owned()))?
            .min(self.commit_signing_max);
        // The key is read so that a broker that lost it says so here, on the screen
        // the owner is looking at, rather than on the approval page.
        let policy = Destination::CommitSigning(self.approvable_commit_signing_policy().await?);
        policy
            .check_window(window)
            .map_err(RequestError::Rejected)?;
        let req = CreateRequest {
            goal: Goal::try_from("Renew commit signing".to_owned())
                .map_err(|_| RequestError::Internal("the renewal goal is not valid"))?,
            access: Access::CommitSigning {},
            window,
            session: None,
            link: None,
        };
        let this = self.clone();
        detached(async move { this.create_renewal(&agent, req).await }).await
    }

    async fn create_renewal(
        &self,
        agent: &AgentName,
        req: CreateRequest,
    ) -> Result<(Id, Url), RequestError> {
        let dedupe_key = format!("{agent}|commit_signing");
        self.expire_due(Scope::Dedupe(dedupe_key.clone())).await?;
        if let Some(existing) = self.pending_in_slot(&dedupe_key).await? {
            let link = self.replace_link(&existing.id).await?;
            return Ok((existing.id, link));
        }
        let token = approval_token()?;
        let link = self.approval_link(&token)?;
        let change = self.recorded_change.lock().await;
        let created = self
            .insert(agent, &req, "commit signing", &dedupe_key, &token)
            .await;
        drop(change);
        if let Err(RequestError::Limited(refusal)) = &created {
            self.record_refusal(agent, *refusal).await;
        }
        Ok((created?.id, link))
    }

    /// Record a refusal to sign for `agent`: one by one, up to a limit per minute,
    /// and after that as a count. Cannot change the outcome: the agent is refused
    /// already, so a failure here is logged.
    pub(crate) async fn record_commit_signing_refusal(
        &self,
        agent: &AgentName,
        grant_id: Option<Id>,
        reason: String,
        payload_sha256: Option<String>,
    ) {
        if !self.signing_refusals.note(agent, self.clock.now()) {
            return;
        }
        let event = AuditEvent::CommitSigningRefused {
            agent: agent.clone(),
            grant_id,
            reason,
            payload_sha256,
        };
        if let Err(e) = self.audit.append(event).await {
            tracing::error!(agent = %agent, error = %e, "could not audit a refusal to sign");
        }
    }

    /// Write the refusals to sign held back since the last time.
    pub(super) async fn flush_signing_refusals(&self) {
        for (agent, count) in self.signing_refusals.take_held() {
            let event = AuditEvent::CommitSigningRefusalsHeld {
                agent: agent.clone(),
                count,
            };
            if let Err(e) = self.audit.append(event).await {
                tracing::error!(agent = %agent, error = %e, "could not audit refusals to sign");
                self.signing_refusals.restore(&agent, count);
            }
        }
    }

    /// Tell the owner about every commit signing grant about to end. A grant is
    /// told about once, and a failed try is repeated once an hour. The notice names
    /// the agent and nothing it wrote, and links to the grants page, where renewing
    /// takes one passkey approval. Failures are logged and never stop anything.
    pub async fn notify_ending_commit_signing(&self) {
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
                tracing::error!(error = %e, "could not read which signing grants end soon");
                return;
            }
        };
        for row in &due {
            if let Err(e) = self.notify_ending(row, now).await {
                tracing::error!(error = %e, "could not tell the owner a signing grant ends soon");
            }
        }
    }

    async fn notify_ending(
        &self,
        row: &sqlx::sqlite::SqliteRow,
        now: i64,
    ) -> Result<(), RequestError> {
        let grant_id: Id = parse(row, "id")?;
        let agent: AgentName = parse(row, "agent")?;
        let not_after: i64 = row.try_get("not_after")?;
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
        let bell = Doorbell {
            title: format!("warden: commit signing for {agent} ends soon"),
            message: format!(
                "It ends in {}. Renewing takes one passkey approval; without it, this agent's \
                 commits fail once it ends.",
                time_left(not_after - now)
            ),
            url,
        };
        match self.notifier.ring(&bell).await {
            Ok(channel) => {
                sqlx::query("UPDATE grants SET renewal_noticed_at = ? WHERE id = ?")
                    .bind(now)
                    .bind(grant_id.as_str())
                    .execute(&self.pool)
                    .await?;
                self.audit
                    .append(AuditEvent::CommitSigningRenewalNotified {
                        grant_id,
                        channel: channel.to_owned(),
                    })
                    .await?;
            }
            Err(e) => {
                tracing::warn!(grant = %grant_id, error = %e, "signing renewal notice failed");
                self.audit
                    .append(AuditEvent::Error {
                        context: "commit signing renewal notice".to_owned(),
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
    use super::{REFUSALS_PER_MINUTE, SigningRefusals, time_left};
    use warden_broker_proto::AgentName;

    fn agent(name: &str) -> AgentName {
        name.parse().unwrap()
    }

    #[test]
    fn refusals_beyond_the_limit_are_counted_not_written() {
        let refusals = SigningRefusals::default();
        let bot = agent("bot");
        assert!(refusals.note(&bot, 1000));
        for _ in 1..REFUSALS_PER_MINUTE {
            assert!(refusals.note(&bot, 1000));
        }
        assert!(!refusals.note(&bot, 1059));
        assert!(!refusals.note(&bot, 1059));
        assert_eq!(refusals.take_held(), [(bot.clone(), 2)]);
        assert_eq!(refusals.take_held(), []);
        // Another agent has its own allowance, and the next minute starts afresh.
        assert!(refusals.note(&agent("other"), 1059));
        assert!(refusals.note(&bot, 1060));
    }

    #[test]
    fn a_count_that_could_not_be_written_is_kept() {
        let refusals = SigningRefusals::default();
        let bot = agent("bot");
        refusals.restore(&bot, 5);
        assert_eq!(refusals.take_held(), [(bot, 5)]);
    }

    #[test]
    fn a_clock_set_back_starts_a_new_minute() {
        let refusals = SigningRefusals::default();
        let bot = agent("bot");
        for _ in 0..REFUSALS_PER_MINUTE {
            assert!(refusals.note(&bot, 1000));
        }
        assert!(!refusals.note(&bot, 1000));
        assert!(refusals.note(&bot, 900));
    }

    #[test]
    fn time_left_reads_as_people_say_it() {
        assert_eq!(time_left(59), "less than an hour");
        assert_eq!(time_left(3600), "1 hour");
        assert_eq!(time_left(7200), "2 hours");
        assert_eq!(time_left(86_400), "1 day");
        assert_eq!(time_left(3 * 86_400), "3 days");
    }
}
