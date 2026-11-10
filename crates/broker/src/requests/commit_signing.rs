//! The commit signing grant's own lifecycle: finding an agent's active grant, its
//! daily limit and recording refusals. Renewing it and the notice before it ends are
//! in `renewal`, with the GitHub token grant's.
//!
//! An agent holds at most one: approving a new grant ends the one it replaces, in
//! the same transaction, so that revoking the grant on the owner's screen really
//! does stop that agent's signatures.

use sqlx::Row as _;
use warden_broker_proto::{AgentName, CommitSigningGrant, GrantAccess, GrantView, Id, Window};

use super::{RequestError, Requests, parse};
use crate::audit::AuditEvent;
use crate::notify::Doorbell;
use crate::policy::{CommitSigningKey, CommitSigningPolicy, PolicyError, check_separate_from_ca};

/// Signatures per grant per UTC day, unless the server says otherwise. Far more than
/// rebases need, and small enough that a looping agent cannot fill the audit log's
/// disk in the life of a grant.
pub const SIGNATURES_PER_DAY: u32 = 5000;

/// A usable commit signing grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveCommitSigning {
    /// The grant.
    pub grant_id: Id,
    /// What was approved.
    pub grant: CommitSigningGrant,
}

/// Whether a commit signing grant may have `window`, under the server's `max`.
pub(super) fn check_window(window: Window, max: Window) -> Result<(), String> {
    if !window.is_commit_signing() {
        return Err("a commit signing grant lasts 1d, 7d, 30d or 90d".to_owned());
    }
    super::check_window(window, max, "commit signing")
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
        let Some(row) = self
            .active_rows(agent, "commit_signing")
            .await?
            .into_iter()
            .next()
        else {
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
        let event = AuditEvent::CommitSigningRefused {
            agent: agent.clone(),
            grant_id,
            reason,
            payload_sha256,
        };
        self.signing_refusals
            .record(
                &self.audit,
                agent,
                self.clock.now(),
                event,
                "a refusal to sign",
            )
            .await;
    }

    /// Write the refusals to sign held back since the last time.
    pub(super) async fn flush_signing_refusals(&self) {
        self.signing_refusals
            .flush(&self.audit, "refusals to sign", |agent, count| {
                AuditEvent::CommitSigningRefusalsHeld { agent, count }
            })
            .await;
    }
}
