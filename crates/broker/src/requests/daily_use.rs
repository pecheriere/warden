//! The daily budget of an API grant: how many calls it may make through the proxy
//! in a UTC day, counted in the database so that a restart does not reset it. The
//! columns are generic because a grant has one kind of use: relay grants count
//! their sessions in them.

use warden_broker_proto::{AgentName, Id, SecretName, TargetName};

use super::{RequestError, Requests};
use crate::audit::{AuditEvent, bounded_text};
use crate::notify::Doorbell;

/// Proxied calls per API grant per UTC day, unless the server says otherwise. Calls
/// refused before they start are recorded one by one up to 30 a minute per
/// agent, and counted beyond that, so a looping agent cannot fill the audit
/// log's disk in the life of a grant.
pub const CALLS_PER_DAY: u32 = 10_000;

/// Relay sessions per relay grant per UTC day, unless the server says otherwise. Sessions
/// refused past it are recorded one by one up to 30 a minute per grant, and
/// counted beyond that.
pub const SESSIONS_PER_DAY: u32 = 1_000;

/// What a grant spends its daily budget on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DailyUse {
    /// A call through the proxy with `secret`.
    ProxyCall {
        /// The secret the grant injects.
        secret: SecretName,
    },
    /// A session to `target` through the relay.
    RelaySession {
        /// The target the grant opens sessions to.
        target: TargetName,
    },
}

impl Requests {
    /// Allow each API grant `limit` proxied calls per UTC day, instead of
    /// [`CALLS_PER_DAY`].
    #[must_use]
    pub const fn with_proxy_calls_per_day(mut self, limit: u32) -> Self {
        self.proxy_calls_per_day = limit;
        self
    }

    /// Allow each relay grant `limit` sessions per UTC day, instead of
    /// [`SESSIONS_PER_DAY`].
    #[must_use]
    pub const fn with_relay_sessions_per_day(mut self, limit: u32) -> Self {
        self.relay_sessions_per_day = limit;
        self
    }

    /// Write the entry of a call that was refused before it started, if `agent`'s
    /// allowance for the minute has room, and count it otherwise: a looping agent
    /// cannot fill the log with refusals. Cannot change the outcome, which is
    /// decided already, so a failure to write is logged.
    pub(crate) async fn record_proxy_refusal(&self, agent: &AgentName, event: AuditEvent) {
        self.proxy_refusals
            .record(&self.audit, agent, self.clock.now(), 1, event)
            .await;
    }

    /// The limit of a day's uses of `kind`.
    pub(crate) const fn daily_limit(&self, kind: &DailyUse) -> u32 {
        match kind {
            DailyUse::ProxyCall { .. } => self.proxy_calls_per_day,
            DailyUse::RelaySession { .. } => self.relay_sessions_per_day,
        }
    }

    /// Take one of `grant`'s uses for today, or say there are none left. In one
    /// statement, so that concurrent calls cannot pass the limit, and in the database,
    /// so that a restart does not reset it.
    ///
    /// # Errors
    /// Storage failures: the caller refuses.
    pub(crate) async fn take_daily_use(
        &self,
        grant: &Id,
        kind: &DailyUse,
    ) -> Result<bool, RequestError> {
        let taken = sqlx::query(
            "UPDATE grants SET use_day = ?1, use_count = \
             CASE WHEN use_day = ?1 THEN use_count + 1 ELSE 1 END \
             WHERE id = ?2 AND (use_day IS NOT ?1 OR use_count < ?3)",
        )
        .bind(self.clock.now().div_euclid(86_400))
        .bind(grant.as_str())
        .bind(self.daily_limit(kind))
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(taken > 0)
    }

    /// Record that `grant` of `agent` reached its limit and tell the owner, once a day
    /// per grant, without holding up the refusal. One try: a failure is logged and
    /// recorded, and the refusals keep being recorded either way.
    pub(crate) async fn daily_limit_reached(&self, agent: &AgentName, grant: &Id, kind: &DailyUse) {
        let claimed = sqlx::query(
            "UPDATE grants SET use_limit_noticed_day = ?1 \
             WHERE id = ?2 AND use_limit_noticed_day IS NOT ?1",
        )
        .bind(self.clock.now().div_euclid(86_400))
        .bind(grant.as_str())
        .execute(&self.pool)
        .await;
        match claimed {
            Ok(done) if done.rows_affected() == 0 => return,
            Ok(_) => {}
            Err(e) => {
                tracing::error!(grant = %grant, error = %e, "could not record a daily limit");
                return;
            }
        }
        let reached = match kind {
            DailyUse::ProxyCall { .. } => AuditEvent::ProxyCallLimitReached {
                grant_id: grant.clone(),
                agent: agent.clone(),
                limit: self.daily_limit(kind),
            },
            DailyUse::RelaySession { .. } => AuditEvent::RelaySessionLimitReached {
                grant_id: grant.clone(),
                agent: agent.clone(),
                limit: self.daily_limit(kind),
            },
        };
        if let Err(e) = self.audit.append(reached).await {
            tracing::error!(grant = %grant, error = %e, "could not audit a daily limit");
        }
        let this = self.clone();
        let (agent, grant, kind) = (agent.clone(), grant.clone(), kind.clone());
        tokio::spawn(async move { this.notify_daily_limit(&agent, &grant, &kind).await });
    }

    async fn notify_daily_limit(&self, agent: &AgentName, grant: &Id, kind: &DailyUse) {
        let mut url = self.public_url.clone();
        let Ok(mut path) = url.path_segments_mut() else {
            tracing::error!("public URL cannot be a base; not sending a daily limit notice");
            return;
        };
        path.pop_if_empty().push("grants");
        drop(path);
        let limit = self.daily_limit(kind);
        let (title, message) = match kind {
            DailyUse::ProxyCall { secret } => (
                format!("warden: {agent} reached its API call limit"),
                format!(
                    "It made {limit} calls with {secret} today, so its calls fail until 00:00 \
                     UTC. If you do not expect this many, revoke its grant."
                ),
            ),
            DailyUse::RelaySession { target } => (
                format!("warden: {agent} reached its relay session limit"),
                format!(
                    "It opened {limit} sessions to {target} today, so new sessions fail until \
                     00:00 UTC. If you do not expect this many, revoke its grant."
                ),
            ),
        };
        let bell = Doorbell {
            title,
            message,
            url,
        };
        let event = match self.notifier.ring(&bell).await {
            Ok(channel) => match kind {
                DailyUse::ProxyCall { .. } => AuditEvent::ProxyCallLimitNotified {
                    grant_id: grant.clone(),
                    channel: channel.to_owned(),
                },
                DailyUse::RelaySession { .. } => AuditEvent::RelaySessionLimitNotified {
                    grant_id: grant.clone(),
                    channel: channel.to_owned(),
                },
            },
            Err(e) => {
                tracing::warn!(grant = %grant, error = %e, "daily limit notice failed");
                AuditEvent::Error {
                    context: match kind {
                        DailyUse::ProxyCall { .. } => "API call limit notice",
                        DailyUse::RelaySession { .. } => "relay session limit notice",
                    }
                    .to_owned(),
                    message: bounded_text(format!("grant {grant}: {e}")),
                }
            }
        };
        if let Err(e) = self.audit.append(event).await {
            tracing::error!(grant = %grant, error = %e, "could not audit a daily limit notice");
        }
    }
}

#[cfg(test)]
mod tests;
