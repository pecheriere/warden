//! The GitHub token grant's own rules: its windows, the policy the App makes and
//! finding an agent's active grant.
//!
//! An agent holds at most one grant per repository: approving a new grant ends the
//! ones it overlaps (see `renewal`), so that revoking a grant really does stop that
//! agent's minting.

use sqlx::Row as _;
use warden_broker_proto::github_token::GrantRepository;
use warden_broker_proto::release::RepoName;
use warden_broker_proto::{AgentName, GithubTokenGrant, GrantAccess, GrantView, Id, Window};

use super::{RequestError, Requests, parse};
use crate::audit::AuditEvent;
use crate::policy::GithubTokenPolicy;

/// A usable GitHub token grant, with the repository of it that was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveGithubToken {
    /// The grant.
    pub grant_id: Id,
    /// What was approved.
    pub grant: GithubTokenGrant,
    /// The repository asked for, as the grant stores it.
    pub repository: GrantRepository,
}

/// What an agent's active grants say about one repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GithubLookup {
    /// No active grant covers it.
    None,
    /// Exactly one does.
    One(ActiveGithubToken),
    /// More than one does, so none can be chosen; holds the first one's id.
    Ambiguous(Id),
}

/// Tokens per agent per hour, unless a test says otherwise. The CLI caches a token for
/// most of its hour, so it mints about once an hour; this is far more, and small
/// enough that a looping agent cannot use up the App's rate limit at GitHub, which
/// every agent shares, or fill the audit log.
pub const MINTS_PER_HOUR: u32 = 60;

/// Whether a GitHub token grant may have `window`, under the server's `max`.
pub(super) fn check_window(window: Window, max: Window) -> Result<(), String> {
    if !window.is_github_token() {
        return Err("a GitHub token grant lasts 1d, 7d or 30d".to_owned());
    }
    super::check_window(window, max, "GitHub tokens")
}

impl Requests {
    /// Allow GitHub token grants of up to `max`, instead of the default 30 days.
    #[must_use]
    pub const fn with_github_token_max(mut self, max: Window) -> Self {
        self.github_token_max = max;
        self
    }

    /// Allow each agent `limit` GitHub tokens per hour, instead of
    /// [`MINTS_PER_HOUR`].
    #[must_use]
    pub const fn with_github_token_per_hour(mut self, limit: u32) -> Self {
        self.github_token_per_hour = limit;
        self
    }

    /// Take one of `agent`'s tokens for this hour, or say there are none left. In one
    /// statement, so that concurrent calls cannot pass the limit, and in the database,
    /// so that a restart does not reset it. Counted per agent, whatever grants it has
    /// held this hour.
    ///
    /// # Errors
    /// Storage failures: the caller refuses.
    pub(crate) async fn take_mint(&self, agent: &AgentName) -> Result<bool, RequestError> {
        let taken = sqlx::query(
            "INSERT INTO github_token_mints (agent, mint_hour, mint_count) VALUES (?1, ?2, 1) \
             ON CONFLICT(agent) DO UPDATE SET \
             mint_count = CASE WHEN mint_hour = excluded.mint_hour THEN mint_count + 1 ELSE 1 END, \
             mint_hour = excluded.mint_hour \
             WHERE mint_hour IS NOT excluded.mint_hour OR mint_count < ?3",
        )
        .bind(agent.as_str())
        .bind(self.clock.now().div_euclid(3600))
        .bind(self.github_token_per_hour)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(taken > 0)
    }

    /// The longest GitHub token grant the server allows.
    #[must_use]
    pub const fn github_token_max(&self) -> Window {
        self.github_token_max
    }

    /// What a GitHub token grant would be bound to now: the App the broker holds.
    ///
    /// # Errors
    /// [`RequestError::Rejected`] if the broker holds no App,
    /// [`RequestError::Unavailable`] if it cannot be read.
    pub(super) async fn github_token_policy(&self) -> Result<GithubTokenPolicy, RequestError> {
        Ok(self
            .backend
            .github_app()
            .await?
            .policy(self.github_token_max))
    }

    /// The GitHub token grant `agent` may mint with now for `repository`, matched
    /// by name in any case. Read for every mint, so that a revocation or the end
    /// of the window stops the next one. A grant stored before scoping covers
    /// nothing. More than one active grant on the repository (by id, or by name
    /// under different ids) is [`GithubLookup::Ambiguous`]: approving replaces an
    /// overlapping grant, so storage holds that only if something went wrong, and
    /// the mint refuses rather than pick one.
    ///
    /// # Errors
    /// Storage failures or an unreadable stored grant: the caller refuses.
    pub async fn active_github_token_for(
        &self,
        agent: &AgentName,
        repository: &RepoName,
    ) -> Result<GithubLookup, RequestError> {
        let mut grants = Vec::new();
        for row in self.active_rows(agent, "github_token").await? {
            let view: String = row.try_get("view")?;
            let view: GrantView = serde_json::from_str(&view)?;
            let GrantAccess::GithubToken(grant) = view.access else {
                return Err(RequestError::Corrupt(
                    "GitHub token grant changed kind".to_owned(),
                ));
            };
            grants.push((parse::<Id>(&row, "id")?, grant));
        }
        let mut covering = grants.iter().filter_map(|(grant_id, grant)| {
            grant
                .repositories
                .covering(repository)
                .map(|found| (grant_id, grant, found))
        });
        let Some((grant_id, grant, found)) = covering.next() else {
            return Ok(GithubLookup::None);
        };
        let found_id = found.id;
        let found = found.clone();
        let sharing = grants
            .iter()
            .filter(|(_, other)| other.repositories.list().iter().any(|r| r.id == found_id))
            .count();
        if covering.next().is_some() || sharing > 1 {
            return Ok(GithubLookup::Ambiguous(grant_id.clone()));
        }
        Ok(GithubLookup::One(ActiveGithubToken {
            grant_id: grant_id.clone(),
            grant: grant.clone(),
            repository: found,
        }))
    }

    /// Record that `agent` was refused a GitHub token, for `reason` (a fixed phrase).
    /// Past a few a minute only a count is kept, written later as one entry.
    pub(crate) async fn record_github_token_refusal(
        &self,
        agent: &AgentName,
        grant_id: Option<Id>,
        reason: String,
    ) {
        let event = AuditEvent::GithubTokenRefused {
            agent: agent.clone(),
            grant_id,
            reason,
        };
        self.github_refusals
            .record(
                &self.audit,
                agent,
                self.clock.now(),
                event,
                "a refusal to mint",
            )
            .await;
    }

    /// Write the refusals to mint held back since the last time.
    pub(super) async fn flush_github_refusals(&self) {
        self.github_refusals
            .flush(&self.audit, "refusals to mint", |agent, count| {
                AuditEvent::GithubTokenRefusalsHeld { agent, count }
            })
            .await;
    }
}
