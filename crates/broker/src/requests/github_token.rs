//! The GitHub token grant's own rules: its windows, the policy the App makes and
//! finding the agent's grant to mint with (the pick itself is in `github_pick`).
//!
//! An agent holds at most one grant per repository and permission set: approving a new
//! grant ends the ones it overlaps with the same set (see `github_overlap`), so that
//! revoking a grant really does stop that agent's minting under that set.

use sqlx::Row as _;
use warden_broker_proto::github_permissions::PermissionSet;
use warden_broker_proto::github_token::{GrantRepository, SENSITIVE_WINDOW};
use warden_broker_proto::release::RepoName;
use warden_broker_proto::{
    AgentName, GithubTokenAccess, GithubTokenGrant, GrantAccess, Id, Window,
};

use super::github_pick::{Candidate, Pick, pick};
use super::{RequestError, Requests, parse};
use crate::audit::{AuditEvent, bounded_text};
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
    /// How long the grant lasts, in seconds: the longest that its `window_secs`,
    /// `not_before` and `not_after` columns and its view say, so that a row changed
    /// since approval in any one of them cannot shorten it.
    pub window_secs: u64,
    /// What to mint with, before the request's own permissions narrow it: the
    /// grant's whole set when the request names permissions, and otherwise the
    /// owner's current default limited to what the grant holds.
    pub mint: PermissionSet,
}

/// What an agent's active grants say about one repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GithubLookup {
    /// No active grant covers it.
    None,
    /// The one to mint with.
    One(ActiveGithubToken),
    /// Two with the same extras do, so none can be chosen; holds the first one's id.
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

/// Whether a GitHub token request for `access` may have `window`, under the
/// server's `max`: a request whose extra permissions include a sensitive one only
/// the short windows, any other only the long ones.
pub(super) fn check_window_for(
    window: Window,
    max: Window,
    access: &GithubTokenAccess,
) -> Result<(), String> {
    if !access.has_sensitive_extra() {
        return check_window(window, max);
    }
    if !window.is_github_token_sensitive() {
        return Err(SENSITIVE_WINDOW.to_owned());
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
    /// by name in any case, and what to mint with, for a request that names `wanted`
    /// (see `github_pick` for the rule). Read for every mint, so that a revocation
    /// or the end of the window stops the next one. A grant stored before scoping
    /// covers nothing. A grant that holds the repository's id under another name is
    /// a candidate too. Two candidates approved with the same extras are
    /// [`GithubLookup::Ambiguous`]: approving replaces a grant with the same extras,
    /// so storage holds that only if something went wrong, and the mint refuses
    /// rather than pick one.
    ///
    /// # Errors
    /// Storage failures, an unreadable stored grant (a covering grant whose
    /// permissions cannot be read refuses, rather than being passed over for
    /// another) or an unreadable owner's default: the caller refuses.
    pub async fn active_github_token_for(
        &self,
        agent: &AgentName,
        repository: &RepoName,
        wanted: Option<&PermissionSet>,
    ) -> Result<GithubLookup, RequestError> {
        let mut grants = Vec::new();
        for row in self.active_rows(agent, "github_token").await? {
            let view: String = row.try_get("view")?;
            let view = super::stored_view(&view)?;
            // The longest any of the stored bounds says: the row's window, its
            // `not_before` and `not_after` columns (which decide whether the grant
            // is active), and the view's, so that a row changed since approval in
            // any one of them cannot shorten what the recheck at mint measures.
            let window: i64 = row.try_get("window_secs")?;
            let not_before: i64 = row.try_get("not_before")?;
            let not_after: i64 = row.try_get("not_after")?;
            let window_secs = [
                window,
                not_after.saturating_sub(not_before),
                view.not_after.saturating_sub(view.not_before),
                not_after.saturating_sub(view.not_before),
                view.not_after.saturating_sub(not_before),
            ]
            .into_iter()
            .max()
            .unwrap_or(0)
            .max(0)
            .unsigned_abs();
            let GrantAccess::GithubToken(grant) = view.access else {
                return Err(RequestError::Corrupt(
                    "GitHub token grant changed kind".to_owned(),
                ));
            };
            grants.push((parse::<Id>(&row, "id")?, grant, window_secs, not_after));
        }
        let ids: Vec<u64> = grants
            .iter()
            .filter_map(|(_, grant, _, _)| grant.repositories.covering(repository))
            .map(|found| found.id)
            .collect();
        let mut candidates = Vec::new();
        for (grant_id, grant, window_secs, not_after) in grants {
            let found = grant.repositories.covering(repository).or_else(|| {
                grant
                    .repositories
                    .list()
                    .iter()
                    .find(|held| ids.contains(&held.id))
            });
            let Some(found) = found.cloned() else {
                continue;
            };
            candidates.push(Candidate::new(
                grant_id,
                grant,
                found,
                window_secs,
                not_after,
            )?);
        }
        let picked = match pick(&candidates, wanted) {
            Pick::None => return Ok(GithubLookup::None),
            Pick::Ambiguous(first) => return Ok(GithubLookup::Ambiguous(first)),
            Pick::One(picked) => picked,
        };
        let mint = self.github_mint_set(picked, wanted).await?;
        Ok(GithubLookup::One(ActiveGithubToken {
            grant_id: picked.grant_id.clone(),
            grant: picked.grant.clone(),
            repository: picked.repository.clone(),
            window_secs: picked.window_secs,
            mint,
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
            reason: bounded_text(reason),
        };
        self.github_refusals
            .record(&self.audit, agent, self.clock.now(), 1, event)
            .await;
    }
}
