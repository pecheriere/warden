//! Which of an agent's GitHub token grants covering a repository a token comes from,
//! and with which permissions.
//!
//! An agent can hold several grants on one repository, one per set of extras. A mint
//! that names permissions takes the least privileged grant holding them all: no
//! sensitive permission first, then the fewest permissions, then the one ending
//! soonest, then the smallest id. The token is then narrowed to what was named, so
//! the pick decides only which grant the audit log names and which revoke stops it.
//! A mint that names nothing takes the least privileged grant the same way and gets
//! the owner's current default set, limited to what that grant holds: an extra
//! permission reaches a token only when the request names it.

use warden_broker_proto::Id;
use warden_broker_proto::github_permissions::PermissionSet;
use warden_broker_proto::github_token::{GithubTokenGrant, GrantRepository};

use super::{RequestError, Requests, github_extras_of, github_permissions_of};

/// An active grant covering the repository asked for, read strictly.
#[derive(Debug, Clone)]
pub(super) struct Candidate {
    pub(super) grant_id: Id,
    pub(super) grant: GithubTokenGrant,
    /// The repository asked for, as the grant stores it.
    pub(super) repository: GrantRepository,
    /// How long the grant lasts, in seconds (see `ActiveGithubToken::window_secs`).
    pub(super) window_secs: u64,
    /// When it ends, as its row says.
    pub(super) not_after: i64,
    /// What its tokens may have.
    permissions: PermissionSet,
    /// The extras it was approved with, `metadata:read` alone for none.
    extras: PermissionSet,
}

impl Candidate {
    /// The candidate for `grant`, its permissions and extras read strictly.
    ///
    /// # Errors
    /// [`RequestError::Corrupt`] when this version cannot act on either set: the
    /// lookup then refuses, rather than skip the grant and pick another, which
    /// would hide the corruption.
    pub(super) fn new(
        grant_id: Id,
        grant: GithubTokenGrant,
        repository: GrantRepository,
        window_secs: u64,
        not_after: i64,
    ) -> Result<Self, RequestError> {
        let permissions = github_permissions_of(&grant)?;
        let extras = github_extras_of(&grant)?.unwrap_or_else(PermissionSet::metadata_only);
        Ok(Self {
            grant_id,
            grant,
            repository,
            window_secs,
            not_after,
            permissions,
            extras,
        })
    }
}

/// What the pick found.
#[derive(Debug)]
pub(super) enum Pick<'a> {
    /// No grant covers the repository.
    None,
    /// The grant to mint with.
    One(&'a Candidate),
    /// Two grants with the same extras cover it, which approving never leaves, so
    /// none is chosen; holds the first one's id.
    Ambiguous(Id),
}

/// The grant among `candidates` to mint with for `wanted`, the permissions the request
/// names: the least privileged one holding them all. If none holds them all, the pick
/// is among every candidate, and the caller refuses naming what it lacks.
pub(super) fn pick<'a>(candidates: &'a [Candidate], wanted: Option<&PermissionSet>) -> Pick<'a> {
    for (at, candidate) in candidates.iter().enumerate() {
        if let Some(first) = candidates[..at]
            .iter()
            .find(|earlier| earlier.extras == candidate.extras)
        {
            return Pick::Ambiguous(first.grant_id.clone());
        }
    }
    let holds = |candidate: &&Candidate| wanted.is_none_or(|w| candidate.permissions.covers_all(w));
    let holders: Vec<&Candidate> = if candidates.iter().any(|c| holds(&c)) {
        candidates.iter().filter(holds).collect()
    } else {
        candidates.iter().collect()
    };
    holders
        .into_iter()
        .min_by(|a, b| privilege(a).cmp(&privilege(b)))
        .map_or(Pick::None, Pick::One)
}

/// The order of the pick, least privileged first: no sensitive permission, the fewest
/// permissions, the soonest end, then the id, so that the order is total.
fn privilege(candidate: &Candidate) -> (bool, usize, i64, &str) {
    (
        candidate.permissions.sensitive().next().is_some(),
        candidate.permissions.iter().count(),
        candidate.not_after,
        candidate.grant_id.as_str(),
    )
}

impl Requests {
    /// The permissions to mint with under `picked` for `wanted`: the grant's own when
    /// the request names permissions (the caller narrows them to what was named), and
    /// otherwise the owner's current default set, limited to what the grant holds.
    ///
    /// # Errors
    /// The owner's default cannot be read: the caller refuses.
    pub(super) async fn github_mint_set(
        &self,
        picked: &Candidate,
        wanted: Option<&PermissionSet>,
    ) -> Result<PermissionSet, RequestError> {
        if wanted.is_some() {
            return Ok(picked.permissions.clone());
        }
        let policy = self.backend.github_permissions().await?;
        Ok(policy.default.intersection(&picked.permissions))
    }
}

#[cfg(test)]
mod tests;
