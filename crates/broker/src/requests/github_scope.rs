//! GitHub token grants are scoped to repositories. Those stored before that named
//! none, so nothing can be minted under them: they end when the broker starts.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use warden_broker_proto::github_token::{
    GithubTokenAccess, GrantRepository, GrantScope, OLD_CLIENT,
};
use warden_broker_proto::release::RepoName;
use warden_broker_proto::{AgentName, Id};

use super::revocation::commit_with_entries;
use super::{RequestError, Requests, begin, parse};
use crate::audit::AuditEvent;
use crate::github_app::{self, MintError, ResolvedRepository};

/// Why a request naming repositories of more than one account is refused: one
/// installation is one account.
const ONE_ACCOUNT: &str = "the repositories of one request must belong to one account";

/// Check a GitHub token request without asking GitHub or reading the App's key.
///
/// # Errors
/// [`RequestError::Rejected`] for a request naming no repository (a CLI from
/// before grants were scoped) or repositories of more than one owner.
pub(super) fn check_request(access: &GithubTokenAccess) -> Result<(), RequestError> {
    let Some(first) = access.repositories.first() else {
        return Err(RequestError::Rejected(OLD_CLIENT.to_owned()));
    };
    if access
        .repositories
        .iter()
        .any(|r| !r.owner().eq_ignore_ascii_case(first.owner()))
    {
        return Err(RequestError::Rejected(ONE_ACCOUNT.to_owned()));
    }
    Ok(())
}

/// A repository of a request, as GitHub resolved it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedRepository {
    /// GitHub's id for it.
    pub id: u64,
    /// Its name in GitHub's case.
    pub name: RepoName,
    /// The name the grant being renewed had, when GitHub's differs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renamed_from: Option<RepoName>,
}

/// What a request's repository names resolved to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Resolution {
    /// The App reaches every repository named.
    Resolved(Vec<ScopedRepository>),
    /// GitHub says the App cannot reach one of them (not installed, or no such
    /// repository).
    NotAccessible,
}

impl Resolution {
    /// The scope an approval of this resolution grants; `None` when it is not
    /// resolved, names nothing, or repeats a repository.
    #[must_use]
    pub fn scope(&self) -> Option<GrantScope> {
        let Self::Resolved(list) = self else {
            return None;
        };
        GrantScope::repositories(
            list.iter()
                .map(|r| GrantRepository {
                    name: r.name.clone(),
                    id: r.id,
                })
                .collect(),
        )
    }
}

/// An active grant that approving the request would end, because it covers one of
/// the same repositories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplacedGrant {
    /// The grant.
    pub grant_id: Id,
    /// What it covers.
    pub scope: GrantScope,
}

/// What the approval page of a GitHub token request shows and binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubPending {
    /// The repositories as GitHub resolved them.
    pub resolution: Resolution,
    /// The agent's grants that approving would end.
    pub replaces: Vec<ReplacedGrant>,
}

impl GithubPending {
    /// What the approval binds besides the App: every resolved id and lowercased
    /// name in order, then the grants replaced, each followed by `\0`.
    #[must_use]
    pub fn digest_input(&self) -> String {
        let mut input = String::from("warden github-token scope v1\0");
        match &self.resolution {
            Resolution::Resolved(list) => {
                for repository in list {
                    input.push_str(&repository.id.to_string());
                    input.push('\0');
                    input.push_str(&repository.name.as_str().to_ascii_lowercase());
                    input.push('\0');
                }
            }
            Resolution::NotAccessible => input.push_str("not accessible\0"),
        }
        for replaced in &self.replaces {
            input.push_str(replaced.grant_id.as_str());
            input.push('\0');
        }
        input
    }

    /// Lowercase hex SHA-256 over the App's digest and what this binds.
    #[must_use]
    pub fn digest(&self, policy_digest: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(policy_digest.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.digest_input().as_bytes());
        hex::encode(hasher.finalize())
    }
}

/// What GitHub's `answer` means for a request. `renewing` is the grant being renewed,
/// if any (a legacy scope otherwise): a repository it holds under another name
/// carries that name as `renamed_from`.
///
/// # Errors
/// [`RequestError::Unavailable`] with a fixed text when the answer is anything but
/// the repositories or "not accessible": nothing GitHub said is in it.
pub(super) fn resolution_of(
    answer: Result<Vec<ResolvedRepository>, MintError>,
    renewing: &GrantScope,
) -> Result<Resolution, RequestError> {
    match answer {
        Ok(found) => Ok(Resolution::Resolved(
            found
                .into_iter()
                .map(|r| ScopedRepository {
                    renamed_from: renewing
                        .list()
                        .iter()
                        .find(|held| held.id == r.id && !held.name.matches(&r.name))
                        .map(|held| held.name.clone()),
                    id: r.id,
                    name: r.name,
                })
                .collect(),
        )),
        Err(MintError::NotAccessible) => Ok(Resolution::NotAccessible),
        // The text of a `MintError` is fixed: nothing GitHub said is in it.
        Err(e) => Err(RequestError::Unavailable(format!(
            "GitHub repositories: {e}"
        ))),
    }
}

impl Requests {
    /// What the repositories of a GitHub token request resolved to, resolving them
    /// on the first call: the broker asks GitHub, writes `github_repositories_resolved`
    /// and stores the answer, which later calls reuse. With the agent's grants that
    /// approving would end.
    ///
    /// # Errors
    /// [`RequestError::Unavailable`] when GitHub or the App cannot be reached (nothing
    /// is stored, so a later call asks again); the audit and storage failures.
    pub(super) async fn github_pending(
        &self,
        id: &Id,
        agent: &AgentName,
        access: &GithubTokenAccess,
    ) -> Result<GithubPending, RequestError> {
        if access.is_legacy() {
            // Nothing to ask GitHub; approving it is refused.
            return Ok(GithubPending {
                resolution: Resolution::Resolved(Vec::new()),
                replaces: Vec::new(),
            });
        }
        let resolution = match self.stored_resolution(id).await? {
            Some(resolution) => resolution,
            None => self.resolve_and_store(id, access).await?,
        };
        let replaces = self.replaced_grants(agent, &resolution).await?;
        Ok(GithubPending {
            resolution,
            replaces,
        })
    }

    async fn stored_resolution(&self, id: &Id) -> Result<Option<Resolution>, RequestError> {
        let Some(row) =
            sqlx::query("SELECT resolution FROM github_repositories WHERE request_id = ?")
                .bind(id.as_str())
                .fetch_optional(&self.pool)
                .await?
        else {
            return Ok(None);
        };
        let text: String = row.try_get("resolution")?;
        Ok(Some(serde_json::from_str(&text)?))
    }

    /// Ask GitHub, record that it was asked, and keep the first answer stored.
    async fn resolve_and_store(
        &self,
        id: &Id,
        access: &GithubTokenAccess,
    ) -> Result<Resolution, RequestError> {
        let app = self.backend.github_app().await?;
        let answer =
            github_app::resolve(&self.github, &app, &access.repositories, self.clock.now()).await;
        let resolution = resolution_of(answer, &GrantScope::Legacy)?;
        self.record_resolution(id, resolution).await
    }

    /// Audit `resolution` of request `id` as `github_repositories_resolved` and keep
    /// the first answer stored for it; returns what is stored.
    pub(super) async fn record_resolution(
        &self,
        id: &Id,
        resolution: Resolution,
    ) -> Result<Resolution, RequestError> {
        let (repository_ids, accessible) = match &resolution {
            Resolution::Resolved(list) => (list.iter().map(|r| r.id).collect(), true),
            Resolution::NotAccessible => (Vec::new(), false),
        };
        self.audit
            .append(AuditEvent::GithubRepositoriesResolved {
                request_id: id.clone(),
                repository_ids,
                accessible,
            })
            .await?;
        // The first render's answer wins when two race.
        sqlx::query(
            "INSERT OR IGNORE INTO github_repositories (request_id, resolution) VALUES (?, ?)",
        )
        .bind(id.as_str())
        .bind(serde_json::to_string(&resolution)?)
        .execute(&self.pool)
        .await?;
        self.stored_resolution(id).await?.ok_or_else(|| {
            RequestError::Corrupt("the stored repositories of a request vanished".to_owned())
        })
    }

    /// The agent's active GitHub token grants that cover one of the resolved
    /// repositories; a legacy grant always does.
    async fn replaced_grants(
        &self,
        agent: &AgentName,
        resolution: &Resolution,
    ) -> Result<Vec<ReplacedGrant>, RequestError> {
        match resolution.scope() {
            Some(new) => self.overlapping_grants(agent, &new).await,
            None => Ok(Vec::new()),
        }
    }

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
