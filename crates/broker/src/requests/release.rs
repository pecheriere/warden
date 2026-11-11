//! A release request: what the broker checks against GitHub, and against the
//! repository's release key, before it asks the owner.
//!
//! The owner approves what the broker read: the commit's title and date, the
//! changelog section, whether the tag is already there. The broker reads it once,
//! when the request is made, and stores it with the request (`release_facts`).
//! Nothing GitHub said is quoted in an error: every refusal here is a fixed
//! message or one made of values the broker validated.

use sha2::{Digest as _, Sha256};
use warden_broker_proto::release::{self, CommitId, ReleaseSteps, ReleaseTag, RepoName};
use warden_broker_proto::{Access, AgentName, CreatedResponse, Window};

use super::{RequestError, Requests, Scope, limits, release_version};
use crate::github_release::{GithubError, ReleaseClient};
use crate::policy::{PolicyError, ReleaseAppKey, ReleaseSigningKey};

/// What the broker says when the commit is not on the default branch.
const OFF_DEFAULT_BRANCH: &str = "the commit is not on the repository's default branch";
/// What the broker says about a tag that already exists but is not its own.
const TAG_NOT_OURS: &str = "the tag exists on another commit or under another key";
/// What the broker says when there is nothing for a grant to do.
const NOTHING_LEFT: &str = "nothing left to do: the tag exists and this repository signs no manifest and publishes nothing";
/// What the broker says when GitHub has no such repository installation or commit.
const NOT_ON_GITHUB: &str =
    "GitHub has no such commit, or the release App is not installed on this repository";
/// What the broker says when GitHub cannot be asked, whatever the reason.
const GITHUB_UNAVAILABLE: &str = "GitHub could not be asked about this release; try again";

/// What the broker read from GitHub for a release request, stored with it as JSON.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReleaseFacts {
    /// The commit's first line.
    pub commit_title: String,
    /// When the commit was made, as `YYYY-MM-DDTHH:MM:SSZ`.
    pub commit_date: String,
    /// Whether the commit is on the default branch. A request for one that is
    /// not is refused, so this is true in every stored request.
    pub on_default_branch: bool,
    /// The changelog section for the version, if the commit has one.
    pub changelog: Option<String>,
    /// Whether `changelog` was cut short, and ends in a marker saying so. Absent
    /// from requests stored before it existed, which were never cut.
    #[serde(default)]
    pub changelog_cut: bool,
    /// Whether the tag was already in place, signed by the repository's key.
    pub tag_in_place: bool,
    /// The highest release tag below this one, for a link to compare them.
    pub previous_tag: Option<ReleaseTag>,
}

/// What a release request is bound to: the repository's key and what it does,
/// and the App that acts on GitHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasePolicy {
    /// The repository.
    pub repository: RepoName,
    /// The `SHA256:...` fingerprint of the key that signs the tag and manifest.
    pub key_fingerprint: String,
    /// The manifest's file name for this version, if the repository signs one.
    pub manifest: Option<String>,
    /// Whether the broker publishes the draft release.
    pub publish: bool,
    /// [`ReleaseSigningKey::destination_digest`].
    pub key_digest: String,
    /// [`ReleaseAppKey::digest`].
    pub app_digest: String,
}

impl ReleasePolicy {
    /// The policy of releasing `tag` with `key` and `app`.
    #[must_use]
    pub fn new(key: &ReleaseSigningKey, app: &ReleaseAppKey, tag: &ReleaseTag) -> Self {
        Self {
            repository: key.repository().clone(),
            key_fingerprint: key.fingerprint(),
            manifest: key.manifest().map(|spec| spec.file_name(tag.version())),
            publish: key.publish(),
            key_digest: key.destination_digest(),
            app_digest: app.digest(),
        }
    }

    /// Lowercase hex digest of what an approval is bound to: the key and the App.
    /// The approval is refused if either changed meanwhile.
    #[must_use]
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"warden release v1\0");
        hasher.update(self.key_digest.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.app_digest.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// The steps a grant covers, given whether the tag was already in place.
    #[must_use]
    pub fn steps(&self, tag_in_place: bool) -> ReleaseSteps {
        ReleaseSteps {
            tag: !tag_in_place,
            manifest: self.manifest.clone(),
            publish: self.publish,
        }
    }
}

/// Whether a release grant may have `window`.
pub(super) fn check_window(window: Window) -> Result<(), String> {
    if window.is_release() {
        Ok(())
    } else {
        Err("a release grant lasts 1d".to_owned())
    }
}

/// The key and App a release of `repository` needs. A repository with no key, or a
/// broker with no App, gets the same answer: releases are not configured.
fn not_configured(e: PolicyError) -> RequestError {
    match e {
        PolicyError::NoReleaseKey | PolicyError::NoReleaseApp => {
            RequestError::Rejected(release::NOT_CONFIGURED.to_owned())
        }
        other => other.into(),
    }
}

/// A refusal for a call to GitHub that failed. The reason is logged by kind only.
fn github_failed(e: &GithubError) -> RequestError {
    tracing::warn!(error = %e, "release request: GitHub could not be asked");
    match e {
        GithubError::NotFound => RequestError::Rejected(NOT_ON_GITHUB.to_owned()),
        _ => RequestError::Rejected(GITHUB_UNAVAILABLE.to_owned()),
    }
}

impl Requests {
    /// The policy of releasing `tag` of `repository` as the key and App are now.
    ///
    /// # Errors
    /// [`RequestError::Rejected`] with [`release::NOT_CONFIGURED`] when the
    /// repository has no key or there is no App, or the backend's errors.
    pub(super) async fn release_policy(
        &self,
        repository: &RepoName,
        tag: &ReleaseTag,
    ) -> Result<ReleasePolicy, RequestError> {
        let key = self
            .backend
            .release_signing(repository)
            .await
            .map_err(not_configured)?;
        let app = self.backend.release_app().await.map_err(not_configured)?;
        Ok(ReleasePolicy::new(&key, &app, tag))
    }

    /// What a release request is bound to before GitHub is asked: its window, the
    /// repository's key, the App, and its dedupe slot and subject.
    ///
    /// # Errors
    /// [`RequestError::Rejected`] for a window other than 1d, or
    /// [`release::NOT_CONFIGURED`], or the backend's errors.
    pub(super) async fn release_slot(
        &self,
        window: Window,
        access: &Access,
        agent: &AgentName,
    ) -> Result<ReleaseSlot, RequestError> {
        let Access::Release {
            repository,
            tag,
            commit,
        } = access
        else {
            return Err(RequestError::Internal("not a release request"));
        };
        check_window(window).map_err(RequestError::Rejected)?;
        let key = self
            .backend
            .release_signing(repository)
            .await
            .map_err(not_configured)?;
        let app = self.backend.release_app().await.map_err(not_configured)?;
        Ok(ReleaseSlot {
            dedupe_key: format!(
                "{agent}|release|{}|{tag}",
                repository.as_str().to_ascii_lowercase()
            ),
            subject: format!("release {repository} {tag}"),
            repository: repository.clone(),
            tag: tag.clone(),
            commit: commit.clone(),
            key,
            app,
        })
    }

    /// What can be answered about a release request without asking GitHub: the
    /// agent's pending request in the same slot, or the refusal that its limits
    /// make. A duplicate is not new, so it is let through the limits as `insert`
    /// lets it; `insert` still enforces them on a request that is stored.
    ///
    /// # Errors
    /// [`RequestError::Limited`], or storage failures.
    pub(super) async fn release_answered_locally(
        &self,
        agent: &AgentName,
        dedupe_key: &str,
    ) -> Result<Option<CreatedResponse>, RequestError> {
        // A stale pending row past its expiry must not hold the slot.
        self.expire_due(Scope::Dedupe(dedupe_key.to_owned()))
            .await?;
        if let Some(existing) = self.pending_in_slot(dedupe_key).await? {
            return Ok(Some(existing));
        }
        let mut conn = self.pool.acquire().await?;
        let checked =
            limits::check(&mut conn, &self.limits, agent, dedupe_key, self.clock.now()).await;
        drop(conn);
        if let Err(RequestError::Limited(refusal)) = &checked {
            self.record_refusal(agent, *refusal).await;
        }
        checked.map(|()| None)
    }

    /// Check a release request against GitHub: the commit, the tag and the
    /// changelog. Returns what GitHub said.
    ///
    /// # Errors
    /// [`RequestError::Rejected`] with a message that quotes nothing GitHub said.
    /// Nothing is stored.
    pub(super) async fn check_release(
        &self,
        slot: &ReleaseSlot,
    ) -> Result<ReleaseFacts, RequestError> {
        let client =
            ReleaseClient::connect(&self.github, &slot.app, &slot.repository, self.clock.now())
                .await
                .map_err(|e| github_failed(&e))?;
        let facts = read_facts(&client, &slot.key, &slot.tag, &slot.commit).await?;
        let policy = ReleasePolicy::new(&slot.key, &slot.app, &slot.tag);
        if facts.tag_in_place && policy.manifest.is_none() && !policy.publish {
            return Err(RequestError::Rejected(NOTHING_LEFT.to_owned()));
        }
        Ok(facts)
    }
}

/// A release request as far as it can be checked without GitHub.
pub(super) struct ReleaseSlot {
    /// The slot the agent's pending request for this release holds.
    pub(super) dedupe_key: String,
    /// What the request asks for, in the owner's notification.
    pub(super) subject: String,
    repository: RepoName,
    tag: ReleaseTag,
    commit: CommitId,
    key: ReleaseSigningKey,
    app: ReleaseAppKey,
}

/// Read what the owner is shown, and refuse a commit off the default branch and a
/// tag that is not the repository key's own at the commit.
async fn read_facts(
    client: &ReleaseClient<'_>,
    key: &ReleaseSigningKey,
    tag: &ReleaseTag,
    commit: &CommitId,
) -> Result<ReleaseFacts, RequestError> {
    let info = client.commit(commit).await.map_err(|e| github_failed(&e))?;
    if !client
        .on_default_branch(commit)
        .await
        .map_err(|e| github_failed(&e))?
    {
        return Err(RequestError::Rejected(OFF_DEFAULT_BRANCH.to_owned()));
    }
    let tag_in_place = match client
        .tag_target(tag)
        .await
        .map_err(|e| github_failed(&e))?
    {
        None => false,
        Some(existing) => {
            let ours = existing.commit.as_ref() == Some(commit)
                && existing
                    .raw
                    .as_deref()
                    .is_some_and(|raw| key.verifies_tag(raw));
            if !ours {
                return Err(RequestError::Rejected(TAG_NOT_OURS.to_owned()));
            }
            true
        }
    };
    let changelog = client
        .changelog_section(commit, tag.version())
        .await
        .map_err(|e| github_failed(&e))?;
    let changelog_cut = changelog.as_ref().is_some_and(|section| section.cut);
    let tags = client.release_tags().await.map_err(|e| github_failed(&e))?;
    Ok(ReleaseFacts {
        commit_title: info.title,
        commit_date: info.date,
        on_default_branch: true,
        changelog: changelog.map(|section| section.text),
        changelog_cut,
        tag_in_place,
        previous_tag: release_version::previous(tag, &tags).cloned(),
    })
}
