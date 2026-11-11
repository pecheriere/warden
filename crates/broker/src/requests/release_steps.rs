//! The steps of a release grant: finding the grant an agent holds for a release,
//! claiming a step so that it is done once, and ending the grant when the last one is.
//!
//! A step is claimed before it is done and a claim is never given back, so a step
//! that fails after its claim stays used: the agent asks the owner again.

use sqlx::Row as _;
use warden_broker_proto::release::{ReleaseGrant, ReleaseSteps, ReleaseTag, RepoName};
use warden_broker_proto::{AgentName, GrantAccess, GrantView, Id};

use crate::audit::AuditEvent;

use super::{RequestError, Requests, parse};

/// One of the steps of a release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseStep {
    /// Create the tag.
    Tag,
    /// Sign the manifest.
    Manifest,
    /// Publish the draft release.
    Publish,
}

impl ReleaseStep {
    /// The statement that claims the step. One literal each, so that nothing a
    /// caller sends reaches the SQL.
    const fn claim_sql(self) -> &'static str {
        match self {
            Self::Tag => {
                "UPDATE release_steps SET tag_claimed_at = ?1 \
                 WHERE grant_id = ?2 AND tag_claimed_at IS NULL \
                 AND EXISTS (SELECT 1 FROM grants g WHERE g.id = ?2 \
                   AND g.revoked_at IS NULL AND g.not_after > ?3)"
            }
            Self::Manifest => {
                "UPDATE release_steps SET manifest_claimed_at = ?1 \
                 WHERE grant_id = ?2 AND manifest_claimed_at IS NULL \
                 AND EXISTS (SELECT 1 FROM grants g WHERE g.id = ?2 \
                   AND g.revoked_at IS NULL AND g.not_after > ?3)"
            }
            Self::Publish => {
                "UPDATE release_steps SET publish_claimed_at = ?1 \
                 WHERE grant_id = ?2 AND publish_claimed_at IS NULL \
                 AND EXISTS (SELECT 1 FROM grants g WHERE g.id = ?2 \
                   AND g.revoked_at IS NULL AND g.not_after > ?3)"
            }
        }
    }

    /// The step's name in the audit log and in refusals.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Tag => "tag",
            Self::Manifest => "manifest",
            Self::Publish => "publish",
        }
    }

    /// Whether the owner approved this step in `steps`.
    #[must_use]
    pub const fn covered_by(self, steps: &ReleaseSteps) -> bool {
        match self {
            Self::Tag => steps.tag,
            Self::Manifest => steps.manifest.is_some(),
            Self::Publish => steps.publish,
        }
    }
}

/// A usable release grant. Only [`Requests::active_release`] makes one, so that
/// holding it means the grant was read from the store for this release: its
/// fields cannot be changed to claim a step the owner did not approve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveRelease {
    grant_id: Id,
    grant: ReleaseGrant,
}

impl ActiveRelease {
    /// The grant's id.
    #[must_use]
    pub const fn grant_id(&self) -> &Id {
        &self.grant_id
    }

    /// What was approved.
    #[must_use]
    pub const fn grant(&self) -> &ReleaseGrant {
        &self.grant
    }
}

/// The digests the manifest step kept: the files it attached to the draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedManifest {
    /// Lowercase hex SHA-256 of the manifest.
    pub manifest_sha256: String,
    /// Lowercase hex SHA-256 of the manifest's signature file.
    pub signature_sha256: String,
}

impl Requests {
    /// The release grant `agent` may act on for `tag` in `repo`, if any. The
    /// repository is matched ignoring ASCII case, as GitHub does. Read for every
    /// step, so that a revocation or the end of the grant stops the next one.
    ///
    /// # Errors
    /// Storage failures, an unreadable stored grant, or more than one active grant
    /// for the same release (which approving a release grant never leaves): the caller refuses.
    pub async fn active_release(
        &self,
        agent: &AgentName,
        repo: &RepoName,
        tag: &ReleaseTag,
    ) -> Result<Option<ActiveRelease>, RequestError> {
        let mut found = Vec::new();
        for row in self.active_rows(agent, "release").await? {
            let view: String = row.try_get("view")?;
            let view: GrantView = serde_json::from_str(&view)?;
            let GrantAccess::Release(grant) = view.access else {
                return Err(RequestError::Corrupt(
                    "release grant changed kind".to_owned(),
                ));
            };
            if grant.repository.matches(repo) && grant.tag == *tag {
                found.push(ActiveRelease {
                    grant_id: parse(&row, "id")?,
                    grant,
                });
            }
        }
        match found.len() {
            0 => Ok(None),
            1 => Ok(found.pop()),
            _ => Err(RequestError::Corrupt(
                "more than one active grant for one release".to_owned(),
            )),
        }
    }

    /// Whether `step` of `release` was claimed already. A read, for the caller to
    /// say so before it asks GitHub anything; only [`Requests::claim_step`] decides
    /// whether a step may run.
    ///
    /// # Errors
    /// Storage failures: the caller refuses.
    pub async fn step_claimed(
        &self,
        release: &ActiveRelease,
        step: ReleaseStep,
    ) -> Result<bool, RequestError> {
        let row = sqlx::query(
            "SELECT tag_claimed_at, manifest_claimed_at, publish_claimed_at \
             FROM release_steps WHERE grant_id = ?",
        )
        .bind(release.grant_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let column = match step {
            ReleaseStep::Tag => "tag_claimed_at",
            ReleaseStep::Manifest => "manifest_claimed_at",
            ReleaseStep::Publish => "publish_claimed_at",
        };
        Ok(row.try_get::<Option<i64>, _>(column)?.is_some())
    }

    /// Claim `step` of `release` at `now`. True for exactly one caller, ever: in one
    /// statement, so that two at once cannot both claim, and in the database, so
    /// that a restart does not forget it.
    ///
    /// The claim is the check that the step may run, so a caller makes it after its
    /// own preparation and before the step's effect, and does the step only on true.
    /// False when the grant does not cover the step (the owner did not approve it),
    /// when the grant was revoked or its window has ended at `now`, when the step was
    /// claimed before whatever became of it, or when the grant has no such row. A
    /// revocation between [`Requests::active_release`] and the claim therefore still
    /// stops the step.
    ///
    /// # Errors
    /// Storage failures: the caller refuses.
    pub async fn claim_step(
        &self,
        release: &ActiveRelease,
        step: ReleaseStep,
        now: i64,
    ) -> Result<bool, RequestError> {
        if !step.covered_by(&release.grant.steps) {
            return Ok(false);
        }
        let claimed = sqlx::query(step.claim_sql())
            .bind(now)
            .bind(release.grant_id.as_str())
            .bind(now)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(claimed > 0)
    }

    /// Keep the digests of the manifest that was signed and of its signature, for
    /// the grants page and the audit trail. Once, and only after the manifest step
    /// was claimed.
    ///
    /// # Errors
    /// [`RequestError::Corrupt`] when the step was not claimed or the digests are
    /// already kept; storage failures.
    pub async fn record_manifest(
        &self,
        grant: &Id,
        manifest_sha256: &str,
        signature_sha256: &str,
    ) -> Result<(), RequestError> {
        let kept = sqlx::query(
            "UPDATE release_steps SET manifest_sha256 = ?, signature_sha256 = ? \
             WHERE grant_id = ? AND manifest_claimed_at IS NOT NULL AND manifest_sha256 IS NULL",
        )
        .bind(manifest_sha256)
        .bind(signature_sha256)
        .bind(grant.as_str())
        .execute(&self.pool)
        .await?
        .rows_affected();
        if kept == 0 {
            return Err(RequestError::Corrupt(
                "the manifest step was not claimed, or its digests are kept already".to_owned(),
            ));
        }
        Ok(())
    }

    /// The digests [`Requests::record_manifest`] kept for `release`, or `None` when
    /// the manifest step has not finished: it was not run, or it failed after its
    /// claim, which leaves nothing recorded.
    ///
    /// # Errors
    /// Storage failures: the caller refuses.
    pub async fn recorded_manifest(
        &self,
        release: &ActiveRelease,
    ) -> Result<Option<RecordedManifest>, RequestError> {
        let row = sqlx::query(
            "SELECT manifest_sha256, signature_sha256 FROM release_steps WHERE grant_id = ?",
        )
        .bind(release.grant_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let manifest: Option<String> = row.try_get("manifest_sha256")?;
        let signature: Option<String> = row.try_get("signature_sha256")?;
        Ok(manifest
            .zip(signature)
            .map(|(manifest_sha256, signature_sha256)| RecordedManifest {
                manifest_sha256,
                signature_sha256,
            }))
    }

    /// End release grant `grant` at `now` when every step it covers is claimed: the
    /// tag if the grant creates it, the manifest if it signs one, the publish if it
    /// publishes. The window only ever gets shorter.
    ///
    /// # Errors
    /// Storage failures or an unreadable stored grant: the caller refuses.
    pub async fn end_if_done(&self, grant: &Id, now: i64) -> Result<(), RequestError> {
        let row = sqlx::query("SELECT view FROM grants WHERE id = ?")
            .bind(grant.as_str())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(RequestError::NotFound)?;
        let view: String = row.try_get("view")?;
        let view: GrantView = serde_json::from_str(&view)?;
        let GrantAccess::Release(release) = view.access else {
            return Err(RequestError::Corrupt(
                "release grant changed kind".to_owned(),
            ));
        };
        let steps = release.steps;
        sqlx::query(
            "UPDATE grants SET not_after = ?1 WHERE id = ?2 AND not_after > ?1 \
             AND EXISTS (SELECT 1 FROM release_steps s WHERE s.grant_id = ?2 \
               AND (?3 = 0 OR s.tag_claimed_at IS NOT NULL) \
               AND (?4 = 0 OR s.manifest_claimed_at IS NOT NULL) \
               AND (?5 = 0 OR s.publish_claimed_at IS NOT NULL))",
        )
        .bind(now)
        .bind(grant.as_str())
        .bind(i64::from(steps.tag))
        .bind(i64::from(steps.manifest.is_some()))
        .bind(i64::from(steps.publish))
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

impl Requests {
    /// Record that `agent` was refused `step` of a release, for `reason` (a fixed
    /// phrase). Past a few a minute only a count is kept, written later as one
    /// entry.
    pub(crate) async fn record_release_refusal(
        &self,
        agent: &AgentName,
        grant_id: Option<Id>,
        step: &str,
        reason: String,
    ) {
        let event = AuditEvent::ReleaseRefused {
            agent: agent.clone(),
            grant_id,
            step: step.to_owned(),
            reason,
        };
        self.release_refusals
            .record(
                &self.audit,
                agent,
                self.clock.now(),
                event,
                "a refusal of a release step",
            )
            .await;
    }

    /// Write the refusals of release steps held back since the last time.
    pub(super) async fn flush_release_refusals(&self) {
        self.release_refusals
            .flush(&self.audit, "refusals of release steps", |agent, count| {
                AuditEvent::ReleaseRefusalsHeld { agent, count }
            })
            .await;
    }
}
