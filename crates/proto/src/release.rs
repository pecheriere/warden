//! Validated names for releases: the repository, the tag and the commit.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{Id, ParseError};

/// The longest tag accepted, in characters.
const MAX_TAG_CHARS: usize = 64;

/// A GitHub repository, `owner/name`. The owner matches
/// `^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`, the name `^[A-Za-z0-9._-]{1,100}$` and is
/// not `.` or `..`. GitHub treats both case-insensitively, so [`Self::matches`]
/// does too; the value keeps the case it was given.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RepoName(String);

impl TryFrom<String> for RepoName {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let refused = || {
            ParseError::new(
                "repository",
                "must be owner/name, with a GitHub owner and a repository name",
            )
        };
        let (owner, name) = value.split_once('/').ok_or_else(refused)?;
        let owner_ok = owner.len() <= 39
            && owner
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphanumeric())
            && owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        let name_ok = (1..=100).contains(&name.len())
            && name != "."
            && name != ".."
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if owner_ok && name_ok {
            Ok(Self(value))
        } else {
            Err(refused())
        }
    }
}
string_newtype!(RepoName);

impl RepoName {
    /// The owner, before the slash.
    #[must_use]
    pub fn owner(&self) -> &str {
        self.0.split_once('/').map_or("", |(owner, _)| owner)
    }

    /// The repository name, after the slash.
    #[must_use]
    pub fn name(&self) -> &str {
        self.0.split_once('/').map_or("", |(_, name)| name)
    }

    /// Whether both name the same repository, ignoring ASCII case.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

/// A release tag: `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`, at most 64
/// characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ReleaseTag(String);

impl TryFrom<String> for ReleaseTag {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let refused = || {
            ParseError::new(
                "release tag",
                "must match ^v[0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.-]+)?$ and be at most 64 characters",
            )
        };
        if value.len() > MAX_TAG_CHARS {
            return Err(refused());
        }
        let version = value.strip_prefix('v').ok_or_else(refused)?;
        let (core, pre) = match version.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (version, None),
        };
        let numbers: Vec<&str> = core.split('.').collect();
        let numeric = |s: &&str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        let pre_ok = pre.is_none_or(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        });
        if numbers.len() == 3 && numbers.iter().all(numeric) && pre_ok {
            Ok(Self(value))
        } else {
            Err(refused())
        }
    }
}
string_newtype!(ReleaseTag);

impl ReleaseTag {
    /// The version, which is the tag without its leading `v`.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.0[1..]
    }
}

/// A Git commit id: exactly 40 lowercase hexadecimal characters. GitHub does not
/// host SHA-256 repositories, so a 64-character id is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CommitId(String);

impl TryFrom<String> for CommitId {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() == 40
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(Self(value))
        } else {
            Err(ParseError::new(
                "commit id",
                "must be 40 lowercase hexadecimal characters",
            ))
        }
    }
}
string_newtype!(CommitId);

/// What the broker says when the agent has no active release grant: never had
/// one, or it ended or was revoked. The CLI recognises it to say how to ask.
pub const NO_ACTIVE_GRANT: &str = "no active release grant for this agent";

/// What the broker says when a step was already done under the grant. A step
/// is claimed once: a repeat is refused, whatever became of the first attempt.
pub const STEP_DONE: &str = "this step of the release was already done";

/// What the broker says when the grant the owner approved does not include the
/// step asked for, such as the tag when it was already in place.
pub const STEP_NOT_IN_GRANT: &str = "this step is not part of the approved release";

/// What the broker says when it holds no release signing key or release App.
pub const NOT_CONFIGURED: &str = "releases are not configured on this broker";

/// The largest manifest the broker signs, in bytes.
pub const MAX_MANIFEST_BYTES: usize = 65_536;

/// Release grant details. The signing key and the App's key are never part of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseGrant {
    /// The repository the release is made in.
    pub repository: RepoName,
    /// The tag the release is made at.
    pub tag: ReleaseTag,
    /// The commit the tag points at, as the owner approved it.
    pub commit: CommitId,
    /// `SHA256:...` fingerprint of the key that signs the manifest.
    pub key_fingerprint: String,
    /// The steps the owner approved.
    pub steps: ReleaseSteps,
    /// Lowercase hex digest of the approved release facts and key: a step is
    /// refused once what the broker reads no longer matches it.
    pub digest: String,
}

/// The steps of a release a grant covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseSteps {
    /// Whether the broker creates the tag. False when the tag was already in
    /// place when the request was made.
    pub tag: bool,
    /// The name of the manifest file the broker signs, if it signs one.
    pub manifest: Option<String>,
    /// Whether the broker publishes the draft release.
    pub publish: bool,
}

/// Body of the tag and publish steps: which release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseTarget {
    /// The repository.
    pub repository: RepoName,
    /// The tag.
    pub tag: ReleaseTag,
}

/// Body of the manifest step: the manifest to sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignManifestRequest {
    /// The repository.
    pub repository: RepoName,
    /// The tag.
    pub tag: ReleaseTag,
    /// The manifest's file name.
    pub name: String,
    /// The manifest, standard base64, at most [`MAX_MANIFEST_BYTES`] decoded.
    pub content_b64: String,
}

/// What the tag step did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagResponse {
    /// The grant it was done under.
    pub grant_id: Id,
    /// The tag.
    pub tag: ReleaseTag,
    /// The id of the tag object created.
    pub object: String,
    /// The commit the tag points at.
    pub commit: CommitId,
}

/// What the manifest step did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestResponse {
    /// The grant it was done under.
    pub grant_id: Id,
    /// The manifest's file name.
    pub name: String,
    /// The signature's file name.
    pub signature_name: String,
    /// Lowercase hex SHA-256 of the manifest signed.
    pub sha256: String,
}

/// What the publish step did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishResponse {
    /// The grant it was done under.
    pub grant_id: Id,
    /// The tag of the release published.
    pub tag: ReleaseTag,
}

#[cfg(test)]
mod tests;
