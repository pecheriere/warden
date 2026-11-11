//! Validated names for releases: the repository, the tag and the commit.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ParseError;

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

#[cfg(test)]
mod tests;
