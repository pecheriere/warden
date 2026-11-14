//! GitHub repository permissions as warden handles them: a permission is
//! `name:level`, a set holds each name once, and a fixed ceiling names what no
//! configuration may grant.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The repository permissions GitHub accepts when creating an installation
/// access token, minus the [`CEILING`]. Read from
/// <https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app>
/// on 2026-11-14. Names are as the REST API spells them.
const KNOWN: &[&str] = &[
    "actions",
    "artifact_metadata",
    "attestations",
    "checks",
    "code_quality",
    "codespaces",
    "contents",
    "deployments",
    "discussions",
    "issues",
    "merge_queues",
    "metadata",
    "packages",
    "pages",
    "pull_requests",
    "repository_custom_properties",
    "repository_hooks",
    "repository_projects",
    "secret_scanning_alerts",
    "security_events",
    "single_file",
    "statuses",
    "vulnerability_alerts",
];

/// The permissions no configuration lifts, besides every `organization_*` one
/// (see [`under_ceiling`]). `dependabot_secrets` is a repository secret under
/// another name.
pub const CEILING: &[&str] = &[
    "administration",
    "workflows",
    "secrets",
    "environments",
    "dependabot_secrets",
];

/// The prefix of the organization permissions, all under the ceiling.
const ORGANIZATION_PREFIX: &str = "organization_";

/// Whether `name` is under the ceiling: one of [`CEILING`] or `organization_*`.
#[must_use]
pub fn under_ceiling(name: &str) -> bool {
    CEILING.contains(&name) || name.starts_with(ORGANIZATION_PREFIX)
}

/// How much a permission allows. `write` covers `read`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Read only.
    Read,
    /// Read and write.
    Write,
}

impl Level {
    /// The word GitHub uses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a permission or a set of them was refused. Each text is fixed and names
/// a permission only when it is one the list knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionError {
    /// Not a permission GitHub documents for installation tokens.
    Unknown,
    /// Under the ceiling: no configuration may grant it.
    Ceiling,
    /// The `admin` level, which warden never grants, on a known permission.
    Admin(&'static str),
    /// Not `name:level` entries, or an empty or repeated one, or
    /// `metadata:write`.
    Malformed,
}

impl fmt::Display for PermissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("a permission name is not one GitHub documents"),
            Self::Ceiling => f.write_str(
                "a permission is above the ceiling (administration, workflows, secrets, \
                 environments, dependabot_secrets, organization_*) that warden never grants",
            ),
            Self::Admin(name) => write!(f, "the admin level of {name} is never granted"),
            Self::Malformed => f.write_str(
                "permissions are name:level entries (level read or write) joined with commas, \
                 each name once, and metadata only read",
            ),
        }
    }
}

impl std::error::Error for PermissionError {}

/// One permission: a known name at a level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permission {
    name: &'static str,
    level: Level,
}

impl Permission {
    /// GitHub's name for it.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The level.
    #[must_use]
    pub fn level(&self) -> Level {
        self.level
    }
}

impl FromStr for Permission {
    type Err = PermissionError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (name, level) = text.split_once(':').ok_or(PermissionError::Malformed)?;
        if under_ceiling(name) {
            return Err(PermissionError::Ceiling);
        }
        let name = KNOWN
            .iter()
            .find(|known| **known == name)
            .ok_or(PermissionError::Unknown)?;
        let level = match level {
            "read" => Level::Read,
            "write" => Level::Write,
            "admin" => return Err(PermissionError::Admin(name)),
            _ => return Err(PermissionError::Malformed),
        };
        Ok(Self { name, level })
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.name, self.level)
    }
}

/// Permissions by name, each once, always with `metadata:read`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PermissionSet(BTreeMap<&'static str, Level>);

impl PermissionSet {
    /// What every token had before permissions were configurable.
    #[must_use]
    pub fn legacy() -> Self {
        Self(BTreeMap::from([
            ("contents", Level::Write),
            ("issues", Level::Write),
            ("metadata", Level::Read),
            ("pull_requests", Level::Write),
        ]))
    }

    /// Only `metadata:read`, what a token that just looks repositories up has.
    #[must_use]
    pub fn metadata_only() -> Self {
        Self(BTreeMap::from([("metadata", Level::Read)]))
    }

    /// Parses the written form: entries split on `,` and trimmed, none empty or
    /// repeated. `metadata:read` is added; `metadata:write` is refused.
    ///
    /// # Errors
    ///
    /// A [`PermissionError`] for the first entry that fails, or `Malformed` for
    /// an empty or repeated one.
    pub fn parse(text: &str) -> Result<Self, PermissionError> {
        let mut map = BTreeMap::new();
        for entry in text.split(',') {
            let permission: Permission = entry.trim().parse()?;
            if permission.name == "metadata" && permission.level != Level::Read {
                return Err(PermissionError::Malformed);
            }
            if map.insert(permission.name, permission.level).is_some() {
                return Err(PermissionError::Malformed);
            }
        }
        map.insert("metadata", Level::Read);
        Ok(Self(map))
    }

    /// Whether the set has `permission` at its level or higher.
    #[must_use]
    pub fn covers(&self, permission: &Permission) -> bool {
        self.0
            .get(permission.name)
            .is_some_and(|have| *have >= permission.level)
    }

    /// Whether the set covers every entry of `other`.
    #[must_use]
    pub fn covers_all(&self, other: &Self) -> bool {
        other.iter().all(|p| self.covers(&p))
    }

    /// Both sets together, the higher level where a name is in both.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let mut map = self.0.clone();
        for (name, level) in &other.0 {
            map.entry(name)
                .and_modify(|have| *have = (*have).max(*level))
                .or_insert(*level);
        }
        Self(map)
    }

    /// The entries of this set that `other` does not cover.
    #[must_use]
    pub fn missing_from(&self, other: &Self) -> Vec<Permission> {
        self.iter().filter(|p| !other.covers(p)).collect()
    }

    /// The entries in name order.
    pub fn iter(&self) -> impl Iterator<Item = Permission> + '_ {
        self.0.iter().map(|(name, level)| Permission {
            name,
            level: *level,
        })
    }

    /// The entries `default` does not cover, without `metadata`.
    #[must_use]
    pub fn extras_beyond(&self, default: &Self) -> Self {
        let mut map: BTreeMap<_, _> = self
            .missing_from(default)
            .into_iter()
            .map(|p| (p.name, p.level))
            .collect();
        map.remove("metadata");
        Self(map)
    }

    /// Whether `metadata:read` is all it holds.
    #[must_use]
    pub fn is_only_metadata(&self) -> bool {
        self.0.len() == 1 && self.0.contains_key("metadata")
    }
}

impl fmt::Display for PermissionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, permission) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{permission}")?;
        }
        Ok(())
    }
}

impl TryFrom<String> for PermissionSet {
    type Error = PermissionError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<PermissionSet> for String {
    fn from(set: PermissionSet) -> Self {
        set.to_string()
    }
}

#[cfg(test)]
mod tests;
