//! GitHub repository permissions as warden handles them: a permission is
//! `name:level`, a set holds each name once, and a fixed list names the
//! sensitive ones, which only the owner's allowlist of extras may hold.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The repository permissions GitHub accepts when creating an installation
/// access token, minus the [`SENSITIVE`] ones. Read from
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
    "repository_projects",
    "secret_scanning_alerts",
    "security_events",
    "single_file",
    "statuses",
    "vulnerability_alerts",
];

/// The sensitive permissions: GitHub documents them for installation tokens,
/// and each reaches past the repository's code or outlives the grant. They are
/// allowed only as extras the owner lists in `extra_permissions`, never in the
/// default. `dependabot_secrets` is a repository secret under another name.
/// `repository_hooks` lets a token create a webhook, which keeps sending the
/// repository's events to whoever set it up after the token has expired and the
/// grant is revoked: access that outlives the grant. The `organization_*` ones
/// are the organization permissions GitHub documents on the page the other
/// permissions are read from, on 2026-11-15; one GitHub does not document there stays unknown.
pub const SENSITIVE: &[&str] = &[
    "administration",
    "dependabot_secrets",
    "environments",
    "organization_administration",
    "organization_announcement_banners",
    "organization_copilot_agent_settings",
    "organization_copilot_requests",
    "organization_copilot_seat_management",
    "organization_custom_org_roles",
    "organization_custom_properties",
    "organization_custom_roles",
    "organization_events",
    "organization_external_properties_for_repos",
    "organization_hooks",
    "organization_packages",
    "organization_personal_access_token_requests",
    "organization_personal_access_tokens",
    "organization_plan",
    "organization_projects",
    "organization_secrets",
    "organization_self_hosted_runners",
    "organization_user_blocking",
    "repository_hooks",
    "secrets",
    "workflows",
];

/// Whether `name` is one of the [`SENSITIVE`] permissions.
#[must_use]
pub fn is_sensitive(name: &str) -> bool {
    SENSITIVE.contains(&name)
}

/// What each [`SENSITIVE`] permission allows at each level, as phrases that
/// complete "can ...", in the order of [`SENSITIVE`]: name, read, write. Worded after
/// GitHub's documentation of fine-grained permissions, and no stronger than it. A
/// name GitHub documents at one level only has the same text at both. A test holds
/// the names to [`SENSITIVE`].
const MEANINGS: &[(&str, &str, &str)] = &[
    (
        "administration",
        "read the repository's settings, collaborators and branch protection",
        "manage the repository's settings, collaborators and branch protection, and delete it",
    ),
    (
        "dependabot_secrets",
        "list the names of the repository's Dependabot secrets (their values cannot be read through the API)",
        "create, replace and delete the repository's Dependabot secrets, which Dependabot then uses",
    ),
    (
        "environments",
        "read the repository's deployment environments, including their protection rules",
        "change the repository's deployment environments, including their protection rules and variables",
    ),
    (
        "organization_administration",
        "read the organization's settings, members and teams",
        "manage the organization's settings, members and teams",
    ),
    (
        "organization_announcement_banners",
        "read the organization's announcement banner",
        "change the organization's announcement banner",
    ),
    (
        "organization_copilot_agent_settings",
        "read the organization's Copilot agent settings",
        "change the organization's Copilot agent settings",
    ),
    (
        "organization_copilot_requests",
        "read information about the organization's Copilot requests",
        "make Copilot requests on the organization's account, which it may pay for",
    ),
    (
        "organization_copilot_seat_management",
        "read the organization's Copilot seats",
        "add and remove the organization's Copilot seats",
    ),
    (
        "organization_custom_org_roles",
        "read the organization's custom organization roles",
        "read and define the organization's custom organization roles",
    ),
    (
        "organization_custom_properties",
        "read the organization's custom properties",
        "read and define the organization's custom properties, and set them for all its repositories",
    ),
    (
        "organization_custom_roles",
        "read the organization's custom repository roles",
        "read and define the organization's custom repository roles",
    ),
    (
        "organization_events",
        "read the organization's events, including activity in its private repositories",
        "read the organization's events, including activity in its private repositories",
    ),
    (
        "organization_external_properties_for_repos",
        "read the organization's custom properties for its repositories",
        "read and change the organization's custom properties for its repositories",
    ),
    (
        "organization_hooks",
        "list the organization's webhooks",
        "create and change the organization's webhooks, which keep sending its events after the grant ends",
    ),
    (
        "organization_packages",
        "read the organization's packages",
        "read, publish and delete the organization's packages",
    ),
    (
        "organization_personal_access_token_requests",
        "list requests for personal access tokens on the organization",
        "approve or deny requests for personal access tokens on the organization",
    ),
    (
        "organization_personal_access_tokens",
        "list the personal access tokens that can reach the organization",
        "list and revoke the personal access tokens that can reach the organization",
    ),
    (
        "organization_plan",
        "read the organization's billing plan",
        "read the organization's billing plan",
    ),
    (
        "organization_projects",
        "read all of the organization's projects",
        "read and change all of the organization's projects",
    ),
    (
        "organization_secrets",
        "list the names of the organization's secrets (their values cannot be read through the API)",
        "create, replace and delete the organization's secrets, which its workflows then use",
    ),
    (
        "organization_self_hosted_runners",
        "list the organization's self-hosted runners",
        "manage the organization's self-hosted runners, which run its workflows",
    ),
    (
        "organization_user_blocking",
        "list the users the organization has blocked",
        "block and unblock users from the organization",
    ),
    (
        "repository_hooks",
        "list the repository's webhooks and their settings",
        "create and change the repository's webhooks, which keep sending its events after the grant ends",
    ),
    (
        "secrets",
        "list the names of the repository's secrets (their values cannot be read through the API)",
        "create, replace and delete the repository's secrets, which its workflows then use",
    ),
    (
        "workflows",
        "change GitHub Actions workflows, which run with the repository's secrets",
        "change GitHub Actions workflows, which run with the repository's secrets",
    ),
];

/// What `permission` allows, as one fixed phrase that completes "can ...", true at
/// the level it names. A permission that is not sensitive gets a general phrase, so
/// a caller never shows nothing.
#[must_use]
pub fn sensitive_meaning(permission: &Permission) -> &'static str {
    MEANINGS
        .iter()
        .find(|(known, _, _)| *known == permission.name)
        .map_or(
            "reach beyond the repository's code",
            |(_, read, write)| match permission.level {
                Level::Read => read,
                Level::Write => write,
            },
        )
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
    /// A sensitive permission in the default set, where none is allowed.
    SensitiveInDefault,
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
            Self::SensitiveInDefault => f.write_str(
                "a sensitive permission (administration, workflows, secrets, environments, \
                 dependabot_secrets, repository_hooks, organization_*) is only allowed in the \
                 extras, never in the default",
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

    /// Whether the permission is one of the [`SENSITIVE`] ones.
    #[must_use]
    pub fn is_sensitive(&self) -> bool {
        is_sensitive(self.name)
    }
}

impl FromStr for Permission {
    type Err = PermissionError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (name, level) = text.split_once(':').ok_or(PermissionError::Malformed)?;
        let name = KNOWN
            .iter()
            .chain(SENSITIVE)
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

    /// The sensitive entries, in name order.
    pub fn sensitive(&self) -> impl Iterator<Item = Permission> + '_ {
        self.iter().filter(Permission::is_sensitive)
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

/// The longest permission name a [`GrantedPermissions`] accepts.
const NAME_MAX: usize = 64;

/// A permission set as the broker reports it to agents, in a grant or with a
/// token. Unlike [`PermissionSet`], a name this version does not know is kept as
/// text, so that a newer broker whose list knows more names does not break an
/// older CLI. Each entry must still be a well-formed `name:level`: a name of
/// lowercase ASCII letters, digits and `_`, a level `read` or `write`, each name
/// once and `metadata` only read. The written form is canonical, as
/// [`PermissionSet`] writes it: sorted by name, with `metadata:read` added, so
/// two values are equal exactly when their written forms are.
///
/// It grants nothing: the broker reads every set it acts on as a
/// [`PermissionSet`], with [`GrantedPermissions::known`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct GrantedPermissions(String);

impl GrantedPermissions {
    /// What every token had before permissions were configurable.
    #[must_use]
    pub fn legacy() -> Self {
        Self::from(&PermissionSet::legacy())
    }

    /// Parses the written form, accepting names this version does not know.
    ///
    /// # Errors
    ///
    /// [`PermissionError::Malformed`] for an entry that is not a well-formed
    /// `name:level`, a repeated name or `metadata` at another level than `read`.
    pub fn parse(text: &str) -> Result<Self, PermissionError> {
        let mut map: BTreeMap<&str, Level> = BTreeMap::new();
        for entry in text.split(',') {
            let (name, level) = entry
                .trim()
                .split_once(':')
                .ok_or(PermissionError::Malformed)?;
            let well_formed = !name.is_empty()
                && name.len() <= NAME_MAX
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
            if !well_formed {
                return Err(PermissionError::Malformed);
            }
            let level = match level {
                "read" => Level::Read,
                "write" => Level::Write,
                _ => return Err(PermissionError::Malformed),
            };
            if name == "metadata" && level != Level::Read {
                return Err(PermissionError::Malformed);
            }
            if map.insert(name, level).is_some() {
                return Err(PermissionError::Malformed);
            }
        }
        map.insert("metadata", Level::Read);
        let written: Vec<String> = map
            .iter()
            .map(|(name, level)| format!("{name}:{level}"))
            .collect();
        Ok(Self(written.join(",")))
    }

    /// The canonical written form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The written form without `metadata:read`, which every set holds, or `None`
    /// when nothing else is in it. This is how a line about extras names them.
    #[must_use]
    pub fn without_metadata(&self) -> Option<String> {
        let rest: Vec<&str> = self
            .0
            .split(',')
            .filter(|entry| *entry != "metadata:read")
            .collect();
        (!rest.is_empty()).then(|| rest.join(","))
    }

    /// The set, read strictly: every name known, sensitive ones included.
    ///
    /// # Errors
    ///
    /// A [`PermissionError`] when this version cannot act on the set.
    pub fn known(&self) -> Result<PermissionSet, PermissionError> {
        PermissionSet::parse(&self.0)
    }
}

impl From<&PermissionSet> for GrantedPermissions {
    fn from(set: &PermissionSet) -> Self {
        Self(set.to_string())
    }
}

impl From<PermissionSet> for GrantedPermissions {
    fn from(set: PermissionSet) -> Self {
        Self::from(&set)
    }
}

impl fmt::Display for GrantedPermissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for GrantedPermissions {
    type Error = PermissionError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text)
    }
}

impl From<GrantedPermissions> for String {
    fn from(set: GrantedPermissions) -> Self {
        set.0
    }
}

#[cfg(test)]
mod tests;
