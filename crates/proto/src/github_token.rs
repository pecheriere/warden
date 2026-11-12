//! Wire types of GitHub App tokens: the broker holds the App's private key and
//! mints short-lived installation tokens for an agent that has an active
//! `github_token` grant. The key never leaves the broker.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::release::RepoName;
use crate::{ParseError, check_free_text};

/// The most repositories one request or grant may name.
pub const MAX_REPOSITORIES: usize = 10;

/// The longest working directory an automatic request may report, in bytes.
const MAX_DIR_BYTES: usize = 512;

/// What the broker says when the agent has no active GitHub token grant: never
/// had one, or it ended or was revoked. The CLI recognises it to say how to ask.
pub const NO_ACTIVE_GRANT: &str = "no active GitHub token grant for this agent and repository";

/// What the broker says to a CLI that asks for a GitHub token grant without
/// naming repositories, as CLIs did before grants were scoped.
pub const OLD_CLIENT: &str = "this warden CLI predates repository-scoped GitHub grants; upgrade it";

/// What the broker says when GitHub will not issue a token for a repository the
/// grant names.
pub const REPOSITORY_UNREACHABLE: &str = "GitHub would not issue a token for this repository: \
                                          the App may no longer reach it, or it was deleted \
                                          or replaced";

/// What the broker says when two active grants cover the repository, so that it
/// cannot tell which one to mint under.
pub const AMBIGUOUS_GRANT: &str =
    "more than one GitHub grant covers this repository; ask the owner to revoke one";

/// What the broker says when the App or installation is no longer the one the
/// owner approved. The CLI recognises it to say a new grant is needed.
pub const APP_CHANGED: &str = "the GitHub App changed; request a new grant";

/// What the broker says when an agent has had all the tokens it may have this hour.
pub const HOURLY_LIMIT: &str = "this agent has reached its limit of GitHub tokens for this \
                                hour; it starts again at the top of the hour";

/// What the broker says when it holds no GitHub App.
pub const NOT_CONFIGURED: &str = "GitHub tokens are not configured on this broker";

/// The permissions every minted token has, as GitHub names them. Fixed: no
/// workflows and no administration, whatever the App itself is allowed.
pub const PERMISSIONS: [(&str, &str); 4] = [
    ("contents", "write"),
    ("pull_requests", "write"),
    ("issues", "write"),
    ("metadata", "read"),
];

/// What asked for the token without the agent typing a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticCaller {
    /// `git`, through the credential helper.
    GitCredential,
    /// The `gh` wrapper.
    GhWrapper,
}

/// Says that a tool asked, not the agent, and from where.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticRequest {
    /// The tool that asked.
    pub by: AutomaticCaller,
    /// The directory it ran in, as the agent reports it: at most 512 bytes,
    /// without control or invisible format characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
}

impl AutomaticRequest {
    fn check(&self) -> Result<(), ParseError> {
        if let Some(dir) = &self.dir {
            if dir.len() > MAX_DIR_BYTES {
                return Err(ParseError::new("directory", "is too long"));
            }
            check_free_text("directory", dir)?;
        }
        Ok(())
    }
}

/// The repositories a GitHub token request asks for. Empty is the shape of
/// requests stored before grants were scoped: the broker refuses new ones.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawGithubTokenAccess")]
pub struct GithubTokenAccess {
    /// The repositories, at most [`MAX_REPOSITORIES`], without repeats.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repositories: Vec<RepoName>,
    /// Set when a tool asked: then exactly one repository.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automatic: Option<AutomaticRequest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGithubTokenAccess {
    #[serde(default)]
    repositories: Vec<RepoName>,
    #[serde(default)]
    automatic: Option<AutomaticRequest>,
}

impl TryFrom<RawGithubTokenAccess> for GithubTokenAccess {
    type Error = ParseError;

    fn try_from(raw: RawGithubTokenAccess) -> Result<Self, Self::Error> {
        Self::new(raw.repositories, raw.automatic)
    }
}

impl GithubTokenAccess {
    /// Checks the list: at most [`MAX_REPOSITORIES`], no repeat ignoring case,
    /// and `automatic` only with exactly one repository.
    ///
    /// # Errors
    ///
    /// When any of those fails.
    pub fn new(
        repositories: Vec<RepoName>,
        automatic: Option<AutomaticRequest>,
    ) -> Result<Self, ParseError> {
        if repositories.len() > MAX_REPOSITORIES {
            return Err(ParseError::new("repositories", "has too many entries"));
        }
        let repeated = repositories
            .iter()
            .enumerate()
            .any(|(i, a)| repositories[..i].iter().any(|b| a.matches(b)));
        if repeated {
            return Err(ParseError::new("repositories", "names a repository twice"));
        }
        if let Some(automatic) = &automatic {
            if repositories.len() != 1 {
                return Err(ParseError::new(
                    "automatic request",
                    "must name exactly one repository",
                ));
            }
            automatic.check()?;
        }
        Ok(Self {
            repositories,
            automatic,
        })
    }

    /// Whether it names no repository: a request stored before grants were scoped.
    #[must_use]
    pub fn is_legacy(&self) -> bool {
        self.repositories.is_empty()
    }

    /// The repositories lowercased, sorted and joined with `,`: equal for the
    /// same set whatever the case or order.
    #[must_use]
    pub fn slot(&self) -> String {
        let mut names: Vec<String> = self
            .repositories
            .iter()
            .map(|r| r.as_str().to_ascii_lowercase())
            .collect();
        names.sort();
        names.join(",")
    }
}

/// A repository a grant covers, with the id GitHub gave it when the owner
/// approved: tokens are minted for the id, so a rename keeps the grant and a
/// deleted and recreated repository does not inherit it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRepository {
    /// The name it had at approval.
    pub name: RepoName,
    /// GitHub's id for it.
    pub id: u64,
}

/// What a grant covers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    try_from = "Option<Vec<GrantRepository>>",
    into = "Option<Vec<GrantRepository>>"
)]
pub enum GrantScope {
    /// Stored before grants were scoped: it names nothing, so nothing is minted
    /// under it.
    #[default]
    Legacy,
    /// One to [`MAX_REPOSITORIES`] repositories, none repeated.
    Repositories(Vec<GrantRepository>),
}

impl TryFrom<Option<Vec<GrantRepository>>> for GrantScope {
    type Error = ParseError;

    fn try_from(list: Option<Vec<GrantRepository>>) -> Result<Self, Self::Error> {
        match list {
            None => Ok(Self::Legacy),
            Some(list) if list.is_empty() => Ok(Self::Legacy),
            Some(list) => Self::repositories(list)
                .ok_or_else(|| ParseError::new("grant repositories", "are repeated or too many")),
        }
    }
}

impl From<GrantScope> for Option<Vec<GrantRepository>> {
    fn from(scope: GrantScope) -> Self {
        match scope {
            GrantScope::Legacy => None,
            GrantScope::Repositories(list) => Some(list),
        }
    }
}

impl GrantScope {
    /// A scope of these repositories; `None` for none, more than
    /// [`MAX_REPOSITORIES`], or a repeated id or name.
    #[must_use]
    pub fn repositories(list: Vec<GrantRepository>) -> Option<Self> {
        if list.is_empty() || list.len() > MAX_REPOSITORIES {
            return None;
        }
        let repeated = list.iter().enumerate().any(|(i, a)| {
            list[..i]
                .iter()
                .any(|b| a.id == b.id || a.name.matches(&b.name))
        });
        (!repeated).then_some(Self::Repositories(list))
    }

    /// Whether it is the scope of a grant stored before scoping.
    #[must_use]
    pub fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy)
    }

    /// The repositories, in the order they were given; none for a legacy scope.
    #[must_use]
    pub fn list(&self) -> &[GrantRepository] {
        match self {
            Self::Legacy => &[],
            Self::Repositories(list) => list,
        }
    }

    /// The ids, in this scope, of the repositories the other scope also covers by id
    /// or by name (ignoring case): a repository recreated under its name has a new id
    /// and still overlaps. None when either is legacy.
    #[must_use]
    pub fn overlapping_ids(&self, other: &Self) -> Vec<u64> {
        self.list()
            .iter()
            .filter(|r| {
                other
                    .list()
                    .iter()
                    .any(|o| o.id == r.id || o.name.matches(&r.name))
            })
            .map(|r| r.id)
            .collect()
    }

    /// The entry for this name, ignoring case; `None` for a legacy scope.
    #[must_use]
    pub fn covering(&self, name: &RepoName) -> Option<&GrantRepository> {
        match self {
            Self::Legacy => None,
            Self::Repositories(list) => list.iter().find(|r| r.name.matches(name)),
        }
    }

    /// Whether the two share a repository, by id or by name (ignoring case): a
    /// repository deleted and recreated under its name has a new id, and a grant
    /// for the name still stands for it. A legacy scope overlaps every scope,
    /// since it may stand for any repository.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Repositories(a), Self::Repositories(b)) => a
                .iter()
                .any(|x| b.iter().any(|y| x.id == y.id || x.name.matches(&y.name))),
            _ => true,
        }
    }
}

/// GitHub token grant details. The private key itself is never part of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubTokenGrant {
    /// The App's id, as the owner approved it.
    pub app_id: String,
    /// The installation the tokens are minted for.
    pub installation_id: u64,
    /// Lowercase hex digest of the approved App and installation: minting is
    /// refused once the broker's App no longer matches it.
    pub digest: String,
    /// The repositories the grant covers.
    #[serde(default, skip_serializing_if = "GrantScope::is_legacy")]
    pub repositories: GrantScope,
}

/// Body of `POST /v1/github-token`: the repository to mint a token for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubTokenRequest {
    /// The repository.
    pub repository: RepoName,
}

/// A token the broker minted and recorded.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubTokenResponse {
    /// The installation token. A secret: `Debug` redacts it.
    pub token: String,
    /// When GitHub ends the token, in seconds since the Unix epoch.
    pub expires_at: i64,
    /// The grant it was minted under.
    pub grant_id: crate::Id,
    /// The repository the token is for.
    pub repository: RepoName,
    /// GitHub's id for it.
    pub repository_id: u64,
}

impl fmt::Debug for GithubTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubTokenResponse")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("grant_id", &self.grant_id)
            .field("repository", &self.repository)
            .field("repository_id", &self.repository_id)
            .finish()
    }
}

#[cfg(test)]
mod tests;
