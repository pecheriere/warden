//! GitHub's answer to a token request, and the checks that show the token was
//! limited as asked. Nothing from the answer reaches an error: only the parsed
//! ids and validated names are kept.

use std::collections::HashMap;

use serde::Deserialize;
use warden_broker_proto::github_token::PERMISSIONS;
use warden_broker_proto::release::RepoName;

use super::{InstallationToken, MintError, ResolvedRepository};
use crate::github_http;

/// Whether GitHub reports `repository_selection` as `selected` for a token minted
/// for named repositories, even on an "All repositories" installation (measured
/// against the real API).
const SELECTION_IS_SELECTED: bool = true;

#[derive(Deserialize)]
struct Wire {
    token: String,
    expires_at: String,
    #[serde(default)]
    repositories: Vec<WireRepository>,
    permissions: HashMap<String, String>,
    #[serde(default)]
    repository_selection: Option<String>,
}

#[derive(Deserialize)]
struct WireRepository {
    id: u64,
    full_name: String,
}

/// A parsed answer: the token and the scope GitHub says it has.
pub(super) struct Answer {
    pub(super) token: InstallationToken,
    repositories: Vec<WireRepository>,
    permissions: HashMap<String, String>,
    selection: Option<String>,
}

/// The rank of a permission level, or `None` for one not known.
fn rank(level: &str) -> Option<u8> {
    match level {
        "read" => Some(1),
        "write" => Some(2),
        "admin" => Some(3),
        _ => None,
    }
}

impl Answer {
    /// The answer in `raw`, whose token must expire after `now` and within two
    /// hours.
    pub(super) fn parse(raw: &[u8], now: i64) -> Result<Self, MintError> {
        let wire: Wire = serde_json::from_slice(raw).map_err(|_| MintError::Malformed)?;
        let token = github_http::checked_token(wire.token, &wire.expires_at, now)
            .ok_or(MintError::Malformed)?;
        Ok(Self {
            token,
            repositories: wire.repositories,
            permissions: wire.permissions,
            selection: wire.repository_selection,
        })
    }

    /// The token is for exactly `repository_id`, with no permission beyond
    /// [`PERMISSIONS`].
    pub(super) fn check_minted(&self, repository_id: u64) -> Result<(), MintError> {
        let [only] = self.repositories.as_slice() else {
            return Err(MintError::WrongScope);
        };
        if only.id != repository_id {
            return Err(MintError::WrongScope);
        }
        if SELECTION_IS_SELECTED && self.selection.as_deref() != Some("selected") {
            return Err(MintError::WrongScope);
        }
        let within = self.permissions.iter().all(|(name, level)| {
            let asked = PERMISSIONS
                .iter()
                .find(|(asked_name, _)| asked_name == name)
                .and_then(|(_, asked_level)| rank(asked_level));
            matches!((rank(level), asked), (Some(got), Some(asked)) if got <= asked)
        });
        if within {
            Ok(())
        } else {
            Err(MintError::WrongScope)
        }
    }

    /// The token reads metadata and nothing else.
    fn check_metadata_only(&self) -> Result<(), MintError> {
        if self.permissions.len() == 1
            && self.permissions.get("metadata").map(String::as_str) == Some("read")
        {
            Ok(())
        } else {
            Err(MintError::WrongScope)
        }
    }

    /// The repositories as validated pairs; a name that is not `owner/name`
    /// makes the answer unusable.
    fn resolved(&self) -> Result<Vec<ResolvedRepository>, MintError> {
        self.repositories
            .iter()
            .map(|repository| {
                Ok(ResolvedRepository {
                    id: repository.id,
                    name: RepoName::try_from(repository.full_name.clone())
                        .map_err(|_| MintError::Malformed)?,
                })
            })
            .collect()
    }

    /// One entry for each of `names`, in their order, owner included.
    pub(super) fn check_names(
        &self,
        names: &[RepoName],
    ) -> Result<Vec<ResolvedRepository>, MintError> {
        self.check_metadata_only()?;
        let found = self.resolved()?;
        if found.len() != names.len() {
            return Err(MintError::WrongScope);
        }
        names
            .iter()
            .map(|name| {
                let mut matching = found.iter().filter(|entry| entry.name.matches(name));
                match (matching.next(), matching.next()) {
                    (Some(entry), None) => Ok(entry.clone()),
                    _ => Err(MintError::WrongScope),
                }
            })
            .collect()
    }

    /// One entry for each of `ids`, in their order.
    pub(super) fn check_ids(&self, ids: &[u64]) -> Result<Vec<ResolvedRepository>, MintError> {
        self.check_metadata_only()?;
        let found = self.resolved()?;
        if found.len() != ids.len() {
            return Err(MintError::WrongScope);
        }
        ids.iter()
            .map(|id| {
                let mut matching = found.iter().filter(|entry| entry.id == *id);
                match (matching.next(), matching.next()) {
                    (Some(entry), None) => Ok(entry.clone()),
                    _ => Err(MintError::WrongScope),
                }
            })
            .collect()
    }
}
