//! What the App's installation holds, read from GitHub. GitHub's own names stay
//! in here: callers learn only which of the permissions they want are missing.

use std::collections::HashMap;

use http::{Method, StatusCode};
use serde::Deserialize;
use warden_broker_proto::github_permissions::{Level, Permission, PermissionSet};

use super::{GithubApi, MintError, jwt};
use crate::github_http::{self, Payload};
use crate::policy::GithubAppKey;

#[derive(Deserialize)]
struct Wire {
    permissions: HashMap<String, String>,
}

/// The permissions an installation holds, as ranks by GitHub's names. The names
/// are private: GitHub's text never leaves this type.
#[derive(Clone)]
pub struct InstallationPermissions(HashMap<String, u8>);

impl std::fmt::Debug for InstallationPermissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InstallationPermissions({} entries)", self.0.len())
    }
}

/// Where a level ranks: `read` below `write` below `admin`. Any other level
/// (`none`, an empty or unexpected string) ranks 0 and covers nothing, so
/// ambiguous input is refused, never allowed.
fn rank(level: &str) -> u8 {
    match level {
        "read" => 1,
        "write" => 2,
        "admin" => 3,
        _ => 0,
    }
}

fn wanted_rank(level: Level) -> u8 {
    match level {
        Level::Read => 1,
        Level::Write => 2,
    }
}

impl InstallationPermissions {
    /// The entries of `wanted` the installation does not hold at that level or
    /// higher, in the set's order.
    #[must_use]
    pub fn missing(&self, wanted: &PermissionSet) -> Vec<Permission> {
        wanted
            .iter()
            .filter(|p| {
                self.0
                    .get(p.name())
                    .is_none_or(|held| *held < wanted_rank(p.level()))
            })
            .collect()
    }
}

/// Read the permissions of `key`'s installation with the App JWT. `now` is Unix
/// seconds. Names GitHub reports that warden does not know are ignored: the
/// installation may hold permissions warden never asks for.
///
/// The client trusts the system roots (or the pinned CA), refuses redirects and
/// never retries.
///
/// # Errors
/// A [`MintError`]; nothing partial is returned.
pub async fn installation_permissions(
    api: &GithubApi,
    key: &GithubAppKey,
    now: i64,
) -> Result<InstallationPermissions, MintError> {
    let signer = key.clone();
    // RSA signing takes milliseconds of CPU: keep it off the async workers.
    let jwt = tokio::task::spawn_blocking(move || jwt(&signer, now))
        .await
        .map_err(|_| MintError::Key)??;
    let url = api
        .base
        .join(&format!("app/installations/{}", key.installation_id()))
        .map_err(|_| MintError::Unreachable)?;
    let request = github_http::request(
        &api.client()?,
        Method::GET,
        url,
        jwt.as_str(),
        github_http::JSON,
        Payload::Empty,
    )?;
    let response = github_http::send(request).await?;
    let status = response.status();
    if status != StatusCode::OK {
        return Err(MintError::Refused(status.as_u16()));
    }
    let raw = github_http::read_body(response, github_http::MAX_RESPONSE_BYTES).await?;
    let wire: Wire = serde_json::from_slice(&raw).map_err(|_| MintError::Malformed)?;
    Ok(InstallationPermissions(
        wire.permissions
            .into_iter()
            .map(|(name, level)| (name, rank(&level)))
            .collect(),
    ))
}
