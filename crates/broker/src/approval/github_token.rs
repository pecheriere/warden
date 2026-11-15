//! Approving a GitHub token request: whether the App reaches every repository it
//! names, and the grant for the repositories GitHub resolved when the owner opened
//! the page.

use warden_broker_proto::github_token::{EXTRA_NOT_ALLOWED, EXTRAS_NOT_ALLOWED};
use warden_broker_proto::{Access, GrantAccess, GrantView, Id, Window};

use super::grant::{GrantFailure, validity};
use crate::policy::GithubTokenPolicy;
use crate::requests::{PendingView, Resolution};

/// Why a request that names repositories the App cannot reach is not approved.
const CANNOT_APPROVE: &str =
    "this request cannot be approved: the App cannot reach every repository it names";

/// Whether `view` can be approved: the request names repositories, GitHub
/// resolved every one of them, what was stored makes a valid scope, which `grant`
/// would otherwise fail to build after the owner's passkey, the owner's allowlist,
/// read for this view, still holds every extra the request names, and the App's
/// installation, read for this view, holds every permission of the request.
pub(super) fn check(view: &PendingView) -> Result<(), String> {
    let Access::GithubToken(access) = &view.request.access else {
        return Err("the request does not match its policy kind".to_owned());
    };
    let Some(github) = view.github.as_ref() else {
        return Err(CANNOT_APPROVE.to_owned());
    };
    match &github.resolution {
        resolution @ Resolution::Resolved(_)
            if !access.is_legacy() && resolution.scope().is_some() => {}
        _ => return Err(CANNOT_APPROVE.to_owned()),
    }
    if !github.not_allowed.is_empty() {
        let names: Vec<String> = github.not_allowed.iter().map(ToString::to_string).collect();
        let lead = if names.len() == 1 {
            EXTRA_NOT_ALLOWED
        } else {
            EXTRAS_NOT_ALLOWED
        };
        return Err(format!("{lead}{}", names.join(", ")));
    }
    github.installation.refusal().map_or(Ok(()), Err)
}

/// The grant for approving `view` for `window` at `now`: valid from `now`, for the
/// repositories and ids GitHub resolved and the permissions the request was created
/// with, which the owner's passkey was bound to.
pub(super) fn grant(
    view: &PendingView,
    policy: &GithubTokenPolicy,
    window: Window,
    now: i64,
) -> Result<GrantView, GrantFailure> {
    let github = view.github.as_ref().ok_or((
        "repositories",
        "the request has no resolved repositories".to_owned(),
    ))?;
    let scope = github.resolution.scope().ok_or((
        "repositories",
        "the request has no resolved repositories".to_owned(),
    ))?;
    let (not_before, not_after) = validity(window, now)?;
    let extras = match &view.request.access {
        Access::GithubToken(access) => access.extra_permissions.clone(),
        _ => None,
    };
    Ok(GrantView {
        grant_id: Id::random(),
        not_before,
        not_after,
        access: GrantAccess::GithubToken(policy.grant(
            scope,
            github.permissions.full.clone(),
            extras,
        )),
    })
}
