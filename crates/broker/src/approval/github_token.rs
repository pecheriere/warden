//! Approving a GitHub token request: whether the App reaches every repository it
//! names, and the grant for the repositories GitHub resolved when the owner opened
//! the page.

use warden_broker_proto::{Access, GrantAccess, GrantView, Id, Window};

use super::grant::{GrantFailure, validity};
use crate::policy::GithubTokenPolicy;
use crate::requests::{PendingView, Resolution};

/// Why a request that names repositories the App cannot reach is not approved.
const CANNOT_APPROVE: &str =
    "this request cannot be approved: the App cannot reach every repository it names";

/// Whether `view` can be approved: the request names repositories, GitHub
/// resolved every one of them, and what was stored makes a valid scope, which `grant`
/// would otherwise fail to build after the owner's passkey.
pub(super) fn check(view: &PendingView) -> Result<(), String> {
    let Access::GithubToken(access) = &view.request.access else {
        return Err("the request does not match its policy kind".to_owned());
    };
    match view.github.as_ref().map(|github| &github.resolution) {
        Some(resolution @ Resolution::Resolved(_))
            if !access.is_legacy() && resolution.scope().is_some() =>
        {
            Ok(())
        }
        _ => Err(CANNOT_APPROVE.to_owned()),
    }
}

/// The grant for approving `view` for `window` at `now`: valid from `now`, for the
/// repositories and ids GitHub resolved, which the owner's passkey was bound to.
pub(super) fn grant(
    view: &PendingView,
    policy: &GithubTokenPolicy,
    window: Window,
    now: i64,
) -> Result<GrantView, GrantFailure> {
    let scope = view
        .github
        .as_ref()
        .and_then(|github| github.resolution.scope())
        .ok_or((
            "repositories",
            "the request has no resolved repositories".to_owned(),
        ))?;
    let (not_before, not_after) = validity(window, now)?;
    Ok(GrantView {
        grant_id: Id::random(),
        not_before,
        not_after,
        access: GrantAccess::GithubToken(policy.grant(scope)),
    })
}
