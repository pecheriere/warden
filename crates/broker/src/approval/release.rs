//! Approving a release request: the second look at GitHub when the owner decides,
//! and the grant that results.

use axum::http::StatusCode;
use axum::response::Response;
use warden_broker_proto::release::ReleaseGrant;
use warden_broker_proto::{Access, GrantAccess, GrantView, Id, Window};

use super::grant::{GrantFailure, validity};
use super::{AppState, json_error, request_error};
use crate::requests::{Destination, PendingView, ReleasePolicy, RequestError};

/// Ask GitHub again about a release request, as the owner decides. Anything but the
/// same answer as when the request was made refuses the approval, with a message
/// that quotes nothing GitHub said, and leaves the request pending. Does nothing for
/// other kinds of request. Returns the response that refuses the approval, if any.
pub(super) async fn recheck(state: &AppState, view: &PendingView) -> Option<Response> {
    if !matches!(view.destination, Destination::Release(_)) {
        return None;
    }
    match state.requests.recheck_release(view).await {
        Ok(()) => None,
        Err(RequestError::Rejected(message)) => Some(json_error(StatusCode::CONFLICT, message)),
        Err(e) => Some(request_error(&e)),
    }
}

/// The grant for approving release request `view` under `policy` with `window` at
/// `now`: the steps the owner was shown, and the digest of the key and App they
/// were approved with.
pub(super) fn grant(
    view: &PendingView,
    policy: &ReleasePolicy,
    window: Window,
    now: i64,
) -> Result<GrantView, GrantFailure> {
    let Access::Release {
        repository,
        tag,
        commit,
    } = &view.request.access
    else {
        return Err(("access kind", "not a release request".to_owned()));
    };
    let Some(facts) = &view.release else {
        return Err(("release facts", "the request has none".to_owned()));
    };
    let (not_before, not_after) = validity(window, now)?;
    Ok(GrantView {
        grant_id: Id::random(),
        not_before,
        not_after,
        access: GrantAccess::Release(ReleaseGrant {
            repository: repository.clone(),
            tag: tag.clone(),
            commit: commit.clone(),
            key_fingerprint: policy.key_fingerprint.clone(),
            steps: policy.steps(facts.tag_in_place),
            digest: policy.digest(),
        }),
    })
}
