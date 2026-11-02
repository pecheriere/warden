//! The pending screen's routes. Behind the same owner check and same-origin JSON
//! check as every other route of the approval listener (see [`super::router`]).
//!
//! Approving is not one of them. Opening a request only replaces its approval
//! link; the owner then decides on the approval page, with the passkey, exactly
//! as from a notification.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use warden_broker_proto::Id;

use super::{DENIED_UNAUDITED, done, internal_page, json_error, pages, request_error};
use crate::AppState;
use crate::requests::{AuditOutcome, RequestError};

/// What a request that cannot be opened or denied any more answers: decided,
/// expired, cancelled or unknown, without saying which.
const NOT_PENDING: &str = "this request is no longer pending";

/// Body of `POST /pending/{id}/open`.
#[derive(Serialize)]
struct Opened {
    /// The request's new approval link.
    link: String,
}

fn refusal(error: &RequestError) -> Response {
    match error {
        RequestError::NotFound => json_error(StatusCode::NOT_FOUND, NOT_PENDING),
        other => request_error(other),
    }
}

/// `GET /pending`.
pub(super) async fn page(State(state): State<AppState>) -> Response {
    match state.requests.pending_requests().await {
        Ok(entries) => pages::pending(&entries, state.clock.now()).into_response(),
        Err(e) => internal_page("pending page", &e),
    }
}

/// `POST /pending/{id}/open`: a new approval link for a pending request.
pub(super) async fn open(State(state): State<AppState>, Path(id): Path<Id>) -> Response {
    match state.requests.replace_link(&id).await {
        Ok(link) => Json(Opened {
            link: link.to_string(),
        })
        .into_response(),
        Err(e) => refusal(&e),
    }
}

/// `POST /pending/{id}/deny`: what `POST /approve/{token}/deny` does.
pub(super) async fn deny(State(state): State<AppState>, Path(id): Path<Id>) -> Response {
    match state.requests.deny_pending(&id).await {
        Ok(AuditOutcome::Recorded) => done("Denied."),
        Ok(AuditOutcome::Missing) => done(DENIED_UNAUDITED),
        Err(e) => refusal(&e),
    }
}
