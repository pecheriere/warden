//! `POST /grants/{id}/renew`: the owner starts renewing a commit signing grant. Like
//! opening a pending request, this only leads to the approval page: renewing takes a
//! passkey approval there, and the grant keeps working until then.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use warden_broker_proto::Id;

use super::{json_error, passkey_error, request_error};
use crate::AppState;
use crate::requests::RequestError;

/// Body of a successful renewal.
#[derive(Serialize)]
struct Opened {
    /// The approval link of the request that renews the grant.
    link: String,
}

pub(super) async fn renew(State(state): State<AppState>, Path(id): Path<Id>) -> Response {
    let (request, link) = match state.requests.renew_commit_signing(&id).await {
        Ok(renewal) => renewal,
        Err(RequestError::NotFound) => {
            return json_error(
                StatusCode::NOT_FOUND,
                "this grant has ended, or is not for commit signing",
            );
        }
        Err(e @ RequestError::Limited(_)) => {
            return json_error(StatusCode::TOO_MANY_REQUESTS, e.to_string());
        }
        Err(e) => return request_error(&e),
    };
    // A ceremony begun on a link this replaced can no longer finish.
    if let Err(e) = state.passkeys.forget_request(&request) {
        return passkey_error(&e);
    }
    Json(Opened {
        link: link.to_string(),
    })
    .into_response()
}
