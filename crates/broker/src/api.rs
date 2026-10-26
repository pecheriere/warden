//! The agent API: create requests, long-poll their status, list and revoke
//! grants. Every route except `/healthz` requires the owner's Tailscale
//! identity and an agent key (see [`AuthedAgent`]).

use std::time::Duration;

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{DefaultBodyLimit, FromRequest, Path, Query, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router, middleware};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use warden_broker_proto::{ApiError, CreateRequest, CreatedResponse, GrantView, Id, RequestStatus};

use crate::AppState;
use crate::identity::AuthedAgent;
use crate::requests::{BACKEND_UNAVAILABLE, RequestError};

/// Largest accepted request body, in bytes.
const BODY_LIMIT: usize = 16 * 1024;

/// Longest a status request may wait for a change, in seconds.
const MAX_WAIT_SECS: u64 = 30;

/// Routes of the agent API listener, with `state` applied.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/requests", post(create_request))
        .route("/v1/requests/{id}", get(request_status))
        .route("/v1/grants", get(list_grants))
        .route("/v1/grants/{id}/revoke", post(revoke_grant))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(middleware::map_response(no_store))
        .with_state(state)
}

async fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// Why an API call failed, rendered as an [`ApiError`] body.
enum Failure {
    /// A lifecycle error; see [`status_of`] for how it maps.
    Request(RequestError),
    /// A malformed call, already described for the agent.
    Client(StatusCode, String),
}

impl From<RequestError> for Failure {
    fn from(e: RequestError) -> Self {
        Self::Request(e)
    }
}

/// The HTTP status for a lifecycle error, or `None` if it is internal and
/// must not be described to the agent.
const fn status_of(e: &RequestError) -> Option<StatusCode> {
    match e {
        RequestError::Rejected(_) | RequestError::TargetInvalid { .. } => {
            Some(StatusCode::BAD_REQUEST)
        }
        RequestError::UnknownTarget(_) | RequestError::NotFound => Some(StatusCode::NOT_FOUND),
        RequestError::AlreadyDecided => Some(StatusCode::CONFLICT),
        RequestError::AgentRevoked => Some(StatusCode::UNAUTHORIZED),
        RequestError::Unavailable(_) | RequestError::Contended => {
            Some(StatusCode::SERVICE_UNAVAILABLE)
        }
        RequestError::UnknownAgent(_)
        | RequestError::Agent(_)
        | RequestError::Db(_)
        | RequestError::Audit(_)
        | RequestError::Encoding(_)
        | RequestError::Corrupt(_)
        | RequestError::Internal(_) => None,
    }
}

fn error_body(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiError {
            error: message.into(),
        }),
    )
        .into_response()
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        match self {
            Self::Client(status, message) => error_body(status, message),
            Self::Request(RequestError::Unavailable(detail)) => {
                tracing::error!(error = %detail, "secret backend unavailable");
                error_body(StatusCode::SERVICE_UNAVAILABLE, BACKEND_UNAVAILABLE)
            }
            Self::Request(e) => status_of(&e).map_or_else(
                || {
                    tracing::error!(error = %e, "agent API request failed internally");
                    error_body(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
                },
                |status| error_body(status, e.to_string()),
            ),
        }
    }
}

/// A JSON body whose rejections are rendered as [`ApiError`].
struct ApiJson<T>(T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Failure;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection @ JsonRejection::BytesRejection(_)) => Err(Failure::Client(
                rejection.status(),
                "request body rejected".to_owned(),
            )),
            Err(rejection) => {
                // A body that parses as JSON but fails validation is still a
                // plain bad request.
                let status = match rejection.status() {
                    StatusCode::UNPROCESSABLE_ENTITY => StatusCode::BAD_REQUEST,
                    other => other,
                };
                Err(Failure::Client(status, rejection.body_text()))
            }
        }
    }
}

fn parse_id(raw: &str) -> Result<Id, Failure> {
    raw.parse()
        .map_err(|_| Failure::Client(StatusCode::BAD_REQUEST, "invalid id".to_owned()))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn not_found() -> Failure {
    Failure::Client(StatusCode::NOT_FOUND, "not found".to_owned())
}

async fn create_request(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
    ApiJson(req): ApiJson<CreateRequest>,
) -> Result<(StatusCode, Json<CreatedResponse>), Failure> {
    let created = state.requests.create(&agent, req).await?;
    tracing::info!(agent = %agent, id = %created.id, "request created");
    Ok((StatusCode::CREATED, Json(created)))
}

#[derive(Deserialize)]
struct StatusQuery {
    wait: Option<u64>,
}

async fn request_status(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
    Path(id): Path<String>,
    query: Result<Query<StatusQuery>, QueryRejection>,
) -> Result<Json<RequestStatus>, Failure> {
    let Query(StatusQuery { wait }) = query.map_err(|_| {
        Failure::Client(
            StatusCode::BAD_REQUEST,
            format!("wait must be a whole number of seconds from 0 to {MAX_WAIT_SECS}"),
        )
    })?;
    let wait = wait.unwrap_or(0);
    if wait > MAX_WAIT_SECS {
        return Err(Failure::Client(
            StatusCode::BAD_REQUEST,
            format!("wait must be at most {MAX_WAIT_SECS} seconds"),
        ));
    }
    let id = parse_id(&id)?;
    let status = state
        .requests
        .status(&agent, &id, Duration::from_secs(wait))
        .await?;
    tracing::debug!(agent = %agent, id = %id, status = status_name(&status), "request polled");
    Ok(Json(status))
}

const fn status_name(status: &RequestStatus) -> &'static str {
    match status {
        RequestStatus::Pending => "pending",
        RequestStatus::Approved(_) => "approved",
        RequestStatus::Denied => "denied",
        RequestStatus::Expired => "expired",
        RequestStatus::Revoked => "revoked",
        RequestStatus::Error { .. } => "error",
    }
}

async fn list_grants(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
) -> Result<Json<Vec<GrantView>>, Failure> {
    Ok(Json(state.requests.grants_for(&agent).await?))
}

async fn revoke_grant(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
    Path(id): Path<String>,
) -> Result<StatusCode, Failure> {
    let id = parse_id(&id)?;
    state.requests.revoke_agent_grant(&agent, &id).await?;
    tracing::info!(agent = %agent, grant = %id, "grant revoked by agent");
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_trouble_is_503_and_storage_trouble_is_internal() {
        assert_eq!(
            status_of(&RequestError::Unavailable("connect down".to_owned())),
            Some(StatusCode::SERVICE_UNAVAILABLE)
        );
        assert_eq!(status_of(&RequestError::Db(sqlx::Error::PoolClosed)), None);
        assert_eq!(status_of(&RequestError::Internal("rng")), None);
        assert_eq!(
            status_of(&RequestError::Rejected("bad".to_owned())),
            Some(StatusCode::BAD_REQUEST)
        );
    }
}
