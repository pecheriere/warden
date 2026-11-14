//! The agent API: create requests, long-poll their status, list and revoke
//! grants, and make HTTP calls with an api grant. Every route except
//! `/healthz` and `/v1/info` requires an authenticated agent: a signed
//! request ([`signed::verify`]) or the owner's Tailscale identity with a
//! bearer key (see [`AuthedAgent`]). Every route, those two included,
//! refuses requests that came through Tailscale Funnel ([`refuse_funnel`]).

use std::time::Duration;

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{DefaultBodyLimit, FromRequest, Path, Query, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get, post};
use axum::{Extension, Json, Router, middleware};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use warden_broker_proto::{
    ApiError, CreateRequest, CreatedResponse, GrantView, Id, InfoResponse, PendingRequest,
    RequestStatus, signing,
};

use warden_broker_proto::release::MAX_MANIFEST_BYTES;

use crate::AppState;
use crate::identity::{AuthedAgent, refuse_funnel};
use crate::load::{ApiLoad, WaitSlots};
use crate::proxy::CallEnd;
use crate::requests::{BACKEND_UNAVAILABLE, RequestError};
use crate::signed;

mod commit_signing;
mod github_token;
mod offers;
mod proxy_call;
mod release;

/// Largest accepted request body, in bytes.
const BODY_LIMIT: usize = 16 * 1024;

/// The manifest step's body: a manifest of at most `MAX_MANIFEST_BYTES`, as base64
/// (a third larger) in JSON.
const MANIFEST_BODY_LIMIT: usize = MAX_MANIFEST_BYTES * 2;

/// Largest accepted body of a proxied call: a 1 MiB request body, base64
/// encoded inside JSON with its headers.
const PROXY_BODY_LIMIT: usize = 2 * 1024 * 1024;

/// What the agent is told when the secret's policy no longer matches its
/// grant (or the secret is gone).
const POLICY_CHANGED: &str = "policy changed; request access again";

/// Longest a status request may wait for a change, in seconds.
const MAX_WAIT_SECS: u64 = 30;

/// Routes of the agent API listener, with `state` applied, within the bounds
/// `load` counts.
pub fn router(state: AppState, load: ApiLoad) -> Router {
    let ApiLoad { waits, bodies } = load;
    // An agent route with bodies of at most `limit` bytes. The signature
    // check sits inside the body limit, which it applies when it reads the
    // body, and times the body by the same limit.
    let agent = |route: MethodRouter<AppState>, limit: usize| {
        let verified: MethodRouter<AppState> = route.layer(middleware::from_fn_with_state(
            signed::SignedRoute::new(state.clone(), limit, bodies.clone()),
            signed::verify,
        ));
        verified.layer(DefaultBodyLimit::max(limit))
    };
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/info", get(info))
        .route(
            "/v1/requests",
            agent(post(create_request).get(list_requests), BODY_LIMIT),
        )
        .route(
            "/v1/requests/{id}",
            agent(get(request_status), BODY_LIMIT).layer(Extension(waits)),
        )
        .route(
            "/v1/requests/{id}/cancel",
            agent(post(cancel_request), BODY_LIMIT),
        )
        .route("/v1/grants", agent(get(list_grants), BODY_LIMIT))
        .route("/v1/offers", agent(get(offers::list), BODY_LIMIT))
        .route(
            "/v1/offers/repository/{owner}/{name}",
            agent(get(offers::repository::answer), BODY_LIMIT),
        )
        .route(
            "/v1/commit-signing/key",
            agent(get(commit_signing::public_key), BODY_LIMIT),
        )
        .route(
            "/v1/commit-signing/sign",
            agent(post(commit_signing::sign), PROXY_BODY_LIMIT),
        )
        .route(
            "/v1/github-token",
            agent(post(github_token::mint), BODY_LIMIT),
        )
        .route("/v1/release/tag", agent(post(release::tag), BODY_LIMIT))
        .route(
            "/v1/release/manifest",
            agent(post(release::manifest), MANIFEST_BODY_LIMIT),
        )
        .route(
            "/v1/release/publish",
            agent(post(release::publish), BODY_LIMIT),
        )
        .route(
            "/v1/grants/{id}/revoke",
            agent(post(revoke_grant), BODY_LIMIT),
        )
        .route(
            "/v1/grants/{id}/http",
            agent(post(proxy_call::proxy_call), PROXY_BODY_LIMIT),
        )
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(middleware::from_fn(refuse_funnel))
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

impl From<CallEnd> for Failure {
    fn from(end: CallEnd) -> Self {
        Self::Client(end.status(), end.message().to_owned())
    }
}

/// The HTTP status for a lifecycle error, or `None` if it is internal and
/// must not be described to the agent.
const fn status_of(e: &RequestError) -> Option<StatusCode> {
    match e {
        RequestError::Rejected(_)
        | RequestError::TargetInvalid { .. }
        | RequestError::SecretInvalid { .. } => Some(StatusCode::BAD_REQUEST),
        RequestError::UnknownTarget(_)
        | RequestError::UnknownSecret(_)
        | RequestError::NotFound => Some(StatusCode::NOT_FOUND),
        RequestError::AlreadyDecided | RequestError::KeyInUse | RequestError::ReplacedChanged => {
            Some(StatusCode::CONFLICT)
        }
        RequestError::AgentRevoked => Some(StatusCode::UNAUTHORIZED),
        RequestError::Limited(_) => Some(StatusCode::TOO_MANY_REQUESTS),
        RequestError::Unavailable(_)
        | RequestError::GithubUnavailable
        | RequestError::Contended => Some(StatusCode::SERVICE_UNAVAILABLE),
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

impl Failure {
    /// What the agent is told, as recorded in the audit log.
    fn outcome(&self) -> String {
        match self {
            Self::Client(_, message) => message.clone(),
            Self::Request(RequestError::Unavailable(_)) => BACKEND_UNAVAILABLE.to_owned(),
            Self::Request(e) => match status_of(e) {
                Some(_) => e.to_string(),
                None => "internal error".to_owned(),
            },
        }
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        match self {
            Self::Client(status, message) => error_body(status, message),
            Self::Request(RequestError::Unavailable(detail)) => {
                tracing::error!(error = %detail, "secret backend unavailable");
                error_body(StatusCode::SERVICE_UNAVAILABLE, BACKEND_UNAVAILABLE)
            }
            Self::Request(RequestError::Limited(refusal)) => (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, refusal.retry_after_secs().to_string())],
                Json(ApiError {
                    error: refusal.to_string(),
                }),
            )
                .into_response(),
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

/// The signing protocols this broker accepts and its audience. Needs no
/// agent key and no owner login: a client reads it before it can sign, and
/// key-signed agents on tagged devices have no user login. The network
/// controls in front of the API (Tailscale Serve, the gateway) still apply.
async fn info(State(state): State<AppState>) -> Json<InfoResponse> {
    Json(InfoResponse {
        protocols: vec![signing::PROTOCOL.to_owned()],
        audience: state.audience,
        github_token_max_window: Some(state.requests.github_token_max()),
        scoped_github_tokens: true,
    })
}

async fn not_found() -> Failure {
    Failure::Client(StatusCode::NOT_FOUND, "not found".to_owned())
}

async fn create_request(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
    ApiJson(req): ApiJson<CreateRequest>,
) -> Result<(StatusCode, Json<CreatedResponse>), Failure> {
    // Parsing applies the rules stored requests are read with; a new request
    // meets the stricter ones too.
    req.check_new()
        .map_err(|e| Failure::Client(StatusCode::BAD_REQUEST, e.to_string()))?;
    let created = state.requests.create(&agent, req).await?;
    tracing::info!(agent = %agent, id = %created.id, "request created");
    Ok((StatusCode::CREATED, Json(created)))
}

/// `GET /v1/requests`: the agent's own pending requests. It only reads, so it
/// notifies nobody and counts against no limit.
async fn list_requests(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
) -> Result<Json<Vec<PendingRequest>>, Failure> {
    Ok(Json(state.requests.pending_for_agent(&agent).await?))
}

#[derive(Deserialize)]
struct StatusQuery {
    wait: Option<u64>,
}

async fn request_status(
    State(state): State<AppState>,
    Extension(waits): Extension<WaitSlots>,
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
    // Only a call that may wait holds a place; an answer now costs nothing.
    let _slot = if wait == 0 {
        None
    } else {
        Some(waits.try_acquire(&agent).ok_or_else(|| {
            Failure::Client(
                StatusCode::TOO_MANY_REQUESTS,
                "too many status requests waiting; try again".to_owned(),
            )
        })?)
    };
    let status = state
        .requests
        .status(&agent, &id, Duration::from_secs(wait))
        .await?;
    tracing::debug!(agent = %agent, id = %id, status = status_name(&status), "request polled");
    Ok(Json(status))
}

/// `POST /v1/requests/{id}/cancel`: withdraw the agent's own pending
/// request. Another agent's or an unknown request is 404, one that is no
/// longer pending 409.
async fn cancel_request(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
    Path(id): Path<String>,
) -> Result<StatusCode, Failure> {
    let id = parse_id(&id)?;
    state.requests.cancel(&agent, &id).await?;
    tracing::info!(agent = %agent, id = %id, "request cancelled by agent");
    Ok(StatusCode::NO_CONTENT)
}

const fn status_name(status: &RequestStatus) -> &'static str {
    match status {
        RequestStatus::Pending => "pending",
        RequestStatus::Approved(_) => "approved",
        RequestStatus::Denied => "denied",
        RequestStatus::Expired => "expired",
        RequestStatus::Cancelled => "cancelled",
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

/// Run `work` on the blocking thread pool, off the async workers: CPU-bound
/// work on a large response must not stall other requests. A panic in
/// `work` is an internal error.
async fn off_runtime<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Failure> {
    tokio::task::spawn_blocking(work).await.map_err(|e| {
        tracing::error!(error = %e, "blocking work failed");
        Failure::Request(RequestError::Internal("blocking work failed"))
    })
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
        let invalid = RequestError::SecretInvalid {
            secret: "github".to_owned(),
            field: "credential".to_owned(),
            reason: "too short".to_owned(),
        };
        assert_eq!(status_of(&invalid), Some(StatusCode::BAD_REQUEST));
        assert_eq!(
            status_of(&RequestError::UnknownSecret("nope".to_owned())),
            Some(StatusCode::NOT_FOUND)
        );
        assert_eq!(
            status_of(&RequestError::KeyInUse),
            Some(StatusCode::CONFLICT)
        );
    }

    #[test]
    fn off_runtime_leaves_the_async_worker_free() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let (tx, rx) = std::sync::mpsc::channel();
            // The runtime's only worker must stay free to run this task
            // while the work waits for it.
            let ping = tokio::spawn(async move { tx.send(()).unwrap() });
            let got = off_runtime(move || rx.recv_timeout(Duration::from_secs(5)).is_ok()).await;
            ping.await.unwrap();
            assert!(matches!(got, Ok(true)));
        });
    }

    #[tokio::test]
    async fn failed_off_runtime_work_is_an_internal_error() {
        let got = off_runtime(|| -> u8 { panic!("redaction bug") }).await;
        let Err(failure) = got else {
            panic!("expected a failure")
        };
        assert_eq!(failure.outcome(), "internal error");
        assert_eq!(
            failure.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
