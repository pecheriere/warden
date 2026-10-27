//! The agent API: create requests, long-poll their status, list and revoke
//! grants, and make HTTP calls with an api grant. Every route except
//! `/healthz` requires the owner's Tailscale identity and an agent key (see
//! [`AuthedAgent`]).

use std::time::Duration;

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{DefaultBodyLimit, FromRequest, Path, Query, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router, middleware};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use url::Url;
use warden_broker_proto::{
    AgentName, ApiError, ApiGrant, CreateRequest, CreatedResponse, GrantAccess, GrantView, Id,
    ProxyRequest, ProxyResponse, RequestStatus,
};

use crate::AppState;
use crate::audit::AuditEvent;
use crate::identity::AuthedAgent;
use crate::policy::{ApiScope, PolicyError};
use crate::proxy::{self, Needles};
use crate::requests::{BACKEND_UNAVAILABLE, RequestError};

/// Largest accepted request body, in bytes.
const BODY_LIMIT: usize = 16 * 1024;

/// Largest accepted body of a proxied call: a 1 MiB request body, base64
/// encoded inside JSON with its headers.
const PROXY_BODY_LIMIT: usize = 2 * 1024 * 1024;

/// What the agent is told when the secret's policy no longer matches its
/// grant (or the secret is gone).
const POLICY_CHANGED: &str = "policy changed; request access again";

/// Longest method name recorded in the audit log as sent.
const MAX_AUDIT_METHOD: usize = 32;

/// Longest URL (origin and path) recorded in the audit log as sent.
const MAX_AUDIT_URL: usize = 512;

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
        .route(
            "/v1/grants/{id}/http",
            post(proxy_call).layer(DefaultBodyLimit::max(PROXY_BODY_LIMIT)),
        )
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
        RequestError::Rejected(_)
        | RequestError::TargetInvalid { .. }
        | RequestError::SecretInvalid { .. } => Some(StatusCode::BAD_REQUEST),
        RequestError::UnknownTarget(_)
        | RequestError::UnknownSecret(_)
        | RequestError::NotFound => Some(StatusCode::NOT_FOUND),
        RequestError::AlreadyDecided | RequestError::KeyInUse => Some(StatusCode::CONFLICT),
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

/// `POST /v1/grants/{id}/http`: make the call in the body with the grant's
/// API secret and return the redacted response.
///
/// The grant must be the agent's (404 otherwise), unrevoked, unexpired and
/// for API access (409 otherwise). Everything after that runs on its own
/// task and is audited as a `proxy_call` before the agent gets an answer,
/// so a disconnecting agent can neither stop a call halfway nor keep it out
/// of the audit log.
async fn proxy_call(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<ProxyRequest>,
) -> Result<Json<ProxyResponse>, Failure> {
    let id = parse_id(&id)?;
    let grant = usable_api_grant(&state, &agent, &id).await?;
    tokio::spawn(audited_call(state, agent, id, grant, req))
        .await
        .map_err(|_| Failure::Request(RequestError::Internal("proxy call task failed")))?
        .map(Json)
}

/// Why a grant of the agent's cannot be used for a call now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unusable {
    Revoked,
    Expired,
    NotApi,
}

impl Unusable {
    const fn message(self) -> &'static str {
        match self {
            Self::Revoked => "grant revoked",
            Self::Expired => "grant expired",
            Self::NotApi => "grant is not for API access",
        }
    }
}

/// The approved details of grant `id` if `agent` may use it now, or why
/// not. The outer error is a failed lookup (404 for another agent's grant).
async fn api_grant_status(
    state: &AppState,
    agent: &AgentName,
    id: &Id,
) -> Result<Result<ApiGrant, Unusable>, Failure> {
    let (view, revoked) = state.requests.agent_grant(agent, id).await?;
    Ok(if revoked {
        Err(Unusable::Revoked)
    } else if state.clock.now() >= view.not_after {
        Err(Unusable::Expired)
    } else {
        match view.access {
            GrantAccess::Api(grant) => Ok(grant),
            GrantAccess::Ssh(_) | GrantAccess::Relay(_) => Err(Unusable::NotApi),
        }
    })
}

/// The approved details of grant `id` if `agent` may use it now; 409 if it
/// is revoked, expired or not for API access.
async fn usable_api_grant(
    state: &AppState,
    agent: &AgentName,
    id: &Id,
) -> Result<ApiGrant, Failure> {
    api_grant_status(state, agent, id)
        .await?
        .map_err(|why| Failure::Client(StatusCode::CONFLICT, why.message().to_owned()))
}

/// What a `proxy_call` audit entry records about a call.
struct CallRecord {
    method: String,
    url: String,
    status: Option<u16>,
    response_bytes: u64,
    redactions: u32,
}

impl CallRecord {
    /// The method and URL as the agent sent them, reduced to what may be
    /// recorded: a method token, and the URL's origin and path (never the
    /// query, which may carry the agent's own data). Unparsable or overlong
    /// values are recorded as `invalid`.
    fn new(req: &ProxyRequest) -> Self {
        let method = http::Method::from_bytes(req.method.as_bytes())
            .ok()
            .filter(|m| m.as_str().len() <= MAX_AUDIT_METHOD)
            .map_or_else(|| "invalid".to_owned(), |m| m.as_str().to_owned());
        let url = Url::parse(&req.url)
            .ok()
            .map(|u| format!("{}{}", u.origin().ascii_serialization(), u.path()))
            .filter(|u| u.len() <= MAX_AUDIT_URL)
            .unwrap_or_else(|| "invalid".to_owned());
        Self {
            method,
            url,
            status: None,
            response_bytes: 0,
            redactions: 0,
        }
    }
}

/// Make the call and record its result. A call that finds the agent or the
/// broker at its limit of calls in flight is refused (429) before anything
/// is sent, and recorded like any other refused call. If the result entry cannot be
/// written, the agent gets an internal error instead of the response. A
/// call whose pre-flight entry could not be written was never sent and gets
/// no result entry either.
async fn audited_call(
    state: AppState,
    agent: AgentName,
    grant_id: Id,
    grant: ApiGrant,
    req: ProxyRequest,
) -> Result<ProxyResponse, Failure> {
    let mut record = CallRecord::new(&req);
    // The slot lives in this task, which runs to the end whether or not the
    // agent stays connected, and is released on every way out of it.
    let result = match state.proxy_calls.try_acquire(&agent) {
        Ok(_slot) => call(&state, &agent, &grant_id, &grant, &req, &mut record).await,
        Err(refused) => Err(Failure::Client(
            StatusCode::TOO_MANY_REQUESTS,
            refused.to_string(),
        )),
    };
    if let Err(Failure::Request(RequestError::Audit(_))) = &result {
        return result;
    }
    let outcome = match &result {
        Ok(_) => "ok".to_owned(),
        Err(failure) => failure.outcome(),
    };
    tracing::info!(agent = %agent, grant = %grant_id, url = %record.url, outcome = %outcome, "proxy call");
    let event = AuditEvent::ProxyCall {
        grant_id: grant_id.clone(),
        method: record.method,
        url: record.url,
        status: record.status,
        response_bytes: record.response_bytes,
        redactions: record.redactions,
        outcome,
    };
    if let Err(e) = state.audit.append(event).await {
        tracing::error!(grant = %grant_id, error = %e, "could not audit a proxy call");
        return Err(Failure::Request(RequestError::Audit(e)));
    }
    result
}

/// Check `req` against the secret's current policy, which must still be
/// the approved one; record that the call starts (or refuse it if that
/// cannot be recorded); send it with the secret; and redact the answer,
/// unless the grant ended while the call was out.
async fn call(
    state: &AppState,
    agent: &AgentName,
    grant_id: &Id,
    grant: &ApiGrant,
    req: &ProxyRequest,
    record: &mut CallRecord,
) -> Result<ProxyResponse, Failure> {
    let (policy, secret) = state
        .backend
        .api_secret_with_value(&grant.secret)
        .await
        .map_err(policy_failure)?;
    if policy.destination_digest() != grant.digest {
        return Err(policy_changed());
    }
    // The grant's scope comes from the broker's own record; every rule of
    // the item then applies to the narrowed policy.
    let scope = ApiScope::try_from(grant).map_err(|e| {
        tracing::error!(grant = %grant_id, error = %e, "stored API grant is unusable");
        Failure::Request(RequestError::Internal("stored grant is unusable"))
    })?;
    let policy = policy.narrowed(&scope);
    let limits = state.config.proxy;
    let prepared = proxy::check(&policy, req, limits.max_request_bytes)
        .map_err(|refusal| Failure::Client(StatusCode::BAD_REQUEST, refusal.to_string()))?;
    let needles = Needles::new(secret.expose(), &policy.format.render(secret.expose()));
    let started = AuditEvent::ProxyCallStarted {
        grant_id: grant_id.clone(),
        method: record.method.clone(),
        url: record.url.clone(),
    };
    if let Err(e) = state.audit.append(started).await {
        tracing::error!(grant = %grant_id, error = %e, "could not audit a proxy call start; not sending it");
        return Err(Failure::Request(RequestError::Audit(e)));
    }
    let upstream = proxy::forward(&policy, &secret, prepared, &limits)
        .await
        .map_err(|e| Failure::Client(e.status(), e.to_string()))?;
    drop(secret);
    record.status = Some(upstream.status.as_u16());
    record.response_bytes = u64::try_from(upstream.body.len()).unwrap_or(u64::MAX);
    let ended =
        |how: &str| Failure::Client(StatusCode::CONFLICT, format!("grant {how} during the call"));
    match api_grant_status(state, agent, grant_id).await {
        Ok(Ok(_)) => {}
        Ok(Err(Unusable::Expired)) => return Err(ended("expired")),
        Ok(Err(Unusable::Revoked | Unusable::NotApi))
        | Err(Failure::Request(RequestError::NotFound)) => return Err(ended("revoked")),
        Err(other) => return Err(other),
    }
    // Redaction scans every needle over up to 1 MiB, then the result is
    // base64 encoded: both run off the async workers. The needles are
    // moved in and wiped when the work ends.
    let response = off_runtime(move || proxy::redact_response(&upstream, &needles)).await?;
    record.redactions = response.redactions;
    Ok(response)
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

/// A failed policy or secret lookup at call time: an outage is a 503 with
/// the fixed message; a secret that is gone or no longer valid means the
/// approved policy no longer holds.
fn policy_failure(e: PolicyError) -> Failure {
    match e {
        PolicyError::Unavailable(detail) => Failure::Request(RequestError::Unavailable(detail)),
        other => {
            tracing::warn!(error = %other, "API secret unusable at call time");
            policy_changed()
        }
    }
}

fn policy_changed() -> Failure {
    Failure::Client(StatusCode::CONFLICT, POLICY_CHANGED.to_owned())
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
