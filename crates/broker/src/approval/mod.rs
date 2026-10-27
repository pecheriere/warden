//! Approval listener: pages and endpoints the owner uses from their phone to
//! enroll passkeys, approve or deny requests, and revoke grants.
//!
//! Every route requires the owner's Tailscale identity. State-changing
//! requests must also be JSON (`Content-Type: application/json`) sent from
//! the public origin, which a cross-site form or a simple cross-origin
//! request cannot produce. Every response carries a strict CSP; the only
//! script is `/static/warden.js`.

use axum::extract::{DefaultBodyLimit, FromRequestParts as _, Path, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use ssh_key::PublicKey;
use warden_broker_proto::{
    Access, ApiError, CreateRequest, GrantAccess, GrantView, Id, RelayGrant, SshGrant, UnixUser,
    Window,
};
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::AppState;
use crate::audit::AuditEvent;
use crate::identity::Owner;
use crate::policy::{ApiScope, ApiSecretPolicy, CaKey, SshMode, SshTarget};
use crate::relay::RelayEndpoint;
use crate::requests::{
    BACKEND_UNAVAILABLE, Destination, PendingView, RELAY_NOT_CONFIGURED, RequestError, sha256_hex,
    window_label,
};
use crate::ssh_ca::{self, IssueInput};

use self::passkeys::{ApprovalBinding, PasskeyError};

pub mod pages;
pub mod passkeys;

/// The browser glue, served as `/static/warden.js`.
const SCRIPT: &str = include_str!("warden.js");

/// Content Security Policy of every response.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                   connect-src 'self'; form-action 'self'; frame-ancestors 'none'";

/// Largest accepted request body; `WebAuthn` responses are a few KiB.
const BODY_LIMIT: usize = 64 * 1024;

/// Requests shown on the history page.
const HISTORY_LIMIT: u32 = 100;

/// The destination (SSH host, port, host keys; API origin, path prefix,
/// methods, header, format, CA) differs from what the owner was shown.
const DESTINATION_CHANGED: &str = "policy changed; reload and review";

/// Recorded as `by` when the owner revokes a grant from the UI.
const REVOKED_BY_OWNER: &str = "owner";

/// Routes of the approval listener, with `state` applied.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/approve/{token}", get(approve_page))
        .route("/approve/{token}/begin", post(approve_begin))
        .route("/approve/{token}/finish", post(approve_finish))
        .route("/approve/{token}/deny", post(deny))
        .route("/grants", get(grants_page))
        .route("/grants/{id}/revoke", post(revoke_grant))
        .route("/history", get(history_page))
        .route("/enroll", get(enroll_page))
        .route("/enroll/begin", post(enroll_begin))
        .route("/enroll/finish", post(enroll_finish))
        .route("/static/warden.js", get(script))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_same_origin_json,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), require_owner))
        .layer(middleware::map_response(security_headers))
        .with_state(state)
}

// --- middleware -------------------------------------------------------------

async fn security_headers(mut resp: Response) -> Response {
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

async fn require_owner(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let (mut parts, body) = req.into_parts();
    if let Err(rejection) = Owner::from_request_parts(&mut parts, &state).await {
        return rejection.into_response();
    }
    next.run(Request::from_parts(parts, body)).await
}

/// CSRF defence for every state-changing request: the browser must say it
/// comes from the public origin, and the body must be JSON.
async fn require_same_origin_json(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    if matches!(*req.method(), Method::GET | Method::HEAD) {
        return next.run(req).await;
    }
    let expected = state.config.public_url.origin().ascii_serialization();
    let origin = req.headers().get(header::ORIGIN).map(HeaderValue::as_bytes);
    if origin != Some(expected.as_bytes()) {
        return json_error(StatusCode::FORBIDDEN, "cross-origin request rejected");
    }
    let is_json = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return json_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "requests must be application/json",
        );
    }
    next.run(req).await
}

// --- bodies -----------------------------------------------------------------

#[derive(Deserialize)]
struct BeginApproval {
    window: Window,
    /// Destination digest the page was rendered with.
    target: String,
}

#[derive(Deserialize)]
struct FinishApproval {
    ceremony: Id,
    credential: PublicKeyCredential,
}

#[derive(Deserialize)]
struct BeginEnrollment {
    code: String,
    label: String,
}

#[derive(Deserialize)]
struct FinishEnrollment {
    ceremony: Id,
    credential: RegisterPublicKeyCredential,
}

#[derive(Serialize)]
struct CeremonyStarted<T> {
    ceremony: Id,
    options: T,
}

#[derive(Serialize)]
struct Done {
    message: String,
}

#[derive(Serialize)]
struct Enrolled {
    message: String,
    passkey_id: String,
}

fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ApiError {
            error: message.into(),
        }),
    )
        .into_response()
}

fn done(message: impl Into<String>) -> Response {
    Json(Done {
        message: message.into(),
    })
    .into_response()
}

fn internal(context: &str, error: &dyn std::fmt::Display) -> Response {
    tracing::error!(context, error = %error, "approval endpoint failed");
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

/// The fixed answer when the secret backend cannot answer; `detail` is
/// logged only.
fn backend_unavailable(detail: &dyn std::fmt::Display) -> Response {
    tracing::error!(error = %detail, "secret backend unavailable");
    json_error(StatusCode::SERVICE_UNAVAILABLE, BACKEND_UNAVAILABLE)
}

fn request_error(e: &RequestError) -> Response {
    match e {
        RequestError::NotFound => {
            json_error(StatusCode::NOT_FOUND, "this request is no longer pending")
        }
        RequestError::AlreadyDecided => {
            json_error(StatusCode::CONFLICT, "this request was already decided")
        }
        RequestError::Rejected(_) => json_error(StatusCode::BAD_REQUEST, e.to_string()),
        RequestError::Unavailable(detail) => backend_unavailable(detail),
        RequestError::UnknownTarget(_)
        | RequestError::UnknownSecret(_)
        | RequestError::TargetInvalid { .. }
        | RequestError::SecretInvalid { .. } => {
            json_error(StatusCode::SERVICE_UNAVAILABLE, e.to_string())
        }
        _ => internal("request", e),
    }
}

fn passkey_error(e: &PasskeyError) -> Response {
    let status = match e {
        PasskeyError::BadCode | PasskeyError::BadLabel | PasskeyError::WrongCeremony => {
            StatusCode::BAD_REQUEST
        }
        PasskeyError::CeremonyExpired => StatusCode::GONE,
        PasskeyError::NoPasskeys | PasskeyError::AlreadyEnrolled => StatusCode::CONFLICT,
        PasskeyError::Verification(_)
        | PasskeyError::UnknownCredential
        | PasskeyError::CounterRegressed => {
            tracing::warn!(error = %e, "passkey verification failed");
            StatusCode::FORBIDDEN
        }
        PasskeyError::NotFound => StatusCode::NOT_FOUND,
        PasskeyError::Busy => StatusCode::TOO_MANY_REQUESTS,
        PasskeyError::Config(_)
        | PasskeyError::Db(_)
        | PasskeyError::Audit(_)
        | PasskeyError::Encoding(_)
        | PasskeyError::Internal(_) => return internal("passkey", e),
    };
    json_error(status, e.to_string())
}

// --- pages ------------------------------------------------------------------

async fn approve_page(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    match state.requests.pending_for_token(&token).await {
        Ok(view) => pages::approve(&view, state.clock.now()).into_response(),
        Err(RequestError::NotFound) => match state.requests.is_cancelled(&token).await {
            Ok(true) => (StatusCode::NOT_FOUND, pages::cancelled()).into_response(),
            Ok(false) => (StatusCode::NOT_FOUND, pages::not_pending()).into_response(),
            Err(e) => internal_page("approve page", &e),
        },
        Err(RequestError::Unavailable(detail)) => {
            tracing::error!(error = %detail, "secret backend unavailable");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                pages::unavailable(BACKEND_UNAVAILABLE),
            )
                .into_response()
        }
        Err(
            e @ (RequestError::UnknownTarget(_)
            | RequestError::UnknownSecret(_)
            | RequestError::TargetInvalid { .. }
            | RequestError::SecretInvalid { .. }),
        ) => (
            StatusCode::SERVICE_UNAVAILABLE,
            pages::unavailable(&e.to_string()),
        )
            .into_response(),
        Err(e) => internal_page("approve page", &e),
    }
}

async fn grants_page(State(state): State<AppState>) -> Response {
    match state.requests.active_grants().await {
        Ok(grants) => pages::grants(&grants, state.clock.now()).into_response(),
        Err(e) => internal_page("grants page", &e),
    }
}

async fn history_page(State(state): State<AppState>) -> Response {
    match state.requests.history(HISTORY_LIMIT).await {
        Ok(entries) => pages::history(&entries).into_response(),
        Err(e) => internal_page("history page", &e),
    }
}

async fn enroll_page() -> Response {
    pages::enroll().into_response()
}

async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, pages::not_found()).into_response()
}

async fn script() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        SCRIPT,
    )
        .into_response()
}

fn internal_page(context: &str, error: &dyn std::fmt::Display) -> Response {
    tracing::error!(context, error = %error, "approval page failed");
    (StatusCode::INTERNAL_SERVER_ERROR, pages::internal_error()).into_response()
}

// --- approval ---------------------------------------------------------------

/// Whether the policy as it is now still allows `view`'s request for
/// `window`, on a broker whose relay is `relay`.
fn check_policy(
    view: &PendingView,
    window: Window,
    relay: Option<&RelayEndpoint>,
) -> Result<(), String> {
    view.destination.check_window(window)?;
    match (&view.request.access, &view.destination) {
        (Access::Ssh { user, .. }, Destination::Ssh(target)) => check_ssh(target, user, relay),
        (Access::Api { .. }, Destination::Api(policy)) => {
            api_scope(&view.request, policy).map(drop)
        }
        _ => Err("the request does not match its policy kind".to_owned()),
    }
}

/// The scope API request `request` asks for, resolved against the current
/// `policy`.
///
/// # Errors
/// A message when the request is not an API request or asks for more than
/// `policy` allows now.
pub(crate) fn api_scope(
    request: &CreateRequest,
    policy: &ApiSecretPolicy,
) -> Result<ApiScope, String> {
    match &request.access {
        Access::Api {
            methods,
            path_prefix,
            ..
        } => policy.scope(methods.as_deref(), path_prefix.as_deref()),
        Access::Ssh { .. } => Err("the request does not match its policy kind".to_owned()),
    }
}

/// The SSH-specific checks: `user` is allowed, and a relay target needs the
/// relay configured.
fn check_ssh(
    target: &SshTarget,
    user: &UnixUser,
    relay: Option<&RelayEndpoint>,
) -> Result<(), String> {
    if !target.users.contains(user) {
        return Err(format!(
            "user {user} is not allowed on target {}",
            target.name
        ));
    }
    if target.mode == SshMode::Relay && relay.is_none() {
        return Err(format!("target {}: {RELAY_NOT_CONFIGURED}", target.name));
    }
    Ok(())
}

async fn approve_begin(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Json(body): Json<BeginApproval>,
) -> Response {
    let view = match state.requests.pending_for_token(&token).await {
        Ok(view) => view,
        Err(e) => return request_error(&e),
    };
    let destination_digest = view.destination.digest();
    if body.target != destination_digest {
        return json_error(StatusCode::CONFLICT, DESTINATION_CHANGED);
    }
    if let Err(message) = check_policy(&view, body.window, state.requests.relay()) {
        return json_error(StatusCode::BAD_REQUEST, message);
    }
    let binding = ApprovalBinding {
        token_hash: sha256_hex(&token),
        window: body.window,
        fingerprint: view.fingerprint,
        destination_digest,
        request_expires_at: view.expires_at,
    };
    match state.passkeys.begin_approval(binding).await {
        Ok((ceremony, options)) => Json(CeremonyStarted { ceremony, options }).into_response(),
        Err(e) => passkey_error(&e),
    }
}

async fn approve_finish(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Json(body): Json<FinishApproval>,
) -> Response {
    let approved = match state
        .passkeys
        .finish_approval(&body.ceremony, &body.credential)
        .await
    {
        Ok(approved) => approved,
        Err(e) => return passkey_error(&e),
    };
    let binding = &approved.binding;
    if binding.token_hash != sha256_hex(&token) {
        return json_error(
            StatusCode::BAD_REQUEST,
            "this passkey prompt belongs to another request",
        );
    }
    let now = state.clock.now();
    let undecidable = || {
        if now >= binding.request_expires_at {
            json_error(
                StatusCode::GONE,
                "this request expired before it was approved",
            )
        } else {
            json_error(StatusCode::CONFLICT, "this request was already decided")
        }
    };
    let view = match state.requests.pending_for_token(&token).await {
        Ok(view) => view,
        Err(RequestError::NotFound) => return undecidable(),
        Err(e) => return request_error(&e),
    };
    if view.fingerprint != binding.fingerprint {
        return json_error(StatusCode::CONFLICT, "the request changed; reload the page");
    }
    // The grant carries the re-fetched destination (SSH host, port and host
    // keys; API origin, prefix, methods and header); it must be the one the
    // owner approved.
    if view.destination.digest() != binding.destination_digest {
        return json_error(StatusCode::CONFLICT, DESTINATION_CHANGED);
    }
    // The policy was fetched fresh by `pending_for_token`; the window is the
    // one stored when the ceremony began.
    let relay = state.requests.relay();
    if let Err(message) = check_policy(&view, binding.window, relay) {
        return json_error(
            StatusCode::CONFLICT,
            format!("policy changed since this page loaded: {message}"),
        );
    }
    let (grant, issued) = match &view.destination {
        Destination::Ssh(target) if target.mode == SshMode::Relay => {
            // `check_policy` already refused a relay target without a relay.
            let Some(relay) = relay else {
                return json_error(StatusCode::CONFLICT, RELAY_NOT_CONFIGURED);
            };
            match relay_grant(&view, relay, binding.window, now) {
                Ok(grant) => (grant, None),
                Err((context, cause)) => return internal(context, &cause),
            }
        }
        Destination::Ssh(target) => {
            let ca = match state.backend.ssh_ca().await {
                Ok(ca) => ca,
                Err(e) => return backend_unavailable(&e),
            };
            match ssh_grant(&view, target, &ca, binding.window, now) {
                Ok((grant, key_id)) => (grant, Some(key_id)),
                Err((context, cause)) => return internal(context, &cause),
            }
        }
        Destination::Api(policy) => match api_grant(&view.request, policy, binding.window, now) {
            Ok(grant) => (grant, None),
            Err((context, cause)) => return internal(context, &cause),
        },
    };
    let (grant_id, not_after) = (grant.grant_id.clone(), grant.not_after);
    match state
        .requests
        .mark_approved(&token, binding.window, grant, &approved.passkey_id)
        .await
    {
        Ok(()) => {}
        Err(RequestError::NotFound | RequestError::AlreadyDecided) => return undecidable(),
        Err(e) => return request_error(&e),
    }
    if let Some(key_id) = issued {
        let issued = AuditEvent::CertIssued {
            grant_id: grant_id.clone(),
            key_id,
            not_after,
        };
        if let Err(e) = state.audit.append(issued).await {
            // The approval itself is committed and audited; record loudly
            // that the issuance entry is missing.
            tracing::error!(grant = %grant_id, error = %e, "could not audit certificate issuance");
        }
    }
    tracing::info!(request = %view.id, grant = %grant_id, "request approved");
    done(format!("Approved for {}.", window_label(binding.window)))
}

/// A failed grant-building step and its cause.
type GrantFailure = (&'static str, String);

/// Validity of a grant approved at `now` for `window`: `(now, now + window)`.
fn validity(window: Window, now: i64) -> Result<(i64, i64), GrantFailure> {
    let length = i64::try_from(window.secs()).map_err(|e| ("window length", e.to_string()))?;
    let not_after = now
        .checked_add(length)
        .ok_or(("grant expiry", "time overflow".to_owned()))?;
    Ok((now, not_after))
}

/// The grant for approving `view` on SSH `target` with `window` at `now`:
/// valid from `now` for exactly the window, with a certificate signed by
/// `ca`. Also returns the certificate's key id. Errors name the failed step
/// and its cause.
fn ssh_grant(
    view: &PendingView,
    target: &SshTarget,
    ca: &CaKey,
    window: Window,
    now: i64,
) -> Result<(GrantView, String), GrantFailure> {
    let Access::Ssh {
        target: target_name,
        user,
        public_key,
    } = &view.request.access
    else {
        return Err(("access kind", "not an ssh request".to_owned()));
    };
    let public_key =
        PublicKey::from_openssh(public_key).map_err(|e| ("stored public key", e.to_string()))?;
    let (not_before, not_after) = validity(window, now)?;
    let grant_id = Id::random();
    let cert = ssh_ca::issue(
        ca,
        &IssueInput {
            agent: &view.agent,
            grant_id: &grant_id,
            target: target_name,
            user,
            public_key: &public_key,
            now,
            not_after,
        },
    )
    .map_err(|e| ("certificate issuance", e.to_string()))?;
    let certificate = cert
        .to_openssh()
        .map_err(|e| ("certificate encoding", e.to_string()))?;
    let host_keys = target
        .host_keys
        .iter()
        .map(PublicKey::to_openssh)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ("host key encoding", e.to_string()))?;
    let grant = GrantView {
        grant_id,
        not_before,
        not_after,
        access: GrantAccess::Ssh(SshGrant {
            certificate,
            host: target.host.clone(),
            port: target.port,
            user: user.clone(),
            host_keys,
        }),
    };
    Ok((grant, cert.key_id().to_owned()))
}

/// The grant for approving `view` on a relay target with `window` at `now`:
/// valid from `now` for exactly the window, naming where the agent reaches
/// `relay` and its host key, and carrying the digest of the approved
/// destination, which the relay checks at every session start. There is no
/// certificate: the relay admits the agent by the public key bound into the
/// approved request.
fn relay_grant(
    view: &PendingView,
    relay: &RelayEndpoint,
    window: Window,
    now: i64,
) -> Result<GrantView, GrantFailure> {
    let Access::Ssh { target, user, .. } = &view.request.access else {
        return Err(("access kind", "not an ssh request".to_owned()));
    };
    let (not_before, not_after) = validity(window, now)?;
    Ok(GrantView {
        grant_id: Id::random(),
        not_before,
        not_after,
        access: GrantAccess::Relay(RelayGrant {
            target: target.clone(),
            user: user.clone(),
            relay_host: relay.host.clone(),
            relay_port: relay.port,
            relay_host_key: relay.host_key.clone(),
            digest: view.destination.digest(),
        }),
    })
}

/// The grant for approving `request` for API secret `policy` with `window`
/// at `now`: valid from `now` for exactly the window, limited to the scope
/// the request asked for. It names where the broker will send the secret;
/// the secret itself is never part of it.
fn api_grant(
    request: &CreateRequest,
    policy: &ApiSecretPolicy,
    window: Window,
    now: i64,
) -> Result<GrantView, GrantFailure> {
    let scope = api_scope(request, policy).map_err(|e| ("API scope", e))?;
    let (not_before, not_after) = validity(window, now)?;
    Ok(GrantView {
        grant_id: Id::random(),
        not_before,
        not_after,
        access: GrantAccess::Api(policy.grant_for(&scope)),
    })
}

async fn deny(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    match state.requests.deny(&token).await {
        Ok(()) => done("Denied."),
        Err(e) => request_error(&e),
    }
}

async fn revoke_grant(State(state): State<AppState>, Path(id): Path<Id>) -> Response {
    match state.requests.revoke_grant(&id, REVOKED_BY_OWNER).await {
        Ok(()) => done("Revoked."),
        Err(RequestError::NotFound) => json_error(StatusCode::NOT_FOUND, "no such grant"),
        Err(e) => request_error(&e),
    }
}

// --- enrollment -------------------------------------------------------------

async fn enroll_begin(
    State(state): State<AppState>,
    Json(body): Json<BeginEnrollment>,
) -> Response {
    match state
        .passkeys
        .begin_registration(&body.code, &body.label)
        .await
    {
        Ok((ceremony, options)) => Json(CeremonyStarted { ceremony, options }).into_response(),
        Err(e) => passkey_error(&e),
    }
}

async fn enroll_finish(
    State(state): State<AppState>,
    Json(body): Json<FinishEnrollment>,
) -> Response {
    match state
        .passkeys
        .finish_registration(&body.ceremony, &body.credential)
        .await
    {
        Ok(passkey_id) => Json(Enrolled {
            message: "Passkey enrolled.".to_owned(),
            passkey_id,
        })
        .into_response(),
        Err(e) => passkey_error(&e),
    }
}
