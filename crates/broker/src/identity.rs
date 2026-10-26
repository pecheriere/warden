//! Caller identity: the Tailscale-authenticated owner and bearer-authenticated agents.

use axum::Json;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use warden_broker_proto::{AgentName, ApiError};

use crate::AppState;
use crate::agents::{self, AgentError};

/// Header set by Tailscale Serve with the authenticated user's login.
const TAILSCALE_LOGIN_HEADER: &str = "Tailscale-User-Login";

/// Determines who is calling from the request headers.
pub trait IdentitySource: Send + Sync + 'static {
    /// The caller's login, if the request carries a usable identity.
    fn caller(&self, headers: &HeaderMap) -> Option<String>;
}

/// Reads the login that Tailscale Serve injects after authenticating the peer.
#[derive(Debug, Clone, Copy, Default)]
pub struct TailscaleServeIdentity;

impl IdentitySource for TailscaleServeIdentity {
    fn caller(&self, headers: &HeaderMap) -> Option<String> {
        headers
            .get(TAILSCALE_LOGIN_HEADER)?
            .to_str()
            .ok()
            .map(str::to_owned)
    }
}

/// Why an extractor rejected a request. Bodies never include presented credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRejection {
    /// The caller is not the owner.
    Forbidden,
    /// The agent key is missing, unknown or revoked.
    Unauthorized,
    /// The database failed while checking the key.
    Internal,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };
        (
            status,
            Json(ApiError {
                error: message.to_owned(),
            }),
        )
            .into_response()
    }
}

/// Extractor: the request comes from the configured owner login.
#[derive(Debug, Clone, Copy)]
pub struct Owner;

impl FromRequestParts<AppState> for Owner {
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match state.identity.caller(&parts.headers) {
            Some(login) if login == state.config.owner_login => Ok(Self),
            _ => Err(AuthRejection::Forbidden),
        }
    }
}

/// Extractor: the owner, presenting a valid `Authorization: Bearer wdn_…` agent key.
#[derive(Debug, Clone)]
pub struct AuthedAgent(pub AgentName);

impl FromRequestParts<AppState> for AuthedAgent {
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Owner::from_request_parts(parts, state).await?;
        let key = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|k| !k.is_empty())
            .ok_or(AuthRejection::Unauthorized)?;
        match agents::authenticate(&state.pool, key).await {
            Ok(name) => Ok(Self(name)),
            Err(AgentError::Unknown | AgentError::Revoked) => Err(AuthRejection::Unauthorized),
            Err(e) => {
                // The error comes from the database, never from the presented key.
                tracing::error!(error = %e, "agent key lookup failed");
                Err(AuthRejection::Internal)
            }
        }
    }
}
