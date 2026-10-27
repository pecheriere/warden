//! Server library for the warden approval broker.

use std::sync::Arc;

use sqlx::SqlitePool;

use warden_broker_proto::signing::Audience;

use crate::approval::passkeys::Passkeys;
use crate::audit::AuditLog;
use crate::config::Config;
use crate::identity::IdentitySource;
use crate::policy::SecretBackend;
use crate::proxy::CallSlots;
use crate::requests::{Clock, Requests};

pub mod agents;
pub mod api;
pub mod approval;
pub mod audience;
pub mod audit;
pub mod config;
pub mod health;
pub mod identity;
pub mod notify;
pub mod policy;
pub mod proxy;
pub mod relay;
pub mod requests;
pub mod ssh_ca;
pub mod store;
#[cfg(feature = "testkit")]
pub mod testkit;

/// Shared state handed to every request handler.
#[derive(Clone)]
pub struct AppState {
    /// `SQLite` pool.
    pub pool: SqlitePool,
    /// Server configuration.
    pub config: Arc<Config>,
    /// Source of caller identity.
    pub identity: Arc<dyn IdentitySource>,
    /// Hash-chained audit log.
    pub audit: Arc<AuditLog>,
    /// Source of targets and the SSH CA key, read fresh on every use.
    pub backend: Arc<dyn SecretBackend>,
    /// Current time; the same clock [`AppState::requests`] uses.
    pub clock: Arc<dyn Clock>,
    /// Request lifecycle.
    pub requests: Requests,
    /// Passkey enrollment and approval ceremonies.
    pub passkeys: Arc<Passkeys>,
    /// Proxied calls in flight, held to the limits in [`Config::proxy`].
    pub proxy_calls: Arc<CallSlots>,
    /// This broker's audience, published at `GET /v1/info`.
    pub audience: Audience,
}

/// The two routers of the broker: the agent API and the approval UI, each
/// with `state` applied. Serve them on separate listeners.
pub fn build_routers(state: AppState) -> (axum::Router, axum::Router) {
    (api::router(state.clone()), approval::router(state))
}
