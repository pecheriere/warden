//! Server library for the warden approval broker.

use std::sync::Arc;

use sqlx::SqlitePool;

use warden_broker_proto::signing::Audience;

use crate::approval::passkeys::Passkeys;
use crate::audit::AuditLog;
use crate::config::Config;
use crate::github_app::GithubApi;
use crate::identity::IdentitySource;
use crate::offers_cache::RepositoryOfferCache;
use crate::policy::SecretBackend;
use crate::requests::{Clock, Requests};

pub mod agents;
pub mod api;
pub mod approval;
pub mod audience;
pub mod audit;
pub mod audit_throttle;
pub mod commit_signing;
pub mod config;
pub mod doctor;
pub mod enrollment;
pub mod github_app;
mod github_http;
pub mod github_release;
pub mod health;
pub mod identity;
pub mod load;
pub mod notify;
pub mod offers_cache;
pub mod policy;
pub mod private_files;
pub mod proxy;
pub mod relay;
pub mod release_signing;
pub mod requests;
pub mod serve;
pub mod signed;
pub mod ssh_ca;
pub mod store;
#[cfg(any(test, feature = "testkit"))]
pub mod test_keys;
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
    /// This broker's audience, published at `GET /v1/info`.
    pub audience: Audience,
    /// Where GitHub's API is, for minting agent tokens.
    pub github: GithubApi,
    /// Recent answers of `GET /v1/offers/repository/{owner}/{name}`.
    pub repository_offers: Arc<RepositoryOfferCache>,
}

/// The two routers of the broker: the agent API and the approval UI, each
/// with `state` applied. Serve them on separate listeners.
pub fn build_routers(state: AppState) -> (axum::Router, axum::Router) {
    (
        api::router(state.clone(), load::ApiLoad::default()),
        approval::router(state),
    )
}
