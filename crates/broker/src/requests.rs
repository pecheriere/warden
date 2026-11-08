//! Request lifecycle: creation with policy checks, owner notification,
//! long-poll status, decisions, expiry and revocation.
//!
//! Every state change runs to completion on its own task (dropping the caller
//! cannot interrupt it) in one `BEGIN IMMEDIATE` transaction. The log is never
//! written inside that transaction. A change that gives access has its entry
//! written first, so the audit trail never misses it (a change that then fails
//! leaves an entry and a note that it did not happen); one that ends access does
//! not wait for the log, see [`revocation`]. After the commit the affected request ids are published
//! on the [`StatusBus`] so long-polls wake up, and relay sessions of revoked
//! grants are ended.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row as _, SqlitePool};
use url::Url;
use warden_broker_proto::{
    AgentName, CreateRequest, Fingerprint, GrantAccess, Id, TargetName, UnixUser, Window,
};

use crate::agents::AgentError;
use crate::audit::{AuditError, AuditLog};
use crate::notify::Notifier;
use crate::policy::{ApiSecretPolicy, CommitSigningPolicy, PolicyError, SecretBackend, SshTarget};
use crate::proxy::{CallSlots, ProxyLimits};
use crate::relay::{LiveSessions, RelayEndpoint};

pub mod revocation;
mod transition;

pub use self::revocation::{AuditOutcome, EntriesWritten, unwritten_entries, write_entries};
pub(crate) use self::transition::{begin, note_if_not_applied, record};

mod bus;
mod commit_signing;
mod limits;
mod link_hosts;
mod pending;

pub use self::bus::StatusBus;
use self::commit_signing::SigningRefusals;
pub use self::commit_signing::{ActiveCommitSigning, SIGNATURES_PER_DAY};
use self::limits::Refusals;
pub use self::limits::{LimitRefusal, RequestLimits};
pub use self::link_hosts::LinkHosts;
pub use self::pending::PendingEntry;

mod create;
mod decide;
mod expiry;
mod grants;

pub use self::expiry::sweep_loop;
pub use self::grants::revoke_agent;

/// How long a request waits for the owner, in seconds.
const PENDING_TTL_SECS: i64 = 600;

/// Source of the current time, Unix seconds.
pub trait Clock: Send + Sync {
    /// Now, Unix seconds.
    fn now(&self) -> i64;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }
}

/// Why a relay target cannot be requested or approved on a broker without
/// `WARDEN_RELAY_PUBLIC_ADDR`.
pub const RELAY_NOT_CONFIGURED: &str = "relay is not configured";

/// What callers are told when the secret backend (targets or the SSH CA)
/// cannot answer; the detail goes to the server log only.
pub const BACKEND_UNAVAILABLE: &str = "secret backend unavailable";

/// Why a request operation failed. Messages never carry secrets, but
/// [`RequestError::Unavailable`] may describe backend internals (addresses,
/// item names) and is shown to callers only as [`BACKEND_UNAVAILABLE`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RequestError {
    /// The request breaks policy or is malformed.
    #[error("{0}")]
    Rejected(String),
    /// No target has this name.
    #[error("unknown target {0}")]
    UnknownTarget(String),
    /// No API secret has this name.
    #[error("unknown API secret {0}")]
    UnknownSecret(String),
    /// The target's policy item is malformed.
    #[error("target {target}: field {field} invalid: {reason}")]
    TargetInvalid {
        /// Target (item) name.
        target: String,
        /// Offending field.
        field: String,
        /// What is wrong with it.
        reason: String,
    },
    /// The API secret's policy item is malformed.
    #[error("secret {secret}: field {field} invalid: {reason}")]
    SecretInvalid {
        /// Secret (item) name.
        secret: String,
        /// Offending field.
        field: String,
        /// What is wrong with it.
        reason: String,
    },
    /// The secret backend could not answer.
    #[error("secret backend unavailable: {0}")]
    Unavailable(String),
    /// No such request or grant (or it belongs to another agent).
    #[error("not found")]
    NotFound,
    /// The request is no longer pending.
    #[error("request already decided")]
    AlreadyDecided,
    /// The requesting agent is revoked (or does not exist).
    #[error("agent revoked")]
    AgentRevoked,
    /// No agent has this name.
    #[error("unknown agent {0}")]
    UnknownAgent(AgentName),
    /// The SSH public key is bound to another live request or grant: one of
    /// another agent, or of this agent for another target.
    #[error("this public key is already bound to another request or grant")]
    KeyInUse,
    /// The agent is over one of its [`RequestLimits`]; nothing was stored and
    /// the owner was not asked about this request.
    #[error(transparent)]
    Limited(LimitRefusal),
    /// Too many concurrent creates for the same slot; retry.
    #[error("request slot contended; retry")]
    Contended,
    /// An agent operation failed.
    #[error(transparent)]
    Agent(AgentError),
    /// The database failed.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// The audit log could not record the transition, so it did not happen.
    #[error(transparent)]
    Audit(#[from] AuditError),
    /// Stored data could not be encoded or decoded.
    #[error("stored data unreadable: {0}")]
    Encoding(#[from] serde_json::Error),
    /// Stored data failed validation.
    #[error("stored data invalid: {0}")]
    Corrupt(String),
    /// A local resource (randomness, configuration) is unusable.
    #[error("internal error: {0}")]
    Internal(&'static str),
}

impl RequestError {
    /// The error for a failed API secret lookup: like the `From` conversion,
    /// but a malformed item is named as a secret, not a target.
    fn from_secret_lookup(e: PolicyError) -> Self {
        match e {
            PolicyError::Invalid {
                item,
                field,
                reason,
            } => Self::SecretInvalid {
                secret: item,
                field,
                reason,
            },
            other => other.into(),
        }
    }
}

impl From<PolicyError> for RequestError {
    fn from(e: PolicyError) -> Self {
        match e {
            PolicyError::NotFound(name) => Self::UnknownTarget(name),
            PolicyError::UnknownSecret(name) => Self::UnknownSecret(name),
            PolicyError::Invalid {
                item,
                field,
                reason,
            } => Self::TargetInvalid {
                target: item,
                field,
                reason,
            },
            PolicyError::Unavailable(m) => Self::Unavailable(m),
            PolicyError::Ca(m) => Self::Unavailable(format!("SSH CA: {m}")),
            PolicyError::NoCommitSigningKey => {
                Self::Rejected(warden_broker_proto::commit_signing::NOT_CONFIGURED.to_owned())
            }
            PolicyError::CommitSigningKey(m) => {
                Self::Unavailable(format!("commit signing key: {m}"))
            }
        }
    }
}

/// The current policy of what a request asks for: where approving it lets
/// the agent go.
#[derive(Debug, Clone)]
pub enum Destination {
    /// An SSH target.
    Ssh(SshTarget),
    /// An API secret.
    Api(ApiSecretPolicy),
    /// Commit signing by the broker's key.
    CommitSigning(CommitSigningPolicy),
}

impl Destination {
    /// Lowercase hex SHA-256 over where the destination sends the agent's
    /// access (see [`SshTarget::destination_digest`] and
    /// [`ApiSecretPolicy::destination_digest`]). The approval page embeds it
    /// and the approval is refused if it changed meanwhile.
    #[must_use]
    pub fn digest(&self) -> String {
        match self {
            Self::Ssh(target) => target.destination_digest(),
            Self::Api(policy) => policy.destination_digest(),
            Self::CommitSigning(policy) => policy.destination_digest(),
        }
    }

    /// Longest window the policy allows.
    #[must_use]
    pub const fn max_window(&self) -> Window {
        match self {
            Self::Ssh(target) => target.max_window,
            Self::Api(policy) => policy.max_window,
            Self::CommitSigning(policy) => policy.max_window,
        }
    }

    /// Whether the policy allows granting `window`.
    ///
    /// # Errors
    /// Why not, as `window 4h exceeds max 1h for secret github`.
    pub fn check_window(&self, window: Window) -> Result<(), String> {
        let subject = match self {
            Self::Ssh(target) => format!("target {}", target.name),
            Self::Api(policy) => format!("secret {}", policy.name),
            Self::CommitSigning(policy) => {
                return commit_signing::check_window(window, policy.max_window);
            }
        };
        check_window(window, self.max_window(), &subject)
    }
}

/// What the approval page shows for a pending request.
#[derive(Debug, Clone)]
pub struct PendingView {
    /// Request id.
    pub id: Id,
    /// Requesting agent.
    pub agent: AgentName,
    /// Fingerprint the agent also sees.
    pub fingerprint: Fingerprint,
    /// The request as made.
    pub request: CreateRequest,
    /// The current policy of what it asks for.
    pub destination: Destination,
    /// When the request expires, Unix seconds.
    pub expires_at: i64,
}

/// One row of the owner's request history.
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    /// Request id.
    pub id: Id,
    /// Requesting agent.
    pub agent: AgentName,
    /// Request fingerprint.
    pub fingerprint: Fingerprint,
    /// The request as made.
    pub request: CreateRequest,
    /// Stored status (`pending`, `approved`, `denied`, `expired`, `revoked`, `error`, `cancelled`).
    pub status: String,
    /// When the request was made, Unix seconds.
    pub created_at: i64,
    /// Granted window in seconds, if the request was approved.
    pub granted_secs: Option<i64>,
}

/// A grant that is still usable.
#[derive(Debug, Clone)]
pub struct ActiveGrant {
    /// Grant id.
    pub grant_id: Id,
    /// Agent holding the grant.
    pub agent: AgentName,
    /// Fingerprint of the approved request.
    pub fingerprint: Fingerprint,
    /// The approved request.
    pub request: CreateRequest,
    /// What the grant gives access to.
    pub access: GrantAccess,
    /// Start of validity, Unix seconds. A certificate grant's only
    /// certificate is issued at this time.
    pub not_before: i64,
    /// End of validity, Unix seconds; also when a certificate grant's
    /// certificate expires.
    pub not_after: i64,
}

/// An active relay grant, as the relay needs it to admit an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayGrantRecord {
    /// Grant id.
    pub grant_id: Id,
    /// Agent holding the grant.
    pub agent: AgentName,
    /// Target the relay opens the session to.
    pub target: TargetName,
    /// Unix account the relay logs in to the target as.
    pub user: UnixUser,
    /// Digest of the destination the owner approved (see
    /// [`SshTarget::destination_digest`]): a session starts only while the
    /// target still matches it.
    pub destination_digest: String,
    /// End of validity, Unix seconds.
    pub not_after: i64,
}

/// How a grant stopped being usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantEnd {
    /// It, or its agent, was revoked.
    Revoked,
    /// Its window is over.
    Expired,
}

/// The request lifecycle service.
#[derive(Clone)]
pub struct Requests {
    pool: SqlitePool,
    audit: Arc<AuditLog>,
    backend: Arc<dyn SecretBackend>,
    notifier: Arc<dyn Notifier>,
    bus: StatusBus,
    public_url: Url,
    clock: Arc<dyn Clock>,
    relay: Option<Arc<RelayEndpoint>>,
    /// Live relay sessions, ended when their grant is revoked.
    sessions: Arc<LiveSessions>,
    /// Proxied calls in flight, stopped when their grant is revoked.
    proxy_calls: Arc<CallSlots>,
    /// Held while writing the waiting audit entries to the log.
    entry_writer: Arc<tokio::sync::Mutex<()>>,
    /// Held from checking a change that gives access until it is applied. Its entry
    /// is written in between, outside any transaction, and without this two racing
    /// changes would both pass the check and both be recorded.
    recorded_change: Arc<tokio::sync::Mutex<()>>,
    /// How many requests each agent may make.
    limits: RequestLimits,
    /// What has been recorded and told about refusals under `limits`.
    refusals: Arc<Refusals>,
    /// Longest commit signing grant the server allows. The only grant allowed to
    /// outlast 4 hours: see `docs/threat-model.md`.
    commit_signing_max: Window,
    /// Signatures per commit signing grant per UTC day.
    commit_signing_per_day: u32,
    /// What has been recorded of refusals to sign.
    signing_refusals: Arc<SigningRefusals>,
    /// Hosts a request may link to.
    link_hosts: LinkHosts,
}

/// Which pending requests an expiry pass looks at.
enum Scope {
    All,
    Dedupe(String),
    Request(Id),
}

impl Requests {
    /// Build the service. Approval links are `<public_url>/approve/<token>`.
    /// Relay targets can be requested only when `relay` (where agents reach
    /// the relay) is given. Agents are held to the default [`RequestLimits`];
    /// see [`Requests::with_limits`]. Proxied calls are held to the default
    /// [`ProxyLimits`]; see [`Requests::with_call_limits`].
    #[must_use]
    pub fn new(
        pool: SqlitePool,
        audit: Arc<AuditLog>,
        backend: Arc<dyn SecretBackend>,
        notifier: Arc<dyn Notifier>,
        public_url: Url,
        clock: Arc<dyn Clock>,
        relay: Option<RelayEndpoint>,
    ) -> Self {
        let calls = ProxyLimits::default();
        Self {
            pool,
            audit,
            backend,
            notifier,
            bus: StatusBus::new(),
            public_url,
            clock,
            relay: relay.map(Arc::new),
            sessions: LiveSessions::new(),
            proxy_calls: CallSlots::new(calls.max_calls_per_agent, calls.max_calls),
            entry_writer: Arc::default(),
            recorded_change: Arc::default(),
            limits: RequestLimits::default(),
            refusals: Arc::default(),
            commit_signing_max: Window::COMMIT_SIGNING_DEFAULT,
            commit_signing_per_day: SIGNATURES_PER_DAY,
            signing_refusals: Arc::default(),
            link_hosts: LinkHosts::default(),
        }
    }

    /// Accept links to `hosts` in requests, instead of no links at all.
    #[must_use]
    pub fn with_link_hosts(mut self, hosts: LinkHosts) -> Self {
        self.link_hosts = hosts;
        self
    }

    /// The hosts requests may link to.
    #[must_use]
    pub const fn link_hosts(&self) -> &LinkHosts {
        &self.link_hosts
    }

    /// The clock this service reads.
    pub(crate) const fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// The live relay sessions.
    pub(crate) const fn live_sessions(&self) -> &Arc<LiveSessions> {
        &self.sessions
    }

    /// Now, by this service's clock (Unix seconds).
    pub(crate) fn now(&self) -> i64 {
        self.clock.now()
    }

    /// Where agents reach the relay, if it is configured.
    #[must_use]
    pub fn relay(&self) -> Option<&RelayEndpoint> {
        self.relay.as_deref()
    }

    /// The bus on which changed request ids are published.
    #[must_use]
    pub const fn bus(&self) -> &StatusBus {
        &self.bus
    }
}

/// Read a validated string column.
fn parse<T>(row: &SqliteRow, column: &str) -> Result<T, RequestError>
where
    T: TryFrom<String, Error = warden_broker_proto::ParseError>,
{
    let raw: String = row.try_get(column)?;
    T::try_from(raw).map_err(|e| RequestError::Corrupt(format!("column {column}: {e}")))
}

/// Refuse a `window` longer than `max`, the limit of `subject` (`target pi`,
/// `secret github`).
fn check_window(window: Window, max: Window, subject: &str) -> Result<(), String> {
    if window > max {
        return Err(format!(
            "window {} exceeds max {} for {subject}",
            window_label(window),
            window_label(max),
        ));
    }
    Ok(())
}

fn check_ed25519(public_key: &str) -> Result<(), RequestError> {
    let key = ssh_key::PublicKey::from_openssh(public_key).map_err(|_| {
        RequestError::Rejected("public_key must be an OpenSSH ssh-ed25519 public key".to_owned())
    })?;
    if key.algorithm() == ssh_key::Algorithm::Ed25519 {
        Ok(())
    } else {
        Err(RequestError::Rejected(format!(
            "public_key must be ssh-ed25519, not {}",
            key.algorithm()
        )))
    }
}

/// A fresh approval token: 32 random bytes, base64url without padding.
fn approval_token() -> Result<String, RequestError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|_| RequestError::Internal("OS random number generator unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Lowercase hex SHA-256 of `token`, as approval tokens are stored.
#[must_use]
pub fn sha256_hex(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// The wire spelling of `window` (`15m`, `30m`, `1h`, `4h`, `1d`, `7d`, `30d`, `90d`).
#[must_use]
pub const fn window_label(window: Window) -> &'static str {
    window.label()
}

#[cfg(test)]
mod tests;
