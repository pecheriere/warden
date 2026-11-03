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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row as _, Sqlite, SqliteConnection, SqlitePool, Transaction};
use url::Url;
use warden_broker_proto::{
    Access, AgentName, CreateRequest, CreatedResponse, Fingerprint, GrantAccess, GrantView, Id,
    RequestStatus, TargetName, UnixUser, Window, fingerprint,
};

use crate::agents::{self, AgentError};
use crate::audit::{AuditError, AuditEvent, AuditLog};
use crate::notify::{Doorbell, Notifier, doorbell};
use crate::policy::{ApiSecretPolicy, PolicyError, SecretBackend, SshMode, SshTarget};
use crate::proxy::{CallSlots, ProxyLimits};
use crate::relay::{LiveSessions, RelayEndpoint};
use crate::ssh_ca;

pub mod revocation;
mod transition;

use self::revocation::commit_with_entries;
pub use self::revocation::{AuditOutcome, EntriesWritten, unwritten_entries, write_entries};
use self::transition::detached;
pub(crate) use self::transition::{begin, note_if_not_applied, record};

mod bus;
mod limits;
mod pending;

pub use self::bus::StatusBus;
use self::bus::next_change;
use self::limits::Refusals;
pub use self::limits::{LimitRefusal, RequestLimits};
pub use self::pending::PendingEntry;

/// How long a request waits for the owner, in seconds.
const PENDING_TTL_SECS: i64 = 600;

/// Longest a status long-poll may wait.
const MAX_WAIT: Duration = Duration::from_secs(30);

/// Attempts to claim the pending slot when racing other creates.
const INSERT_ATTEMPTS: usize = 3;

/// Recorded as `by` for grants ended by revoking their agent.
const AGENT_REVOKE: &str = "agent revoke";

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
        }
    }

    /// Longest window the policy allows.
    #[must_use]
    pub const fn max_window(&self) -> Window {
        match self {
            Self::Ssh(target) => target.max_window,
            Self::Api(policy) => policy.max_window,
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

/// Active relay grants for a target (`?1` now, `?2` the target), with the
/// request that bound their key, longest lasting first. Grants are found by
/// `not_after` through its index, so a login check never scans the history.
const ACTIVE_RELAY_GRANTS: &str = "\
    SELECT g.id, g.agent, g.not_after, g.view, r.body \
    FROM grants g JOIN requests r ON r.id = g.request_id \
    WHERE g.not_after > ?1 AND g.revoked_at IS NULL \
    AND json_extract(g.view, '$.access.kind') = 'relay' \
    AND json_extract(g.view, '$.access.target') = ?2 \
    ORDER BY g.not_after DESC, g.id";

/// Of the grants listed in `?2` (a JSON array of ids), those revoked or
/// past their window at `?1` (now), each with whether it was revoked.
/// Grants are found by primary key: the relay's periodic check costs one
/// lookup per grant with a live session.
const ENDED_GRANTS: &str = "\
    SELECT id, revoked_at IS NOT NULL AS revoked FROM grants \
    WHERE id IN (SELECT value FROM json_each(?2)) \
    AND (revoked_at IS NOT NULL OR not_after <= ?1)";

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
        }
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

    /// Which of `grant_ids` are revoked or past their window now.
    ///
    /// # Errors
    /// Storage failures or unreadable stored rows.
    pub(crate) async fn ended_grants(
        &self,
        grant_ids: &[Id],
    ) -> Result<Vec<(Id, GrantEnd)>, RequestError> {
        let ids = serde_json::to_string(&grant_ids.iter().map(Id::as_str).collect::<Vec<_>>())?;
        sqlx::query(ENDED_GRANTS)
            .bind(self.clock.now())
            .bind(ids)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(|row| {
                let end = if row.try_get::<bool, _>("revoked")? {
                    GrantEnd::Revoked
                } else {
                    GrantEnd::Expired
                };
                Ok((parse(row, "id")?, end))
            })
            .collect()
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

    /// Validate `req` against policy, store it and notify the owner in the
    /// background. A duplicate of the agent's pending request for the same
    /// target (or secret) and kind returns that request instead, whatever
    /// the agent's limits.
    ///
    /// # Errors
    /// [`RequestError::Limited`] if the agent is over its [`RequestLimits`],
    /// [`RequestError::Rejected`] for policy violations,
    /// [`RequestError::KeyInUse`] if the SSH public key backs another live
    /// request or grant, the target or secret errors from the backend,
    /// [`RequestError::AgentRevoked`], or storage failures. No row is stored
    /// and nobody is notified on error.
    pub async fn create(
        &self,
        agent: &AgentName,
        req: CreateRequest,
    ) -> Result<CreatedResponse, RequestError> {
        let (dedupe_key, subject) = match &req.access {
            Access::Ssh {
                target,
                user,
                public_key,
            } => {
                check_ed25519(public_key)?;
                let policy = self.backend.ssh_target(target).await?;
                if !policy.users.contains(user) {
                    return Err(RequestError::Rejected(format!(
                        "user {user} not allowed for target {target}"
                    )));
                }
                check_window(req.window, policy.max_window, &format!("target {target}"))
                    .map_err(RequestError::Rejected)?;
                if policy.mode == SshMode::Relay && self.relay.is_none() {
                    return Err(RequestError::Rejected(format!(
                        "target {target}: {RELAY_NOT_CONFIGURED}"
                    )));
                }
                (
                    format!("{agent}|ssh|{target}"),
                    format!("ssh {user}@{target}"),
                )
            }
            Access::Api {
                secret,
                methods,
                path_prefix,
            } => {
                let policy = self
                    .backend
                    .api_secret(secret)
                    .await
                    .map_err(RequestError::from_secret_lookup)?;
                check_window(req.window, policy.max_window, &format!("secret {secret}"))
                    .map_err(RequestError::Rejected)?;
                let scope = policy
                    .scope(methods.as_deref(), path_prefix.as_deref())
                    .map_err(RequestError::Rejected)?;
                let methods: Vec<&str> = scope.methods().iter().map(http::Method::as_str).collect();
                (
                    format!(
                        "{agent}|api|{secret}|{}|{}",
                        methods.join(","),
                        scope.path_prefix()
                    ),
                    scope.subject(secret),
                )
            }
        };
        for _ in 0..INSERT_ATTEMPTS {
            // A stale pending row past its expiry must not hold the slot.
            self.expire_due(Scope::Dedupe(dedupe_key.clone())).await?;
            let change = Arc::clone(&self.recorded_change).lock_owned().await;
            // Checked here so a request that stores nothing writes nothing; the
            // transaction that stores one checks again.
            if let Access::Ssh {
                target, public_key, ..
            } = &req.access
            {
                let mut conn = self.pool.acquire().await?;
                check_key_unbound(&mut conn, agent, target, public_key, self.clock.now()).await?;
            }
            if let Some(existing) = self.pending_in_slot(&dedupe_key).await? {
                return Ok(existing);
            }
            let token = approval_token()?;
            let link = self.approval_link(&token)?;
            // Insert and ring as one detached unit: a caller dropped while the
            // insert commits must not leave a pending row nobody was told about.
            let inserted = {
                let (this, agent, req, key, subject) = (
                    self.clone(),
                    agent.clone(),
                    req.clone(),
                    dedupe_key.clone(),
                    subject.clone(),
                );
                detached(async move {
                    let created = this.insert(&agent, &req, &subject, &key, &token).await;
                    drop(change);
                    if let Err(RequestError::Limited(refusal)) = &created {
                        this.record_refusal(&agent, *refusal).await;
                    }
                    let created = created?;
                    this.spawn_notify(created.id.clone(), doorbell(&agent, &subject, &req, link));
                    Ok(created)
                })
                .await
            };
            match inserted {
                Ok(created) => return Ok(created),
                Err(RequestError::Db(sqlx::Error::Database(e))) if e.is_unique_violation() => {
                    if let Some(existing) = self.pending_in_slot(&dedupe_key).await? {
                        return Ok(existing);
                    }
                    // The other request was decided meanwhile; try again.
                }
                Err(e) => return Err(e),
            }
        }
        Err(RequestError::Contended)
    }

    async fn insert(
        &self,
        agent: &AgentName,
        req: &CreateRequest,
        subject: &str,
        dedupe_key: &str,
        token: &str,
    ) -> Result<CreatedResponse, RequestError> {
        let id = Id::random();
        let fp = fingerprint(agent, req);
        let body = serde_json::to_string(req)?;
        let active = sqlx::query("SELECT 1 FROM agents WHERE name = ? AND revoked_at IS NULL")
            .bind(agent.as_str())
            .fetch_optional(&self.pool)
            .await?;
        if active.is_none() {
            return Err(RequestError::AgentRevoked);
        }
        // Checked here so a refused request writes nothing; the transaction that
        // stores one checks again.
        let mut conn = self.pool.acquire().await?;
        limits::check(&mut conn, &self.limits, agent, dedupe_key, self.clock.now()).await?;
        drop(conn);
        let created = AuditEvent::RequestCreated {
            id: id.clone(),
            agent: agent.clone(),
            fingerprint: fp.clone(),
            summary: format!("{subject} for {}: {}", window_label(req.window), req.goal),
        };
        let transition = format!("creation of request {id}");
        record(&self.audit, vec![created], &transition).await?;
        let applied = async {
            let mut tx = begin(&self.pool).await?;
            // Read after the write lock: a create that queued for it must see the
            // requests made meanwhile as earlier than itself, or the limits miss them.
            let now = self.clock.now();
            if let Access::Ssh {
                target, public_key, ..
            } = &req.access
            {
                // In the write transaction, so no concurrent create can bind the
                // key between this check and the insert.
                check_key_unbound(&mut tx, agent, target, public_key, now).await?;
            }
            // Also in the write transaction, so concurrent creates are counted.
            limits::check(&mut tx, &self.limits, agent, dedupe_key, now).await?;
            let inserted = sqlx::query(
                "INSERT INTO requests (id, agent, fingerprint, dedupe_key, body, \
                 approval_token_hash, status, created_at, expires_at) \
                 SELECT ?, ?, ?, ?, ?, ?, 'pending', ?, ? \
                 WHERE EXISTS (SELECT 1 FROM agents WHERE name = ? AND revoked_at IS NULL)",
            )
            .bind(id.as_str())
            .bind(agent.as_str())
            .bind(fp.as_str())
            .bind(dedupe_key)
            .bind(&body)
            .bind(sha256_hex(token))
            .bind(now)
            .bind(now + PENDING_TTL_SECS)
            .bind(agent.as_str())
            .execute(&mut *tx)
            .await?;
            if inserted.rows_affected() == 0 {
                return Err(RequestError::AgentRevoked);
            }
            tx.commit().await?;
            Ok(())
        }
        .await;
        note_if_not_applied(&self.audit, &applied, &transition).await;
        applied?;
        Ok(CreatedResponse {
            id,
            fingerprint: fp,
        })
    }

    async fn pending_in_slot(
        &self,
        dedupe_key: &str,
    ) -> Result<Option<CreatedResponse>, RequestError> {
        let row = sqlx::query(
            "SELECT id, fingerprint FROM requests WHERE dedupe_key = ? AND status = 'pending'",
        )
        .bind(dedupe_key)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(CreatedResponse {
                id: parse(&row, "id")?,
                fingerprint: parse(&row, "fingerprint")?,
            })
        })
        .transpose()
    }

    fn approval_link(&self, token: &str) -> Result<Url, RequestError> {
        let mut url = self.public_url.clone();
        url.path_segments_mut()
            .map_err(|()| RequestError::Internal("public URL cannot be a base"))?
            .pop_if_empty()
            .extend(["approve", token]);
        Ok(url)
    }

    fn spawn_notify(&self, id: Id, bell: Doorbell) {
        let this = self.clone();
        tokio::spawn(async move {
            if let Err(e) = this.notify(&id, &bell).await {
                tracing::error!(request = %id, error = %e, "recording notification outcome failed");
            }
        });
    }

    /// Ring the owner; on failure end the request in `error`.
    async fn notify(&self, id: &Id, bell: &Doorbell) -> Result<(), RequestError> {
        let result = match self.notifier.ring(bell).await {
            Ok(channel) => self
                .audit
                .append(AuditEvent::Notified {
                    id: id.clone(),
                    channel: channel.to_owned(),
                })
                .await
                .map_err(RequestError::from),
            Err(e) => {
                tracing::warn!(request = %id, error = %e, "owner notification failed");
                self.fail_notification(id, self.notifier.name().to_owned(), e.to_string())
                    .await
            }
        };
        self.bus.publish(id);
        result
    }

    async fn fail_notification(
        &self,
        id: &Id,
        channel: String,
        reason: String,
    ) -> Result<(), RequestError> {
        let now = self.clock.now();
        let mut tx = begin(&self.pool).await?;
        sqlx::query(
            "UPDATE requests SET status = 'error', error = ?, decided_at = ? \
             WHERE id = ? AND status = 'pending'",
        )
        .bind(format!("could not notify the owner: {reason}"))
        .bind(now)
        .bind(id.as_str())
        .execute(&mut *tx)
        .await?;
        let failed = AuditEvent::NotifyFailed {
            id: id.clone(),
            channel,
            reason,
        };
        commit_with_entries(tx, vec![failed], now).await?;
        self.settle_entries().await;
        Ok(())
    }

    /// The state of `agent`'s request `id`. While it is pending and `wait`
    /// is non-zero, wait (at most 30 s) for it to change.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if no such request belongs to `agent`;
    /// storage failures.
    pub async fn status(
        &self,
        agent: &AgentName,
        id: &Id,
        wait: Duration,
    ) -> Result<RequestStatus, RequestError> {
        // Subscribe before the first read so no change can slip between them.
        let mut rx = self.bus.subscribe();
        let deadline = tokio::time::Instant::now() + wait.min(MAX_WAIT);
        loop {
            let status = self.read_status(agent, id).await?;
            if status != RequestStatus::Pending || wait.is_zero() {
                return Ok(status);
            }
            match tokio::time::timeout_at(deadline, next_change(&mut rx, id)).await {
                Ok(true) => {}
                Ok(false) | Err(_) => return self.read_status(agent, id).await,
            }
        }
    }

    async fn read_status(&self, agent: &AgentName, id: &Id) -> Result<RequestStatus, RequestError> {
        let row = self.status_row(agent, id).await?;
        let status: String = row.try_get("status")?;
        let expires_at: i64 = row.try_get("expires_at")?;
        if status == "pending" && expires_at <= self.clock.now() {
            self.expire_due(Scope::Request(id.clone())).await?;
            return to_status(&self.status_row(agent, id).await?);
        }
        to_status(&row)
    }

    async fn status_row(&self, agent: &AgentName, id: &Id) -> Result<SqliteRow, RequestError> {
        sqlx::query(
            "SELECT r.status, r.error, r.expires_at, g.view FROM requests r \
             LEFT JOIN grants g ON g.request_id = r.id WHERE r.id = ? AND r.agent = ?",
        )
        .bind(id.as_str())
        .bind(agent.as_str())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(RequestError::NotFound)
    }

    /// The pending request behind an approval token, with the current
    /// policy of its target or secret.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if the token is unknown or its request is
    /// no longer pending; backend and storage failures.
    pub async fn pending_for_token(&self, token: &str) -> Result<PendingView, RequestError> {
        let row = sqlx::query(
            "SELECT id, agent, fingerprint, body, expires_at FROM requests \
             WHERE approval_token_hash = ? AND status = 'pending' AND expires_at > ?",
        )
        .bind(sha256_hex(token))
        .bind(self.clock.now())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(RequestError::NotFound)?;
        let body: String = row.try_get("body")?;
        let request: CreateRequest = serde_json::from_str(&body)?;
        let destination = self.destination(&request).await?;
        Ok(PendingView {
            id: parse(&row, "id")?,
            agent: parse(&row, "agent")?,
            fingerprint: parse(&row, "fingerprint")?,
            destination,
            expires_at: row.try_get("expires_at")?,
            request,
        })
    }

    /// Deny the pending request behind `token`, whatever state the audit log is
    /// in; [`AuditOutcome::Missing`] says it is not on record yet.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] for an unknown token,
    /// [`RequestError::AlreadyDecided`] if it is no longer pending.
    pub async fn deny(&self, token: &str) -> Result<AuditOutcome, RequestError> {
        let this = self.clone();
        let token = token.to_owned();
        detached(async move { this.deny_now(&token).await }).await
    }

    async fn deny_now(&self, token: &str) -> Result<AuditOutcome, RequestError> {
        let hash = sha256_hex(token);
        let now = self.clock.now();
        let mut tx = begin(&self.pool).await?;
        let Some(row) = sqlx::query(
            "UPDATE requests SET status = 'denied', decided_at = ?1 \
             WHERE approval_token_hash = ?2 AND status = 'pending' AND expires_at > ?1 \
             RETURNING id",
        )
        .bind(now)
        .bind(&hash)
        .fetch_optional(&mut *tx)
        .await?
        else {
            drop(tx);
            return Err(self.not_pending(&hash).await);
        };
        let id: Id = parse(&row, "id")?;
        self.finish_denial(tx, &id, now).await
    }

    /// Commit the denial of `id` made in `tx`, with its audit entry, and tell
    /// whoever waits on the request.
    async fn finish_denial(
        &self,
        tx: Transaction<'static, Sqlite>,
        id: &Id,
        now: i64,
    ) -> Result<AuditOutcome, RequestError> {
        let denied = AuditEvent::Denied { id: id.clone() };
        commit_with_entries(tx, vec![denied], now).await?;
        let outcome = self.settle_entries().await;
        self.bus.publish(id);
        Ok(outcome)
    }

    /// Withdraw `agent`'s own pending request `id`. The request becomes
    /// `cancelled` and its approval link stops working; nothing else about
    /// it changes.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if no such request belongs to `agent`;
    /// [`RequestError::AlreadyDecided`] if it is no longer pending (decided,
    /// cancelled or past its expiry).
    pub async fn cancel(&self, agent: &AgentName, id: &Id) -> Result<(), RequestError> {
        let this = self.clone();
        let (agent, id) = (agent.clone(), id.clone());
        detached(async move { this.cancel_now(&agent, &id).await }).await
    }

    async fn cancel_now(&self, agent: &AgentName, id: &Id) -> Result<(), RequestError> {
        let now = self.clock.now();
        let mut tx = begin(&self.pool).await?;
        let cancelled = sqlx::query(
            "UPDATE requests SET status = 'cancelled', decided_at = ?1 \
             WHERE id = ?2 AND agent = ?3 AND status = 'pending' AND expires_at > ?1",
        )
        .bind(now)
        .bind(id.as_str())
        .bind(agent.as_str())
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if cancelled == 0 {
            drop(tx);
            // Existence is only revealed for the agent's own requests.
            return Err(match self.status_row(agent, id).await {
                Ok(_) => RequestError::AlreadyDecided,
                Err(e) => e,
            });
        }
        let event = AuditEvent::RequestCancelled {
            id: id.clone(),
            agent: agent.clone(),
        };
        commit_with_entries(tx, vec![event], now).await?;
        self.settle_entries().await;
        self.bus.publish(id);
        Ok(())
    }

    /// Whether the approval link `token` belongs to a request its agent
    /// cancelled.
    ///
    /// # Errors
    /// Storage failures.
    pub async fn is_cancelled(&self, token: &str) -> Result<bool, RequestError> {
        Ok(sqlx::query(
            "SELECT 1 FROM requests WHERE approval_token_hash = ? AND status = 'cancelled'",
        )
        .bind(sha256_hex(token))
        .fetch_optional(&self.pool)
        .await?
        .is_some())
    }

    /// Approve the pending request behind `token` with `grant`, atomically:
    /// either the request flips to approved, the grant is stored and both
    /// are audited (with `cert_issued` for a grant holding a certificate), or
    /// nothing changes and the request stays pending. A grant's certificate
    /// reaches the agent only through the stored grant, so a certificate that
    /// could not be audited never leaves the broker.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] for an unknown token;
    /// [`RequestError::AlreadyDecided`] if the request is no longer pending,
    /// has expired or its agent was revoked; [`RequestError::Audit`] if an
    /// entry could not be written.
    pub async fn mark_approved(
        &self,
        token: &str,
        window: Window,
        grant: GrantView,
        passkey_id: &str,
    ) -> Result<(), RequestError> {
        let this = self.clone();
        let (token, passkey_id) = (token.to_owned(), passkey_id.to_owned());
        detached(async move {
            this.mark_approved_now(&token, window, grant, &passkey_id)
                .await
        })
        .await
    }

    async fn mark_approved_now(
        &self,
        token: &str,
        window: Window,
        grant: GrantView,
        passkey_id: &str,
    ) -> Result<(), RequestError> {
        let hash = sha256_hex(token);
        let now = self.clock.now();
        let window_secs = u32::try_from(window.secs())
            .map_err(|_| RequestError::Internal("window length out of range"))?;
        // The grant must span exactly the approved window.
        if grant.not_after.checked_sub(grant.not_before) != Some(i64::from(window_secs)) {
            return Err(RequestError::Internal(
                "grant validity does not match the window",
            ));
        }
        let _change = self.recorded_change.lock().await;
        // Checked here so an approval that cannot apply writes nothing; the
        // update below checks again.
        let Some(row) = sqlx::query(
            "SELECT id, agent FROM requests \
             WHERE approval_token_hash = ?1 AND status = 'pending' AND expires_at > ?2 \
             AND EXISTS (SELECT 1 FROM agents \
                         WHERE agents.name = requests.agent AND agents.revoked_at IS NULL)",
        )
        .bind(&hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?
        else {
            return Err(self.not_pending(&hash).await);
        };
        let id: Id = parse(&row, "id")?;
        let agent: AgentName = parse(&row, "agent")?;
        let view = serde_json::to_string(&grant)?;
        let mut events = vec![AuditEvent::Approved {
            id: id.clone(),
            grant_id: grant.grant_id.clone(),
            window_secs,
            passkey_id: passkey_id.to_owned(),
        }];
        if matches!(grant.access, GrantAccess::Ssh(_)) {
            events.push(AuditEvent::CertIssued {
                key_id: ssh_ca::key_id(&agent, &grant.grant_id),
                grant_id: grant.grant_id.clone(),
                not_after: grant.not_after,
            });
        }
        let transition = format!("approval of request {id}");
        record(&self.audit, events, &transition).await?;
        let applied = async {
            let mut tx = begin(&self.pool).await?;
            // The time again: writing the log may have taken long. The token again
            // too: a link that was replaced approves nothing.
            let approved = sqlx::query(
                "UPDATE requests SET status = 'approved', decided_at = ?1 \
                 WHERE id = ?2 AND approval_token_hash = ?3 \
                 AND status = 'pending' AND expires_at > ?1 \
                 AND EXISTS (SELECT 1 FROM agents \
                             WHERE agents.name = requests.agent AND agents.revoked_at IS NULL)",
            )
            .bind(self.clock.now())
            .bind(id.as_str())
            .bind(&hash)
            .execute(&mut *tx)
            .await?;
            if approved.rows_affected() == 0 {
                return Err(RequestError::AlreadyDecided);
            }
            sqlx::query(
                "INSERT INTO grants \
                 (id, request_id, agent, window_secs, not_before, not_after, view) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(grant.grant_id.as_str())
            .bind(id.as_str())
            .bind(agent.as_str())
            .bind(window_secs)
            .bind(grant.not_before)
            .bind(grant.not_after)
            .bind(&view)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(())
        }
        .await;
        note_if_not_applied(&self.audit, &applied, &transition).await;
        applied?;
        self.bus.publish(&id);
        Ok(())
    }

    /// Why a token matched no pending request.
    async fn not_pending(&self, hash: &str) -> RequestError {
        match sqlx::query("SELECT 1 FROM requests WHERE approval_token_hash = ?")
            .bind(hash)
            .fetch_optional(&self.pool)
            .await
        {
            Ok(Some(_)) => RequestError::AlreadyDecided,
            Ok(None) => RequestError::NotFound,
            Err(e) => e.into(),
        }
    }

    /// End a grant now, whatever state the audit log is in: if its entry cannot
    /// be written, the owner is told and this returns [`AuditOutcome::Missing`].
    /// Revoking an already revoked grant changes nothing, and reports the same.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if no such grant exists; storage failures,
    /// which mean the grant was not revoked.
    pub async fn revoke_grant(
        &self,
        grant_id: &Id,
        by: &str,
    ) -> Result<AuditOutcome, RequestError> {
        let this = self.clone();
        let (grant_id, by) = (grant_id.clone(), by.to_owned());
        detached(async move { this.revoke_grant_now(&grant_id, &by).await }).await
    }

    async fn revoke_grant_now(
        &self,
        grant_id: &Id,
        by: &str,
    ) -> Result<AuditOutcome, RequestError> {
        let now = self.clock.now();
        let mut tx = begin(&self.pool).await?;
        let Some(row) = sqlx::query(
            "UPDATE grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL \
             RETURNING request_id",
        )
        .bind(now)
        .bind(grant_id.as_str())
        .fetch_optional(&mut *tx)
        .await?
        else {
            let exists = sqlx::query("SELECT 1 FROM grants WHERE id = ?")
                .bind(grant_id.as_str())
                .fetch_optional(&mut *tx)
                .await?;
            // Revoked already, perhaps by another process: its sessions and
            // calls end now rather than at their next check.
            drop(tx);
            exists.ok_or(RequestError::NotFound)?;
            self.sessions.revoke_grant(grant_id);
            self.proxy_calls.revoke_grant(grant_id);
            return Ok(self.settle_entries().await);
        };
        let request_id: Id = parse(&row, "request_id")?;
        sqlx::query("UPDATE requests SET status = 'revoked' WHERE id = ? AND status = 'approved'")
            .bind(request_id.as_str())
            .execute(&mut *tx)
            .await?;
        let revoked = AuditEvent::GrantRevoked {
            grant_id: grant_id.clone(),
            by: by.to_owned(),
        };
        commit_with_entries(tx, vec![revoked], now).await?;
        self.sessions.revoke_grant(grant_id);
        self.proxy_calls.revoke_grant(grant_id);
        let outcome = self.settle_entries().await;
        self.bus.publish(&request_id);
        if outcome == AuditOutcome::Missing {
            self.tell_owner_unaudited(format!("Revoking grant {grant_id}"));
        }
        Ok(outcome)
    }

    /// Revoke an agent and everything it holds, whatever state the audit log is
    /// in (the owner is told if its entries cannot be written); see
    /// [`revoke_agent`].
    ///
    /// # Errors
    /// [`RequestError::UnknownAgent`] or storage failures.
    pub async fn revoke_agent(&self, name: &AgentName) -> Result<AuditOutcome, RequestError> {
        let this = self.clone();
        let name = name.clone();
        detached(async move {
            let affected = revoke_agent(&this.pool, &name, this.clock.now()).await?;
            this.sessions.revoke_agent(&name);
            this.proxy_calls.revoke_agent(&name);
            let outcome = this.settle_entries().await;
            for id in &affected {
                this.bus.publish(id);
            }
            if outcome == AuditOutcome::Missing {
                this.tell_owner_unaudited(format!("Revoking agent {name}"));
            }
            Ok(outcome)
        })
        .await
    }

    /// The most recent `limit` requests, newest first, for the owner's
    /// read-only history.
    ///
    /// # Errors
    /// Storage failures or unreadable stored rows.
    pub async fn history(&self, limit: u32) -> Result<Vec<HistoryEntry>, RequestError> {
        let rows = sqlx::query(
            "SELECT r.id, r.agent, r.fingerprint, r.body, r.status, r.created_at, g.window_secs \
             FROM requests r LEFT JOIN grants g ON g.request_id = r.id \
             ORDER BY r.created_at DESC, r.rowid DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let body: String = row.try_get("body")?;
                Ok(HistoryEntry {
                    id: parse(row, "id")?,
                    agent: parse(row, "agent")?,
                    fingerprint: parse(row, "fingerprint")?,
                    request: serde_json::from_str(&body)?,
                    status: row.try_get("status")?,
                    created_at: row.try_get("created_at")?,
                    granted_secs: row.try_get("window_secs")?,
                })
            })
            .collect()
    }

    /// Grants that are neither revoked nor expired, soonest expiry first.
    ///
    /// # Errors
    /// Storage failures or unreadable stored rows.
    pub async fn active_grants(&self) -> Result<Vec<ActiveGrant>, RequestError> {
        let rows = sqlx::query(
            "SELECT g.id, g.agent, g.not_before, g.not_after, g.view, r.body, r.fingerprint \
             FROM grants g JOIN requests r ON r.id = g.request_id \
             WHERE g.revoked_at IS NULL AND g.not_after > ? ORDER BY g.not_after, g.id",
        )
        .bind(self.clock.now())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let body: String = row.try_get("body")?;
                let view: String = row.try_get("view")?;
                let view: GrantView = serde_json::from_str(&view)?;
                Ok(ActiveGrant {
                    grant_id: parse(row, "id")?,
                    agent: parse(row, "agent")?,
                    fingerprint: parse(row, "fingerprint")?,
                    request: serde_json::from_str(&body)?,
                    access: view.access,
                    not_before: row.try_get("not_before")?,
                    not_after: row.try_get("not_after")?,
                })
            })
            .collect()
    }

    /// The usable grants (neither revoked nor expired) of `agent`, soonest
    /// expiry first.
    ///
    /// # Errors
    /// Storage failures or unreadable stored rows.
    pub async fn grants_for(&self, agent: &AgentName) -> Result<Vec<GrantView>, RequestError> {
        let rows = sqlx::query(
            "SELECT view FROM grants WHERE agent = ? AND revoked_at IS NULL AND not_after > ? \
             ORDER BY not_after, id",
        )
        .bind(agent.as_str())
        .bind(self.clock.now())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let view: String = row.try_get("view")?;
                Ok(serde_json::from_str(&view)?)
            })
            .collect()
    }

    /// Grant `grant_id` of `agent` as approved, whatever its state, and
    /// whether it was revoked. Whether it expired is the caller's check
    /// against `not_after`.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if the grant does not exist or belongs to
    /// another agent; storage failures or an unreadable stored grant.
    pub async fn agent_grant(
        &self,
        agent: &AgentName,
        grant_id: &Id,
    ) -> Result<(GrantView, bool), RequestError> {
        let row = sqlx::query("SELECT view, revoked_at FROM grants WHERE id = ? AND agent = ?")
            .bind(grant_id.as_str())
            .bind(agent.as_str())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(RequestError::NotFound)?;
        let view: String = row.try_get("view")?;
        let revoked_at: Option<i64> = row.try_get("revoked_at")?;
        Ok((serde_json::from_str(&view)?, revoked_at.is_some()))
    }

    /// The active (neither revoked nor expired) relay grant for `target`
    /// whose approved request bound `public_key`, if there is one: the relay
    /// admits an agent offering that key for that target. Keys are compared
    /// by key data, so comments do not matter. If several match, the one
    /// lasting longest is returned.
    ///
    /// # Errors
    /// Storage failures or unreadable stored rows.
    pub async fn active_relay_grant(
        &self,
        target: &TargetName,
        public_key: &ssh_key::PublicKey,
    ) -> Result<Option<RelayGrantRecord>, RequestError> {
        let rows = sqlx::query(ACTIVE_RELAY_GRANTS)
            .bind(self.clock.now())
            .bind(target.as_str())
            .fetch_all(&self.pool)
            .await?;
        for row in &rows {
            let body: String = row.try_get("body")?;
            let request: CreateRequest = serde_json::from_str(&body)?;
            let Access::Ssh {
                public_key: bound, ..
            } = &request.access
            else {
                return Err(RequestError::Corrupt(
                    "relay grant for a non-SSH request".to_owned(),
                ));
            };
            let bound = ssh_key::PublicKey::from_openssh(bound)
                .map_err(|e| RequestError::Corrupt(format!("bound public key: {e}")))?;
            if bound.key_data() != public_key.key_data() {
                continue;
            }
            let view: String = row.try_get("view")?;
            let view: GrantView = serde_json::from_str(&view)?;
            let GrantAccess::Relay(grant) = view.access else {
                return Err(RequestError::Corrupt("relay grant changed kind".to_owned()));
            };
            if grant.target != *target {
                return Err(RequestError::Corrupt(
                    "relay grant changed target".to_owned(),
                ));
            }
            return Ok(Some(RelayGrantRecord {
                grant_id: parse(row, "id")?,
                agent: parse(row, "agent")?,
                target: grant.target,
                user: grant.user,
                destination_digest: grant.digest,
                not_after: row.try_get("not_after")?,
            }));
        }
        Ok(None)
    }

    /// End a grant on behalf of the agent that holds it, as
    /// [`Requests::revoke_grant`] does. Revoking an already revoked grant does
    /// nothing.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if the grant does not exist or belongs to
    /// another agent; storage failures.
    pub async fn revoke_agent_grant(
        &self,
        agent: &AgentName,
        grant_id: &Id,
    ) -> Result<AuditOutcome, RequestError> {
        sqlx::query("SELECT 1 FROM grants WHERE id = ? AND agent = ?")
            .bind(grant_id.as_str())
            .bind(agent.as_str())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(RequestError::NotFound)?;
        self.revoke_grant(grant_id, &format!("agent:{agent}")).await
    }

    /// Expire every pending request past its deadline.
    ///
    /// # Errors
    /// Storage or audit failures.
    pub async fn sweep_expired(&self) -> Result<u64, RequestError> {
        let expired = self.expire_due(Scope::All).await?;
        u64::try_from(expired.len()).map_err(|_| RequestError::Internal("count out of range"))
    }

    /// Forget the nonces of signed requests whose retention has ended (see
    /// [`crate::signed::NONCE_RETENTION_SECS`]).
    ///
    /// # Errors
    /// Storage failures.
    pub async fn sweep_nonces(&self) -> Result<u64, RequestError> {
        Ok(crate::signed::sweep_nonces(&self.pool, self.clock.now()).await?)
    }

    async fn expire_due(&self, scope: Scope) -> Result<Vec<Id>, RequestError> {
        let this = self.clone();
        detached(async move { this.expire_due_now(&scope).await }).await
    }

    async fn expire_due_now(&self, scope: &Scope) -> Result<Vec<Id>, RequestError> {
        let now = self.clock.now();
        let mut tx = begin(&self.pool).await?;
        let query = match scope {
            Scope::All => sqlx::query(
                "UPDATE requests SET status = 'expired', decided_at = ?1 \
                 WHERE status = 'pending' AND expires_at <= ?1 RETURNING id",
            )
            .bind(now),
            Scope::Dedupe(key) => sqlx::query(
                "UPDATE requests SET status = 'expired', decided_at = ?1 \
                 WHERE status = 'pending' AND expires_at <= ?1 AND dedupe_key = ?2 RETURNING id",
            )
            .bind(now)
            .bind(key),
            Scope::Request(id) => sqlx::query(
                "UPDATE requests SET status = 'expired', decided_at = ?1 \
                 WHERE status = 'pending' AND expires_at <= ?1 AND id = ?2 RETURNING id",
            )
            .bind(now)
            .bind(id.as_str()),
        };
        let ids = query
            .fetch_all(&mut *tx)
            .await?
            .iter()
            .map(|row| parse(row, "id"))
            .collect::<Result<Vec<Id>, _>>()?;
        if ids.is_empty() {
            return Ok(ids);
        }
        let events = ids
            .iter()
            .map(|id| AuditEvent::Expired { id: id.clone() })
            .collect();
        commit_with_entries(tx, events, now).await?;
        self.settle_entries().await;
        for id in &ids {
            self.bus.publish(id);
        }
        Ok(ids)
    }
}

/// The bound key of every live SSH access: pending requests not past their
/// deadline (`pending` = 1), and requests whose grant is neither revoked nor
/// expired (`pending` = 0). `?1` is now, `?2` now minus the pending TTL. Both
/// halves read through an index (pending requests are at most
/// [`PENDING_TTL_SECS`] old; grants are found by `not_after`), so the check
/// never scans the whole history.
const LIVE_SSH_KEYS: &str = "\
    SELECT r.agent, r.body, 1 AS pending FROM requests r \
    WHERE r.created_at > ?2 AND r.status = 'pending' AND r.expires_at > ?1 \
    AND json_extract(r.body, '$.access.kind') = 'ssh' \
    UNION ALL \
    SELECT r.agent, r.body, 0 AS pending FROM grants g JOIN requests r ON r.id = g.request_id \
    WHERE g.not_after > ?1 AND g.revoked_at IS NULL \
    AND json_extract(r.body, '$.access.kind') = 'ssh'";

/// Refuse `public_key` for `agent`'s request on `target` if it is bound to
/// a live SSH access (see [`LIVE_SSH_KEYS`]) other than the agent's own
/// pending request for the same target, which is the dedupe path and is
/// left to it: each ephemeral key backs exactly one live access, so the
/// relay can attribute a key to one grant. A live grant holds its key even
/// for its own agent and target. Keys are compared by key data, so comments
/// do not matter.
///
/// # Errors
/// [`RequestError::KeyInUse`]; storage failures; [`RequestError::Corrupt`]
/// for a stored key that no longer parses.
async fn check_key_unbound(
    conn: &mut SqliteConnection,
    agent: &AgentName,
    target: &TargetName,
    public_key: &str,
    now: i64,
) -> Result<(), RequestError> {
    let offered = ssh_key::PublicKey::from_openssh(public_key).map_err(|_| {
        RequestError::Rejected("public_key must be an OpenSSH ssh-ed25519 public key".to_owned())
    })?;
    let rows = sqlx::query(LIVE_SSH_KEYS)
        .bind(now)
        .bind(now - PENDING_TTL_SECS)
        .fetch_all(&mut *conn)
        .await?;
    for row in &rows {
        let body: String = row.try_get("body")?;
        let request: CreateRequest = serde_json::from_str(&body)?;
        let Access::Ssh {
            target: bound_target,
            public_key: bound_key,
            ..
        } = &request.access
        else {
            return Err(RequestError::Corrupt(
                "ssh request without ssh access".to_owned(),
            ));
        };
        let bound_key = ssh_key::PublicKey::from_openssh(bound_key)
            .map_err(|e| RequestError::Corrupt(format!("bound public key: {e}")))?;
        if bound_key.key_data() != offered.key_data() {
            continue;
        }
        let bound_agent: AgentName = parse(row, "agent")?;
        let pending: bool = row.try_get("pending")?;
        // Only the agent's own pending request for the same target may
        // share the key: that is the dedupe path, which returns it.
        if !pending || bound_agent != *agent || bound_target != target {
            return Err(RequestError::KeyInUse);
        }
    }
    Ok(())
}

/// Revoke agent `name` at `now` in one transaction: its key stops working,
/// its pending requests end as revoked, and its active grants are revoked
/// (their requests too). Returns the ids of every affected request so a
/// running server can wake their long-polls.
///
/// This does not touch the audit log: the entries wait in the database, and the
/// caller then writes them with [`write_entries`] and reports what it could not.
///
/// When this runs in another process (the `agent revoke` admin command), the
/// server's in-process [`StatusBus`] is not told; its long-polls see
/// `revoked` on their next re-read, within the 30 s wait cap, and its relay
/// ends the agent's sessions at its next grant check (every second).
///
/// # Errors
/// [`RequestError::UnknownAgent`] if no such agent exists; storage failures
/// (nothing changes then).
pub async fn revoke_agent(
    pool: &SqlitePool,
    name: &AgentName,
    now: i64,
) -> Result<Vec<Id>, RequestError> {
    let mut tx = begin(pool).await?;
    agents::revoke(&mut *tx, name, now)
        .await
        .map_err(|e| match e {
            AgentError::Unknown => RequestError::UnknownAgent(name.clone()),
            AgentError::Db(e) => RequestError::Db(e),
            other => RequestError::Agent(other),
        })?;
    let mut affected = sqlx::query(
        "UPDATE requests SET status = 'revoked', decided_at = ?1 \
         WHERE agent = ?2 AND status = 'pending' RETURNING id",
    )
    .bind(now)
    .bind(name.as_str())
    .fetch_all(&mut *tx)
    .await?
    .iter()
    .map(|row| parse(row, "id"))
    .collect::<Result<Vec<Id>, _>>()?;
    let grants = sqlx::query(
        "UPDATE grants SET revoked_at = ?1 \
         WHERE agent = ?2 AND revoked_at IS NULL AND not_after > ?1 \
         RETURNING id, request_id",
    )
    .bind(now)
    .bind(name.as_str())
    .fetch_all(&mut *tx)
    .await?
    .iter()
    .map(|row| Ok((parse(row, "id")?, parse(row, "request_id")?)))
    .collect::<Result<Vec<(Id, Id)>, RequestError>>()?;
    for (_, request_id) in &grants {
        sqlx::query("UPDATE requests SET status = 'revoked' WHERE id = ? AND status = 'approved'")
            .bind(request_id.as_str())
            .execute(&mut *tx)
            .await?;
    }
    let mut events = vec![AuditEvent::AgentRevoked {
        agent: name.clone(),
    }];
    for (grant_id, request_id) in grants {
        events.push(AuditEvent::GrantRevoked {
            grant_id,
            by: AGENT_REVOKE.to_owned(),
        });
        affected.push(request_id);
    }
    commit_with_entries(tx, events, now).await?;
    Ok(affected)
}

fn to_status(row: &SqliteRow) -> Result<RequestStatus, RequestError> {
    let status: String = row.try_get("status")?;
    Ok(match status.as_str() {
        "pending" => RequestStatus::Pending,
        "approved" => {
            let view: Option<String> = row.try_get("view")?;
            let view = view
                .ok_or_else(|| RequestError::Corrupt("approved request has no grant".to_owned()))?;
            RequestStatus::Approved(serde_json::from_str(&view)?)
        }
        "denied" => RequestStatus::Denied,
        "expired" => RequestStatus::Expired,
        "cancelled" => RequestStatus::Cancelled,
        "revoked" => RequestStatus::Revoked,
        "error" => RequestStatus::Error {
            message: row
                .try_get::<Option<String>, _>("error")?
                .unwrap_or_else(|| "request failed".to_owned()),
        },
        other => return Err(RequestError::Corrupt(format!("unknown status {other}"))),
    })
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

/// The wire spelling of `window` (`15m`, `30m`, `1h`, `4h`).
#[must_use]
pub const fn window_label(window: Window) -> &'static str {
    match window {
        Window::M15 => "15m",
        Window::M30 => "30m",
        Window::H1 => "1h",
        Window::H4 => "4h",
    }
}

/// Expire due pending requests, forget expired nonces and record held-back
/// limit refusals every `every` until `shutdown` changes (or its sender is dropped). Failures are logged
/// and never end the loop.
pub async fn sweep_loop(
    requests: Requests,
    every: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                match requests.sweep_expired().await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(expired = n, "expired pending requests"),
                    Err(e) => tracing::error!(error = %e, "expiry sweep failed"),
                }
                if let Err(e) = requests.sweep_nonces().await {
                    tracing::error!(error = %e, "nonce sweep failed");
                }
                requests.flush_waiting_entries().await;
                // On its own task: it writes the log, which may have stalled, and
                // must not hold up expiry or the waiting entries.
                let flushing = requests.clone();
                drop(tokio::spawn(async move { flushing.flush_refusals(false).await }));
            }
            // Any change, or the sender going away, means stop.
            _ = shutdown.changed() => {
                let flushed = requests.flush_refusals(true);
                if tokio::time::timeout(revocation::WRITE_WAIT, flushed).await.is_err() {
                    tracing::error!("the audit log did not take the refusal counts at shutdown");
                }
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ACTIVE_RELAY_GRANTS, ENDED_GRANTS, LIVE_SSH_KEYS};
    use crate::store;
    use sqlx::Row as _;

    /// The query plan of `sql`, one step per line.
    async fn plan(pool: &sqlx::SqlitePool, sql: &str) -> Vec<String> {
        // Test-only: `sql` is one of this module's constant queries.
        sqlx::query(sqlx::AssertSqlSafe(format!("EXPLAIN QUERY PLAN {sql}")))
            .bind(0_i64)
            .bind("x")
            .fetch_all(pool)
            .await
            .unwrap()
            .iter()
            .map(|row| row.get::<String, _>("detail"))
            .collect()
    }

    #[tokio::test]
    async fn live_access_lookups_never_scan_whole_tables() {
        let dir = tempfile::tempdir().unwrap();
        let pool = store::open(&dir.path().join("warden.db")).await.unwrap();
        let keys = plan(&pool, LIVE_SSH_KEYS).await;
        assert!(
            keys.iter()
                .any(|s| s.contains("USING INDEX requests_created_at")),
            "{keys:?}"
        );
        let grants = plan(&pool, ACTIVE_RELAY_GRANTS).await;
        for steps in [&keys, &grants] {
            assert!(
                steps
                    .iter()
                    .any(|s| s.contains("USING INDEX grants_not_after")),
                "{steps:?}"
            );
            // A bare SCAN reads every row of a table.
            assert!(
                !steps
                    .iter()
                    .any(|s| s.starts_with("SCAN ") && !s.contains("INDEX")),
                "{steps:?}"
            );
        }
        // The relay's check looks grants up by id.
        let ended = plan(&pool, ENDED_GRANTS).await;
        assert!(
            ended
                .iter()
                .any(|s| s.starts_with("SEARCH grants USING INDEX sqlite_autoindex_grants_1")),
            "{ended:?}"
        );
        assert!(
            !ended.iter().any(|s| s.starts_with("SCAN grants")),
            "{ended:?}"
        );
    }

    #[tokio::test]
    async fn ended_grants_are_the_listed_revoked_or_expired_ones() {
        let dir = tempfile::tempdir().unwrap();
        let pool = store::open(&dir.path().join("warden.db")).await.unwrap();
        let mut conn = pool.acquire().await.unwrap();
        // Bare grant rows: their requests and agents do not matter here.
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&mut *conn)
            .await
            .unwrap();
        for (id, not_after, revoked_at) in [
            ("live", 1000, None),
            ("revoked", 1000, Some(500)),
            ("expired", 1000, None),
            ("both", 900, Some(800)),
            ("unlisted", 900, Some(800)),
        ] {
            let not_after = if id == "expired" { 999 } else { not_after };
            sqlx::query(
                "INSERT INTO grants (id, request_id, agent, window_secs, not_before, not_after, revoked_at, view) \
                 VALUES (?, ?, 'a', 900, 0, ?, ?, '{}')",
            )
            .bind(id)
            .bind(format!("r-{id}"))
            .bind(not_after)
            .bind(revoked_at)
            .execute(&mut *conn)
            .await
            .unwrap();
        }
        let mut ended: Vec<(String, bool)> = sqlx::query(ENDED_GRANTS)
            .bind(999_i64)
            .bind(r#"["live","revoked","expired","both","missing"]"#)
            .fetch_all(&mut *conn)
            .await
            .unwrap()
            .iter()
            .map(|row| (row.get("id"), row.get("revoked")))
            .collect();
        ended.sort();
        assert_eq!(
            ended,
            [
                ("both".to_owned(), true),
                ("expired".to_owned(), false),
                ("revoked".to_owned(), true),
            ]
        );
    }
}
