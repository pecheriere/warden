//! Request lifecycle: creation with policy checks, owner notification,
//! long-poll status, decisions, expiry and revocation.
//!
//! Every state change runs to completion on its own task (dropping the caller
//! cannot interrupt it) in one `BEGIN IMMEDIATE` transaction whose audit
//! entry is appended before the commit, so the audit trail never misses a
//! transition (a failed commit can at worst leave an entry for a change that
//! did not happen). After the commit the affected request ids are published
//! on the [`StatusBus`] so long-polls wake up.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row as _, Sqlite, SqlitePool, Transaction};
use tokio::sync::broadcast;
use url::Url;
use warden_broker_proto::{
    Access, AgentName, CreateRequest, CreatedResponse, Fingerprint, GrantAccess, GrantView, Id,
    RequestStatus, Window, fingerprint,
};

use crate::agents::{self, AgentError};
use crate::audit::{AuditError, AuditEvent, AuditLog};
use crate::notify::{Doorbell, Notifier, doorbell};
use crate::policy::{ApiSecretPolicy, PolicyError, SecretBackend, SshMode, SshTarget};

/// How long a request waits for the owner, in seconds.
const PENDING_TTL_SECS: i64 = 600;

/// Longest a status long-poll may wait.
const MAX_WAIT: Duration = Duration::from_secs(30);

/// Messages a slow long-poll may fall behind before it re-reads.
const BUS_CAPACITY: usize = 256;

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

/// Broadcasts the id of every request whose state may have changed; a
/// receiver re-reads the request to learn what happened.
#[derive(Debug, Clone)]
pub struct StatusBus {
    tx: broadcast::Sender<Id>,
}

impl StatusBus {
    /// A bus with no subscribers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tx: broadcast::channel(BUS_CAPACITY).0,
        }
    }

    /// Receive ids published from now on.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Id> {
        self.tx.subscribe()
    }

    /// Announce that request `id` may have changed.
    pub fn publish(&self, id: &Id) {
        // An error only means nobody is listening, which is fine.
        let _ = self.tx.send(id.clone());
    }

    /// Number of live subscribers.
    #[must_use]
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for StatusBus {
    fn default() -> Self {
        Self::new()
    }
}

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
    /// Too many concurrent creates for the same slot; retry.
    #[error("request slot contended; retry")]
    Contended,
    /// An agent operation failed.
    #[error(transparent)]
    Agent(AgentError),
    /// The database failed.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// The audit log could not record the transition.
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
    /// Stored status (`pending`, `approved`, `denied`, `expired`, `revoked`, `error`).
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
    /// End of validity, Unix seconds.
    pub not_after: i64,
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
}

/// Which pending requests an expiry pass looks at.
enum Scope {
    All,
    Dedupe(String),
    Request(Id),
}

impl Requests {
    /// Build the service. Approval links are `<public_url>/approve/<token>`.
    #[must_use]
    pub fn new(
        pool: SqlitePool,
        audit: Arc<AuditLog>,
        backend: Arc<dyn SecretBackend>,
        notifier: Arc<dyn Notifier>,
        public_url: Url,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            pool,
            audit,
            backend,
            notifier,
            bus: StatusBus::new(),
            public_url,
            clock,
        }
    }

    /// The bus on which changed request ids are published.
    #[must_use]
    pub const fn bus(&self) -> &StatusBus {
        &self.bus
    }

    /// Validate `req` against policy, store it and notify the owner in the
    /// background. A duplicate of the agent's pending request for the same
    /// target (or secret) and kind returns that request instead.
    ///
    /// # Errors
    /// [`RequestError::Rejected`] for policy violations, the target or
    /// secret errors from the backend, [`RequestError::AgentRevoked`], or
    /// storage failures. No row is stored and nobody is notified on error.
    pub async fn create(
        &self,
        agent: &AgentName,
        req: CreateRequest,
    ) -> Result<CreatedResponse, RequestError> {
        let dedupe_key = match &req.access {
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
                if policy.mode != SshMode::Cert {
                    return Err(RequestError::Rejected(format!(
                        "target {target}: relay mode not supported yet"
                    )));
                }
                format!("{agent}|ssh|{target}")
            }
            Access::Api { secret } => {
                let policy = self
                    .backend
                    .api_secret(secret)
                    .await
                    .map_err(RequestError::from_secret_lookup)?;
                check_window(req.window, policy.max_window, &format!("secret {secret}"))
                    .map_err(RequestError::Rejected)?;
                format!("{agent}|api|{secret}")
            }
        };
        for _ in 0..INSERT_ATTEMPTS {
            // A stale pending row past its expiry must not hold the slot.
            self.expire_due(Scope::Dedupe(dedupe_key.clone())).await?;
            let token = approval_token()?;
            let link = self.approval_link(&token)?;
            // Insert and ring as one detached unit: a caller dropped while the
            // insert commits must not leave a pending row nobody was told about.
            let inserted = {
                let (this, agent, req, key) =
                    (self.clone(), agent.clone(), req.clone(), dedupe_key.clone());
                detached(async move {
                    let created = this.insert(&agent, &req, &key, &token).await?;
                    this.spawn_notify(created.id.clone(), doorbell(&agent, &req, link));
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
        dedupe_key: &str,
        token: &str,
    ) -> Result<CreatedResponse, RequestError> {
        let now = self.clock.now();
        let id = Id::random();
        let fp = fingerprint(agent, req);
        let mut tx = begin(&self.pool).await?;
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
        .bind(serde_json::to_string(req)?)
        .bind(sha256_hex(token))
        .bind(now)
        .bind(now + PENDING_TTL_SECS)
        .bind(agent.as_str())
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() == 0 {
            return Err(RequestError::AgentRevoked);
        }
        let subject = match &req.access {
            Access::Ssh { target, user, .. } => format!("ssh {user}@{target}"),
            Access::Api { secret } => format!("api {secret}"),
        };
        let created = AuditEvent::RequestCreated {
            id: id.clone(),
            agent: agent.clone(),
            fingerprint: fp.clone(),
            summary: format!("{subject} for {}: {}", window_label(req.window), req.goal),
        };
        audit_and_commit(
            &self.audit,
            tx,
            vec![created],
            &format!("creation of request {id}"),
        )
        .await?;
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
        let channel = self.notifier.name().to_owned();
        let result = match self.notifier.ring(bell).await {
            Ok(()) => self
                .audit
                .append(AuditEvent::Notified {
                    id: id.clone(),
                    channel,
                })
                .await
                .map_err(RequestError::from),
            Err(e) => {
                tracing::warn!(request = %id, error = %e, "owner notification failed");
                self.fail_notification(id, channel, e.to_string()).await
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
        let mut tx = begin(&self.pool).await?;
        sqlx::query(
            "UPDATE requests SET status = 'error', error = ?, decided_at = ? \
             WHERE id = ? AND status = 'pending'",
        )
        .bind(format!("could not notify the owner: {reason}"))
        .bind(self.clock.now())
        .bind(id.as_str())
        .execute(&mut *tx)
        .await?;
        let failed = AuditEvent::NotifyFailed {
            id: id.clone(),
            channel,
            reason,
        };
        audit_and_commit(
            &self.audit,
            tx,
            vec![failed],
            &format!("notification failure of request {id}"),
        )
        .await
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
        let destination = match &request.access {
            Access::Ssh { target, .. } => Destination::Ssh(self.backend.ssh_target(target).await?),
            Access::Api { secret } => Destination::Api(
                self.backend
                    .api_secret(secret)
                    .await
                    .map_err(RequestError::from_secret_lookup)?,
            ),
        };
        Ok(PendingView {
            id: parse(&row, "id")?,
            agent: parse(&row, "agent")?,
            fingerprint: parse(&row, "fingerprint")?,
            destination,
            expires_at: row.try_get("expires_at")?,
            request,
        })
    }

    /// Deny the pending request behind `token`.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] for an unknown token,
    /// [`RequestError::AlreadyDecided`] if it is no longer pending.
    pub async fn deny(&self, token: &str) -> Result<(), RequestError> {
        let this = self.clone();
        let token = token.to_owned();
        detached(async move { this.deny_now(&token).await }).await
    }

    async fn deny_now(&self, token: &str) -> Result<(), RequestError> {
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
        let denied = AuditEvent::Denied { id: id.clone() };
        audit_and_commit(
            &self.audit,
            tx,
            vec![denied],
            &format!("denial of request {id}"),
        )
        .await?;
        self.bus.publish(&id);
        Ok(())
    }

    /// Approve the pending request behind `token` with `grant`, atomically:
    /// either the request flips to approved and the grant is stored, or
    /// nothing changes.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] for an unknown token;
    /// [`RequestError::AlreadyDecided`] if the request is no longer pending,
    /// has expired or its agent was revoked.
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
        let mut tx = begin(&self.pool).await?;
        let Some(row) = sqlx::query(
            "UPDATE requests SET status = 'approved', decided_at = ?1 \
             WHERE approval_token_hash = ?2 AND status = 'pending' AND expires_at > ?1 \
             AND EXISTS (SELECT 1 FROM agents \
                         WHERE agents.name = requests.agent AND agents.revoked_at IS NULL) \
             RETURNING id, agent",
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
        let agent: String = row.try_get("agent")?;
        sqlx::query(
            "INSERT INTO grants (id, request_id, agent, window_secs, not_before, not_after, view) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(grant.grant_id.as_str())
        .bind(id.as_str())
        .bind(agent)
        .bind(window_secs)
        .bind(grant.not_before)
        .bind(grant.not_after)
        .bind(serde_json::to_string(&grant)?)
        .execute(&mut *tx)
        .await?;
        let approved = AuditEvent::Approved {
            id: id.clone(),
            grant_id: grant.grant_id,
            window_secs,
            passkey_id: passkey_id.to_owned(),
        };
        audit_and_commit(
            &self.audit,
            tx,
            vec![approved],
            &format!("approval of request {id}"),
        )
        .await?;
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

    /// End a grant now. Revoking an already revoked grant does nothing.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if no such grant exists.
    pub async fn revoke_grant(&self, grant_id: &Id, by: &str) -> Result<(), RequestError> {
        let this = self.clone();
        let (grant_id, by) = (grant_id.clone(), by.to_owned());
        detached(async move { this.revoke_grant_now(&grant_id, &by).await }).await
    }

    async fn revoke_grant_now(&self, grant_id: &Id, by: &str) -> Result<(), RequestError> {
        let mut tx = begin(&self.pool).await?;
        let Some(row) = sqlx::query(
            "UPDATE grants SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL \
             RETURNING request_id",
        )
        .bind(self.clock.now())
        .bind(grant_id.as_str())
        .fetch_optional(&mut *tx)
        .await?
        else {
            let exists = sqlx::query("SELECT 1 FROM grants WHERE id = ?")
                .bind(grant_id.as_str())
                .fetch_optional(&mut *tx)
                .await?;
            return exists.map(|_| ()).ok_or(RequestError::NotFound);
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
        audit_and_commit(
            &self.audit,
            tx,
            vec![revoked],
            &format!("revocation of grant {grant_id}"),
        )
        .await?;
        self.bus.publish(&request_id);
        Ok(())
    }

    /// Revoke an agent and everything it holds; see [`revoke_agent`].
    ///
    /// # Errors
    /// [`RequestError::UnknownAgent`] or storage failures.
    pub async fn revoke_agent(&self, name: &AgentName) -> Result<(), RequestError> {
        let this = self.clone();
        let name = name.clone();
        detached(async move {
            let affected = revoke_agent(&this.pool, &this.audit, &name, this.clock.now()).await?;
            for id in &affected {
                this.bus.publish(id);
            }
            Ok(())
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
            "SELECT g.id, g.agent, g.not_after, g.view, r.body, r.fingerprint \
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

    /// End a grant on behalf of the agent that holds it. Revoking an already
    /// revoked grant does nothing.
    ///
    /// # Errors
    /// [`RequestError::NotFound`] if the grant does not exist or belongs to
    /// another agent; storage failures.
    pub async fn revoke_agent_grant(
        &self,
        agent: &AgentName,
        grant_id: &Id,
    ) -> Result<(), RequestError> {
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
        let listed = ids.iter().map(Id::as_str).collect::<Vec<_>>().join(", ");
        audit_and_commit(
            &self.audit,
            tx,
            events,
            &format!("expiry of request(s) {listed}"),
        )
        .await?;
        for id in &ids {
            self.bus.publish(id);
        }
        Ok(ids)
    }
}

/// Revoke agent `name` at `now` in one transaction: its key stops working,
/// its pending requests end as revoked, and its active grants are revoked
/// (their requests too). Returns the ids of every affected request so a
/// running server can wake their long-polls.
///
/// When this runs in another process (the `agent revoke` admin command), the
/// server's in-process [`StatusBus`] is not told; its long-polls see
/// `revoked` on their next re-read, within the 30 s wait cap.
///
/// # Errors
/// [`RequestError::UnknownAgent`] if no such agent exists; storage or audit
/// failures (nothing changes then).
pub async fn revoke_agent(
    pool: &SqlitePool,
    audit: &AuditLog,
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
    audit_and_commit(audit, tx, events, &format!("revocation of agent {name}")).await?;
    Ok(affected)
}

/// Record `events`, then commit `tx`.
///
/// The audit entries come first so no change ever lands unaudited. If a
/// later step fails after something was recorded (a further entry or the
/// commit), an `Error { context: "commit" }` entry states that `transition`
/// did not take effect.
pub(crate) async fn audit_and_commit(
    audit: &AuditLog,
    tx: Transaction<'static, Sqlite>,
    events: Vec<AuditEvent>,
    transition: &str,
) -> Result<(), RequestError> {
    let mut recorded = false;
    for event in events {
        if let Err(e) = audit.append(event).await {
            if recorded {
                record_not_committed(audit, transition, &e.to_string()).await;
            }
            return Err(e.into());
        }
        recorded = true;
    }
    if let Err(e) = tx.commit().await {
        record_not_committed(audit, transition, &e.to_string()).await;
        return Err(e.into());
    }
    Ok(())
}

async fn record_not_committed(audit: &AuditLog, transition: &str, cause: &str) {
    let event = AuditEvent::Error {
        context: "commit".to_owned(),
        message: format!("{transition} did not take effect: {cause}"),
    };
    if let Err(e) = audit.append(event).await {
        tracing::error!(transition, error = %e, "could not record an uncommitted transition");
    }
}

/// Run a state transition to completion on its own task, so dropping the
/// caller (for example a disconnected HTTP client) never stops it halfway.
async fn detached<T>(
    work: impl Future<Output = Result<T, RequestError>> + Send + 'static,
) -> Result<T, RequestError>
where
    T: Send + 'static,
{
    tokio::spawn(work)
        .await
        .map_err(|_| RequestError::Internal("state transition task failed"))?
}

/// Start a write transaction that takes the write lock up front, so
/// concurrent writers queue on the busy timeout instead of failing.
pub(crate) async fn begin(pool: &SqlitePool) -> Result<Transaction<'static, Sqlite>, sqlx::Error> {
    pool.begin_with("BEGIN IMMEDIATE").await
}

/// Wait for a bus message about `id`. `true` means re-read (it changed or
/// messages were missed); `false` means the bus is gone.
async fn next_change(rx: &mut broadcast::Receiver<Id>, id: &Id) -> bool {
    loop {
        match rx.recv().await {
            Ok(changed) if changed == *id => return true,
            Ok(_) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => return true,
            Err(broadcast::error::RecvError::Closed) => return false,
        }
    }
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

/// Expire due pending requests every `every` until `shutdown` changes (or
/// its sender is dropped). Failures are logged and never end the loop.
pub async fn sweep_loop(
    requests: Requests,
    every: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ticker.tick() => match requests.sweep_expired().await {
                Ok(0) => {}
                Ok(n) => tracing::info!(expired = n, "expired pending requests"),
                Err(e) => tracing::error!(error = %e, "expiry sweep failed"),
            },
            // Any change, or the sender going away, means stop.
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AuditEvent, AuditLog, RequestError, audit_and_commit, begin};
    use crate::store;
    use warden_broker_proto::Id;

    #[tokio::test]
    async fn failed_commit_is_recorded_as_not_taking_effect() {
        let dir = tempfile::tempdir().unwrap();
        let pool = store::open(&dir.path().join("warden.db")).await.unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).await.unwrap();

        // A deferred foreign-key violation makes the commit itself fail.
        let mut tx = begin(&pool).await.unwrap();
        sqlx::query("PRAGMA defer_foreign_keys = ON")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO grants (id, request_id, agent, window_secs, not_before, not_after, view) \
             VALUES ('g', 'no-such-request', 'a', 900, 0, 900, '{}')",
        )
        .execute(&mut *tx)
        .await
        .unwrap();
        let id = Id::random();
        let result = audit_and_commit(
            &audit,
            tx,
            vec![AuditEvent::Denied { id: id.clone() }],
            &format!("denial of request {id}"),
        )
        .await;
        assert!(matches!(result, Err(RequestError::Db(_))), "{result:?}");

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[0].contains(r#""type":"denied""#));
        assert!(lines[1].contains(r#""context":"commit""#), "{text}");
        assert!(
            lines[1].contains(&format!("denial of request {id} did not take effect")),
            "{text}"
        );
        assert_eq!(crate::audit::verify(&path).unwrap(), 2);
        let grants: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM grants")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(grants, 0);
    }
}
