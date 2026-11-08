//! Creating a request: policy checks, the key binding and limit checks, the
//! pending row and the owner's notification.

use std::sync::Arc;

use sqlx::{Row as _, SqliteConnection};
use url::Url;
use warden_broker_proto::{
    Access, AgentName, CreateRequest, CreatedResponse, Id, TargetName, fingerprint,
};

use super::revocation::commit_with_entries;
use super::transition::detached;
use super::{
    PENDING_TTL_SECS, RELAY_NOT_CONFIGURED, RequestError, Requests, Scope, approval_token, begin,
    check_ed25519, check_window, commit_signing, limits, note_if_not_applied, parse, record,
    sha256_hex, window_label,
};
use crate::audit::AuditEvent;
use crate::notify::{Doorbell, doorbell};
use crate::policy::SshMode;

/// Attempts to claim the pending slot when racing other creates.
const INSERT_ATTEMPTS: usize = 3;

impl Requests {
    /// Validate `req` against policy, store it and notify the owner in the
    /// background. A duplicate of the agent's pending request for the same
    /// target (or secret) and kind returns that request instead, whatever
    /// the agent's limits.
    ///
    /// # Errors
    /// [`RequestError::Limited`] if the agent is over its [`RequestLimits`](crate::requests::RequestLimits),
    /// [`RequestError::Rejected`] for policy violations, or a link to a host
    /// that is not in [`LinkHosts`](crate::requests::LinkHosts),
    /// [`RequestError::KeyInUse`] if the SSH public key backs another live
    /// request or grant, the target or secret errors from the backend,
    /// [`RequestError::AgentRevoked`], or storage failures. No row is stored
    /// and nobody is notified on error.
    pub async fn create(
        &self,
        agent: &AgentName,
        req: CreateRequest,
    ) -> Result<CreatedResponse, RequestError> {
        self.link_hosts.check(req.link.as_ref())?;
        let (dedupe_key, subject) = self.check_against_policy(agent, &req).await?;
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

    /// Check `req` of `agent` against the policy as it is now. Returns its dedupe
    /// slot, and what it asks for in the owner's notification.
    async fn check_against_policy(
        &self,
        agent: &AgentName,
        req: &CreateRequest,
    ) -> Result<(String, String), RequestError> {
        Ok(match &req.access {
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
            Access::CommitSigning {} => {
                // Does not read the key: any enrolled agent can get this far.
                if !self.backend.has_commit_signing_key().await? {
                    return Err(RequestError::Rejected(
                        warden_broker_proto::commit_signing::NOT_CONFIGURED.to_owned(),
                    ));
                }
                commit_signing::check_window(req.window, self.commit_signing_max)
                    .map_err(RequestError::Rejected)?;
                (
                    format!("{agent}|commit_signing"),
                    "commit signing".to_owned(),
                )
            }
        })
    }

    pub(super) async fn insert(
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
            session: req.session.as_ref().map(ToString::to_string),
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

    pub(super) async fn pending_in_slot(
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

    pub(super) fn approval_link(&self, token: &str) -> Result<Url, RequestError> {
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
}

/// The bound key of every live SSH access: pending requests not past their
/// deadline (`pending` = 1), and requests whose grant is neither revoked nor
/// expired (`pending` = 0). `?1` is now, `?2` now minus the pending TTL. Both
/// halves read through an index (pending requests are at most
/// [`PENDING_TTL_SECS`] old; grants are found by `not_after`), so the check
/// never scans the whole history.
pub(super) const LIVE_SSH_KEYS: &str = "\
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
