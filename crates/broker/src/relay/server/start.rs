//! Starting a session: the checks made again before it starts, the onward
//! connection, and recording its refusal or end.

use std::sync::atomic::Ordering;

use tokio::sync::watch;
use warden_broker_proto::Id;

use crate::audit::{AuditEvent, AuditLog};
use crate::policy::{PolicyError, RelayCredential, SshMode, SshTarget};
use crate::requests::GrantEnd;

use crate::relay::onward;
use crate::relay::session::{self, Outcome, Program, PtyRequest, Registration};

use super::conn::stopping;
use super::grant_check::grant_query;
use super::handler::Login;
use super::{
    GRANT_LOOKUP_FAILED, GRANT_QUERY_TIMEOUT, NO_LONGER_VALID, NOT_A_RELAY_TARGET, SHUTTING_DOWN,
    Shared, TARGET_READ_TIMEOUT, UNAVAILABLE, UNRECORDED,
};

/// Record that a session ended.
pub(super) async fn record_end(audit: &AuditLog, grant_id: &Id, outcome: &Outcome) {
    tracing::info!(grant = %grant_id, reason = outcome.reason, "relay: session ended");
    let event = AuditEvent::RelaySessionEnded {
        grant_id: grant_id.clone(),
        reason: outcome.reason.to_owned(),
        bytes_to_target: outcome.bytes_to_target,
        bytes_from_target: outcome.bytes_from_target,
        exit_status: outcome.exit_status,
    };
    if let Err(e) = audit.append(event).await {
        tracing::error!(grant = %grant_id, error = %e, "relay: could not record a session end");
    }
}

/// Record that a session was refused for `reason`, and give the agent
/// `message`.
pub(super) async fn refuse_session(
    shared: &Shared,
    grant_id: &Id,
    reason: &str,
    message: &'static str,
) -> &'static str {
    tracing::warn!(grant = %grant_id, reason, "relay: session refused");
    let event = AuditEvent::RelaySessionRefused {
        grant_id: grant_id.clone(),
        reason: reason.to_owned(),
    };
    if let Err(e) = shared.audit.append(event).await {
        tracing::error!(grant = %grant_id, error = %e, "relay: could not record a refused session");
    }
    message
}

/// Why a session may not start: the reason on record and the message for
/// the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Refusal {
    reason: &'static str,
    message: &'static str,
}

impl Refusal {
    pub(super) const fn new(reason: &'static str, message: &'static str) -> Self {
        Self { reason, message }
    }
}

/// Check, before anything is recorded, that `login`'s grant is still active
/// and that its target is still the relay destination the owner approved
/// (address, port and pinned host keys, by digest) with the approved user
/// allowed; return the target's policy and onward credential, from one read
/// of its item. The grant lookup is bounded by [`GRANT_QUERY_TIMEOUT`] and
/// the read by [`TARGET_READ_TIMEOUT`].
async fn check_session(
    shared: &Shared,
    login: &Login,
) -> Result<(SshTarget, RelayCredential), Refusal> {
    let grant = &login.grant;
    // The grant may have been revoked or expired since login.
    let lookup = shared
        .requests
        .active_relay_grant(&grant.target, &login.key);
    match tokio::time::timeout(GRANT_QUERY_TIMEOUT, lookup).await {
        Ok(Ok(Some(now))) if now.grant_id == grant.grant_id => {}
        Ok(Ok(_)) => return Err(Refusal::new("grant no longer active", NO_LONGER_VALID)),
        Ok(Err(e)) => {
            tracing::error!(grant = %grant.grant_id, error = %e, "relay: grant lookup failed");
            return Err(GRANT_LOOKUP_FAILED);
        }
        Err(_) => {
            tracing::error!(grant = %grant.grant_id, timeout = ?GRANT_QUERY_TIMEOUT, "relay: grant lookup timed out");
            return Err(GRANT_LOOKUP_FAILED);
        }
    }
    // The policy and the credential, in one read.
    let read = shared.backend.relay_target_with_credential(&grant.target);
    let (target, credential) = match tokio::time::timeout(TARGET_READ_TIMEOUT, read).await {
        Ok(Ok(read)) => read,
        Ok(Err(PolicyError::Invalid { field, .. })) if field == "mode" => {
            return Err(NOT_A_RELAY_TARGET);
        }
        Ok(Err(PolicyError::NotFound(_))) => {
            return Err(Refusal::new("target no longer exists", NO_LONGER_VALID));
        }
        Ok(Err(PolicyError::Unavailable(detail))) => {
            tracing::error!(grant = %grant.grant_id, detail, "relay: secret backend unavailable");
            return Err(Refusal::new("secret backend unavailable", UNAVAILABLE));
        }
        Ok(Err(e)) => {
            tracing::warn!(grant = %grant.grant_id, error = %e, "relay: target policy invalid");
            return Err(Refusal::new("target policy invalid", NO_LONGER_VALID));
        }
        Err(_) => {
            tracing::error!(grant = %grant.grant_id, timeout = ?TARGET_READ_TIMEOUT, "relay: target lookup timed out");
            return Err(Refusal::new("target lookup failed", UNAVAILABLE));
        }
    };
    if target.mode != SshMode::Relay {
        return Err(NOT_A_RELAY_TARGET);
    }
    if !target.users.contains(&grant.user) {
        return Err(Refusal::new(
            "user no longer allowed on the target",
            NO_LONGER_VALID,
        ));
    }
    // The relay connects only where the owner approved: same address and
    // port, same pinned host keys. A rotated credential alone is fine.
    if target.destination_digest() != grant.destination_digest {
        return Err(Refusal::new("target policy changed", NO_LONGER_VALID));
    }
    Ok((target, credential))
}

/// Everything between the agent's `shell`/`exec` and a running session on
/// the target. Returns the message for the agent on failure.
///
/// A stop, revocation or expiry ends it at any point: while the session is
/// checked (nothing recorded yet) it is refused, on record; once its start
/// is recorded, its end is.
pub(super) async fn open_target(
    shared: &Shared,
    login: &Login,
    pty: Option<&PtyRequest>,
    env: &[(String, String)],
    program: &Program,
    stop: &mut watch::Receiver<bool>,
    live: &mut Registration,
) -> Result<onward::Started, &'static str> {
    let grant = &login.grant;
    let refuse =
        |refusal: Refusal| refuse_session(shared, &grant.grant_id, refusal.reason, refusal.message);
    // Failed closed: no grant can be told revoked, so none is used.
    if shared.grant_state_lost.load(Ordering::Acquire) {
        return Err(refuse(Refusal::new(
            session::reason::GRANT_STATE_UNAVAILABLE,
            session::reason::GRANT_STATE_NOTICE,
        ))
        .await);
    }
    // Neither a slow database nor a slow secret backend holds up a stop,
    // a revocation or an expiry.
    let checked = tokio::select! {
        checked = check_session(shared, login) => checked,
        () = stopping(stop) => Err(Refusal::new(session::reason::SHUTDOWN, SHUTTING_DOWN)),
        ending = live.ended() => Err(Refusal::new(
            ending,
            session::reason::notice(ending).unwrap_or(NO_LONGER_VALID),
        )),
    };
    let (target, credential) = match checked {
        Ok(checked) => checked,
        Err(refusal) => return Err(refuse(refusal).await),
    };
    // Pre-flight: on record before any byte reaches the target.
    let started = AuditEvent::RelaySessionStarted {
        grant_id: grant.grant_id.clone(),
        target: grant.target.clone(),
        user: grant.user.clone(),
        command: program.audited(),
    };
    if let Err(e) = shared.audit.append(started).await {
        tracing::error!(grant = %grant.grant_id, error = %e, "relay: could not record a session start; not starting it");
        return Err(UNRECORDED);
    }
    let ended_early = |reason: &'static str| async move {
        let outcome = Outcome {
            reason,
            bytes_to_target: 0,
            bytes_from_target: 0,
            exit_status: None,
        };
        record_end(&shared.audit, &grant.grant_id, &outcome).await;
    };
    // Writing the log can take long, and a revocation does not wait for it: the
    // grant may have ended meanwhile, and then nothing reaches the target.
    let ended = grant_query(shared.requests.clone(), vec![grant.grant_id.clone()]).await;
    let ending = match ended {
        Ok(ended) => ended.first().map(|(_, end)| match end {
            GrantEnd::Revoked => session::reason::REVOKED,
            GrantEnd::Expired => session::reason::EXPIRED,
        }),
        Err(_) => Some(session::reason::GRANT_STATE_UNAVAILABLE),
    };
    if let Some(ending) = ending {
        ended_early(ending).await;
        return Err(session::reason::notice(ending).unwrap_or(NO_LONGER_VALID));
    }
    let timeout = shared.limits.onward_timeout;
    let onward = async {
        onward::connect(&target, &grant.user, credential, timeout)
            .await?
            .start(pty, env, program, timeout)
            .await
    };
    // A stopping relay does not wait for a slow target: the session ends
    // now, on record, and dropping the attempt closes its connection.
    tokio::select! {
        opened = onward => match opened {
            Ok(started) => Ok(started),
            Err(e) => {
                ended_early(e.audit_reason()).await;
                Err(e.message())
            }
        },
        () = stopping(stop) => {
            ended_early(session::reason::SHUTDOWN).await;
            Err(SHUTTING_DOWN)
        }
        // Revoked or expired while connecting: ended the same way.
        ending = live.ended() => {
            ended_early(ending).await;
            Err(session::reason::notice(ending).unwrap_or(NO_LONGER_VALID))
        }
    }
}
