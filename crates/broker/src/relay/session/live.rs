//! The live relay sessions, so that revocation and expiry can end them,
//! and each session's registration among them.

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::watch;
use warden_broker_proto::{AgentName, Id};

use crate::requests::RelayGrantRecord;

use super::reason;

/// The live relay sessions, so that revoking a grant or an agent, and a
/// grant's expiry, end them at once. Shared by the relay and the request
/// service (whose revocations tell it directly); revocations made by
/// another process and expiry are found by the relay's periodic check.
#[derive(Debug, Default)]
pub(crate) struct LiveSessions {
    entries: Mutex<BTreeMap<u64, LiveSession>>,
    next: AtomicU64,
}

#[derive(Debug)]
struct LiveSession {
    grant_id: Id,
    agent: AgentName,
    not_after: i64,
    /// Unix seconds when the session was listed.
    started_at: i64,
    /// Data bytes delivered to the target and to the agent so far, shared
    /// with the relay loop that counts them.
    bytes_to_target: Arc<AtomicU64>,
    bytes_from_target: Arc<AtomicU64>,
    /// Unix seconds when bytes last moved either way (when the session was
    /// listed, until they do), shared with the session's watchdog.
    last_activity: Arc<AtomicI64>,
    /// Why the relay must end the session, once it must.
    end: watch::Sender<Option<&'static str>>,
}

impl LiveSession {
    /// Tell the session to end for `reason`; the first reason given stands.
    fn end(&self, reason: &'static str) {
        self.end.send_if_modified(|ending| {
            if ending.is_some() {
                return false;
            }
            *ending = Some(reason);
            true
        });
    }
}

/// What a live session looks like from outside: for display only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveSessionInfo {
    pub grant_id: Id,
    /// Unix seconds.
    pub started_at: i64,
    pub bytes_to_target: u64,
    pub bytes_from_target: u64,
    /// Unix seconds when bytes last moved either way, as seen by the
    /// session's watchdog; when the session started, until they do.
    pub last_activity: i64,
}

impl LiveSessions {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Add a session of `grant` that started at `now` (Unix seconds); it is
    /// listed until the registration is dropped.
    pub(crate) fn register(self: &Arc<Self>, grant: &RelayGrantRecord, now: i64) -> Registration {
        let (end, ended) = watch::channel(None);
        let (bytes_to_target, bytes_from_target) =
            (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let last_activity = Arc::new(AtomicI64::new(now));
        let key = self.next.fetch_add(1, Ordering::Relaxed);
        self.lock().insert(
            key,
            LiveSession {
                grant_id: grant.grant_id.clone(),
                agent: grant.agent.clone(),
                not_after: grant.not_after,
                started_at: now,
                bytes_to_target: Arc::clone(&bytes_to_target),
                bytes_from_target: Arc::clone(&bytes_from_target),
                last_activity: Arc::clone(&last_activity),
                end,
            },
        );
        Registration {
            sessions: Arc::clone(self),
            key,
            ended,
            bytes_to_target,
            bytes_from_target,
            last_activity,
        }
    }

    /// End the sessions of grant `grant_id`: it was revoked.
    pub(crate) fn revoke_grant(&self, grant_id: &Id) {
        self.end_where(|s| s.grant_id == *grant_id, reason::REVOKED);
    }

    /// End the sessions of every grant of `agent`: it was revoked.
    pub(crate) fn revoke_agent(&self, agent: &AgentName) {
        self.end_where(|s| s.agent == *agent, reason::REVOKED);
    }

    /// End the sessions of grant `grant_id`: its window is over.
    pub(crate) fn expire_grant(&self, grant_id: &Id) {
        self.end_where(|s| s.grant_id == *grant_id, reason::EXPIRED);
    }

    /// End the sessions whose grant's window is over at `now` (Unix
    /// seconds), as known when they started.
    pub(crate) fn expire_due(&self, now: i64) {
        self.end_where(|s| s.not_after <= now, reason::EXPIRED);
    }

    /// End every session: the state of grants cannot be read.
    pub(crate) fn fail_closed(&self) {
        self.end_where(|_| true, reason::GRANT_STATE_UNAVAILABLE);
    }

    /// The grants with live sessions, each once.
    pub(crate) fn grant_ids(&self) -> Vec<Id> {
        self.lock()
            .values()
            .map(|s| s.grant_id.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect()
    }

    /// The live sessions as they are now, oldest first (ties by grant, then
    /// by when they were listed).
    pub(crate) fn snapshot(&self) -> Vec<LiveSessionInfo> {
        let mut sessions: Vec<_> = self
            .lock()
            .values()
            .map(|s| LiveSessionInfo {
                grant_id: s.grant_id.clone(),
                started_at: s.started_at,
                bytes_to_target: s.bytes_to_target.load(Ordering::Relaxed),
                bytes_from_target: s.bytes_from_target.load(Ordering::Relaxed),
                last_activity: s.last_activity.load(Ordering::Relaxed),
            })
            .collect();
        sessions.sort_by(|a, b| {
            (a.started_at, a.grant_id.as_str()).cmp(&(b.started_at, b.grant_id.as_str()))
        });
        sessions
    }

    fn end_where(&self, matches: impl Fn(&LiveSession) -> bool, reason: &'static str) {
        for session in self.lock().values().filter(|s| matches(s)) {
            session.end(reason);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u64, LiveSession>> {
        // Every update is a single insert or removal: a holder that
        // panicked leaves the map consistent.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A session's place in [`LiveSessions`], removed when dropped.
#[derive(Debug)]
pub(crate) struct Registration {
    sessions: Arc<LiveSessions>,
    key: u64,
    ended: watch::Receiver<Option<&'static str>>,
    bytes_to_target: Arc<AtomicU64>,
    bytes_from_target: Arc<AtomicU64>,
    pub(super) last_activity: Arc<AtomicI64>,
}

impl Registration {
    /// Resolves, with the reason, once the relay must end the session.
    pub(crate) async fn ended(&mut self) -> &'static str {
        // The sender lives in the registry entry, which outlives `self`.
        let ending = self
            .ended
            .wait_for(Option::is_some)
            .await
            .map_or(None, |ending| *ending);
        match ending {
            Some(reason) => reason,
            None => std::future::pending().await,
        }
    }

    /// The session's byte counters, to the target and from it, which the
    /// relay loop keeps current.
    pub(super) fn counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
        (
            Arc::clone(&self.bytes_to_target),
            Arc::clone(&self.bytes_from_target),
        )
    }

    /// Why the relay was told to end the session, if it was by now.
    pub(crate) fn told(&self) -> Option<&'static str> {
        *self.ended.borrow()
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.sessions.lock().remove(&self.key);
    }
}

#[cfg(test)]
mod tests;
