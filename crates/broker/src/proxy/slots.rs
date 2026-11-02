//! Concurrency limits for proxied calls: how many may be in flight at once
//! per agent and overall. Each call holds a [`CallSlot`] for as long as it
//! runs; the slot is released when it is dropped, whatever way the call
//! ends. A slot also carries what ends the call early: revoking a grant or
//! an agent tells its slots, without waiting for anything, and the call stops.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use http::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use warden_broker_proto::{AgentName, Id};

/// Why a call got no slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("too many concurrent calls")]
pub struct TooManyCalls;

/// A call in flight, as shown to the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallInfo {
    pub grant_id: Id,
    pub method: String,
    /// The URL's path, without query string or fragment (which may carry the
    /// agent's own data).
    pub path: String,
    /// Unix seconds.
    pub started_at: i64,
}

impl CallInfo {
    /// A call of `grant_id` to `path` (anything from a `?` or `#` on is
    /// dropped) that started at `started_at` (Unix seconds).
    #[must_use]
    pub fn new(grant_id: Id, method: String, mut path: String, started_at: i64) -> Self {
        path.truncate(path.find(['?', '#']).unwrap_or(path.len()));
        Self {
            grant_id,
            method,
            path,
            started_at,
        }
    }
}

/// Why a call in flight must stop before it has finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallEnd {
    /// The grant, or the agent holding it, was revoked.
    Revoked,
    /// The grant's window is over.
    Expired,
    /// The grant's state could not be read for too long, so the call fails
    /// closed.
    GrantStateUnavailable,
}

impl CallEnd {
    /// What the agent is told, and the audit's `outcome`.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Revoked => "grant revoked during the call",
            Self::Expired => "grant expired during the call",
            Self::GrantStateUnavailable => "grant state unavailable during the call",
        }
    }

    /// The status the agent gets: 409 for a grant that ended, 503 if nobody
    /// can tell.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::Revoked | Self::Expired => StatusCode::CONFLICT,
            Self::GrantStateUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// How far the upstream's answer to a call has come, for the audit entry of
/// a call that is stopped part-way. Holds counts only, never response data.
#[derive(Debug, Default)]
pub struct CallProgress {
    /// The status received, or 0 before one arrived.
    status: AtomicU16,
    bytes: AtomicU64,
}

impl CallProgress {
    /// The response's head arrived, with `status`.
    pub(crate) fn response_started(&self, status: StatusCode) {
        self.status.store(status.as_u16(), Ordering::Relaxed);
    }

    /// `bytes` more of the response's body arrived.
    pub(crate) fn received(&self, bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// The upstream's status, if its answer has started.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self.status.load(Ordering::Relaxed) {
            0 => None,
            status => Some(status),
        }
    }

    /// Bytes of the response's body received so far, before redaction.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
}

/// A call in flight, as the registry holds it.
#[derive(Debug)]
struct LiveCall {
    info: CallInfo,
    agent: AgentName,
    /// Only tests read this from the registry; the call has its own handle.
    #[cfg(feature = "testkit")]
    progress: Arc<CallProgress>,
    /// Why the call must stop, once it must.
    end: watch::Sender<Option<CallEnd>>,
}

impl LiveCall {
    /// Tell the call to stop for `end`; the first reason given stands.
    fn stop(&self, end: CallEnd) {
        self.end.send_if_modified(|ending| {
            if ending.is_some() {
                return false;
            }
            *ending = Some(end);
            true
        });
    }
}

#[derive(Debug, Default)]
struct Counts {
    total: usize,
    per_agent: HashMap<AgentName, usize>,
    calls: BTreeMap<u64, LiveCall>,
    next: u64,
}

/// The calls in flight, counted per agent and overall.
#[derive(Debug)]
pub struct CallSlots {
    max_per_agent: usize,
    max_total: usize,
    counts: Mutex<Counts>,
}

impl CallSlots {
    /// Limits of `max_per_agent` calls for one agent and `max_total` overall.
    #[must_use]
    pub fn new(max_per_agent: usize, max_total: usize) -> Arc<Self> {
        Arc::new(Self {
            max_per_agent,
            max_total,
            counts: Mutex::new(Counts::default()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Counts> {
        // The counts are updated in single steps that cannot panic, so a
        // poisoned lock still holds consistent numbers.
        self.counts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Take a slot for `call` of `agent`, without waiting; the call is
    /// listed by [`snapshot`](Self::snapshot) while the slot lives.
    ///
    /// # Errors
    ///
    /// [`TooManyCalls`] if the agent or the broker is at its limit.
    pub fn try_acquire(
        self: &Arc<Self>,
        agent: &AgentName,
        call: CallInfo,
    ) -> Result<CallSlot, TooManyCalls> {
        let mut counts = self.lock();
        if counts.total >= self.max_total {
            return Err(TooManyCalls);
        }
        match counts.per_agent.entry(agent.clone()) {
            Entry::Occupied(mut held) => {
                if *held.get() >= self.max_per_agent {
                    return Err(TooManyCalls);
                }
                *held.get_mut() += 1;
            }
            Entry::Vacant(free) => {
                free.insert(1);
            }
        }
        counts.total += 1;
        let key = counts.next;
        counts.next = counts.next.wrapping_add(1);
        let (end, ended) = watch::channel(None);
        let progress = Arc::new(CallProgress::default());
        counts.calls.insert(
            key,
            LiveCall {
                info: call,
                agent: agent.clone(),
                #[cfg(feature = "testkit")]
                progress: Arc::clone(&progress),
                end,
            },
        );
        Ok(CallSlot {
            slots: Arc::clone(self),
            agent: agent.clone(),
            key,
            ended,
            progress,
        })
    }

    /// Stop the calls of grant `grant_id`: it was revoked. Does not wait for
    /// them to stop.
    pub fn revoke_grant(&self, grant_id: &Id) {
        for call in self.lock().calls.values() {
            if call.info.grant_id == *grant_id {
                call.stop(CallEnd::Revoked);
            }
        }
    }

    /// Stop the calls of `agent`, on every grant: it was revoked. Does not
    /// wait for them to stop.
    pub fn revoke_agent(&self, agent: &AgentName) {
        for call in self.lock().calls.values() {
            if call.agent == *agent {
                call.stop(CallEnd::Revoked);
            }
        }
    }

    /// The calls in flight, oldest first (ties by grant, then by when they
    /// were admitted).
    #[must_use]
    pub fn snapshot(&self) -> Vec<CallInfo> {
        let mut calls: Vec<_> = self
            .lock()
            .calls
            .values()
            .map(|call| call.info.clone())
            .collect();
        calls.sort_by(|a, b| {
            (a.started_at, a.grant_id.as_str()).cmp(&(b.started_at, b.grant_id.as_str()))
        });
        calls
    }

    /// Response bytes received so far by all the calls in flight, for tests
    /// to wait on a response that has really started arriving.
    #[cfg(feature = "testkit")]
    #[must_use]
    pub fn response_bytes_in_flight(&self) -> u64 {
        self.lock()
            .calls
            .values()
            .map(|call| call.progress.bytes())
            .sum()
    }
}

/// A call's place among the calls in flight, released on drop.
#[derive(Debug)]
pub struct CallSlot {
    slots: Arc<CallSlots>,
    agent: AgentName,
    key: u64,
    ended: watch::Receiver<Option<CallEnd>>,
    progress: Arc<CallProgress>,
}

impl CallSlot {
    /// Resolves, with the reason, once the call must stop. The reason is
    /// kept, so a slot told before this is called still resolves at once.
    pub async fn ended(&self) -> CallEnd {
        let mut ended = self.ended.clone();
        // The sender lives in the registry entry, which this slot removes
        // only when dropped, so it outlives the wait.
        let ending = ended
            .wait_for(Option::is_some)
            .await
            .map_or(None, |ending| *ending);
        match ending {
            Some(end) => end,
            None => std::future::pending().await,
        }
    }

    /// How far the upstream's answer has come.
    #[must_use]
    pub fn progress(&self) -> &CallProgress {
        &self.progress
    }
}

impl Drop for CallSlot {
    fn drop(&mut self) {
        let mut counts = self.slots.lock();
        counts.total = counts.total.saturating_sub(1);
        counts.calls.remove(&self.key);
        if let Entry::Occupied(mut held) = counts.per_agent.entry(self.agent.clone()) {
            if *held.get() <= 1 {
                held.remove();
            } else {
                *held.get_mut() -= 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(name: &str) -> AgentName {
        AgentName::try_from(name.to_owned()).unwrap()
    }

    fn info(path: &str) -> CallInfo {
        CallInfo::new(Id::random(), "GET".to_owned(), path.to_owned(), 100)
    }

    #[test]
    fn per_agent_limit_refuses_excess_and_spares_others() {
        let slots = CallSlots::new(2, 10);
        let a = agent("a");
        let _one = slots.try_acquire(&a, info("/")).unwrap();
        let _two = slots.try_acquire(&a, info("/")).unwrap();
        assert_eq!(slots.try_acquire(&a, info("/")).unwrap_err(), TooManyCalls);
        assert!(slots.try_acquire(&agent("b"), info("/")).is_ok());
    }

    #[test]
    fn overall_limit_refuses_excess() {
        let slots = CallSlots::new(2, 3);
        let _a1 = slots.try_acquire(&agent("a"), info("/")).unwrap();
        let _a2 = slots.try_acquire(&agent("a"), info("/")).unwrap();
        let _b1 = slots.try_acquire(&agent("b"), info("/")).unwrap();
        assert_eq!(
            slots.try_acquire(&agent("b"), info("/")).unwrap_err(),
            TooManyCalls
        );
        assert_eq!(
            slots.try_acquire(&agent("c"), info("/")).unwrap_err(),
            TooManyCalls
        );
    }

    #[test]
    fn dropping_a_slot_frees_it_and_forgets_idle_agents() {
        let slots = CallSlots::new(1, 1);
        let a = agent("a");
        let held = slots.try_acquire(&a, info("/")).unwrap();
        assert!(slots.try_acquire(&a, info("/")).is_err());
        drop(held);
        assert!(slots.lock().per_agent.is_empty());
        assert_eq!(slots.lock().total, 0);
        assert!(slots.try_acquire(&a, info("/")).is_ok());
    }

    #[test]
    fn call_listed_while_slot_held() {
        let slots = CallSlots::new(2, 10);
        assert_eq!(slots.snapshot(), [] as [crate::proxy::slots::CallInfo; 0]);
        let call = info("/v1/items");
        let held = slots.try_acquire(&agent("a"), call.clone()).unwrap();
        assert_eq!(slots.snapshot(), vec![call]);
        drop(held);
        assert_eq!(slots.snapshot(), [] as [crate::proxy::slots::CallInfo; 0]);
        let refused = CallSlots::new(0, 0);
        refused.try_acquire(&agent("a"), info("/")).unwrap_err();
        assert_eq!(refused.snapshot(), [] as [crate::proxy::slots::CallInfo; 0]);
    }

    /// Whether `slot` has been told to stop, without waiting for it.
    async fn told(slot: &CallSlot) -> Option<CallEnd> {
        tokio::select! {
            biased;
            end = slot.ended() => Some(end),
            () = std::future::ready(()) => None,
        }
    }

    #[tokio::test]
    async fn revoking_a_grant_stops_only_its_calls() {
        let slots = CallSlots::new(10, 10);
        let grant = Id::random();
        let call = CallInfo::new(grant.clone(), "GET".to_owned(), "/".to_owned(), 100);
        let mine = slots.try_acquire(&agent("a"), call.clone()).unwrap();
        let mine_too = slots.try_acquire(&agent("a"), call).unwrap();
        let other_grant = slots.try_acquire(&agent("a"), info("/")).unwrap();
        slots.revoke_grant(&grant);
        assert_eq!(told(&mine).await, Some(CallEnd::Revoked));
        assert_eq!(told(&mine_too).await, Some(CallEnd::Revoked));
        assert_eq!(told(&other_grant).await, None);
    }

    #[tokio::test]
    async fn revoking_an_agent_stops_only_its_calls() {
        let slots = CallSlots::new(10, 10);
        let one = slots.try_acquire(&agent("a"), info("/")).unwrap();
        let two = slots.try_acquire(&agent("a"), info("/")).unwrap();
        let other = slots.try_acquire(&agent("b"), info("/")).unwrap();
        slots.revoke_agent(&agent("a"));
        assert_eq!(told(&one).await, Some(CallEnd::Revoked));
        assert_eq!(told(&two).await, Some(CallEnd::Revoked));
        assert_eq!(told(&other).await, None);
    }

    #[tokio::test]
    async fn the_first_reason_stands() {
        let slots = CallSlots::new(10, 10);
        let grant = Id::random();
        let call = CallInfo::new(grant.clone(), "GET".to_owned(), "/".to_owned(), 100);
        let slot = slots.try_acquire(&agent("a"), call).unwrap();
        slots.lock().calls[&slot.key].stop(CallEnd::Expired);
        slots.revoke_grant(&grant);
        assert_eq!(told(&slot).await, Some(CallEnd::Expired));
    }

    #[tokio::test]
    async fn a_waiting_slot_wakes_when_told() {
        let slots = CallSlots::new(10, 10);
        let slot = slots.try_acquire(&agent("a"), info("/")).unwrap();
        let revoke = async {
            tokio::task::yield_now().await;
            slots.revoke_agent(&agent("a"));
        };
        let (end, ()) = tokio::join!(slot.ended(), revoke);
        assert_eq!(end, CallEnd::Revoked);
    }

    #[test]
    fn progress_counts_the_answer_so_far() {
        let progress = CallProgress::default();
        assert_eq!((progress.status(), progress.bytes()), (None, 0));
        progress.response_started(StatusCode::CREATED);
        progress.received(10);
        progress.received(5);
        assert_eq!((progress.status(), progress.bytes()), (Some(201), 15));
    }

    #[test]
    fn an_ended_call_has_a_fixed_status_and_audit_name() {
        assert_eq!(CallEnd::Revoked.status(), StatusCode::CONFLICT);
        assert_eq!(CallEnd::Expired.status(), StatusCode::CONFLICT);
        assert_eq!(
            CallEnd::GrantStateUnavailable.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            serde_json::to_string(&CallEnd::GrantStateUnavailable).unwrap(),
            r#""grant_state_unavailable""#
        );
    }

    #[test]
    fn call_path_has_no_query() {
        assert_eq!(info("/v1/items?token=abc#top").path, "/v1/items");
        assert_eq!(info("/v1/items#top?x").path, "/v1/items");
        assert_eq!(info("/v1/items").path, "/v1/items");
    }

    #[test]
    fn calls_of_one_grant_keep_insertion_order() {
        let slots = CallSlots::new(10, 10);
        let grant = Id::random();
        let call =
            |path: &str| CallInfo::new(grant.clone(), "GET".to_owned(), path.to_owned(), 100);
        let _slots: Vec<_> = ["/a", "/b", "/c"]
            .into_iter()
            .map(|path| slots.try_acquire(&agent("a"), call(path)).unwrap())
            .collect();
        let paths: Vec<_> = slots.snapshot().into_iter().map(|c| c.path).collect();
        assert_eq!(paths, ["/a", "/b", "/c"]);
    }
}
