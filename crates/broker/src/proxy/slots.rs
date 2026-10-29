//! Concurrency limits for proxied calls: how many may be in flight at once
//! per agent and overall. Each call holds a [`CallSlot`] for as long as it
//! runs; the slot is released when it is dropped, whatever way the call
//! ends.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

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

#[derive(Debug, Default)]
struct Counts {
    total: usize,
    per_agent: HashMap<AgentName, usize>,
    calls: BTreeMap<u64, CallInfo>,
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
        counts.calls.insert(key, call);
        Ok(CallSlot {
            slots: Arc::clone(self),
            agent: agent.clone(),
            key,
        })
    }

    /// The calls in flight, oldest first (ties by grant, then by when they
    /// were admitted).
    #[must_use]
    pub fn snapshot(&self) -> Vec<CallInfo> {
        let mut calls: Vec<_> = self.lock().calls.values().cloned().collect();
        calls.sort_by(|a, b| {
            (a.started_at, a.grant_id.as_str()).cmp(&(b.started_at, b.grant_id.as_str()))
        });
        calls
    }
}

/// A call's place among the calls in flight, released on drop.
#[derive(Debug)]
pub struct CallSlot {
    slots: Arc<CallSlots>,
    agent: AgentName,
    key: u64,
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
        assert!(slots.snapshot().is_empty());
        let call = info("/v1/items");
        let held = slots.try_acquire(&agent("a"), call.clone()).unwrap();
        assert_eq!(slots.snapshot(), vec![call]);
        drop(held);
        assert!(slots.snapshot().is_empty());
        let refused = CallSlots::new(0, 0);
        refused.try_acquire(&agent("a"), info("/")).unwrap_err();
        assert!(refused.snapshot().is_empty());
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
