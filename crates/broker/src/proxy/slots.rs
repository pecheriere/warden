//! Concurrency limits for proxied calls: how many may be in flight at once
//! per agent and overall. Each call holds a [`CallSlot`] for as long as it
//! runs; the slot is released when it is dropped, whatever way the call
//! ends.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use warden_broker_proto::AgentName;

/// Why a call got no slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("too many concurrent calls")]
pub struct TooManyCalls;

#[derive(Debug, Default)]
struct Counts {
    total: usize,
    per_agent: HashMap<AgentName, usize>,
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

    /// Take a slot for a call of `agent`, without waiting.
    ///
    /// # Errors
    ///
    /// [`TooManyCalls`] if the agent or the broker is at its limit.
    pub fn try_acquire(self: &Arc<Self>, agent: &AgentName) -> Result<CallSlot, TooManyCalls> {
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
        Ok(CallSlot {
            slots: Arc::clone(self),
            agent: agent.clone(),
        })
    }
}

/// A call's place among the calls in flight, released on drop.
#[derive(Debug)]
pub struct CallSlot {
    slots: Arc<CallSlots>,
    agent: AgentName,
}

impl Drop for CallSlot {
    fn drop(&mut self) {
        let mut counts = self.slots.lock();
        counts.total = counts.total.saturating_sub(1);
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

    #[test]
    fn per_agent_limit_refuses_excess_and_spares_others() {
        let slots = CallSlots::new(2, 10);
        let a = agent("a");
        let _one = slots.try_acquire(&a).unwrap();
        let _two = slots.try_acquire(&a).unwrap();
        assert_eq!(slots.try_acquire(&a).unwrap_err(), TooManyCalls);
        assert!(slots.try_acquire(&agent("b")).is_ok());
    }

    #[test]
    fn overall_limit_refuses_excess() {
        let slots = CallSlots::new(2, 3);
        let _a1 = slots.try_acquire(&agent("a")).unwrap();
        let _a2 = slots.try_acquire(&agent("a")).unwrap();
        let _b1 = slots.try_acquire(&agent("b")).unwrap();
        assert_eq!(slots.try_acquire(&agent("b")).unwrap_err(), TooManyCalls);
        assert_eq!(slots.try_acquire(&agent("c")).unwrap_err(), TooManyCalls);
    }

    #[test]
    fn dropping_a_slot_frees_it_and_forgets_idle_agents() {
        let slots = CallSlots::new(1, 1);
        let a = agent("a");
        let held = slots.try_acquire(&a).unwrap();
        assert!(slots.try_acquire(&a).is_err());
        drop(held);
        assert!(slots.lock().per_agent.is_empty());
        assert_eq!(slots.lock().total, 0);
        assert!(slots.try_acquire(&a).is_ok());
    }
}
