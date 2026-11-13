//! Bounds on what callers of the agent API can hold at once, so that agents
//! cannot use up the process the approval UI shares with them.
//!
//! - [`WaitSlots`]: status long-polls in flight, per agent; one more is a 429.
//! - [`BodyBudget`]: bytes of request bodies being read before their
//!   signature is verified, overall; a body that does not fit is a 503.
//!
//! The listeners' connection caps are in [`crate::serve`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use warden_broker_proto::AgentName;

/// Most status long-polls one agent may have waiting at once. Each
/// `warden request` holds one while it waits, so this covers sixteen
/// sessions of one agent waiting together, far more than one agent runs.
pub const MAX_WAITS_PER_AGENT: usize = 16;

/// Most bytes of request bodies read at once before their signature is
/// verified, over all callers. A caller naming a known agent needs no key to
/// make the broker read a body, so this bounds the memory such callers can
/// hold: sixteen proxied calls of the largest size, or a thousand small
/// requests, at a time.
pub const PRE_SIGNATURE_BODY_BUDGET: usize = 32 * 1024 * 1024;

/// The unit [`BodyBudget`] counts in: a semaphore's permits are a `u32`.
const BUDGET_UNIT: usize = 1024;

/// What the agent API's routes share to apply these bounds. Clones share the
/// same counts.
#[derive(Clone, Debug)]
pub struct ApiLoad {
    /// Status long-polls in flight, per agent.
    pub waits: WaitSlots,
    /// Bodies being read before their signature is verified.
    pub bodies: BodyBudget,
}

impl Default for ApiLoad {
    fn default() -> Self {
        Self {
            waits: WaitSlots::new(MAX_WAITS_PER_AGENT),
            bodies: BodyBudget::new(PRE_SIGNATURE_BODY_BUDGET),
        }
    }
}

/// Counts the status long-polls each agent has waiting.
#[derive(Clone, Debug)]
pub struct WaitSlots {
    max_per_agent: usize,
    held: Arc<Mutex<HashMap<AgentName, usize>>>,
}

/// A waiting long-poll's place, given back when dropped.
#[derive(Debug)]
pub struct WaitSlot {
    held: Arc<Mutex<HashMap<AgentName, usize>>>,
    agent: AgentName,
}

impl WaitSlots {
    /// Slots for at most `max_per_agent` waits per agent.
    #[must_use]
    pub fn new(max_per_agent: usize) -> Self {
        Self {
            max_per_agent,
            held: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Take a place for one of `agent`'s waits, or `None` if it already has
    /// as many as allowed.
    #[must_use]
    pub fn try_acquire(&self, agent: &AgentName) -> Option<WaitSlot> {
        // Every update is a single increment or decrement, so the counts
        // stay consistent even if a holder panicked while holding the lock.
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let count = held.entry(agent.clone()).or_insert(0);
        if *count >= self.max_per_agent {
            return None;
        }
        *count += 1;
        Some(WaitSlot {
            held: Arc::clone(&self.held),
            agent: agent.clone(),
        })
    }
}

impl Drop for WaitSlot {
    fn drop(&mut self) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.agent) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                held.remove(&self.agent);
            }
        }
    }
}

/// Bytes that bodies read before their signature is verified may take.
#[derive(Clone, Debug)]
pub struct BodyBudget {
    units: Arc<Semaphore>,
}

/// Bytes reserved for one body, given back when dropped.
#[derive(Debug)]
pub struct BodyReservation {
    // Only held, for its drop.
    _permit: Option<OwnedSemaphorePermit>,
}

impl BodyBudget {
    /// A budget of `bytes` (rounded up to whole KiB, at most `u32::MAX` KiB).
    #[must_use]
    pub fn new(bytes: usize) -> Self {
        Self {
            units: Arc::new(Semaphore::new(
                usize::try_from(units(bytes))
                    .unwrap_or(usize::MAX)
                    .min(Semaphore::MAX_PERMITS),
            )),
        }
    }

    /// Reserve room for a body of at most `bytes`, or `None` if the budget
    /// has not that much left. An empty body takes nothing.
    #[must_use]
    pub fn try_reserve(&self, bytes: usize) -> Option<BodyReservation> {
        let wanted = units(bytes);
        if wanted == 0 {
            return Some(BodyReservation { _permit: None });
        }
        Arc::clone(&self.units)
            .try_acquire_many_owned(wanted)
            .ok()
            .map(|permit| BodyReservation {
                _permit: Some(permit),
            })
    }
}

/// `bytes` in [`BUDGET_UNIT`]s, rounded up; a size beyond `u32::MAX` units
/// is more than any budget holds.
fn units(bytes: usize) -> u32 {
    u32::try_from(bytes.div_ceil(BUDGET_UNIT)).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(name: &str) -> AgentName {
        AgentName::try_from(name.to_owned()).unwrap()
    }

    #[test]
    fn waits_are_counted_per_agent_and_given_back() {
        let slots = WaitSlots::new(2);
        let (a, b) = (agent("build-agent"), agent("other-agent"));
        let a1 = slots.try_acquire(&a).unwrap();
        let a2 = slots.try_acquire(&a).unwrap();
        assert!(slots.try_acquire(&a).is_none());
        // Another agent has its own slots.
        let _b1 = slots.try_acquire(&b).unwrap();
        drop(a1);
        let _a3 = slots.try_acquire(&a).unwrap();
        assert!(slots.try_acquire(&a).is_none());
        drop(a2);
        assert!(slots.try_acquire(&a).is_some());
    }

    #[test]
    fn body_budget_counts_bytes_and_empty_bodies_take_nothing() {
        let budget = BodyBudget::new(4 * 1024);
        let three = budget.try_reserve(3 * 1024).unwrap();
        // A partial KiB counts as a whole one.
        assert!(budget.try_reserve(1025).is_none());
        let one = budget.try_reserve(1).unwrap();
        assert!(budget.try_reserve(1).is_none());
        assert!(budget.try_reserve(0).is_some());
        drop(three);
        drop(one);
        assert!(budget.try_reserve(4 * 1024).is_some());
        // More than the whole budget never fits.
        assert!(budget.try_reserve(usize::MAX).is_none());
    }
}
