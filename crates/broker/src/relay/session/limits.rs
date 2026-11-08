//! How many relayed sessions may run, and how many connections may be
//! logging in at once.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

use warden_broker_proto::Id;

/// Which limit refused a new session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotRefusal {
    /// The grant already has its maximum of sessions.
    Grant,
    /// The relay as a whole is at its maximum.
    Total,
}

impl SlotRefusal {
    /// What the agent is told (in the SSH disconnect message).
    #[must_use]
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::Grant => "warden relay: too many sessions for this grant",
            Self::Total => "warden relay: too many relay sessions; try again later",
        }
    }
}

#[derive(Debug, Default)]
struct SlotCounts {
    total: usize,
    per_grant: HashMap<Id, usize>,
}

/// Counts live relay sessions, overall and per grant.
#[derive(Debug)]
pub(crate) struct SessionSlots {
    max_total: usize,
    max_per_grant: usize,
    counts: Mutex<SlotCounts>,
}

/// A session's place, given back when dropped.
#[derive(Debug)]
pub(crate) struct SessionSlot {
    slots: Arc<SessionSlots>,
    grant_id: Id,
}

impl SessionSlots {
    pub(crate) fn new(max_total: usize, max_per_grant: usize) -> Arc<Self> {
        Arc::new(Self {
            max_total,
            max_per_grant,
            counts: Mutex::new(SlotCounts::default()),
        })
    }

    /// Take a place for a session of `grant_id`, if both limits allow.
    pub(crate) fn try_acquire(self: &Arc<Self>, grant_id: &Id) -> Result<SessionSlot, SlotRefusal> {
        // The counts stay consistent even if a holder panicked mid-update:
        // every update is a single increment or decrement.
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let held = counts.per_grant.get(grant_id).copied().unwrap_or(0);
        if held >= self.max_per_grant {
            return Err(SlotRefusal::Grant);
        }
        if counts.total >= self.max_total {
            return Err(SlotRefusal::Total);
        }
        counts.total += 1;
        *counts.per_grant.entry(grant_id.clone()).or_insert(0) += 1;
        Ok(SessionSlot {
            slots: Arc::clone(self),
            grant_id: grant_id.clone(),
        })
    }

    #[cfg(test)]
    fn live(&self) -> (usize, usize) {
        let counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        (counts.total, counts.per_grant.len())
    }
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        let mut counts = self
            .slots
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        counts.total = counts.total.saturating_sub(1);
        if let Some(held) = counts.per_grant.get_mut(&self.grant_id) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                counts.per_grant.remove(&self.grant_id);
            }
        }
    }
}

#[derive(Debug, Default)]
struct PreAuthCounts {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

/// Counts connections that have not logged in yet, overall and per peer
/// address, so unauthenticated peers cannot exhaust the relay.
#[derive(Debug)]
pub(crate) struct PreAuthLimiter {
    max_total: usize,
    max_per_ip: usize,
    counts: Mutex<PreAuthCounts>,
}

/// A pre-login place, given back when dropped (at login or disconnect).
#[derive(Debug)]
pub(crate) struct PreAuthPermit {
    limiter: Arc<PreAuthLimiter>,
    ip: IpAddr,
}

impl PreAuthLimiter {
    pub(crate) fn new(max_total: usize, max_per_ip: usize) -> Arc<Self> {
        Arc::new(Self {
            max_total,
            max_per_ip,
            counts: Mutex::new(PreAuthCounts::default()),
        })
    }

    /// Admit a new connection from `ip`, if both limits allow.
    pub(crate) fn try_admit(self: &Arc<Self>, ip: IpAddr) -> Option<PreAuthPermit> {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let from_ip = counts.per_ip.get(&ip).copied().unwrap_or(0);
        if from_ip >= self.max_per_ip || counts.total >= self.max_total {
            return None;
        }
        counts.total += 1;
        *counts.per_ip.entry(ip).or_insert(0) += 1;
        Some(PreAuthPermit {
            limiter: Arc::clone(self),
            ip,
        })
    }
}

impl Drop for PreAuthPermit {
    fn drop(&mut self) {
        let mut counts = self
            .limiter
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        counts.total = counts.total.saturating_sub(1);
        if let Some(held) = counts.per_ip.get_mut(&self.ip) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                counts.per_ip.remove(&self.ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use warden_broker_proto::Id;

    use super::{PreAuthLimiter, SessionSlots, SlotRefusal};

    #[test]
    fn sessions_limited_per_grant_and_overall() {
        let slots = SessionSlots::new(3, 2);
        let (a, b) = (Id::random(), Id::random());
        let a1 = slots.try_acquire(&a).unwrap();
        let a2 = slots.try_acquire(&a).unwrap();
        assert_eq!(slots.try_acquire(&a).unwrap_err(), SlotRefusal::Grant);
        let b1 = slots.try_acquire(&b).unwrap();
        assert_eq!(slots.try_acquire(&b).unwrap_err(), SlotRefusal::Total);
        drop(a1);
        let b2 = slots.try_acquire(&b).unwrap();
        assert_eq!(slots.live(), (3, 2));
        drop((a2, b1, b2));
        // Nothing is left behind for grants with no session.
        assert_eq!(slots.live(), (0, 0));
    }

    #[test]
    fn unauthenticated_connections_limited_per_address_and_overall() {
        let limiter = PreAuthLimiter::new(3, 2);
        let ip = |n| IpAddr::V4(Ipv4Addr::new(192, 0, 2, n));
        let first = limiter.try_admit(ip(1)).unwrap();
        let _second = limiter.try_admit(ip(1)).unwrap();
        assert!(limiter.try_admit(ip(1)).is_none());
        let _third = limiter.try_admit(ip(2)).unwrap();
        assert!(limiter.try_admit(ip(3)).is_none());
        drop(first);
        assert!(limiter.try_admit(ip(3)).is_some());
        let again = limiter.try_admit(ip(1));
        assert!(again.is_some());
    }
}
