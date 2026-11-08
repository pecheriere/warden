//! A clock for tests that only moves when told to.

use std::sync::atomic::{AtomicI64, Ordering};

use crate::requests::Clock;

/// A clock that only moves when told to.
#[derive(Debug)]
pub struct ManualClock(AtomicI64);

impl ManualClock {
    /// A clock reading `now` (Unix seconds).
    #[must_use]
    pub const fn new(now: i64) -> Self {
        Self(AtomicI64::new(now))
    }

    /// Move the clock forward by `secs`.
    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }

    /// Set the clock to `now`.
    pub fn set(&self, now: i64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
