//! How many audited refusals of one kind are written to the audit log one by one.
//!
//! The audit log is append-only and the broker stops when it cannot write, so a
//! caller that can be refused as fast as it can call must not be able to add an
//! entry per call. A [`Throttle`] writes the first few entries of a minute, keeps
//! only a count of the rest, and [`FlushHeld::flush`] writes that count later as one
//! entry. Counts are in memory: a restart can at worst lose the counts of a minute.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;

use crate::audit::{AuditEvent, AuditLog};

/// Seconds in a limiter minute.
const MINUTE: i64 = 60;

/// What is held for the calls that were not written one by one.
pub trait Tally: Copy + Default + Send + Sync + 'static {
    /// Add `other` to this tally.
    fn add(&mut self, other: Self);
}

impl Tally for u64 {
    fn add(&mut self, other: Self) {
        *self = self.saturating_add(other);
    }
}

/// How many entries a minute may write one by one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Allowance {
    /// Entries per key per minute.
    pub per_key: u32,
    /// Entries per minute over all keys, if bounded.
    pub overall: Option<u32>,
}

/// How what is held is written.
#[derive(Clone, Copy, Debug)]
pub enum Summary<K, V> {
    /// One entry per key with something held, once that key's minute is over. Only
    /// for keys that come from enrolled agents or stored grants, so there is no
    /// cap on how many.
    PerKey(fn(K, V) -> AuditEvent),
    /// One entry for all keys once the limiter's minute is over. The `u64` it gets
    /// is the number of distinct keys counted: those held, plus one if a key
    /// that arrived when `max_keys` were held was counted without being added.
    Aggregate {
        /// The most distinct keys held at once.
        max_keys: usize,
        /// The entry, from the number of keys and the summed tally.
        event: fn(u64, V) -> AuditEvent,
    },
}

/// One key's calls in its current minute.
struct KeyMinute<V> {
    started_at: i64,
    written: u32,
    /// The tally held, with `holding` saying whether anything is.
    held: V,
    holding: bool,
}

impl<V: Default> KeyMinute<V> {
    fn new(now: i64) -> Self {
        Self {
            started_at: now,
            written: 0,
            held: V::default(),
            holding: false,
        }
    }
}

/// The calls of every key together, for the overall allowance and an aggregate.
struct Overall<V> {
    started: bool,
    started_at: i64,
    written: u32,
    held: V,
    holding: bool,
    /// A key arrived when the map was full and was only counted.
    overflowed: bool,
    /// Keys of a summary that could not be written, to be counted in the next.
    carried_keys: u64,
}

struct Inner<K, V> {
    keys: HashMap<K, KeyMinute<V>>,
    overall: Overall<V>,
}

/// Whether the minute that began at `started_at` is over at `now`. A clock set back
/// ends it too.
fn minute_over(started_at: i64, now: i64) -> bool {
    now < started_at || now - started_at >= MINUTE
}

/// The limiter for one kind of audited refusal. In memory.
pub struct Throttle<K, V> {
    what: &'static str,
    allowance: Allowance,
    summary: Summary<K, V>,
    inner: Mutex<Inner<K, V>>,
}

impl<K, V> Throttle<K, V>
where
    K: Clone + Eq + Hash + Send + Sync + 'static,
    V: Tally,
{
    /// A limiter for entries described by `what` in the log of a failed write, with
    /// `allowance` and the `summary` that writes what is held.
    #[must_use]
    pub fn new(what: &'static str, allowance: Allowance, summary: Summary<K, V>) -> Arc<Self> {
        Arc::new(Self {
            what,
            allowance,
            summary,
            inner: Mutex::new(Inner {
                keys: HashMap::new(),
                overall: Overall {
                    started: false,
                    started_at: 0,
                    written: 0,
                    held: V::default(),
                    holding: false,
                    overflowed: false,
                    carried_keys: 0,
                },
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner<K, V>> {
        // Every update is a few steps that cannot panic, and at worst this
        // miscounts: the call has already been decided.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Count a call of `key` at `now` with `tally`. Whether to write it in full; if
    /// not, `tally` is held.
    fn note(&self, key: &K, now: i64, tally: V) -> bool {
        let mut guard = self.lock();
        let inner = &mut *guard;
        if !inner.overall.started || minute_over(inner.overall.started_at, now) {
            inner.overall.started = true;
            inner.overall.started_at = now;
            inner.overall.written = 0;
        }
        if let Summary::Aggregate { max_keys, .. } = self.summary
            && !inner.keys.contains_key(key)
            && inner.keys.len() >= max_keys
        {
            inner.overall.overflowed = true;
            inner.overall.held.add(tally);
            inner.overall.holding = true;
            return false;
        }
        let minute = inner
            .keys
            .entry(key.clone())
            .or_insert_with(|| KeyMinute::new(now));
        if minute_over(minute.started_at, now) {
            minute.started_at = now;
            minute.written = 0;
        }
        let overall_room = self
            .allowance
            .overall
            .is_none_or(|overall| inner.overall.written < overall);
        if minute.written < self.allowance.per_key && overall_room {
            minute.written += 1;
            inner.overall.written = inner.overall.written.saturating_add(1);
            return true;
        }
        match self.summary {
            Summary::PerKey(_) => {
                minute.held.add(tally);
                minute.holding = true;
            }
            Summary::Aggregate { .. } => {
                inner.overall.held.add(tally);
                inner.overall.holding = true;
            }
        }
        false
    }

    /// Write `event` for a call of `key` at `now` if the minute's allowance has
    /// room, and hold `tally` otherwise. Cannot change the outcome of the call,
    /// which is decided already, so a failure to write is logged, as `what`.
    pub async fn record(&self, audit: &AuditLog, key: &K, now: i64, tally: V, event: AuditEvent) {
        if !self.note(key, now, tally) {
            return;
        }
        if let Err(e) = audit.append(event).await {
            tracing::error!(error = %e, "could not audit {}", self.what);
        }
    }

    /// Take what is due: per key, each key whose minute is over (all if `all`),
    /// and drop the keys whose minute is over and that hold nothing.
    fn take_per_key(&self, now: i64, all: bool) -> Vec<(K, V)> {
        let mut inner = self.lock();
        let mut due = Vec::new();
        for (key, minute) in &mut inner.keys {
            if minute.holding && (all || minute_over(minute.started_at, now)) {
                minute.holding = false;
                due.push((key.clone(), std::mem::take(&mut minute.held)));
            }
        }
        inner
            .keys
            .retain(|_, minute| minute.holding || !minute_over(minute.started_at, now));
        due
    }

    /// Take the aggregate if the limiter's minute is over (or `all`): the number of
    /// keys and the tally, if anything is held. Starts afresh either way.
    fn take_aggregate(&self, now: i64, all: bool) -> Option<(u64, V)> {
        let mut inner = self.lock();
        let overall = &mut inner.overall;
        if overall.started && !all && !minute_over(overall.started_at, now) {
            return None;
        }
        let holding = std::mem::take(&mut overall.holding);
        let tally = std::mem::take(&mut overall.held);
        let overflow = u64::from(std::mem::take(&mut overall.overflowed));
        let carried = std::mem::take(&mut overall.carried_keys);
        let counted = u64::try_from(inner.keys.len())
            .unwrap_or(u64::MAX)
            .saturating_add(overflow)
            .saturating_add(carried);
        inner.keys.clear();
        holding.then_some((counted, tally))
    }

    fn restore_key(&self, key: &K, tally: V) {
        let mut inner = self.lock();
        let minute = inner
            .keys
            .entry(key.clone())
            .or_insert_with(|| KeyMinute::new(0));
        minute.held.add(tally);
        minute.holding = true;
    }

    fn restore_aggregate(&self, counted: u64, tally: V) {
        let mut inner = self.lock();
        inner.overall.held.add(tally);
        inner.overall.holding = true;
        inner.overall.carried_keys = inner.overall.carried_keys.saturating_add(counted);
    }
}

/// Something that writes the counts it holds back.
#[async_trait]
pub trait FlushHeld: Send + Sync {
    /// Write what is held: the count of a key when its minute is over, or every
    /// count when `all`. A count whose write fails is put back for the next time.
    async fn flush(&self, audit: &AuditLog, now: i64, all: bool);
}

#[async_trait]
impl<K, V> FlushHeld for Throttle<K, V>
where
    K: Clone + Eq + Hash + Send + Sync + 'static,
    V: Tally,
{
    async fn flush(&self, audit: &AuditLog, now: i64, all: bool) {
        match self.summary {
            Summary::PerKey(event) => {
                for (key, tally) in self.take_per_key(now, all) {
                    if let Err(e) = audit.append(event(key.clone(), tally)).await {
                        tracing::error!(error = %e, "could not audit {}", self.what);
                        self.restore_key(&key, tally);
                    }
                }
            }
            Summary::Aggregate { event, .. } => {
                if let Some((counted, tally)) = self.take_aggregate(now, all)
                    && let Err(e) = audit.append(event(counted, tally)).await
                {
                    tracing::error!(error = %e, "could not audit {}", self.what);
                    self.restore_aggregate(counted, tally);
                }
            }
        }
    }
}

/// Every limiter, so that one call writes what they all hold.
#[derive(Default)]
pub struct AuditThrottles {
    throttles: Mutex<Vec<Arc<dyn FlushHeld>>>,
}

impl AuditThrottles {
    /// Add `throttle` to those flushed.
    pub fn register(&self, throttle: Arc<dyn FlushHeld>) {
        self.throttles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(throttle);
    }

    /// Flush every registered limiter, as [`FlushHeld::flush`].
    pub async fn flush(&self, audit: &AuditLog, now: i64, all: bool) {
        let throttles = self
            .throttles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        for throttle in throttles {
            throttle.flush(audit, now, all).await;
        }
    }
}

#[cfg(test)]
mod tests;
