//! How many audited refusals of one kind are written to the audit log one by one.
//!
//! The audit log is append-only and the broker stops when it cannot write, so a
//! caller that can be refused as fast as it can call must not be able to add an
//! entry per call. A [`Throttle`] writes the first few entries of a minute, keeps
//! only a count of the rest, and [`FlushHeld::flush`] writes that count later as one
//! entry once the minute that held it is over, however long the calls go on. Counts
//! are in memory: a restart can at worst lose the counts of the last minute or two.

use std::collections::HashMap;
use std::fmt::Debug;
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
    /// is the number of distinct keys counted: those held during that minute, plus
    /// one if a key that arrived when `max_keys` were held was counted without
    /// being added. After a failed write the next entry also counts the keys of
    /// the one that failed, so a key present in both minutes is counted twice: the
    /// number of keys can be too high, but the summed tally stays exact.
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
    /// What an earlier minute held, due to be written at the next flush, with
    /// `due_holding` saying whether anything is.
    due: V,
    due_holding: bool,
}

impl<V: Tally> KeyMinute<V> {
    fn new(now: i64) -> Self {
        Self {
            started_at: now,
            written: 0,
            held: V::default(),
            holding: false,
            due: V::default(),
            due_holding: false,
        }
    }

    /// Start a new minute at `now`: what the old one held becomes due.
    fn roll_over(&mut self, now: i64) {
        if std::mem::take(&mut self.holding) {
            self.due.add(std::mem::take(&mut self.held));
            self.due_holding = true;
        }
        self.started_at = now;
        self.written = 0;
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
    /// What earlier minutes held, if anything, due to be written at the next
    /// flush: the tally and the number of keys counted.
    due: Option<(V, u64)>,
}

impl<V: Tally> Overall<V> {
    /// The keys counted for what is held: those in the map, plus one for overflow.
    fn counted(&mut self, held_keys: usize) -> u64 {
        u64::try_from(held_keys)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::from(std::mem::take(&mut self.overflowed)))
    }

    fn add_due(&mut self, tally: V, keys: u64) {
        let (due, due_keys) = self.due.get_or_insert_with(|| (V::default(), 0));
        due.add(tally);
        *due_keys = due_keys.saturating_add(keys);
    }

    /// Start a new minute at `now`. What the old one held, for an aggregate, becomes
    /// due with its keys.
    fn roll_over(&mut self, now: i64, held_keys: usize, aggregate: bool) {
        if aggregate && std::mem::take(&mut self.holding) {
            let counted = self.counted(held_keys);
            let held = std::mem::take(&mut self.held);
            self.add_due(held, counted);
        }
        self.started = true;
        self.started_at = now;
        self.written = 0;
    }
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
    K: Clone + Debug + Eq + Hash + Send + Sync + 'static,
    V: Tally,
{
    /// A limiter for entries described by `what` in the log of a failed write, with
    /// `allowance` and the `summary` that writes what is held. It is not registered:
    /// use [`AuditThrottles::throttle`] unless the limiter must exist before the
    /// registry does, and then pass it to [`AuditThrottles::register`] exactly once.
    pub(crate) fn new(
        what: &'static str,
        allowance: Allowance,
        summary: Summary<K, V>,
    ) -> Arc<Self> {
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
                    due: None,
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
            let aggregate = matches!(self.summary, Summary::Aggregate { .. });
            inner.overall.roll_over(now, inner.keys.len(), aggregate);
            if aggregate {
                // The keys of the minute that is over are counted now.
                inner.keys.clear();
                inner.overall.overflowed = false;
            }
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
            minute.roll_over(now);
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
            tracing::error!(error = %e, key = ?key, "could not audit {}", self.what);
        }
    }

    /// Take what is due: per key, what earlier minutes held, and what the current
    /// minute holds if it is over (all of it if `all`). Drops the keys whose minute
    /// is over and that hold nothing.
    fn take_per_key(&self, now: i64, all: bool) -> Vec<(K, V)> {
        let mut inner = self.lock();
        let mut due = Vec::new();
        for (key, minute) in &mut inner.keys {
            let mut tally = V::default();
            let mut any = false;
            if std::mem::take(&mut minute.due_holding) {
                tally.add(std::mem::take(&mut minute.due));
                any = true;
            }
            if minute.holding && (all || minute_over(minute.started_at, now)) {
                minute.holding = false;
                tally.add(std::mem::take(&mut minute.held));
                any = true;
            }
            if any {
                due.push((key.clone(), tally));
            }
        }
        inner.keys.retain(|_, minute| {
            minute.holding || minute.due_holding || !minute_over(minute.started_at, now)
        });
        due
    }

    /// Take the aggregates that are due: the number of keys and the tally of each,
    /// the earlier minutes first, then the current one if its minute is over (or
    /// `all`). An aggregate's keys are cleared once its minute is over.
    fn take_aggregate(&self, now: i64, all: bool) -> Vec<(u64, V)> {
        let mut inner = self.lock();
        let mut taken = Vec::new();
        if let Some((tally, keys)) = inner.overall.due.take() {
            taken.push((keys, tally));
        }
        let over = inner.overall.started && minute_over(inner.overall.started_at, now);
        if all || over {
            let held_keys = inner.keys.len();
            let overall = &mut inner.overall;
            if std::mem::take(&mut overall.holding) {
                let counted = overall.counted(held_keys);
                taken.push((counted, std::mem::take(&mut overall.held)));
            }
            overall.overflowed = false;
            inner.keys.clear();
        }
        taken
    }

    fn restore_key(&self, key: &K, tally: V) {
        let mut inner = self.lock();
        let minute = inner
            .keys
            .entry(key.clone())
            // Started at 0, so that its minute is over: the key is dropped once
            // this is written, and not kept for a minute.
            .or_insert_with(|| KeyMinute::new(0));
        minute.due.add(tally);
        minute.due_holding = true;
    }

    fn restore_aggregate(&self, counted: u64, tally: V) {
        let mut inner = self.lock();
        inner.overall.add_due(tally, counted);
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
    K: Clone + Debug + Eq + Hash + Send + Sync + 'static,
    V: Tally,
{
    async fn flush(&self, audit: &AuditLog, now: i64, all: bool) {
        match self.summary {
            Summary::PerKey(event) => {
                for (key, tally) in self.take_per_key(now, all) {
                    if let Err(e) = audit.append(event(key.clone(), tally)).await {
                        tracing::error!(error = %e, key = ?key, "could not audit {}", self.what);
                        self.restore_key(&key, tally);
                    }
                }
            }
            Summary::Aggregate { event, .. } => {
                for (counted, tally) in self.take_aggregate(now, all) {
                    if let Err(e) = audit.append(event(counted, tally)).await {
                        tracing::error!(error = %e, "could not audit {}", self.what);
                        self.restore_aggregate(counted, tally);
                    }
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
    /// A limiter for entries described by `what`, registered here so that what it
    /// holds is flushed. The way to build one, so none can be left out, except
    /// for what [`AuditThrottles::register`] says.
    #[must_use]
    pub fn throttle<K, V>(
        &self,
        what: &'static str,
        allowance: Allowance,
        summary: Summary<K, V>,
    ) -> Arc<Throttle<K, V>>
    where
        K: Clone + Debug + Eq + Hash + Send + Sync + 'static,
        V: Tally,
    {
        let throttle = Throttle::new(what, allowance, summary);
        self.register(throttle.clone());
        throttle
    }

    /// Add `throttle` to those flushed. Only for a limiter built with
    /// `Throttle::new` before the registry existed, such as the local secret
    /// backend's, which is opened before the requests; register each exactly once,
    /// or what it holds is never written, or written twice. Every other limiter is
    /// built by [`AuditThrottles::throttle`].
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
