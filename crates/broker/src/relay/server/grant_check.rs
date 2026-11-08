//! The relay's periodic check of the grants of its live sessions, and
//! failing closed when the state of grants cannot be read.

use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::time::Instant;
use warden_broker_proto::Id;

use crate::requests::{GrantEnd, RequestError, Requests};

use super::{CHECK_FAILURE_LOG_EVERY, FAIL_CLOSED_AFTER, GRANT_QUERY_TIMEOUT, Shared};

/// End the live sessions whose grant expired or was revoked, every
/// `every`; fail closed while the state of grants cannot be read. Never
/// returns.
///
/// Expiry is enforced on every tick from memory, whatever the database
/// does. Revocation needs a query: at most one runs at a time, each bounded
/// by [`GRANT_QUERY_TIMEOUT`], and the ticks go on meanwhile, so a query
/// that hangs counts as failed and the outage (time since the last
/// successful query) is seen as it grows.
pub(super) async fn check_grants_every(shared: &Shared, every: Duration) {
    let requests = &shared.requests;
    let sessions = requests.live_sessions();
    let mut ticker = tokio::time::interval(every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut health = CheckHealth::new(Instant::now());
    let mut query: Option<GrantQuery> = None;
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                sessions.expire_due(requests.now());
                if query.is_none() {
                    query = Some(grant_query(requests.clone(), sessions.grant_ids()));
                }
                mark_grant_state(shared, health.lost(Instant::now()));
            }
            Some(result) = in_flight(&mut query) => {
                query = None;
                let now = Instant::now();
                match result {
                    Ok(ended) => {
                        for (grant_id, end) in ended {
                            match end {
                                GrantEnd::Revoked => sessions.revoke_grant(&grant_id),
                                GrantEnd::Expired => sessions.expire_grant(&grant_id),
                            }
                        }
                        health.succeeded(now);
                        mark_grant_state(shared, false);
                    }
                    Err(failure) => {
                        if health.failed(now) {
                            tracing::warn!(error = %failure, "relay: checking the grants of live sessions failed");
                        }
                    }
                }
            }
        }
    }
}

/// A grant query on its way.
type GrantQuery = Pin<Box<dyn Future<Output = Result<Vec<(Id, GrantEnd)>, CheckFailure>> + Send>>;

/// Why a grant query failed.
#[derive(Debug, thiserror::Error)]
pub(super) enum CheckFailure {
    #[error(transparent)]
    Query(#[from] RequestError),
    #[error("no answer within {GRANT_QUERY_TIMEOUT:?}")]
    TimedOut,
}

/// Which of `grant_ids` ended, asked of the database within
/// [`GRANT_QUERY_TIMEOUT`]. The lookup runs even with no live session, so
/// it also tells whether the state of grants can be read.
pub(super) fn grant_query(requests: Requests, grant_ids: Vec<Id>) -> GrantQuery {
    Box::pin(async move {
        tokio::time::timeout(GRANT_QUERY_TIMEOUT, requests.ended_grants(&grant_ids))
            .await
            .map_err(|_| CheckFailure::TimedOut)?
            .map_err(CheckFailure::from)
    })
}

/// The answer of the query in flight; never resolves without one.
async fn in_flight(
    query: &mut Option<GrantQuery>,
) -> Option<Result<Vec<(Id, GrantEnd)>, CheckFailure>> {
    match query {
        Some(query) => Some(query.await),
        None => std::future::pending().await,
    }
}

/// Fail closed (`lost`), or open again, logging the transitions.
fn mark_grant_state(shared: &Shared, lost: bool) {
    let was_lost = shared.grant_state_lost.swap(lost, Ordering::AcqRel);
    if lost {
        if !was_lost {
            tracing::error!("relay: grant state unreadable for too long; ending every session");
        }
        // Also sessions that started just before the flag was set.
        shared.requests.live_sessions().fail_closed();
    } else if was_lost {
        tracing::info!("relay: grant state readable again");
    }
}

/// How the grant queries are going.
#[derive(Debug)]
struct CheckHealth {
    /// When the last query succeeded (or checking began).
    last_success: Instant,
    /// When a failure was last logged, in the current run of failures.
    last_logged: Option<Instant>,
}

impl CheckHealth {
    const fn new(now: Instant) -> Self {
        Self {
            last_success: now,
            last_logged: None,
        }
    }

    fn succeeded(&mut self, now: Instant) {
        self.last_success = now;
        self.last_logged = None;
    }

    /// Record a failed query at `now`; whether to log it (the first of a
    /// run, then every [`CHECK_FAILURE_LOG_EVERY`]).
    fn failed(&mut self, now: Instant) -> bool {
        let log = self
            .last_logged
            .is_none_or(|logged| now.duration_since(logged) >= CHECK_FAILURE_LOG_EVERY);
        if log {
            self.last_logged = Some(now);
        }
        log
    }

    /// Whether, at `now`, no query has succeeded for [`FAIL_CLOSED_AFTER`].
    fn lost(&self, now: Instant) -> bool {
        now.duration_since(self.last_success) >= FAIL_CLOSED_AFTER
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::Instant;

    use super::CheckHealth;

    #[test]
    fn fails_closed_ten_seconds_after_the_last_success() {
        let start = Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        let mut health = CheckHealth::new(start);
        // Measured from the start until a first success.
        assert!(!health.lost(at(9)));
        assert!(health.lost(at(10)));
        health.succeeded(at(10));
        assert!(!health.lost(at(19)));
        // A query that hangs (no failure recorded yet) still loses it.
        assert!(health.lost(at(20)));
        health.succeeded(at(21));
        assert!(!health.lost(at(30)));
    }

    #[test]
    fn failures_logged_first_then_every_thirty_seconds() {
        let start = Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        let mut health = CheckHealth::new(start);
        assert!(health.failed(at(1)));
        assert!(!health.failed(at(2)));
        assert!(!health.failed(at(30)));
        assert!(health.failed(at(31)));
        assert!(!health.failed(at(32)));
        // A success ends the run: the next failure is logged.
        health.succeeded(at(33));
        assert!(health.failed(at(34)));
    }
}
