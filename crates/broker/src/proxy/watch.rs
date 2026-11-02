//! Watching a grant while a call runs on it. Revocations made by this broker
//! reach a call's slot directly; these checks find the rest (a revocation by
//! another process, such as `warden-server agent revoke`, and the end of the
//! window), and stop the call if the grant's state cannot be read, as the relay
//! does for its sessions.

use std::future::Future;
use std::time::Duration;

use tokio::time::{Instant, MissedTickBehavior, interval_at, timeout};

use super::slots::CallEnd;

/// What one check of a grant found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantState {
    /// The grant is still good.
    Usable,
    /// The grant has ended.
    Ended(CallEnd),
    /// The grant's state could not be read.
    Unreadable,
}

/// How often a grant is checked, and how long it may stay unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantChecks {
    /// Time between checks.
    pub every: Duration,
    /// Time one check may take; a check that takes longer found nothing.
    pub check_limit: Duration,
    /// Time without a good check after which the call must stop.
    pub lost_after: Duration,
}

impl Default for GrantChecks {
    /// Each second, each check bounded to 1.5 s, failing closed after 10 s: the
    /// same as the relay's checks of its sessions.
    fn default() -> Self {
        Self {
            every: Duration::from_secs(1),
            check_limit: Duration::from_millis(1500),
            lost_after: Duration::from_secs(10),
        }
    }
}

/// Run `check` as `checks` says until it finds the grant ended, and return why;
/// if no check has succeeded for [`GrantChecks::lost_after`], return
/// [`CallEnd::GrantStateUnavailable`]. The first check comes one period in, as
/// the caller has just checked the grant.
pub async fn until_grant_ends<C, F>(checks: GrantChecks, mut check: C) -> CallEnd
where
    C: FnMut() -> F,
    F: Future<Output = GrantState>,
{
    let mut last_good = Instant::now();
    let mut ticker = interval_at(last_good + checks.every, checks.every);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match timeout(checks.check_limit, check()).await {
            Ok(GrantState::Usable) => last_good = Instant::now(),
            Ok(GrantState::Ended(end)) => return end,
            Ok(GrantState::Unreadable) | Err(_) => {
                if last_good.elapsed() >= checks.lost_after {
                    return CallEnd::GrantStateUnavailable;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::{CallEnd, Duration, GrantChecks, GrantState, until_grant_ends};

    /// Checks with nothing to wait for between them, which never give up
    /// before the number of checks a test wants has run.
    const QUICK: GrantChecks = GrantChecks {
        every: Duration::from_millis(1),
        check_limit: Duration::from_secs(60),
        lost_after: Duration::from_secs(600),
    };

    #[tokio::test]
    async fn checks_until_the_grant_is_found_ended() {
        for end in [CallEnd::Revoked, CallEnd::Expired] {
            let checks = Cell::new(0);
            let found = until_grant_ends(QUICK, || async {
                checks.set(checks.get() + 1);
                if checks.get() < 3 {
                    GrantState::Usable
                } else {
                    GrantState::Ended(end)
                }
            })
            .await;
            assert_eq!(found, end);
            assert_eq!(checks.get(), 3);
        }
    }

    #[tokio::test]
    async fn a_grant_that_stays_unreadable_fails_closed() {
        let found = until_grant_ends(
            GrantChecks {
                lost_after: Duration::from_millis(5),
                ..QUICK
            },
            || async { GrantState::Unreadable },
        )
        .await;
        assert_eq!(found, CallEnd::GrantStateUnavailable);
    }

    #[tokio::test]
    async fn a_check_that_hangs_counts_as_unreadable() {
        let found = until_grant_ends(
            GrantChecks {
                check_limit: Duration::from_millis(1),
                lost_after: Duration::from_millis(5),
                ..QUICK
            },
            std::future::pending::<GrantState>,
        )
        .await;
        assert_eq!(found, CallEnd::GrantStateUnavailable);
    }

    /// A failed check is not the end: the call goes on while the outage is
    /// short, and a later answer decides.
    #[tokio::test]
    async fn a_short_outage_does_not_end_the_call() {
        let checks = Cell::new(0);
        let found = until_grant_ends(QUICK, || async {
            checks.set(checks.get() + 1);
            match checks.get() {
                4 => GrantState::Usable,
                1..=3 | 5 => GrantState::Unreadable,
                _ => GrantState::Ended(CallEnd::Revoked),
            }
        })
        .await;
        assert_eq!(found, CallEnd::Revoked);
        assert_eq!(checks.get(), 6);
    }
}
