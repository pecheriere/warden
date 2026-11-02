//! Per-agent limits on requests: how many may be pending at once and how many
//! new ones may be made in a sliding window, so that an enrolled agent cannot
//! flood the owner with notifications or grow the database without bound.
//!
//! The counts are read from the `requests` table in the transaction that
//! would insert the request, so concurrent creates cannot slip past them and a
//! database that cannot be read refuses the request. Every stored request
//! counts towards the window whatever became of it, cancelled ones included,
//! so cancelling and asking again gains nothing. Counts are per agent: an
//! agent can only ever use up its own allowance.
//!
//! A refused request stores nothing and does not ring. The first refusal is
//! audited and the rest are counted and written at most once a minute, so
//! that refused requests, which an agent can send as fast as it likes, cannot
//! fill the audit log instead; and the owner gets one notice an hour per agent
//! at most. This bookkeeping is in memory: a restart can at worst cost one more
//! entry and one more notice. A failure to record a refusal never lets the
//! request through.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use sqlx::{Row as _, SqliteConnection};
use url::Url;
use warden_broker_proto::AgentName;

use super::{PENDING_TTL_SECS, RequestError, Requests};
use crate::audit::AuditEvent;
use crate::notify::Doorbell;

/// Longest between audit entries for an agent still being refused, in seconds.
const AUDIT_EVERY_SECS: i64 = 60;

/// Least time between notices to the owner about one agent, in seconds.
const NOTICE_EVERY_SECS: i64 = 3600;

/// The requests of an agent (`?1`) still pending at `?3`, newest first, from
/// `?2` on (the oldest a pending request can be); `?4` skips to the one that
/// is at the limit, which is found through the index without counting.
const PENDING_AT_LIMIT: &str = "\
    SELECT expires_at FROM requests \
    WHERE agent = ?1 AND created_at > ?2 AND status = 'pending' AND expires_at > ?3 \
    ORDER BY created_at DESC LIMIT 1 OFFSET ?4";

/// The requests of an agent (`?1`) made after `?2` and up to now (`?4`), newest
/// first; `?3` skips to the one that is at the limit, which is found through
/// the index without counting. A row dated after now (the clock was set back)
/// does not count: it would hold the limit until the clock caught up, however
/// far that is, and the window must stay the longest this limit can last.
const NEW_AT_LIMIT: &str = "\
    SELECT created_at FROM requests \
    WHERE agent = ?1 AND created_at > ?2 AND created_at <= ?4 \
    ORDER BY created_at DESC LIMIT 1 OFFSET ?3";

/// How many requests each agent may make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLimits {
    /// Requests of one agent that may be pending at once.
    pub max_pending: u32,
    /// Requests one agent may make per window.
    pub max_new: u32,
    /// Length of the sliding window, in seconds. It is also the longest the
    /// limit on new requests can hold back a request.
    pub window_secs: u32,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_pending: 5,
            max_new: 10,
            window_secs: 600,
        }
    }
}

/// Why a new request of an agent was refused, as the agent is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LimitRefusal {
    /// Too many of its requests are pending.
    #[error(
        "too many pending requests: at most {max} per agent. Cancel one or wait for the owner; a slot frees within {retry_after_secs} s"
    )]
    Pending {
        /// The limit.
        max: u32,
        /// When a slot frees at the latest, in seconds.
        retry_after_secs: u32,
    },
    /// It made too many new requests, however they ended.
    #[error(
        "too many new requests: at most {max} every {window_secs} s, cancelled ones included. Try again in {retry_after_secs} s"
    )]
    Rate {
        /// The limit.
        max: u32,
        /// Length of the window, in seconds.
        window_secs: u32,
        /// When a new request will be accepted, in seconds.
        retry_after_secs: u32,
    },
}

impl LimitRefusal {
    /// How long to wait before trying again, in seconds.
    #[must_use]
    pub const fn retry_after_secs(self) -> u32 {
        match self {
            Self::Pending {
                retry_after_secs, ..
            }
            | Self::Rate {
                retry_after_secs, ..
            } => retry_after_secs,
        }
    }
}

/// Seconds from `now` to `at`, at least 1 and at most `longest`.
fn wait_until(at: i64, now: i64, longest: u32) -> u32 {
    u32::try_from(at.saturating_sub(now))
        .unwrap_or(if at < now { 1 } else { longest })
        .clamp(1, longest)
}

/// Refuse a new request of `agent` if it is over `limits`. A request that takes
/// the dedupe path (the agent's pending request in the slot `dedupe_key`) is
/// not new: it stores nothing and rings nobody, so it is always let through.
///
/// # Errors
/// [`RequestError::Limited`], or storage failures, which also refuse it.
pub(super) async fn check(
    conn: &mut SqliteConnection,
    limits: &RequestLimits,
    agent: &AgentName,
    dedupe_key: &str,
    now: i64,
) -> Result<(), RequestError> {
    let duplicate =
        sqlx::query("SELECT 1 FROM requests WHERE dedupe_key = ? AND status = 'pending'")
            .bind(dedupe_key)
            .fetch_optional(&mut *conn)
            .await?;
    if duplicate.is_some() {
        return Ok(());
    }
    let pending = sqlx::query(PENDING_AT_LIMIT)
        .bind(agent.as_str())
        .bind(now - PENDING_TTL_SECS)
        .bind(now)
        .bind(i64::from(limits.max_pending) - 1)
        .fetch_optional(&mut *conn)
        .await?;
    if let Some(row) = pending {
        let expires_at: i64 = row.try_get("expires_at")?;
        // Not capped at the pending time: a pending request dated ahead of a
        // clock set back really is pending until then, and the agent is told
        // so. It can cancel one to free a slot at once.
        return Err(RequestError::Limited(LimitRefusal::Pending {
            max: limits.max_pending,
            retry_after_secs: wait_until(expires_at, now, u32::MAX),
        }));
    }
    let window = i64::from(limits.window_secs);
    let recent = sqlx::query(NEW_AT_LIMIT)
        .bind(agent.as_str())
        .bind(now - window)
        .bind(i64::from(limits.max_new) - 1)
        .bind(now)
        .fetch_optional(&mut *conn)
        .await?;
    if let Some(row) = recent {
        let created_at: i64 = row.try_get("created_at")?;
        return Err(RequestError::Limited(LimitRefusal::Rate {
            max: limits.max_new,
            window_secs: limits.window_secs,
            retry_after_secs: wait_until(
                created_at.saturating_add(window),
                now,
                limits.window_secs,
            ),
        }));
    }
    Ok(())
}

/// Refusals not yet in the audit log, by kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Tally {
    pending: u64,
    rate: u64,
}

impl Tally {
    const fn is_empty(self) -> bool {
        self.pending == 0 && self.rate == 0
    }

    const fn add(&mut self, other: Self) {
        self.pending = self.pending.saturating_add(other.pending);
        self.rate = self.rate.saturating_add(other.rate);
    }
}

/// What has been recorded and told about one agent's refusals.
#[derive(Debug, Default)]
struct AgentRefusals {
    unrecorded: Tally,
    audited_at: Option<i64>,
    noticed_at: Option<i64>,
}

/// What to do about a refusal that was just counted.
#[derive(Debug, PartialEq, Eq)]
struct Steps {
    /// Write this tally to the audit log.
    audit: Option<Tally>,
    /// Tell the owner.
    notify: bool,
}

/// Whether an action last taken at `last` is due again at `now`, `every`
/// seconds later. A clock set back counts as due: nothing here is worth
/// staying silent for until it catches up.
fn due(last: Option<i64>, now: i64, every: i64) -> bool {
    last.is_none_or(|last| now < last || now - last >= every)
}

/// The refusals of every agent. Enrolled agents are the only callers that get
/// this far, so this holds an entry per enrolled agent at most.
#[derive(Debug, Default)]
pub(super) struct Refusals {
    agents: Mutex<HashMap<AgentName, AgentRefusals>>,
}

impl Refusals {
    fn lock(&self) -> MutexGuard<'_, HashMap<AgentName, AgentRefusals>> {
        // Every update is a few steps that cannot panic, and at worst this
        // bookkeeping miscounts: requests are refused from the database.
        self.agents.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Count `refusal` of `agent` at `now`; returns what is due.
    fn note(&self, agent: &AgentName, refusal: LimitRefusal, now: i64) -> Steps {
        let mut agents = self.lock();
        let state = agents.entry(agent.clone()).or_default();
        state.unrecorded.add(match refusal {
            LimitRefusal::Pending { .. } => Tally {
                pending: 1,
                rate: 0,
            },
            LimitRefusal::Rate { .. } => Tally {
                pending: 0,
                rate: 1,
            },
        });
        let notify = due(state.noticed_at, now, NOTICE_EVERY_SECS);
        if notify {
            state.noticed_at = Some(now);
        }
        let audit = due(state.audited_at, now, AUDIT_EVERY_SECS).then(|| {
            state.audited_at = Some(now);
            std::mem::take(&mut state.unrecorded)
        });
        Steps { audit, notify }
    }

    /// Put back `tally`, which could not be written. It is tried again when the
    /// next entry is due, not sooner: during an audit outage, every refusal
    /// trying again would flood the server log with the failure.
    fn restore(&self, agent: &AgentName, tally: Tally) {
        let mut agents = self.lock();
        let state = agents.entry(agent.clone()).or_default();
        state.unrecorded.add(tally);
    }

    /// Take the tallies that are due at `now`, or all of them if `all`.
    fn take_due(&self, now: i64, all: bool) -> Vec<(AgentName, Tally)> {
        self.lock()
            .iter_mut()
            .filter(|(_, state)| {
                !state.unrecorded.is_empty()
                    && (all || due(state.audited_at, now, AUDIT_EVERY_SECS))
            })
            .map(|(agent, state)| {
                state.audited_at = Some(now);
                (agent.clone(), std::mem::take(&mut state.unrecorded))
            })
            .collect()
    }
}

impl Requests {
    /// Hold agents to `limits` instead of the default [`RequestLimits`].
    #[must_use]
    pub const fn with_limits(mut self, limits: RequestLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Allow `max_per_agent` proxied calls in flight per agent and `max_total`
    /// overall, instead of the default [`ProxyLimits`](crate::proxy::ProxyLimits).
    #[must_use]
    pub fn with_call_limits(mut self, max_per_agent: usize, max_total: usize) -> Self {
        self.proxy_calls = crate::proxy::CallSlots::new(max_per_agent, max_total);
        self
    }

    /// The proxied calls in flight.
    #[must_use]
    pub const fn proxy_calls(&self) -> &std::sync::Arc<crate::proxy::CallSlots> {
        &self.proxy_calls
    }

    /// Record that `agent` was refused, and tell the owner if that is due.
    /// Neither can change the outcome: the request is refused already, so a
    /// failure here is logged and the next refusal tries again.
    pub(super) async fn record_refusal(&self, agent: &AgentName, refusal: LimitRefusal) {
        let now = self.clock.now();
        let steps = self.refusals.note(agent, refusal, now);
        // As often as the audit entry, not per refusal: refused requests must
        // not be able to fill the server's log either.
        if let Some(tally) = steps.audit {
            tracing::warn!(
                agent = %agent,
                %refusal,
                refused = tally.pending.saturating_add(tally.rate),
                "requests refused by a limit"
            );
            self.write_tally(agent, tally).await;
        }
        if steps.notify {
            self.send_limit_notice(agent).await;
        }
    }

    /// Write the refusals held back since the last entry, if a minute has
    /// passed (or whatever the time, if `all`).
    pub async fn flush_refusals(&self, all: bool) {
        let due = self.refusals.take_due(self.clock.now(), all);
        for (agent, tally) in due {
            self.write_tally(&agent, tally).await;
        }
    }

    async fn write_tally(&self, agent: &AgentName, tally: Tally) {
        let event = AuditEvent::RequestLimited {
            agent: agent.clone(),
            pending: tally.pending,
            rate: tally.rate,
        };
        if let Err(e) = self.audit.append(event).await {
            tracing::error!(agent = %agent, error = %e, "could not audit refused requests");
            self.refusals.restore(agent, tally);
        }
    }

    /// Tell the owner, once in a while, that `agent` is being refused. The
    /// notice names the agent and nothing it wrote, and links to the history.
    async fn send_limit_notice(&self, agent: &AgentName) {
        let Some(url) = history_link(&self.public_url) else {
            tracing::error!("public URL cannot be a base; not sending a limit notice");
            return;
        };
        let bell = Doorbell {
            title: format!("warden: {agent} is over its request limit"),
            message: "Its new requests are being refused for now. If you do not expect this \
                      many, check its history or revoke the agent."
                .to_owned(),
            url,
        };
        let event = match self.notifier.ring(&bell).await {
            Ok(channel) => AuditEvent::LimitNotified {
                agent: agent.clone(),
                channel: channel.to_owned(),
            },
            Err(e) => {
                tracing::warn!(agent = %agent, error = %e, "request limit notice failed");
                AuditEvent::Error {
                    context: "request limit notice".to_owned(),
                    message: format!("{agent}: {e}"),
                }
            }
        };
        if let Err(e) = self.audit.append(event).await {
            tracing::error!(agent = %agent, error = %e, "could not audit a request limit notice");
        }
    }
}

/// The owner's request history under `public_url`.
fn history_link(public_url: &Url) -> Option<Url> {
    let mut url = public_url.clone();
    url.path_segments_mut().ok()?.pop_if_empty().push("history");
    Some(url)
}

#[cfg(test)]
mod tests {
    use std::future::{Future as _, poll_fn};
    use std::task::Poll;

    use sqlx::Row as _;
    use url::Url;
    use warden_broker_proto::{AgentName, Window};

    use super::{
        AUDIT_EVERY_SECS, LimitRefusal, NEW_AT_LIMIT, NOTICE_EVERY_SECS, PENDING_AT_LIMIT,
        Refusals, RequestError, RequestLimits, Steps, Tally, check, due, history_link, wait_until,
    };
    use crate::requests::Clock as _;
    use crate::store;
    use crate::testkit::TestBroker;

    fn agent(name: &str) -> AgentName {
        name.parse().unwrap()
    }

    const PENDING: LimitRefusal = LimitRefusal::Pending {
        max: 1,
        retry_after_secs: 1,
    };
    const RATE: LimitRefusal = LimitRefusal::Rate {
        max: 1,
        window_secs: 60,
        retry_after_secs: 1,
    };

    const fn tally(pending: u64, rate: u64) -> Tally {
        Tally { pending, rate }
    }

    #[test]
    fn first_refusal_is_audited_and_told_then_held_back() {
        let refusals = Refusals::default();
        let bot = agent("bot");
        assert_eq!(
            refusals.note(&bot, PENDING, 1000),
            Steps {
                audit: Some(tally(1, 0)),
                notify: true
            }
        );
        for _ in 0..3 {
            assert_eq!(
                refusals.note(&bot, RATE, 1000 + AUDIT_EVERY_SECS - 1),
                Steps {
                    audit: None,
                    notify: false
                }
            );
        }
        assert_eq!(
            refusals.note(&bot, PENDING, 1000 + AUDIT_EVERY_SECS),
            Steps {
                audit: Some(tally(1, 3)),
                notify: false
            }
        );
    }

    #[test]
    fn notice_is_due_again_only_after_an_hour() {
        let refusals = Refusals::default();
        let bot = agent("bot");
        assert!(refusals.note(&bot, RATE, 1000).notify);
        assert!(
            !refusals
                .note(&bot, RATE, 1000 + NOTICE_EVERY_SECS - 1)
                .notify
        );
        assert!(refusals.note(&bot, RATE, 1000 + NOTICE_EVERY_SECS).notify);
    }

    #[test]
    fn one_agent_being_refused_changes_nothing_for_another() {
        let refusals = Refusals::default();
        assert!(refusals.note(&agent("bot"), RATE, 1000).notify);
        assert_eq!(
            refusals.note(&agent("other"), PENDING, 1000),
            Steps {
                audit: Some(tally(1, 0)),
                notify: true
            }
        );
    }

    #[test]
    fn a_tally_that_could_not_be_written_is_tried_again() {
        let refusals = Refusals::default();
        let bot = agent("bot");
        let Some(lost) = refusals.note(&bot, RATE, 1000).audit else {
            panic!("the first refusal is audited");
        };
        refusals.restore(&bot, lost);
        // Not on every refusal, which would flood the server log during an outage.
        assert_eq!(refusals.note(&bot, PENDING, 1001).audit, None);
        assert_eq!(
            refusals.note(&bot, PENDING, 1000 + AUDIT_EVERY_SECS).audit,
            Some(tally(2, 1))
        );
    }

    #[test]
    fn flush_takes_only_what_is_due_unless_asked_for_all() {
        let refusals = Refusals::default();
        let bot = agent("bot");
        let nothing: [(AgentName, Tally); 0] = [];
        refusals.note(&bot, RATE, 1000);
        // Recorded with the first refusal: nothing is held back.
        assert_eq!(refusals.take_due(1000 + AUDIT_EVERY_SECS, true), nothing);
        refusals.note(&bot, RATE, 1001);
        assert_eq!(refusals.take_due(1001, false), nothing);
        assert_eq!(
            refusals.take_due(1000 + AUDIT_EVERY_SECS, false),
            [(bot.clone(), tally(0, 1))]
        );
        assert_eq!(
            refusals.take_due(1000 + 2 * AUDIT_EVERY_SECS, false),
            nothing
        );
        refusals.note(&bot, PENDING, 1000 + AUDIT_EVERY_SECS + 1);
        assert_eq!(
            refusals.take_due(1000 + AUDIT_EVERY_SECS + 1, true),
            [(bot, tally(1, 0))]
        );
    }

    #[test]
    fn a_clock_set_back_makes_things_due_rather_than_silent() {
        assert!(due(Some(1000), 999, 60));
        assert!(due(None, 0, 60));
        assert!(!due(Some(1000), 1059, 60));
        assert!(due(Some(1000), 1060, 60));
    }

    #[test]
    fn waits_are_stated_within_bounds() {
        assert_eq!(wait_until(1100, 1000, 600), 100);
        assert_eq!(wait_until(1000, 1000, 600), 1);
        assert_eq!(wait_until(900, 1000, 600), 1);
        // A row dated far ahead of the clock.
        assert_eq!(wait_until(5000, 1000, 600), 600);
        assert_eq!(wait_until(i64::MAX, i64::MIN, 600), 600);
        assert_eq!(wait_until(i64::MIN, i64::MAX, 600), 1);
    }

    #[test]
    fn refusals_say_what_to_do_and_when() {
        let pending = LimitRefusal::Pending {
            max: 5,
            retry_after_secs: 90,
        };
        assert_eq!(pending.retry_after_secs(), 90);
        assert_eq!(
            pending.to_string(),
            "too many pending requests: at most 5 per agent. Cancel one or wait for the owner; a slot frees within 90 s"
        );
        let rate = LimitRefusal::Rate {
            max: 10,
            window_secs: 600,
            retry_after_secs: 42,
        };
        assert_eq!(rate.retry_after_secs(), 42);
        assert_eq!(
            rate.to_string(),
            "too many new requests: at most 10 every 600 s, cancelled ones included. Try again in 42 s"
        );
    }

    #[test]
    fn history_link_keeps_a_path_prefix() {
        let link = |base: &str| history_link(&Url::parse(base).unwrap()).unwrap();
        assert_eq!(
            link("https://warden.example.ts.net/").as_str(),
            "https://warden.example.ts.net/history"
        );
        assert_eq!(
            link("https://warden.example.ts.net/w/").as_str(),
            "https://warden.example.ts.net/w/history"
        );
    }

    #[tokio::test]
    async fn a_database_that_cannot_be_read_refuses_the_request() {
        let dir = tempfile::tempdir().unwrap();
        let pool = store::open(&dir.path().join("warden.db")).await.unwrap();
        let mut conn = pool.acquire().await.unwrap();
        sqlx::query("ALTER TABLE requests RENAME TO requests_gone")
            .execute(&mut *conn)
            .await
            .unwrap();
        let got = check(
            &mut conn,
            &RequestLimits::default(),
            &agent("bot"),
            "slot",
            1000,
        )
        .await;
        assert!(matches!(got, Err(RequestError::Db(_))), "{got:?}");
    }

    #[tokio::test]
    async fn limit_lookups_read_through_the_agent_index() {
        let dir = tempfile::tempdir().unwrap();
        let pool = store::open(&dir.path().join("warden.db")).await.unwrap();
        for sql in [PENDING_AT_LIMIT, NEW_AT_LIMIT] {
            // Test-only: `sql` is one of this module's constant queries.
            let steps: Vec<String> =
                sqlx::query(sqlx::AssertSqlSafe(format!("EXPLAIN QUERY PLAN {sql}")))
                    .bind("bot")
                    .bind(0_i64)
                    .bind(0_i64)
                    .bind(0_i64)
                    .fetch_all(&pool)
                    .await
                    .unwrap()
                    .iter()
                    .map(|row| row.get::<String, _>("detail"))
                    .collect();
            assert!(
                steps
                    .iter()
                    .any(|s| s.contains("INDEX requests_agent_created_at")),
                "{steps:?}"
            );
            // The index gives the order, so nothing is sorted or scanned.
            assert!(
                !steps.iter().any(|s| s.contains("TEMP B-TREE")),
                "{steps:?}"
            );
        }
    }

    /// A create that queued for the write lock counts what was added while it
    /// waited. If it read the clock before taking the lock, those rows would
    /// look newer than itself, be taken for the work of a clock set back, and
    /// go uncounted.
    #[tokio::test]
    async fn a_create_queued_for_the_write_lock_counts_what_it_waited_for() {
        let broker = TestBroker::with_request_limits(RequestLimits {
            max_pending: 10,
            max_new: 1,
            window_secs: 300,
        })
        .await;
        broker.add_agent("bot").await;
        let state = broker.state();

        let mut holder = state.pool.acquire().await.unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *holder)
            .await
            .unwrap();

        // One poll runs everything up to the wait for the lock, which `holder`
        // keeps from being granted, so any earlier clock read happens now.
        let bot = agent("bot");
        let req = TestBroker::api_request("github", "triage issue 42", Window::M15);
        let create = state
            .requests
            .insert(&bot, &req, "subject", "slot", "token");
        tokio::pin!(create);
        poll_fn(|cx| {
            assert!(create.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;

        broker.clock.advance(1);
        sqlx::query(
            "INSERT INTO requests (id, agent, fingerprint, dedupe_key, body, \
             approval_token_hash, status, created_at, expires_at) \
             VALUES ('earlier', 'bot', 'f', 'other-slot', '{}', 'h', 'pending', ?1, ?1 + 900)",
        )
        .bind(broker.clock.now())
        .execute(&mut *holder)
        .await
        .unwrap();
        sqlx::query("COMMIT").execute(&mut *holder).await.unwrap();

        assert!(matches!(
            create.await,
            Err(RequestError::Limited(LimitRefusal::Rate { .. }))
        ));
    }
}
