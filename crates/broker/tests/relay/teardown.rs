//! Teardown on revocation, expiry and idleness.

use std::time::{Duration, Instant};

use russh::ChannelMsg;
use serde_json::Value;
use warden_broker::relay::RelayLimits;
use warden_broker::requests::AuditOutcome;
use warden_broker::testkit::TestBroker;
use warden_broker::testkit::sshd::Sshd;
use warden_broker::testkit::wait::{self, HANG};
use warden_broker_proto::AgentName;

use super::{
    Connected, Setup, TARGET, approved_agent, assert_each_start_ended, audit_events, await_events,
    collect, events_of, hold_session, key_target, key_target_with, login, reply,
    reply_keeping_stderr, take_every_connection, text,
};

/// How often the relay checks the state of grants in the tests of outages,
/// instead of every second: the last successful check came about this long
/// before an outage began, plus any delay of the tick (see `FAIL_CLOSED_AFTER`).
const CHECK_EVERY: Duration = Duration::from_millis(100);

/// How long the relay may go without reading the state of grants before it
/// fails closed, in the test where every query fails at once (an unreadable
/// database): shorter than the 10 s default, and ten checks long.
///
/// The relay's timer runs from the last query that succeeded, which came up to
/// one check interval (plus any delay of a tick or of the query on a loaded
/// machine) before the test notices the outage. The test therefore requires
/// only half the window (`FAIL_CLOSED_AFTER / 2`) to have passed: a relay that
/// fails closed on the first failed query ends the session within a tick or
/// two (about 100 ms), far below that, while a delay of 500 ms or more would
/// be needed to fail the bound by chance.
const FAIL_CLOSED_AFTER: Duration = Duration::from_secs(1);

/// The longest a query may take in the test of an unreadable database, instead
/// of 1.5 s: a quarter of the window, so that a slow query before the outage
/// (an fsync on a loaded machine) cannot fail the relay closed on its own,
/// while the database is still readable.
const DB_QUERY_TIMEOUT: Duration = Duration::from_millis(250);

/// The window of the test that proves expiry needs no query: a tick runs
/// the expiry before it marks the grant state lost, so expiry shows only if
/// the clock is advanced before the window can elapse. With checks every
/// 100 ms, the first tick after the advance comes within 100 ms, a fifteenth
/// of the window, and even a delay of a second leaves the expiry first.
const EXPIRY_FIRST_WINDOW: Duration = Duration::from_millis(1500);

/// The longest a grant query may take in the test of a hung one, instead of
/// 1.5 s: past it the query counts as failed and the next tick asks again.
/// Well above a query that is not held up, which takes milliseconds.
const HUNG_QUERY_TIMEOUT: Duration = Duration::from_millis(500);

/// The wait of a revocation for its audit entries in the test of held appends,
/// instead of the 2 s of production.
const SHORT_WRITE_WAIT: Duration = Duration::from_millis(50);

/// Connections to `sshd` (the relay's onward ones) not yet ended, by its
/// log: each is named by its client port.
fn sshd_open_connections(sshd: &Sshd) -> usize {
    let port_of = |line: &str| {
        let rest = &line[line.find(" port ")? + 6..];
        let digits = rest.split(|c: char| !c.is_ascii_digit()).next()?;
        digits.parse::<u16>().ok()
    };
    let (mut opened, mut closed) = (
        std::collections::BTreeSet::new(),
        std::collections::BTreeSet::new(),
    );
    for line in sshd.log().lines() {
        let set = if line.starts_with("Connection from ") {
            &mut opened
        } else if [
            "Connection closed by",
            "Connection reset by",
            "Disconnected from",
            "Closing connection to",
        ]
        .iter()
        .any(|ended| line.contains(ended))
        {
            &mut closed
        } else {
            continue;
        };
        if let Some(port) = port_of(line) {
            set.insert(port);
        }
    }
    opened.difference(&closed).count()
}

/// Wait for the relay to have closed the agent's connection `c` and for
/// `sshd` to be down to `still_open` connections.
async fn assert_both_sides_closed(s: &Setup, c: &Connected, still_open: usize) {
    let deadline = Instant::now() + HANG;
    loop {
        let (agent_gone, onward) = (c.handle.is_closed(), sshd_open_connections(&s.sshd));
        if agent_gone && onward == still_open {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "agent connection closed: {agent_gone}, onward connections open: {onward}\n{}",
            s.sshd.log()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Exactly one `relay_session_ended` (per started session), all with
/// `reason`; then the relay still stops, adding no further end. The stop
/// returns only once every session task is done, so a duplicate end would
/// be on record by then.
async fn assert_ended_once_then_stop(s: &Setup, sessions: usize, reason: &str) {
    let ended = await_events(&s.broker, "relay_session_ended", sessions).await;
    for end in &ended {
        assert_eq!(end["reason"], reason, "{:?}", audit_events(&s.broker));
        assert_eq!(end["exit_status"], Value::Null);
    }
    wait::within_hang("the relay stopping", s.broker.stop_relay()).await;
    assert_eq!(
        events_of(&s.broker, "relay_session_ended").len(),
        sessions,
        "{:?}",
        audit_events(&s.broker)
    );
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_closes_live_session() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let (c, mut channel) = hold_session(&s, &agent.key).await;
    s.broker
        .state()
        .requests
        .revoke_grant(&agent.grant_id, "owner")
        .await
        .unwrap();
    assert_both_sides_closed(&s, &c, 0).await;
    let out = collect(&mut channel).await;
    assert!(
        text(&out.stderr).contains("warden relay: access revoked"),
        "{out:?}"
    );
    assert_ended_once_then_stop(&s, 1, "revoked").await;
}

/// Make every append to the broker's audit log fail from now on.
fn break_audit_log(broker: &TestBroker) {
    let mut log = std::fs::read(broker.audit_path()).unwrap();
    log.extend_from_slice(b"not an audit line\n");
    std::fs::write(broker.audit_path(), &log).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_closes_live_session_when_the_audit_log_cannot_be_written() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let (c, mut channel) = hold_session(&s, &agent.key).await;
    break_audit_log(&s.broker);
    let outcome = s
        .broker
        .state()
        .requests
        .revoke_grant(&agent.grant_id, "owner")
        .await
        .unwrap();
    assert_eq!(outcome, AuditOutcome::Missing);
    assert_both_sides_closed(&s, &c, 0).await;
    let out = collect(&mut channel).await;
    assert!(
        text(&out.stderr).contains("warden relay: access revoked"),
        "{out:?}"
    );
}

/// A revocation from another process, while a session waits to record its start,
/// holds once the log answers: nothing reaches the target.
#[tokio::test(flavor = "multi_thread")]
async fn revoked_while_a_session_waits_to_record_its_start_opens_nothing() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    let holder = std::fs::File::open(s.broker.audit_path()).unwrap();
    holder.lock().unwrap();
    channel.exec(true, "echo reached-the-target").await.unwrap();
    while s.broker.live_relay_bytes().is_empty() {
        tokio::task::yield_now().await;
    }
    let state = s.broker.state();
    warden_broker::requests::revoke_agent(
        &state.pool,
        &AgentName::try_from("bot".to_owned()).unwrap(),
        state.clock.now(),
    )
    .await
    .unwrap();
    drop(holder);
    let out = collect(&mut channel).await;
    assert!(!text(&out.stdout).contains("reached-the-target"), "{out:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_closes_live_session_while_audit_appends_are_held() {
    let s = key_target().await;
    s.broker
        .state()
        .requests
        .set_audit_write_wait(SHORT_WRITE_WAIT)
        .await;
    let agent = approved_agent(&s.broker, "bot").await;
    let (c, mut channel) = hold_session(&s, &agent.key).await;
    let audit = s.broker.state().audit.clone();
    let stall = audit.stall_appends(|_| true);
    let revoke = {
        let requests = s.broker.state().requests.clone();
        let grant = agent.grant_id.clone();
        tokio::spawn(async move { requests.revoke_grant(&grant, "owner").await })
    };
    assert_both_sides_closed(&s, &c, 0).await;
    let out = collect(&mut channel).await;
    assert!(
        text(&out.stderr).contains("warden relay: access revoked"),
        "{out:?}"
    );
    assert_eq!(revoke.await.unwrap().unwrap(), AuditOutcome::Missing);
    assert!(stall.holding() >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_revoke_closes_sessions_when_the_audit_log_cannot_be_written() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let (c, mut channel) = hold_session(&s, &agent.key).await;
    break_audit_log(&s.broker);
    let outcome = s
        .broker
        .state()
        .requests
        .revoke_agent(&AgentName::try_from("bot".to_owned()).unwrap())
        .await
        .unwrap();
    assert_eq!(outcome, AuditOutcome::Missing);
    assert_both_sides_closed(&s, &c, 0).await;
    let out = collect(&mut channel).await;
    assert!(
        text(&out.stderr).contains("warden relay: access revoked"),
        "{out:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn db_revoke_with_no_audit_log_closes_session_from_another_process() {
    let s = key_target_with(RelayLimits {
        grant_check_every: CHECK_EVERY,
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    let (c, mut channel) = hold_session(&s, &agent.key).await;
    break_audit_log(&s.broker);
    // `warden-server agent revoke`, which never needs the log to revoke.
    let state = s.broker.state();
    warden_broker::requests::revoke_agent(
        &state.pool,
        &AgentName::try_from("bot".to_owned()).unwrap(),
        state.clock.now(),
    )
    .await
    .unwrap();
    assert_both_sides_closed(&s, &c, 0).await;
    let out = collect(&mut channel).await;
    assert!(
        text(&out.stderr).contains("warden relay: access revoked"),
        "{out:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn expiry_closes_live_session() {
    let s = key_target_with(RelayLimits {
        grant_check_every: CHECK_EVERY,
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    let (c, _channel) = hold_session(&s, &agent.key).await;
    // Window 15 min: one second past it.
    s.broker.clock.advance(15 * 60 + 1);
    assert_both_sides_closed(&s, &c, 0).await;
    assert_ended_once_then_stop(&s, 1, "expired").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_revoke_closes_sessions() {
    let s = key_target().await;
    let bot = approved_agent(&s.broker, "bot").await;
    let other = approved_agent(&s.broker, "other").await;
    let (first, _first_channel) = hold_session(&s, &bot.key).await;
    let (second, _second_channel) = hold_session(&s, &bot.key).await;
    let (kept, kept_channel) = hold_session(&s, &other.key).await;
    s.broker
        .state()
        .requests
        .revoke_agent(&AgentName::try_from("bot".to_owned()).unwrap())
        .await
        .unwrap();
    assert_both_sides_closed(&s, &first, 1).await;
    assert_both_sides_closed(&s, &second, 1).await;
    let ended = await_events(&s.broker, "relay_session_ended", 2).await;
    for end in &ended {
        assert_eq!(end["grant_id"], bot.grant_id.as_str());
        assert_eq!(end["reason"], "revoked");
    }
    // The other agent's session goes on.
    assert!(!kept.handle.is_closed());
    kept_channel.data(&b"x"[..]).await.unwrap();
    assert_eq!(events_of(&s.broker, "relay_session_ended").len(), 2);
    wait::within_hang("the relay stopping", s.broker.stop_relay()).await;
    let ended = events_of(&s.broker, "relay_session_ended");
    assert_eq!(ended.len(), 3, "{:?}", audit_events(&s.broker));
    assert_eq!(ended[2]["grant_id"], other.grant_id.as_str());
    assert_eq!(ended[2]["reason"], "relay shutting down");
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn db_revoke_from_another_process_closes_session() {
    let s = key_target_with(RelayLimits {
        grant_check_every: CHECK_EVERY,
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    let (c, _channel) = hold_session(&s, &agent.key).await;
    // What `warden-server agent revoke` does from its own process: the
    // database changes, and the running relay is not told.
    let state = s.broker.state();
    warden_broker::requests::revoke_agent(
        &state.pool,
        &AgentName::try_from("bot".to_owned()).unwrap(),
        state.clock.now(),
    )
    .await
    .unwrap();
    assert_both_sides_closed(&s, &c, 0).await;
    assert_ended_once_then_stop(&s, 1, "revoked").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_session_times_out() {
    const IDLE: Duration = Duration::from_millis(750);
    let s = key_target_with(RelayLimits {
        idle_timeout: IDLE,
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    // Lines sent to `cat`, each once the one before came back, for half as
    // long again as the idle timeout: bytes move all along, never idle, so
    // it runs to its end although it lasts longer than the idle timeout.
    let busy = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = busy.handle.channel_open_session().await.unwrap();
    channel.exec(true, "cat").await.unwrap();
    assert!(reply(&mut channel).await);
    let busy_since = Instant::now();
    let (mut sent, mut echoed) = (0, 0);
    while busy_since.elapsed() < IDLE + IDLE / 2 {
        channel.data(&b"busy\n"[..]).await.unwrap();
        sent += 5;
        while echoed < sent {
            match wait::within_hang("the line echoed", channel.wait()).await {
                Some(ChannelMsg::Data { data }) => echoed += data.len(),
                Some(_) => {}
                None => panic!("the busy session ended after {:?}", busy_since.elapsed()),
            }
        }
    }
    channel.eof().await.unwrap();
    let out = collect(&mut channel).await;
    assert_eq!(out.exit_status, Some(0), "{out:?}");
    let ended = await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(ended[0]["reason"], "exited");

    // Silent for the idle timeout: ended, both sides closed. Not before the
    // idle timeout: its last byte came after `quiet`, so by then `quiet` is
    // at least that long ago, however slow the machine.
    let quiet = Instant::now();
    let (c, mut channel) = hold_session(&s, &agent.key).await;
    assert_both_sides_closed(&s, &c, 0).await;
    assert!(
        quiet.elapsed() >= IDLE,
        "ended before the idle timeout: {:?}",
        quiet.elapsed()
    );
    let out = collect(&mut channel).await;
    assert!(text(&out.stderr).contains("idle"), "{out:?}");
    let ended = await_events(&s.broker, "relay_session_ended", 2).await;
    assert_eq!(ended[1]["reason"], "idle timeout");
    wait::within_hang("the relay stopping", s.broker.stop_relay()).await;
    assert_eq!(events_of(&s.broker, "relay_session_ended").len(), 2);
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unstarted_authenticated_connection_is_closed() {
    let s = key_target_with(RelayLimits {
        start_timeout: Duration::from_secs(2),
        max_sessions_per_grant: 1,
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    // Logged in, a session channel open, never started. The start timeout
    // runs from the login, which is after `logging_in`.
    let logging_in = Instant::now();
    let idle = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let _channel = idle.handle.channel_open_session().await.unwrap();
    wait::until("the unstarted connection closed", || {
        idle.handle.is_closed()
    })
    .await;
    assert!(logging_in.elapsed() >= Duration::from_secs(2));
    // Nothing started, so nothing is recorded; its place is free again.
    assert_eq!(
        events_of(&s.broker, "relay_session_started"),
        [] as [serde_json::Value; 0]
    );
    assert_eq!(
        events_of(&s.broker, "relay_session_ended"),
        [] as [serde_json::Value; 0]
    );
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel.exec(true, "echo ok").await.unwrap();
    assert!(reply(&mut channel).await);
    assert_eq!(text(&collect(&mut channel).await.stdout), "ok\n");
    wait::within_hang("the relay stopping", s.broker.stop_relay()).await;
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn db_unreadable_fails_closed() {
    let s = key_target_with(RelayLimits {
        fail_closed_after: FAIL_CLOSED_AFTER,
        grant_check_every: CHECK_EVERY,
        grant_query_timeout: DB_QUERY_TIMEOUT,
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    let (running, mut running_channel) = hold_session(&s, &agent.key).await;
    // Logged in before the outage, its session not started yet.
    let waiting = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut waiting_channel = waiting.handle.channel_open_session().await.unwrap();

    // Every query fails from now on.
    s.broker.state().pool.close().await;
    let lost = Instant::now();
    // The session ends, both sides closed ...
    assert_both_sides_closed(&s, &running, 0).await;
    // ... not before the state has been unreadable for the window: the last
    // successful check came before `lost`, so only half the window is
    // required (see `FAIL_CLOSED_AFTER`).
    assert!(
        lost.elapsed() >= FAIL_CLOSED_AFTER / 2,
        "ended after {:?} of failures",
        lost.elapsed()
    );
    let out = collect(&mut running_channel).await;
    assert!(
        text(&out.stderr).contains("warden relay: access cannot be checked right now"),
        "{out:?}"
    );

    // A session cannot start meanwhile, on record.
    waiting_channel.exec(true, "echo ok").await.unwrap();
    let mut stderr = Vec::new();
    assert!(reply_keeping_stderr(&mut waiting_channel, &mut stderr).await);
    let out = collect(&mut waiting_channel).await;
    stderr.extend_from_slice(&out.stderr);
    assert!(out.stdout.is_empty(), "{out:?}");
    assert_eq!(out.exit_status, Some(255));
    assert!(
        text(&stderr).contains("warden relay: access cannot be checked right now"),
        "{}",
        text(&stderr)
    );
    let refused = await_events(&s.broker, "relay_session_refused", 1).await;
    assert_eq!(refused.len(), 1, "{:?}", audit_events(&s.broker));
    assert_eq!(refused[0]["reason"], "grant state unavailable");

    assert_ended_once_then_stop(&s, 1, "grant state unavailable").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hung_grant_query_still_fails_closed_and_expires() {
    let s = key_target_with(RelayLimits {
        fail_closed_after: EXPIRY_FIRST_WINDOW,
        grant_check_every: CHECK_EVERY,
        grant_query_timeout: HUNG_QUERY_TIMEOUT,
        ..RelayLimits::default()
    })
    .await;
    // `bot`'s grant ends 10 minutes before `other`'s.
    let expiring = approved_agent(&s.broker, "bot").await;
    s.broker.clock.advance(600);
    let other = approved_agent(&s.broker, "other").await;
    let (ending, _ending_channel) = hold_session(&s, &expiring.key).await;
    let (kept, _kept_channel) = hold_session(&s, &other.key).await;

    // Every connection of the pool taken: from now on a grant query waits
    // for one (sqlx's 30 s acquire timeout), as on a hung disk. The last
    // successful check came before this, so only half the window is required
    // below (the reasoning at `FAIL_CLOSED_AFTER` holds for `EXPIRY_FIRST_WINDOW`).
    let hung = Instant::now();
    let held = take_every_connection(&s.broker).await;

    // `bot`'s window ends: expiry needs no query, so it is not held up.
    s.broker.clock.advance(15 * 60 - 600 + 1);
    assert_both_sides_closed(&s, &ending, 1).await;
    let ended = await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(ended[0]["grant_id"], expiring.grant_id.as_str());
    assert_eq!(ended[0]["reason"], "expired");

    // `other`'s session ends once no query has succeeded for the window:
    // not before half the window after the queries started hanging.
    assert_both_sides_closed(&s, &kept, 0).await;
    assert!(
        hung.elapsed() >= EXPIRY_FIRST_WINDOW / 2,
        "failed closed too early: {:?}",
        hung.elapsed()
    );
    let ended = await_events(&s.broker, "relay_session_ended", 2).await;
    assert_eq!(ended[1]["grant_id"], other.grant_id.as_str());
    assert_eq!(ended[1]["reason"], "grant state unavailable");

    drop(held);
    wait::within_hang("the relay stopping", s.broker.stop_relay()).await;
    assert_eq!(events_of(&s.broker, "relay_session_ended").len(), 2);
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn connection_closed_once_its_session_is_over() {
    let s = key_target_with(RelayLimits {
        stall_timeout: Duration::from_secs(2),
        // Past the deadline below, so that only the session being over can
        // close the connection in time.
        start_timeout: Duration::from_secs(600),
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    // The start is refused (the grant was revoked after login) ...
    s.broker
        .state()
        .requests
        .revoke_grant(&agent.grant_id, "owner")
        .await
        .unwrap();
    let asked = Instant::now();
    channel.exec(true, "echo ok").await.unwrap();
    let mut stderr = Vec::new();
    assert!(reply_keeping_stderr(&mut channel, &mut stderr).await);
    let out = collect(&mut channel).await;
    assert_eq!(out.exit_status, Some(255), "{out:?}");
    // ... and the agent keeps the connection: the relay hangs up once it
    // has had the stall timeout (2 s here) to leave, counted from the
    // refusal, which came after `asked`.
    wait::until("the connection closed", || c.handle.is_closed()).await;
    assert!(
        asked.elapsed() >= Duration::from_secs(2),
        "{:?}",
        asked.elapsed()
    );
    assert_eq!(events_of(&s.broker, "relay_session_refused").len(), 1);
    assert_eq!(
        events_of(&s.broker, "relay_session_started"),
        [] as [serde_json::Value; 0]
    );
    wait::within_hang("the relay stopping", s.broker.stop_relay()).await;
}
