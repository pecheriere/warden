//! The live sessions listing, and the limits on sessions and on
//! connections logging in.

use std::time::{Duration, Instant};

use russh::{ChannelMsg, Disconnect};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use warden_broker::relay::RelayLimits;
use warden_broker::requests::Clock as _;

use super::{
    OpenSsh, TARGET, approved_agent, assert_each_start_ended, await_events, collect, events_of,
    hold_session, key_target, key_target_daily, key_target_with, login, reply, text, too_many,
};

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_counts_bytes() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel.exec(true, "cat").await.unwrap();
    assert!(reply(&mut channel).await);
    assert_eq!(s.broker.live_relay_bytes().len(), 1);

    channel.data(&b"hello"[..]).await.unwrap();
    let mut echoed = 0;
    while echoed < 5 {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => echoed += data.len(),
            Some(_) => {}
            None => panic!("the session ended before echoing"),
        }
    }
    // The echo was delivered to the agent, so both counts are final.
    assert_eq!(s.broker.live_relay_bytes(), vec![(5, 5)]);

    channel.close().await.unwrap();
    await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(s.broker.live_relay_bytes(), [] as [(u64, u64); 0]);
}

/// A session's last activity stays while nothing moves and follows the bytes
/// that move, by the broker's clock.
#[tokio::test(flavor = "multi_thread")]
async fn snapshot_tracks_last_activity() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel.exec(true, "cat").await.unwrap();
    assert!(reply(&mut channel).await);
    let started = s.broker.clock.now();
    assert_eq!(s.broker.live_relay_last_activity(), vec![started]);

    s.broker.clock.advance(100);
    assert_eq!(s.broker.live_relay_last_activity(), vec![started]);

    channel.data(&b"hello"[..]).await.unwrap();
    // The watchdog notes it at its next check.
    let deadline = Instant::now() + Duration::from_secs(15);
    while s.broker.live_relay_last_activity() != vec![started + 100] {
        assert!(
            Instant::now() < deadline,
            "last activity never moved: {:?}",
            s.broker.live_relay_last_activity()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    channel.close().await.unwrap();
    await_events(&s.broker, "relay_session_ended", 1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrency_limits_enforced() {
    let s = key_target_with(RelayLimits {
        max_sessions: 5,
        ..RelayLimits::default()
    })
    .await;
    let a = approved_agent(&s.broker, "a").await;
    let b = approved_agent(&s.broker, "b").await;

    // 4 sessions per grant.
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(hold_session(&s, &a.key).await);
    }
    let ssh_a = OpenSsh::new(&s.broker, s.relay, &a.key);
    too_many(
        &ssh_a.run(&["true"]).await,
        "warden relay: too many sessions for this grant",
    );

    // 5 overall (configured): b gets one, then none.
    held.push(hold_session(&s, &b.key).await);
    let ssh_b = OpenSsh::new(&s.broker, s.relay, &b.key);
    too_many(
        &ssh_b.run(&["true"]).await,
        "warden relay: too many relay sessions",
    );

    // Ending a session frees its place.
    let (c, channel) = held.remove(0);
    drop(channel);
    c.handle
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let out = ssh_b.run(&["echo", "ok"]).await;
        if out.status.success() {
            assert_eq!(text(&out.stdout), "ok\n");
            break;
        }
        assert!(Instant::now() < deadline, "{}", text(&out.stderr));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    drop(held);
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_connections_limited_and_timed_out() {
    let s = key_target_with(RelayLimits {
        max_unauthenticated_per_ip: 2,
        auth_timeout: Duration::from_secs(2),
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;

    // Two stalled connections take this address's pre-login places: one
    // says nothing, the other stops after the version exchange.
    let mut silent = Vec::new();
    for version in [None, Some(b"SSH-2.0-stalled\r\n")] {
        let mut conn = TcpStream::connect(s.relay).await.unwrap();
        let mut banner = [0_u8; 8];
        conn.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"SSH-2.0-");
        if let Some(version) = version {
            conn.write_all(version).await.unwrap();
        }
        silent.push(conn);
    }
    // A third is closed at once, without a banner.
    let mut third = TcpStream::connect(s.relay).await.unwrap();
    let mut buf = [0_u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(1), third.read(&mut buf))
        .await
        .expect("closed at once")
        .unwrap_or(0);
    assert_eq!(n, 0);

    // The stalled ones are cut off after the login timeout (2 s) and the
    // goodbye wait (5 s) ...
    for conn in &mut silent {
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(12), conn.read_to_end(&mut rest))
            .await
            .expect("closed after the login timeout")
            .ok();
    }
    // ... which frees their places.
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel.exec(true, "echo ok").await.unwrap();
    assert!(reply(&mut channel).await);
    assert_eq!(text(&collect(&mut channel).await.stdout), "ok\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_ends_live_sessions_audited() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let (_c, mut channel) = hold_session(&s, &agent.key).await;
    s.broker.stop_relay().await;
    let out = collect(&mut channel).await;
    assert_eq!(out.exit_status, None);
    let ended = await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(ended[0]["reason"], "relay shutting down");
    assert_each_start_ended(&s.broker).await;
}

const SESSION_LIMIT_MESSAGE: &str =
    "this grant reached its daily limit of sessions; new sessions fail until 00:00 UTC";

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_grant_stops_at_its_daily_session_limit_and_the_owner_hears_once() {
    let s = key_target_daily(2, RelayLimits::default()).await;
    // A grant of its own, made a minute before a UTC midnight: it lasts past the
    // start of the next day, which its window could not otherwise reach.
    let now = s.broker.clock.now();
    s.broker.clock.advance(86_400 - 60 - now.rem_euclid(86_400));
    let agent = approved_agent(&s.broker, "late").await;
    let other = approved_agent(&s.broker, "other").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    for _ in 0..2 {
        let out = ssh.run(&["echo", "ok"]).await;
        assert_eq!(text(&out.stdout), "ok\n", "{}", text(&out.stderr));
    }

    let out = ssh.run(&["echo", "ok"]).await;
    assert_ne!(out.status.code(), Some(0));
    assert!(
        text(&out.stderr).contains(SESSION_LIMIT_MESSAGE),
        "{}",
        text(&out.stderr)
    );
    let bell = s.broker.capture.next().await;
    assert_eq!(bell.title, "warden: late reached its relay session limit");
    assert!(
        bell.message.contains("It opened 2 sessions to nas today"),
        "{}",
        bell.message
    );
    assert_ne!(ssh.run(&["echo", "ok"]).await.status.code(), Some(0));
    let reached = await_events(&s.broker, "relay_session_limit_reached", 1).await;
    assert_eq!(reached.len(), 1, "once a day");
    assert_eq!(reached[0]["grant_id"], agent.grant_id.as_str());
    assert_eq!(reached[0]["limit"], 2);
    // Refused sessions are in the log, and none of them started.
    assert_eq!(events_of(&s.broker, "relay_session_started").len(), 2);
    let refused = events_of(&s.broker, "relay_session_refused");
    assert_eq!(refused.len(), 2);
    assert_eq!(refused[0]["reason"], "daily_limit");

    // Per grant: another agent's sessions go on.
    let theirs = OpenSsh::new(&s.broker, s.relay, &other.key)
        .run(&["echo", "ok"])
        .await;
    assert_eq!(text(&theirs.stdout), "ok\n", "{}", text(&theirs.stderr));

    // The next UTC day starts again, and can be told about again.
    s.broker.clock.advance(120);
    for _ in 0..2 {
        let out = ssh.run(&["echo", "ok"]).await;
        assert_eq!(text(&out.stdout), "ok\n", "{}", text(&out.stderr));
    }
    assert_ne!(ssh.run(&["echo", "ok"]).await.status.code(), Some(0));
    await_events(&s.broker, "relay_session_limit_reached", 2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_sessions_at_the_daily_limit_pass_exactly_the_limit() {
    let s = key_target_daily(
        3,
        RelayLimits {
            max_sessions_per_grant: 8,
            ..RelayLimits::default()
        },
    )
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let outs = tokio::join!(
        ssh.run(&["echo", "ok"]),
        ssh.run(&["echo", "ok"]),
        ssh.run(&["echo", "ok"]),
        ssh.run(&["echo", "ok"]),
        ssh.run(&["echo", "ok"]),
    );
    let outs = [outs.0, outs.1, outs.2, outs.3, outs.4];
    let ok = outs.iter().filter(|o| text(&o.stdout) == "ok\n").count();
    assert_eq!(ok, 3);
    assert_eq!(events_of(&s.broker, "relay_session_started").len(), 3);
    let refused = events_of(&s.broker, "relay_session_refused");
    assert_eq!(refused.len(), 2);
    assert!(refused.iter().all(|e| e["reason"] == "daily_limit"));
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_sessions_beyond_the_allowance_are_counted() {
    let s = key_target_daily(1, RelayLimits::default()).await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let out = ssh.run(&["echo", "ok"]).await;
    assert_eq!(text(&out.stdout), "ok\n", "{}", text(&out.stderr));
    for _ in 0..35 {
        assert_ne!(ssh.run(&["echo", "ok"]).await.status.code(), Some(0));
    }
    assert_eq!(events_of(&s.broker, "relay_session_refused").len(), 30);
    assert_eq!(
        events_of(&s.broker, "relay_sessions_refused_held"),
        [] as [serde_json::Value; 0]
    );
    s.broker.state().requests.flush_refusals(true).await;
    let held = events_of(&s.broker, "relay_sessions_refused_held");
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0]["grant_id"], agent.grant_id.as_str());
    assert_eq!(held[0]["count"], 5);
}
