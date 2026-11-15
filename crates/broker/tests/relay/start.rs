//! A session being set up: a stop, a revocation or a slow lookup on the
//! way, and input sent before it starts.

use std::time::{Duration, Instant};

use russh::Disconnect;
use russh::client::AuthResult;
use warden_broker::policy::RelayCredential;
use warden_broker::relay::RelayLimits;
use warden_broker::requests::Clock as _;
use warden_broker::testkit::wait::{self, HANG};

use super::{
    Agent, Collected, Connected, OpenSsh, Setup, TARGET, approved_agent, audit_events,
    await_events, collect, connect, events_of, key_target, key_target_with, login, nas,
    openssh_private, reply_keeping_stderr, russh_key, sshd_connections, take_every_connection,
    text,
};

/// How long a slow secret backend takes to read a relay target: longer than
/// any test waits, so that only the relay's own bound can end the wait.
const SLOW_READ: Duration = HANG.saturating_mul(2);

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_during_onward_setup_records_end() {
    let s = key_target_with(RelayLimits {
        onward_timeout: Duration::from_secs(600),
        ..RelayLimits::default()
    })
    .await;
    // The target accepts TCP connections but never speaks SSH, so the
    // relay is stuck connecting onward, for far longer than the stop below
    // is given.
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut target = nas(&s.sshd);
    target.port = silent.local_addr().unwrap().port();
    s.broker
        .backend
        .set_relay_target(target, RelayCredential::Key(openssh_private(&s.onward)));
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let client = tokio::spawn(async move { ssh.run(&["true"]).await });
    let (_held, _) = silent.accept().await.unwrap();
    await_events(&s.broker, "relay_session_started", 1).await;

    wait::within_hang(
        "the relay stopping without waiting for the onward connection",
        s.broker.stop_relay(),
    )
    .await;
    // The stop returns only once the session's end is on record.
    let ended = events_of(&s.broker, "relay_session_ended");
    assert_eq!(ended.len(), 1, "{:?}", audit_events(&s.broker));
    assert_eq!(ended[0]["reason"], "relay shutting down");
    assert_eq!(ended[0]["grant_id"], agent.grant_id.as_str());
    let out = client.await.unwrap();
    assert_ne!(out.status.code(), Some(0));
}

/// Log `agent` in, open its session channel and ask for `echo ok`; the
/// reply and everything after it are collected on a task. Returns the
/// connection, the task, and when the start was asked for.
async fn exec_in_background(
    s: &Setup,
    agent: &Agent,
) -> (
    Connected,
    tokio::task::JoinHandle<(bool, Vec<u8>, Collected)>,
    Instant,
) {
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel.exec(true, "echo ok").await.unwrap();
    let asked = Instant::now();
    let task = tokio::spawn(async move {
        let mut stderr = Vec::new();
        let replied = reply_keeping_stderr(&mut channel, &mut stderr).await;
        let out = collect(&mut channel).await;
        stderr.extend_from_slice(&out.stderr);
        (replied, stderr, out)
    });
    (c, task, asked)
}

/// The session was refused once for `reason`, on record, before anything
/// started or reached the target. Stops the relay: the stop returns only
/// once every connection's task is done, so a duplicate would be on record.
async fn assert_refused_once(s: &Setup, reason: &str) {
    let refused = await_events(&s.broker, "relay_session_refused", 1).await;
    wait::within_hang("the relay stopping", s.broker.stop_relay()).await;
    let refused_now = events_of(&s.broker, "relay_session_refused");
    assert_eq!(refused_now.len(), 1, "{:?}", audit_events(&s.broker));
    assert_eq!(
        refused[0]["reason"],
        reason,
        "{:?}",
        audit_events(&s.broker)
    );
    assert_eq!(
        events_of(&s.broker, "relay_session_started"),
        [] as [serde_json::Value; 0]
    );
    assert_eq!(
        events_of(&s.broker, "relay_session_ended"),
        [] as [serde_json::Value; 0]
    );
    assert_eq!(sshd_connections(&s.sshd), 0, "{}", s.sshd.log());
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_during_slow_target_read_is_prompt() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    // The secret backend answers only after `SLOW_READ`, far past the bound.
    s.broker.backend.set_relay_read_delay(Some(SLOW_READ));
    let (_c, client, _) = exec_in_background(&s, &agent).await;
    wait::until("the target read began", || {
        s.broker.backend.relay_reads_started() > 0
    })
    .await;

    wait::within_hang("the relay stopping", s.broker.stop_relay()).await;
    // Refused, not started: so no end either. A stop held up by the read
    // would see it time out after 10 s, and be refused for that instead.
    assert_refused_once(&s, "relay shutting down").await;
    wait::within_hang("the agent got an answer or was hung up on", client)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_during_slow_target_read_refuses() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    s.broker.backend.set_relay_read_delay(Some(SLOW_READ));
    let (_c, client, _) = exec_in_background(&s, &agent).await;
    wait::until("the target read began", || {
        s.broker.backend.relay_reads_started() > 0
    })
    .await;

    s.broker
        .state()
        .requests
        .revoke_grant(&agent.grant_id, "owner")
        .await
        .unwrap();
    // A revocation held up by the read would see it time out after 10 s,
    // and be refused for that instead: the notice below tells them apart.
    let (replied, stderr, out) = wait::within_hang("the agent got an answer", client)
        .await
        .unwrap();
    assert!(replied);
    assert_eq!(out.exit_status, Some(255), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(
        text(&stderr).contains("warden relay: access revoked"),
        "{}",
        text(&stderr)
    );
    assert_refused_once(&s, "revoked").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_during_slow_grant_lookup_refuses() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    // Logged in, channel open: the next grant lookup is the session's.
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();

    // Every connection of the pool taken: a grant lookup now waits for one
    // (sqlx's 30 s acquire timeout), as on a hung disk. The grant is
    // revoked meanwhile through one of them, as by another process.
    let mut held = take_every_connection(&s.broker).await;
    let revoked = sqlx::query("UPDATE grants SET revoked_at = ? WHERE id = ?")
        .bind(s.broker.clock.now())
        .bind(agent.grant_id.as_str())
        .execute(&mut *held[0])
        .await
        .unwrap();
    assert_eq!(revoked.rows_affected(), 1);

    channel.exec(true, "echo ok").await.unwrap();
    let asked = Instant::now();
    let mut stderr = Vec::new();
    assert!(reply_keeping_stderr(&mut channel, &mut stderr).await);
    let out = collect(&mut channel).await;
    stderr.extend_from_slice(&out.stderr);
    // Bounded by the 1.5 s grant query timeout, not the pool's 30 s, which
    // would give the same refusal: as long as a loaded machine could need,
    // while still telling the two apart.
    assert!(
        asked.elapsed() < Duration::from_secs(20),
        "{:?}",
        asked.elapsed()
    );
    assert_eq!(out.exit_status, Some(255), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    assert!(
        text(&stderr).contains("warden relay: access cannot be checked right now"),
        "{}",
        text(&stderr)
    );
    drop(held);
    assert_refused_once(&s, "grant lookup failed").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn login_grant_lookup_is_bounded() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let mut c = connect(&s.broker, s.relay).await;

    // Every connection of the pool taken: the login's grant lookup waits
    // for one (sqlx's 30 s acquire timeout), as on a hung disk.
    let held = take_every_connection(&s.broker).await;

    let asked = Instant::now();
    let auth = c
        .handle
        .authenticate_publickey(TARGET, russh_key(&agent.key))
        .await;
    // Refused once the 1.5 s lookup bound (plus the 1 s rejection delay)
    // is over.
    assert!(
        matches!(auth, Ok(AuthResult::Failure { .. })),
        "{auth:?} after {:?}",
        asked.elapsed()
    );
    // Without that bound the 10 s login timeout has hung up by now, so this
    // fails on the closed connection.
    c.handle
        .disconnect(Disconnect::ByApplication, "", "en")
        .await
        .unwrap();

    // Audited like any refused login, without key material.
    let refused = await_events(&s.broker, "relay_login_refused", 1).await;
    assert_eq!(refused[0]["user"], TARGET, "{refused:?}");
    assert_eq!(refused[0]["attempts"], 1, "{refused:?}");
    let log = std::fs::read_to_string(s.broker.audit_path()).unwrap();
    let public = agent.key.public_key().to_openssh().unwrap();
    assert!(!log.contains(public.split(' ').nth(1).unwrap()));
    assert!(
        !log.contains(
            &agent
                .key
                .public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string()
        )
    );

    // Once the database answers again, the same key logs in.
    drop(held);
    login(&s.broker, s.relay, TARGET, &agent.key).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_target_read_is_refused_after_its_bound() {
    const READ_BOUND: Duration = Duration::from_secs(2);
    let s = key_target_with(RelayLimits {
        target_read_timeout: READ_BOUND,
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    s.broker.backend.set_relay_read_delay(Some(SLOW_READ));
    let (_c, client, asked) = exec_in_background(&s, &agent).await;
    // Refused rather than answered: the read itself takes `SLOW_READ`.
    let (replied, stderr, out) =
        wait::within_hang("refused once the target read took too long", client)
            .await
            .unwrap();
    // The read is given its bound.
    let waited = asked.elapsed();
    assert!(
        waited >= READ_BOUND.saturating_sub(Duration::from_millis(500)),
        "{waited:?}"
    );
    assert!(replied);
    assert_eq!(out.exit_status, Some(255), "{out:?}");
    assert!(
        text(&stderr).contains("warden relay: the target's policy cannot be read right now"),
        "{}",
        text(&stderr)
    );
    assert_refused_once(&s, "target lookup failed").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn input_flood_before_start_disconnects() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let channel = c.handle.channel_open_session().await.unwrap();
    // Data before any shell or exec, past the 32-message allowance.
    for _ in 0..40 {
        if channel.data_bytes(&b"x"[..]).await.is_err() {
            break;
        }
    }
    wait::until("the relay dropped the connection", || c.handle.is_closed()).await;
    let refused = await_events(&s.broker, "relay_session_refused", 1).await;
    assert_eq!(
        refused[0]["reason"],
        "too much input before the session started"
    );
    assert_eq!(refused[0]["grant_id"], agent.grant_id.as_str());
    assert_eq!(sshd_connections(&s.sshd), 0, "{}", s.sshd.log());

    // Bytes count too: one 70 KiB write is over the 64 KiB allowance.
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let channel = c.handle.channel_open_session().await.unwrap();
    let _ = channel.data_bytes(vec![b'y'; 70 * 1024]).await;
    wait::until("the relay dropped the connection", || c.handle.is_closed()).await;
    await_events(&s.broker, "relay_session_refused", 2).await;
}
