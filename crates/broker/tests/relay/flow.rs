//! Data through a session: large transfers, slow and wedged readers, an
//! agent that leaves or stays, and each session ended exactly once.

use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt as _;
use warden_broker::policy::RelayCredential;
use warden_broker::relay::RelayLimits;

use super::{
    Agent, OpenSsh, Setup, TARGET, approved_agent, assert_each_start_ended, audit_events,
    await_events, await_events_within, collect, events_of, key_target, key_target_with, login, nas,
    nas_pinned, openssh_private, random_key, reply, text, too_many,
};

#[tokio::test(flavor = "multi_thread")]
async fn large_transfers_both_ways() {
    use sha2::{Digest as _, Sha256};
    const SIZE: usize = 16 * 1024 * 1024;
    // All eight log in at once, from one address.
    let s = key_target_with(RelayLimits {
        max_unauthenticated_per_ip: 10,
        ..RelayLimits::default()
    })
    .await;
    let agents = [
        approved_agent(&s.broker, "bot").await,
        approved_agent(&s.broker, "other").await,
    ];
    // Eight sessions at once (four per grant), each sending 16 MiB of
    // incompressible bytes up through `cat` and reading them back: both
    // directions of every session run against full windows and queues at
    // the same time, which is when the two connections could stall each
    // other.
    let mut transfers = Vec::new();
    for i in 0..8 {
        let ssh = OpenSsh::new(&s.broker, s.relay, &agents[i % 2].key);
        transfers.push(tokio::spawn(async move {
            let mut payload = vec![0_u8; SIZE];
            getrandom::fill(&mut payload).unwrap();
            let out = ssh.run_as(TARGET, &[], &["cat"], &payload).await;
            assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
            assert_eq!(out.stdout.len(), payload.len());
            assert_eq!(Sha256::digest(&out.stdout), Sha256::digest(&payload));
        }));
    }
    for transfer in transfers {
        if let Err(e) = transfer.await {
            panic!("{e}: {:?}", events_of(&s.broker, "relay_session_ended"));
        }
    }
    for ended in await_events(&s.broker, "relay_session_ended", 8).await {
        assert_eq!(ended["reason"], "exited");
        assert_eq!(ended["bytes_to_target"], SIZE);
        assert_eq!(ended["bytes_from_target"], SIZE);
    }
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_agent_gets_the_end_of_its_output() {
    const SIZE: usize = 1024 * 1024;
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    // Less than the client's window: the relay hands all of it over, with
    // the exit status and the close, and its session is over. The agent
    // takes its output only well after that, as over a slow link or with a
    // busy reader.
    let child = ssh
        .command(TARGET, &[], &["head", "-c", &SIZE.to_string(), "/dev/zero"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let ended = await_events(&s.broker, "relay_session_ended", 1).await;
    assert_eq!(ended[0]["reason"], "exited", "{ended:?}");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // It still gets every byte and the exit status, not a hang-up.
    let out = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
        .await
        .expect("ssh finished")
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(out.stdout.len(), SIZE);
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_that_stays_after_its_session_is_hung_up() {
    let s = key_target_with(RelayLimits {
        stall_timeout: Duration::from_secs(2),
        max_sessions_per_grant: 1,
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel.exec(true, "echo ok").await.unwrap();
    assert!(reply(&mut channel).await);
    let out = collect(&mut channel).await;
    assert_eq!(
        (text(&out.stdout).as_str(), out.exit_status),
        ("ok\n", Some(0))
    );
    let over = Instant::now();
    await_events(&s.broker, "relay_session_ended", 1).await;

    // The session is over but the agent stays: until it is hung up, it
    // keeps its place.
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    too_many(
        &ssh.run(&["true"]).await,
        "warden relay: too many sessions for this grant",
    );
    let deadline = over + Duration::from_secs(2 + 5);
    while !c.handle.is_closed() {
        assert!(Instant::now() < deadline, "the relay kept the connection");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(over.elapsed() >= Duration::from_millis(1500));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let out = ssh.run(&["echo", "ok"]).await;
        if out.status.success() {
            assert_eq!(text(&out.stdout), "ok\n");
            break;
        }
        assert!(Instant::now() < deadline, "{}", text(&out.stderr));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_each_start_ended(&s.broker).await;
}

/// How much input an agent has got rid of so far, in MiB.
struct Fed(Arc<AtomicUsize>);

impl Fed {
    fn mib(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }
}

/// An agent running `cat` on the target that feeds it input and never reads
/// the output (see [`feed_until_held`]).
async fn wedge(ssh: &OpenSsh) -> (tokio::process::Child, tokio::process::ChildStdout, Fed) {
    feed_until_held(ssh, &["cat"]).await
}

/// An agent running `remote` on the target that never reads the output and
/// goes on feeding input, up to 96 MiB, until its input stops being accepted
/// or `ssh` is gone. Returns the ssh child, its unread stdout and what it fed.
///
/// A pause in the feed proves nothing: `ssh` takes nothing beyond its stdin
/// pipe until it has logged in, however long that takes, and less than a
/// window of input would all reach it, leaving no data held anywhere. So the
/// feed runs by itself, whatever this returns, and the data ends up held.
/// This returns once the agent has logged in (it got rid of more than the
/// pipe holds) and the feed has paused for a second, which is usually the
/// input being held; a test must wait for what follows from that, not assume
/// it has happened.
async fn feed_until_held(
    ssh: &OpenSsh,
    remote: &[&str],
) -> (tokio::process::Child, tokio::process::ChildStdout, Fed) {
    let mut child = ssh
        .command(TARGET, &[], remote)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let fed = Arc::new(AtomicUsize::new(0));
    let feeder = tokio::spawn({
        let fed = Arc::clone(&fed);
        async move {
            let chunk = vec![0_u8; 1 << 20];
            while fed.load(Ordering::Acquire) < 96 {
                if input.write_all(&chunk).await.is_err() {
                    return;
                }
                fed.fetch_add(1, Ordering::AcqRel);
            }
            // Stdin stays open, as a stuck agent's would.
            std::future::pending::<()>().await;
        }
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let (mut seen, mut since) = (0, Instant::now());
    while !feeder.is_finished() {
        let count = fed.load(Ordering::Acquire);
        if count != seen {
            (seen, since) = (count, Instant::now());
        } else if seen > 0 && since.elapsed() >= Duration::from_secs(1) {
            break;
        }
        assert!(Instant::now() < deadline, "the agent never got to feed");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (child, stdout, Fed(fed))
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_disconnect_ends_wedged_session() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let (mut child, stdout, _) = wedge(&ssh).await;
    child.kill().await.unwrap();
    drop(stdout);
    let gone = Instant::now();
    let ended = tokio::time::timeout(
        Duration::from_secs(5),
        await_events(&s.broker, "relay_session_ended", 1),
    )
    .await
    .expect("the session ended within 5 s of the agent leaving");
    // Either the agent leaving or the wedge itself ends the session (the
    // wedge may have done so already).
    let reason = ended[0]["reason"].as_str().unwrap();
    assert!(
        reason == "client closed" || reason == "flow control: both directions held up",
        "{reason} after {:?}",
        gone.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_disconnect_with_stalled_target_ends_quickly() {
    // Default limits: the stall watchdog would take 60 s, and with nothing
    // coming back from the target the wedge watchdog never fires.
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    // `sleep` never reads its input: the agent's input fills the target's
    // window, the relay's queue and the agent's window, and stops there.
    let (mut child, stdout, fed) = feed_until_held(&ssh, &["sleep", "600"]).await;
    assert!(fed.mib() < 32, "{} MiB accepted", fed.mib());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        events_of(&s.broker, "relay_session_ended").is_empty(),
        "{:?}",
        audit_events(&s.broker)
    );
    child.kill().await.unwrap();
    drop(stdout);
    let gone = Instant::now();
    let ended = tokio::time::timeout(
        Duration::from_secs(5),
        await_events(&s.broker, "relay_session_ended", 1),
    )
    .await
    .expect("the session ended within 5 s of the agent leaving");
    assert_eq!(
        ended[0]["reason"],
        "client closed",
        "after {:?}",
        gone.elapsed()
    );
    assert_each_start_ended(&s.broker).await;
    assert_eq!(events_of(&s.broker, "relay_session_ended").len(), 1);
}

/// A session whose input has been held for longer than the agent-left
/// grace (2 s), ended by the relay with `end`: the reason on record is the
/// one the relay gave, not the agent leaving because the relay cut it.
async fn held_session_ended_by_relay(end: impl AsyncFnOnce(&Setup, &Agent), reason: &str) {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let (_child, _stdout, fed) = feed_until_held(&ssh, &["sleep", "600"]).await;
    assert!(fed.mib() < 32, "{} MiB accepted", fed.mib());
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        events_of(&s.broker, "relay_session_ended").is_empty(),
        "{:?}",
        audit_events(&s.broker)
    );
    end(&s, &agent).await;
    let ended = tokio::time::timeout(
        Duration::from_secs(10),
        await_events(&s.broker, "relay_session_ended", 1),
    )
    .await
    .expect("the session ended");
    assert_eq!(ended[0]["reason"], reason, "{:?}", audit_events(&s.broker));
    s.broker.stop_relay().await;
    assert_eq!(events_of(&s.broker, "relay_session_ended").len(), 1);
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_relay_wins_over_the_agent_leaving() {
    held_session_ended_by_relay(
        async |s, _| {
            tokio::time::timeout(Duration::from_secs(10), s.broker.stop_relay())
                .await
                .expect("the relay stopped promptly");
        },
        "relay shutting down",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_wins_over_the_agent_leaving() {
    held_session_ended_by_relay(
        async |s, agent| {
            s.broker
                .state()
                .requests
                .revoke_grant(&agent.grant_id, "owner")
                .await
                .unwrap();
        },
        "revoked",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_relay_completes_with_wedged_session() {
    // The wedge is left in place (no wedge timeout) for the stop to meet.
    let s = key_target_with(RelayLimits {
        wedge_timeout: Duration::from_secs(600),
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let (_child, _stdout, _) = wedge(&ssh).await;
    tokio::time::timeout(Duration::from_secs(10), s.broker.stop_relay())
        .await
        .expect("stop_relay finished within 10 s");
    let ended = events_of(&s.broker, "relay_session_ended");
    assert_eq!(ended.len(), 1, "{:?}", audit_events(&s.broker));
    assert_eq!(ended[0]["reason"], "relay shutting down");
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_not_reading_output_ends_session() {
    // The wedge watchdog is kept out of the way: this is the stall rule.
    let s = key_target_with(RelayLimits {
        stall_timeout: Duration::from_secs(3),
        wedge_timeout: Duration::from_secs(600),
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    let started = Instant::now();
    let (mut child, _stdout, fed) = wedge(&ssh).await;
    // The stuck output ends the session, while the agent is still there.
    let ended =
        await_events_within(&s.broker, "relay_session_ended", 1, Duration::from_secs(60)).await;
    assert_eq!(
        ended[0]["reason"],
        "flow control: output to the agent not drained",
        "after {:?}",
        started.elapsed()
    );
    // The agent's input was held back by its window once the queues were
    // full: well short of the 96 MiB it tried to send. What it got rid of
    // sat in the relay's two queues (2 MiB and 8 MiB), the SSH windows and
    // socket buffers on both connections, and `cat`.
    assert!(fed.mib() < 32, "{} MiB accepted", fed.mib());
    // And the agent's connection is closed.
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("ssh exited")
        .unwrap();
    assert!(!status.success());
    assert_each_start_ended(&s.broker).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pty_full_environment_and_window_changes_fit_before_start() {
    let s = key_target().await;
    let agent = approved_agent(&s.broker, "bot").await;
    let c = login(&s.broker, s.relay, TARGET, &agent.key).await;
    let mut channel = c.handle.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    assert!(reply(&mut channel).await);
    // The most variables the relay passes on (16), each answered.
    for i in 0..16 {
        channel
            .set_env(true, format!("LC_V{}", char::from(b'A' + i)), "C")
            .await
            .unwrap();
        assert!(reply(&mut channel).await, "variable {i}");
    }
    // A 17th is refused, but the session goes on.
    channel.set_env(true, "LANG", "C").await.unwrap();
    assert!(!reply(&mut channel).await);
    for cols in [90, 100, 110, 120, 132] {
        channel.window_change(cols, 40, 0, 0).await.unwrap();
    }
    channel.exec(true, "stty size").await.unwrap();
    assert!(reply(&mut channel).await);
    let out = collect(&mut channel).await;
    assert!(text(&out.stdout).contains("40 132"), "{out:?}");
    assert_eq!(out.exit_status, Some(0));
}

#[tokio::test(flavor = "multi_thread")]
async fn every_started_session_has_exactly_one_end() {
    let s = key_target_with(RelayLimits {
        stall_timeout: Duration::from_secs(2),
        ..RelayLimits::default()
    })
    .await;
    let agent = approved_agent(&s.broker, "bot").await;
    let ssh = OpenSsh::new(&s.broker, s.relay, &agent.key);
    // A command that exits, one killed by a signal, a session the agent
    // leaves mid-way, one that stalls, a refused onward login, a host key
    // mismatch, and one the relay stops in the middle of.
    ssh.run(&["echo", "ok"]).await;
    ssh.run(&["kill -TERM $$"]).await;
    let mut leaving = ssh
        .command(TARGET, &[], &["sleep", "30"])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    await_events(&s.broker, "relay_session_started", 3).await;
    leaving.kill().await.unwrap();
    let (mut stalled, _stdout, _) = wedge(&ssh).await;
    await_events(&s.broker, "relay_session_ended", 4).await;
    stalled.kill().await.unwrap();
    s.broker.backend.set_relay_target(
        nas(&s.sshd),
        RelayCredential::Key(openssh_private(&random_key())),
    );
    ssh.run(&["true"]).await;
    // A host key mismatch needs a grant approved for the wrong pin: one
    // whose pin changed since approval is refused before connecting.
    s.broker.backend.set_relay_target(
        nas_pinned(&s.sshd, random_key().public_key().clone()),
        RelayCredential::Key(openssh_private(&s.onward)),
    );
    let mispinned = approved_agent(&s.broker, "other").await;
    OpenSsh::new(&s.broker, s.relay, &mispinned.key)
        .run(&["true"])
        .await;
    // Back to the destination `bot` was approved for.
    s.broker.backend.set_relay_target(
        nas(&s.sshd),
        RelayCredential::Key(openssh_private(&s.onward)),
    );
    let mut held = ssh
        .command(TARGET, &[], &["sleep", "30"])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    await_events(&s.broker, "relay_session_started", 7).await;
    s.broker.stop_relay().await;
    let _ = held.kill().await;
    assert_each_start_ended(&s.broker).await;
    assert_eq!(events_of(&s.broker, "relay_session_ended").len(), 7);
}
