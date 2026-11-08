//! Tests of the relay loop's queues and watchdog: room and progress, an
//! agent that leaves, idleness, and stalled or wedged directions.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use std::time::Duration;

use super::super::reason;
use super::{Progress, Queue, Watch, agent_left, watchdog};

fn data(len: usize) -> russh::ChannelMsg {
    russh::ChannelMsg::Data {
        data: vec![0_u8; len].into(),
    }
}

#[tokio::test]
async fn queue_waits_for_room_and_reports_progress() {
    let progress = Arc::new(Progress::default());
    let (queue, mut rx) = Queue::new(1000, Arc::clone(&progress));
    assert!(queue.push(data(600)).await);
    // Control messages take room too, so they cannot pile up for free.
    assert!(queue.push(russh::ChannelMsg::Eof).await);
    assert_eq!(progress.queued.load(Ordering::Acquire), 664);
    let blocked = tokio::time::timeout(Duration::from_millis(100), queue.push(data(600))).await;
    assert!(blocked.is_err(), "a full queue makes the reader wait");
    // Delivering frees room and counts as progress.
    let first = rx.recv().await.unwrap();
    first.delivered(&progress);
    drop(first);
    assert_eq!(progress.delivered.load(Ordering::Acquire), 1);
    assert!(!progress.waiting.load(Ordering::Acquire));
    assert!(queue.push(data(600)).await);
    // A message larger than the whole queue still fits on its own.
    drop(rx.recv().await.unwrap());
    drop(rx.recv().await.unwrap());
    assert!(queue.push(data(5000)).await);
    drop(rx);
    assert!(!queue.push(data(1)).await, "the other end is gone");
}

#[tokio::test(start_paused = true)]
async fn agent_left_ends_once_input_is_held_without_delivery() {
    let (told, rx) = tokio::sync::watch::channel(false);
    let up = Progress::default();
    up.waiting.store(true, Ordering::Release);
    up.queued.store(10, Ordering::Release);
    let left = agent_left(super::AgentGone::new(rx), &up);
    tokio::pin!(left);
    // Held up, but the agent is still there: nothing ends.
    tokio::select! {
        () = &mut left => panic!("ended with the agent there"),
        () = tokio::time::sleep(Duration::from_secs(120)) => {}
    }
    told.send_replace(true);
    // Gone, while the target still takes input: the input is delivered.
    let moving = async {
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            up.delivered.fetch_add(1, Ordering::AcqRel);
        }
    };
    tokio::select! {
        () = &mut left => panic!("ended while input was delivered"),
        () = moving => {}
    }
    // Then held up with nothing delivered: ended after 2 s, not before.
    let held = tokio::time::Instant::now();
    (&mut left).await;
    let after = held.elapsed();
    assert!(
        after >= Duration::from_secs(2) && after < Duration::from_millis(2600),
        "{after:?}"
    );
}

fn limits(stall_secs: u64) -> Watch {
    Watch {
        stall: Duration::from_secs(stall_secs),
        wedge: Duration::from_secs(2),
        idle: Duration::from_mins(15),
    }
}

#[tokio::test(start_paused = true)]
async fn idle_is_measured_from_the_last_byte_either_way() {
    let (up, down) = (Progress::default(), Progress::default());
    let limits = Watch {
        idle: Duration::from_secs(10),
        ..limits(60)
    };
    let watching = watchdog(&up, &down, limits, || ());
    tokio::pin!(watching);
    // Bytes one way, then the other, every 8 s: never idle for 10 s.
    for (i, progress) in [&up, &down, &up, &down].into_iter().enumerate() {
        tokio::select! {
            why = &mut watching => panic!("ended after {i} rounds: {why}"),
            () = tokio::time::sleep(Duration::from_secs(8)) => {}
        }
        progress.received.fetch_add(1, Ordering::AcqRel);
    }
    // Then quiet: ended 10 s (and a check) after the last byte.
    let quiet = tokio::time::Instant::now();
    assert_eq!((&mut watching).await, reason::IDLE);
    let after = quiet.elapsed();
    assert!(
        after >= Duration::from_secs(10) && after <= Duration::from_millis(10_500),
        "{after:?}"
    );
}

/// Bytes read either way are noted once, at the next check; quiet time and
/// messages that are not bytes are not.
#[tokio::test(start_paused = true)]
async fn watchdog_notes_when_bytes_were_read_either_way() {
    let (up, down) = (Progress::default(), Progress::default());
    let noted = AtomicU64::new(0);
    let moved = || {
        noted.fetch_add(1, Ordering::Relaxed);
    };
    let watching = watchdog(&up, &down, limits(600), moved);
    tokio::pin!(watching);
    let still_watching = Duration::from_secs(5);
    tokio::time::timeout(still_watching, &mut watching)
        .await
        .unwrap_err();
    assert_eq!(noted.load(Ordering::Relaxed), 0, "nothing moved");

    up.read(&russh::ChannelMsg::Data {
        data: vec![0_u8; 2].into(),
    });
    tokio::time::timeout(still_watching, &mut watching)
        .await
        .unwrap_err();
    assert_eq!(noted.load(Ordering::Relaxed), 1, "read from the agent");

    down.read(&russh::ChannelMsg::ExtendedData {
        data: vec![0_u8; 3].into(),
        ext: 1,
    });
    tokio::time::timeout(still_watching, &mut watching)
        .await
        .unwrap_err();
    assert_eq!(noted.load(Ordering::Relaxed), 2, "read from the target");

    up.read(&russh::ChannelMsg::Eof);
    tokio::time::timeout(still_watching, &mut watching)
        .await
        .unwrap_err();
    assert_eq!(noted.load(Ordering::Relaxed), 2, "not bytes");
}

#[tokio::test(start_paused = true)]
async fn watchdog_ends_wedged_and_stalled_sessions_only() {
    // Both directions held up (a waiting reader means a full queue),
    // nothing delivered: ended after 2 s.
    let (up, down) = (Progress::default(), Progress::default());
    for progress in [&up, &down] {
        progress.waiting.store(true, Ordering::Release);
        progress.queued.store(10, Ordering::Release);
    }
    let started = tokio::time::Instant::now();
    let why = watchdog(&up, &down, limits(60), || ()).await;
    assert_eq!(why, reason::WEDGED);
    assert!(reason::forced(why));
    assert_eq!(reason::notice(why), None);
    assert!(started.elapsed() < Duration::from_secs(3));

    // One direction holding data nothing delivers: ended after the
    // stall timeout, not before.
    let (up, down) = (Progress::default(), Progress::default());
    up.queued.store(10, Ordering::Release);
    up.waiting.store(true, Ordering::Release);
    let started = tokio::time::Instant::now();
    let why = watchdog(&up, &down, limits(60), || ()).await;
    assert_eq!(why, reason::UPSTREAM_STALLED);
    assert!(started.elapsed() >= Duration::from_secs(60));

    // Progress keeps a session alive, even with the other direction
    // held up all along.
    let (up, down) = (Progress::default(), Progress::default());
    for progress in [&up, &down] {
        progress.waiting.store(true, Ordering::Release);
        progress.queued.store(10, Ordering::Release);
    }
    let moving = async {
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            down.delivered.fetch_add(1, Ordering::AcqRel);
        }
    };
    tokio::select! {
        why = watchdog(&up, &down, limits(60), || ()) => panic!("ended: {why}"),
        () = moving => {}
    }
}

#[tokio::test(start_paused = true)]
async fn idle_then_prompt_delivery_is_not_stalled() {
    // An idle shell: nothing queued or delivered for over a minute.
    let (up, down) = (Progress::default(), Progress::default());
    let watching = watchdog(&up, &down, limits(60), || ());
    tokio::pin!(watching);
    tokio::select! {
        why = &mut watching => panic!("idle session ended: {why}"),
        () = tokio::time::sleep(Duration::from_secs(61)) => {}
    }
    // A keystroke is queued and delivered 300 ms later.
    up.queued.store(64, Ordering::Release);
    tokio::select! {
        why = &mut watching => panic!("first keystroke ended the session: {why}"),
        () = tokio::time::sleep(Duration::from_millis(300)) => {}
    }
    up.queued.store(0, Ordering::Release);
    up.delivered.fetch_add(1, Ordering::AcqRel);
    tokio::select! {
        why = &mut watching => panic!("ended after delivery: {why}"),
        () = tokio::time::sleep(Duration::from_secs(5)) => {}
    }
}

#[tokio::test(start_paused = true)]
async fn held_data_without_delivery_still_stalls() {
    // After a long idle spell, data that is then held for the stall
    // timeout without any delivery ends the session, and not before.
    let (up, down) = (Progress::default(), Progress::default());
    let watching = watchdog(&up, &down, limits(60), || ());
    tokio::pin!(watching);
    tokio::select! {
        why = &mut watching => panic!("idle session ended: {why}"),
        () = tokio::time::sleep(Duration::from_secs(120)) => {}
    }
    down.queued.store(4096, Ordering::Release);
    let held = tokio::time::Instant::now();
    tokio::select! {
        why = &mut watching => panic!("ended early: {why}"),
        () = tokio::time::sleep(Duration::from_secs(59)) => {}
    }
    let why = (&mut watching).await;
    assert_eq!(why, reason::DOWNSTREAM_STALLED);
    let after = held.elapsed();
    assert!(
        after >= Duration::from_secs(60) && after < Duration::from_secs(62),
        "{after:?}"
    );
}
