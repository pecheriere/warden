//! Tests of the live sessions: ending them by revocation, expiry or failing
//! closed, their listing, and the reason recorded when an end races another.

use std::sync::atomic::Ordering;

use std::time::Duration;

use warden_broker_proto::{AgentName, Id, TargetName, UnixUser};

use crate::requests::RelayGrantRecord;

use super::super::pump::first_end;
use super::super::{Outcome, reason};
use super::{LiveSessionInfo, LiveSessions, Registration};

fn grant(agent: &str, not_after: i64) -> RelayGrantRecord {
    RelayGrantRecord {
        grant_id: Id::random(),
        agent: AgentName::try_from(agent.to_owned()).unwrap(),
        target: TargetName::try_from("nas".to_owned()).unwrap(),
        user: UnixUser::try_from("backup".to_owned()).unwrap(),
        destination_digest: "ab".repeat(32),
        not_after,
    }
}

/// The reason `live` was told to end for, if it was.
async fn told(live: &mut Registration) -> Option<&'static str> {
    tokio::time::timeout(Duration::from_millis(10), live.ended())
        .await
        .ok()
}

#[tokio::test]
async fn told_end_wins_over_the_session_ending_by_itself() {
    // The session also ended by itself (the agent's side closed, as it
    // does once the relay cuts it): the cause the relay told wins.
    let left = || std::future::ready((reason::CLIENT_CLOSED, true));
    let sessions = LiveSessions::new();
    let (stopping, mut stop) = tokio::sync::watch::channel(false);
    let mut live = sessions.register(&grant("a", 100), 0);
    stopping.send_replace(true);
    assert_eq!(
        first_end(&mut live, &mut stop, left()).await,
        (reason::SHUTDOWN, false)
    );
    let (_running, mut stop) = tokio::sync::watch::channel(false);
    for why in [
        reason::REVOKED,
        reason::EXPIRED,
        reason::GRANT_STATE_UNAVAILABLE,
    ] {
        let g = grant("b", 100);
        let mut live = sessions.register(&g, 0);
        match why {
            reason::REVOKED => sessions.revoke_agent(&g.agent),
            reason::EXPIRED => sessions.expire_grant(&g.grant_id),
            _ => sessions.fail_closed(),
        }
        assert_eq!(first_end(&mut live, &mut stop, left()).await, (why, false));
    }
    // Nothing told: as the session ended.
    let mut live = sessions.register(&grant("c", 100), 0);
    assert_eq!(
        first_end(&mut live, &mut stop, left()).await,
        (reason::CLIENT_CLOSED, true)
    );
}

#[tokio::test]
async fn live_sessions_end_by_grant_agent_or_expiry() {
    let sessions = LiveSessions::new();
    let (a, b, c) = (grant("a", 100), grant("a", 200), grant("c", 300));
    let mut a1 = sessions.register(&a, 0);
    let mut a2 = sessions.register(&a, 0);
    let mut b1 = sessions.register(&b, 0);
    let mut c1 = sessions.register(&c, 0);
    let mut ids = sessions.grant_ids();
    ids.sort_by(|x, y| x.as_str().cmp(y.as_str()));
    let mut want = vec![a.grant_id.clone(), b.grant_id.clone(), c.grant_id.clone()];
    want.sort_by(|x, y| x.as_str().cmp(y.as_str()));
    assert_eq!(ids, want, "each grant once");

    sessions.revoke_grant(&a.grant_id);
    assert_eq!(told(&mut a1).await, Some(reason::REVOKED));
    assert_eq!(told(&mut a2).await, Some(reason::REVOKED));
    assert_eq!(told(&mut b1).await, None, "another grant of the agent");
    assert_eq!(told(&mut c1).await, None);

    // The first reason stands.
    sessions.expire_due(150);
    assert_eq!(told(&mut a1).await, Some(reason::REVOKED));
    assert_eq!(told(&mut b1).await, None, "not past its window");
    sessions.expire_due(200);
    assert_eq!(told(&mut b1).await, Some(reason::EXPIRED));

    sessions.revoke_agent(&AgentName::try_from("c".to_owned()).unwrap());
    assert_eq!(told(&mut c1).await, Some(reason::REVOKED));
    sessions.expire_grant(&c.grant_id);
    assert_eq!(told(&mut c1).await, Some(reason::REVOKED));
    let mut fresh = sessions.register(&grant("d", 400), 0);
    sessions.fail_closed();
    assert_eq!(
        told(&mut fresh).await,
        Some(reason::GRANT_STATE_UNAVAILABLE)
    );
    assert_eq!(
        told(&mut c1).await,
        Some(reason::REVOKED),
        "the first reason stands"
    );
    drop(fresh);

    // Dropped registrations are no longer listed.
    drop((a1, a2, b1));
    assert_eq!(sessions.grant_ids(), vec![c.grant_id.clone()]);
    drop(c1);
    assert_eq!(sessions.grant_ids(), [] as [warden_broker_proto::Id; 0]);
}

#[test]
fn snapshot_lists_live_session_until_dropped() {
    let sessions = LiveSessions::new();
    assert_eq!(
        sessions.snapshot(),
        [] as [crate::relay::session::LiveSessionInfo; 0]
    );
    let (late, early) = (grant("a", 100), grant("b", 100));
    let first = sessions.register(&late, 20);
    let second = sessions.register(&early, 10);
    let (to_target, from_target) = first.counters();
    to_target.fetch_add(3, Ordering::Relaxed);
    from_target.fetch_add(5, Ordering::Relaxed);
    assert_eq!(
        sessions.snapshot(),
        vec![
            LiveSessionInfo {
                grant_id: early.grant_id.clone(),
                started_at: 10,
                bytes_to_target: 0,
                bytes_from_target: 0,
                last_activity: 10,
            },
            LiveSessionInfo {
                grant_id: late.grant_id.clone(),
                started_at: 20,
                bytes_to_target: 3,
                bytes_from_target: 5,
                last_activity: 20,
            },
        ],
        "oldest first, with the shared counters"
    );
    // Two sessions of one grant in the same second: the one registered
    // first is listed first, told apart by its byte count.
    let twin = sessions.register(&early, 10);
    twin.counters().0.fetch_add(7, Ordering::Relaxed);
    let listed: Vec<_> = sessions
        .snapshot()
        .iter()
        .map(|s| (s.started_at, s.grant_id.clone(), s.bytes_to_target))
        .collect();
    assert_eq!(
        listed,
        vec![
            (10, early.grant_id.clone(), 0),
            (10, early.grant_id.clone(), 7),
            (20, late.grant_id.clone(), 3),
        ],
        "same second: in the order registered"
    );
    drop(twin);
    drop(first);
    assert_eq!(sessions.snapshot().len(), 1);
    drop(second);
    assert_eq!(
        sessions.snapshot(),
        [] as [crate::relay::session::LiveSessionInfo; 0]
    );
}

#[test]
fn revoke_racing_exit_records_revoked() {
    let exited = Outcome {
        reason: reason::EXITED,
        bytes_to_target: 3,
        bytes_from_target: 5,
        exit_status: Some(0),
    };
    let sessions = LiveSessions::new();
    let (a, b, c) = (grant("a", 100), grant("b", 100), grant("c", 100));
    let (revoked, expired, lost) = (
        sessions.register(&a, 0),
        sessions.register(&b, 0),
        sessions.register(&c, 0),
    );
    let untold = sessions.register(&grant("d", 100), 0);

    // The target exited and the relay loop ended on that, but the
    // revocation (or expiry) reached the session before its teardown
    // completed: that is the reason on record, the rest is kept.
    sessions.revoke_grant(&a.grant_id);
    sessions.expire_grant(&b.grant_id);
    assert_eq!(
        exited.clone().settled(revoked.told()),
        Outcome {
            reason: reason::REVOKED,
            ..exited.clone()
        }
    );
    assert_eq!(
        exited.clone().settled(expired.told()).reason,
        reason::EXPIRED
    );
    // Whatever else ended the session.
    for other in [
        reason::TARGET_CLOSED,
        reason::CLIENT_CLOSED,
        reason::IDLE,
        reason::SHUTDOWN,
    ] {
        let outcome = Outcome {
            reason: other,
            ..exited.clone()
        };
        assert_eq!(outcome.settled(revoked.told()).reason, reason::REVOKED);
    }

    // Nothing told, or told for another reason: as the session ended.
    assert_eq!(untold.told(), None);
    assert_eq!(exited.clone().settled(untold.told()), exited);
    sessions.fail_closed();
    assert_eq!(lost.told(), Some(reason::GRANT_STATE_UNAVAILABLE));
    assert_eq!(exited.clone().settled(lost.told()), exited);
    // The first reason told still stands.
    assert_eq!(revoked.told(), Some(reason::REVOKED));
}
