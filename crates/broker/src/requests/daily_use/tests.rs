//! The daily use budget of a grant.

use std::sync::Arc;

use warden_broker_proto::{AgentName, Id, SecretName};

use super::DailyUse;
use crate::audit::AuditLog;
use crate::requests::Requests;
use crate::store;
use crate::testkit::{CapturingNotifier, FakeBackend, ManualClock};

const DAY: i64 = 86_400;

struct Fixture {
    requests: Requests,
    clock: Arc<ManualClock>,
    notifier: Arc<CapturingNotifier>,
    audit_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn fixture(limit: u32) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let pool = store::open(&dir.path().join("warden.db")).await.unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditLog::open(&audit_path).await.unwrap());
    let clock = Arc::new(ManualClock::new(10 * DAY + 5));
    let notifier = Arc::new(CapturingNotifier::new());
    let requests = Requests::new(
        pool,
        audit,
        Arc::new(FakeBackend::new()),
        notifier.clone(),
        "https://warden.example.ts.net/".parse().unwrap(),
        clock.clone(),
        None,
    )
    .with_proxy_calls_per_day(limit);
    Fixture {
        requests,
        clock,
        notifier,
        audit_path,
        _dir: dir,
    }
}

/// A bare grant row: its request and agent do not matter here.
async fn grant(requests: &Requests, id: &str) -> Id {
    let mut conn = requests.pool.acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO grants (id, request_id, agent, window_secs, not_before, not_after, view) \
         VALUES (?, ?, 'a', 900, 0, 9999999999, '{}')",
    )
    .bind(id)
    .bind(format!("r{}", &id[1..]))
    .execute(&mut *conn)
    .await
    .unwrap();
    Id::try_from(id.to_owned()).unwrap()
}

fn call() -> DailyUse {
    DailyUse::ProxyCall {
        secret: SecretName::try_from("home-api".to_owned()).unwrap(),
    }
}

#[tokio::test]
async fn take_daily_use_stops_at_the_limit_and_resets_the_next_day() {
    let f = fixture(2).await;
    let grant = grant(&f.requests, "11111111111111111111111111111111").await;
    assert!(f.requests.take_daily_use(&grant, &call()).await.unwrap());
    assert!(f.requests.take_daily_use(&grant, &call()).await.unwrap());
    assert!(!f.requests.take_daily_use(&grant, &call()).await.unwrap());
    assert!(!f.requests.take_daily_use(&grant, &call()).await.unwrap());
    f.clock.advance(DAY);
    assert!(f.requests.take_daily_use(&grant, &call()).await.unwrap());
    assert!(f.requests.take_daily_use(&grant, &call()).await.unwrap());
    assert!(!f.requests.take_daily_use(&grant, &call()).await.unwrap());
}

#[tokio::test]
async fn take_daily_use_holds_for_concurrent_takes() {
    let f = fixture(3).await;
    let grant = grant(&f.requests, "11111111111111111111111111111111").await;
    let kind = call();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..5 {
        let (requests, grant, kind) = (f.requests.clone(), grant.clone(), kind.clone());
        tasks.spawn(async move { requests.take_daily_use(&grant, &kind).await });
    }
    let mut granted = 0;
    while let Some(done) = tasks.join_next().await {
        if done.unwrap().unwrap() {
            granted += 1;
        }
    }
    assert_eq!(granted, 3);
}

#[tokio::test]
async fn take_daily_use_counts_per_grant() {
    let f = fixture(1).await;
    let first = grant(&f.requests, "11111111111111111111111111111111").await;
    let second = grant(&f.requests, "22222222222222222222222222222222").await;
    assert!(f.requests.take_daily_use(&first, &call()).await.unwrap());
    assert!(!f.requests.take_daily_use(&first, &call()).await.unwrap());
    assert!(f.requests.take_daily_use(&second, &call()).await.unwrap());
}

#[tokio::test]
async fn the_limit_is_recorded_and_told_once_a_day() {
    let f = fixture(7).await;
    let grant = grant(&f.requests, "11111111111111111111111111111111").await;
    let agent = AgentName::try_from("build-agent".to_owned()).unwrap();
    f.requests
        .daily_limit_reached(&agent, &grant, &call())
        .await;
    f.requests
        .daily_limit_reached(&agent, &grant, &call())
        .await;
    let bell = f.notifier.next().await;
    assert_eq!(bell.title, "warden: build-agent reached its API call limit");
    assert_eq!(
        bell.message,
        "It made 7 calls with home-api today, so its calls fail until 00:00 UTC. If you do \
         not expect this many, revoke its grant."
    );
    assert_eq!(bell.url.as_str(), "https://warden.example.ts.net/grants");
    let log = std::fs::read_to_string(&f.audit_path).unwrap();
    assert_eq!(log.matches("proxy_call_limit_reached").count(), 1, "{log}");

    f.clock.advance(DAY);
    f.requests
        .daily_limit_reached(&agent, &grant, &call())
        .await;
    let log = std::fs::read_to_string(&f.audit_path).unwrap();
    assert_eq!(log.matches("proxy_call_limit_reached").count(), 2, "{log}");
}
