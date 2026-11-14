use std::fs::File;
use std::sync::Arc;

use tempfile::TempDir;
use warden_broker_proto::AgentName;

use super::{Allowance, AuditThrottles, FlushHeld, Summary, Throttle};
use crate::audit::{AuditEvent, AuditLog};

fn agent(name: &str) -> AgentName {
    name.parse().unwrap()
}

fn refusal(agent: &AgentName) -> AuditEvent {
    AuditEvent::CommitSigningRefused {
        agent: agent.clone(),
        grant_id: None,
        reason: "test".to_owned(),
        payload_sha256: None,
    }
}

fn held(agent: AgentName, count: u64) -> AuditEvent {
    AuditEvent::CommitSigningRefusalsHeld { agent, count }
}

fn aggregate(keys: u64, count: u64) -> AuditEvent {
    AuditEvent::Error {
        context: "aggregate".to_owned(),
        message: format!("{keys} {count}"),
    }
}

fn per_key(per_key: u32, overall: Option<u32>) -> Arc<Throttle<AgentName, u64>> {
    Throttle::new(
        "test refusals",
        Allowance { per_key, overall },
        Summary::PerKey(held),
    )
}

async fn open() -> (TempDir, AuditLog) {
    let dir = TempDir::new().unwrap();
    let log = AuditLog::open(&dir.path().join("audit.jsonl"))
        .await
        .unwrap();
    (dir, log)
}

/// The `event` of every line written so far.
fn entries(dir: &TempDir) -> Vec<serde_json::Value> {
    std::fs::read_to_string(dir.path().join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|line| {
            let mut line: serde_json::Value = serde_json::from_str(line).unwrap();
            line["event"].take()
        })
        .collect()
}

fn of_type(dir: &TempDir, kind: &str) -> Vec<serde_json::Value> {
    entries(dir)
        .into_iter()
        .filter(|event| event["type"] == kind)
        .collect()
}

async fn record(t: &Throttle<AgentName, u64>, log: &AuditLog, key: &AgentName, now: i64) {
    t.record(log, key, now, 1, refusal(key)).await;
}

#[tokio::test]
async fn per_key_allowance_writes_then_counts() {
    let (dir, log) = open().await;
    let t = per_key(30, None);
    let bot = agent("bot");
    for _ in 0..32 {
        record(&t, &log, &bot, 1000).await;
    }
    assert_eq!(of_type(&dir, "commit_signing_refused").len(), 30);
    t.flush(&log, 1030, false).await;
    assert_eq!(of_type(&dir, "commit_signing_refusals_held").len(), 0);
    t.flush(&log, 1060, false).await;
    let summaries = of_type(&dir, "commit_signing_refusals_held");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0]["count"], 2);
    t.flush(&log, 1120, false).await;
    assert_eq!(of_type(&dir, "commit_signing_refusals_held").len(), 1);
}

#[tokio::test]
async fn another_key_has_its_own_allowance() {
    let (dir, log) = open().await;
    let t = per_key(1, None);
    let (bot, other) = (agent("bot"), agent("other"));
    for _ in 0..3 {
        record(&t, &log, &bot, 1000).await;
    }
    record(&t, &log, &other, 1000).await;
    assert_eq!(of_type(&dir, "commit_signing_refused").len(), 2);
    assert!(t.note(&bot, 1060, 1));
    assert!(!t.note(&other, 1059, 1));
}

#[tokio::test]
async fn overall_allowance_binds_across_keys() {
    let (dir, log) = open().await;
    let t = per_key(5, Some(10));
    for name in ["a", "b", "c"] {
        let key = agent(name);
        for _ in 0..5 {
            record(&t, &log, &key, 1000).await;
        }
    }
    assert_eq!(of_type(&dir, "commit_signing_refused").len(), 10);
    t.flush(&log, 1060, false).await;
    let total: u64 = of_type(&dir, "commit_signing_refusals_held")
        .iter()
        .map(|event| event["count"].as_u64().unwrap())
        .sum();
    assert_eq!(total, 5);
}

#[tokio::test]
async fn aggregate_writes_one_summary_for_all_keys() {
    let (dir, log) = open().await;
    let t: Arc<Throttle<u32, u64>> = Throttle::new(
        "test refusals",
        Allowance {
            per_key: 1,
            overall: Some(2),
        },
        Summary::Aggregate {
            max_keys: 4,
            event: aggregate,
        },
    );
    for key in 0..100 {
        t.record(&log, &key, 1000, 1, aggregate(0, 0)).await;
    }
    assert_eq!(entries(&dir).len(), 2);
    t.flush(&log, 1030, false).await;
    assert_eq!(entries(&dir).len(), 2);
    t.flush(&log, 1060, false).await;
    let events = entries(&dir);
    assert_eq!(events.len(), 3);
    assert_eq!(events[2]["message"], "5 98");
    t.flush(&log, 1120, false).await;
    assert_eq!(entries(&dir).len(), 3);
}

#[tokio::test]
async fn a_failed_flush_keeps_the_count() {
    let (dir, log) = open().await;
    let t = per_key(1, None);
    let bot = agent("bot");
    for _ in 0..4 {
        record(&t, &log, &bot, 1000).await;
    }
    // Another holder of the log's file lock makes an append fail, as another
    // process appending with the lock stuck would.
    let path = dir.path().join("audit.jsonl");
    let other = File::options().append(true).open(&path).unwrap();
    other.lock().unwrap();
    t.flush(&log, 1060, false).await;
    other.unlock().unwrap();
    assert_eq!(of_type(&dir, "commit_signing_refusals_held").len(), 0);
    t.flush(&log, 1061, false).await;
    let summaries = of_type(&dir, "commit_signing_refusals_held");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0]["count"], 3);
}

#[tokio::test]
async fn flush_all_writes_counts_before_their_minute_is_over() {
    let (dir, log) = open().await;
    let t = per_key(1, None);
    let bot = agent("bot");
    for _ in 0..3 {
        record(&t, &log, &bot, 1000).await;
    }
    t.flush(&log, 1001, true).await;
    let summaries = of_type(&dir, "commit_signing_refusals_held");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0]["count"], 2);
}

#[tokio::test]
async fn a_clock_set_back_starts_a_new_minute() {
    let t = per_key(2, None);
    let bot = agent("bot");
    assert!(t.note(&bot, 1000, 1));
    assert!(t.note(&bot, 1000, 1));
    assert!(!t.note(&bot, 1000, 1));
    assert!(t.note(&bot, 900, 1));
}

#[tokio::test]
async fn registry_flushes_every_registered_throttle() {
    let (dir, log) = open().await;
    let (first, second) = (per_key(1, None), per_key(1, None));
    let registry = AuditThrottles::default();
    registry.register(first.clone());
    registry.register(second.clone());
    let bot = agent("bot");
    for t in [&first, &second] {
        for _ in 0..2 {
            record(t, &log, &bot, 1000).await;
        }
    }
    registry.flush(&log, 1060, false).await;
    assert_eq!(of_type(&dir, "commit_signing_refusals_held").len(), 2);
}
