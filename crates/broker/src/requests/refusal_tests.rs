//! What the audit log keeps of a refusal's reason.

use std::path::Path;
use std::sync::Arc;

use serde_json::Value;
use warden_broker_proto::AgentName;

use super::Requests;
use crate::audit::AuditLog;
use crate::store;
use crate::testkit::{CapturingNotifier, FakeBackend, ManualClock};

async fn open(dir: &Path) -> Requests {
    let pool = store::open(&dir.join("warden.db")).await.unwrap();
    let audit = Arc::new(AuditLog::open(&dir.join("audit.jsonl")).await.unwrap());
    Requests::new(
        pool,
        audit,
        Arc::new(FakeBackend::new()),
        Arc::new(CapturingNotifier::new()),
        "https://warden.example.ts.net/".parse().unwrap(),
        Arc::new(ManualClock::new(1_800_000_000)),
        None,
    )
}

/// The `reason` of every entry in the log, oldest first, by type.
fn reasons(dir: &Path) -> Vec<(String, String)> {
    std::fs::read_to_string(dir.join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap()["event"].clone())
        .map(|e| {
            (
                e["type"].as_str().unwrap().to_owned(),
                e["reason"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[tokio::test]
async fn a_long_refusal_reason_is_cut_in_its_entry() {
    let dir = tempfile::tempdir().unwrap();
    let requests = open(dir.path()).await;
    let agent = AgentName::try_from("build-agent".to_owned()).unwrap();
    // One ASCII byte, then control characters, each 6 bytes once written as JSON.
    let reason = format!("x{}", "\u{1}".repeat(2000));
    requests
        .record_commit_signing_refusal(&agent, None, reason.clone(), None)
        .await;
    requests
        .record_github_token_refusal(&agent, None, reason.clone())
        .await;
    requests
        .record_release_refusal(&agent, None, "tag", reason.clone())
        .await;
    let recorded = reasons(dir.path());
    let types: Vec<&str> = recorded.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(
        types,
        [
            "commit_signing_refused",
            "github_token_refused",
            "release_refused"
        ]
    );
    for (kind, recorded) in &recorded {
        let kept = recorded
            .strip_suffix(" (truncated)")
            .unwrap_or_else(|| panic!("{kind}: not marked as cut"));
        assert!(reason.starts_with(kept), "{kind}: {recorded:?}");
        // 1 + 6 × 85 = 511 bytes: one more character would pass 512.
        assert_eq!(
            serde_json::to_string(kept).unwrap().len() - 2,
            511,
            "{kind}"
        );
    }
}
