//! The local backend's `error` audit entries go through the shared limiter.

use std::fs;
use std::sync::Arc;

use axum::http::StatusCode;
use warden_broker::audit::AuditLog;
use warden_broker::policy::LocalBackend;
use warden_broker::testkit::{HttpsUpstream, TestBroker};

mod local_backend_support;
use local_backend_support::{CREDENTIAL, Files, api_entry, backend_audit};

/// While the files are unusable every read is refused, and `GET /v1/offers` reads
/// three times: the audit log gets ten of those entries a minute, and the sweep
/// writes the count of the rest.
#[tokio::test]
async fn errors_beyond_ten_a_minute_are_counted() {
    let upstream = HttpsUpstream::start().await;
    let files = Files::new();
    files.policy(&api_entry(&upstream, ""));
    files.secret("svc-token", CREDENTIAL);
    let audit = Arc::new(
        AuditLog::open(&files.root.join("backend-audit.jsonl"))
            .await
            .unwrap(),
    );
    // In production the backend and the broker share one audit log; this test uses two files.
    let backend = Arc::new(LocalBackend::open(&files.settings, audit).await.unwrap());
    let broker = TestBroker::with_secret_backend(backend.clone()).await;
    broker
        .state()
        .requests
        .audit_throttles()
        .register(backend.audit_throttle());
    let key = broker.add_agent("bot").await;
    fs::write(&files.settings.policy_file, "not a policy").unwrap();

    for _ in 0..15 {
        let resp = broker.api_get(&key, "/v1/offers").await;
        assert_eq!(
            resp.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{}",
            resp.body
        );
    }

    let written = backend_audit(&files);
    assert_eq!(
        written.matches("\"type\":\"error\"").count(),
        10,
        "{written}"
    );
    assert!(
        !broker
            .audit_types()
            .contains(&"local_backend_errors_held".to_owned())
    );

    broker.state().requests.flush_refusals(true).await;
    let log = fs::read_to_string(broker.audit_path()).unwrap();
    let held: Vec<serde_json::Value> = log
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["event"].clone())
        .filter(|event| event["type"] == "local_backend_errors_held")
        .collect();
    assert_eq!(held.len(), 1, "{log}");
    assert_eq!(held[0]["count"], 35);
}
