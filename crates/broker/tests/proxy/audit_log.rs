//! Every call in the audit log, never with the secret, and calls refused when
//! the log cannot record them.

use std::time::Duration;

use axum::http::StatusCode;
use serde_json::json;
use warden_broker::audit;

use super::{
    ROTATED, SECRET, assert_clean, audit_events, call_as, get, proxied, proxy_calls, setup,
};

#[tokio::test]
async fn every_call_audited_without_secret() {
    let s = setup().await;
    let (ok, _) = proxied(&get(&s, "/v1/hello?token=agent-query-value").await);
    assert_eq!(ok.status, 200);
    let (echo, _) = proxied(&get(&s, "/echo").await);
    let (moved, _) = proxied(&get(&s, "/redirect").await);
    let url = s.upstream.url("/v1/hello");
    let refused = call_as(&s.broker, &s.key, &s.grant, "DELETE", &url, None).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert_eq!(
        refused.body,
        r#"{"error":"method is not allowed for this secret"}"#
    );
    s.broker
        .backend
        .set_api_secret(s.upstream.policy("svc"), ROTATED);
    let (rotated, _) = proxied(&get(&s, "/echo").await);
    let mut moved_policy = s.upstream.policy("svc");
    moved_policy.path_prefix = "/v1".to_owned();
    s.broker.backend.set_api_secret(moved_policy, ROTATED);
    let changed = get(&s, "/v1/hello").await;
    assert_eq!(changed.status, StatusCode::CONFLICT);

    let calls = proxy_calls(&s.broker);
    let origin = s.upstream.origin();
    let grant = s.grant.as_str();
    let expected = [
        json!({"type": "proxy_call", "grant_id": grant, "method": "GET",
               "url": format!("{origin}/v1/hello"), "status": 200,
               "response_bytes": 19, "redactions": 0, "outcome": "ok"}),
        json!({"type": "proxy_call", "grant_id": grant, "method": "GET",
               "url": format!("{origin}/echo"), "status": 200,
               "response_bytes": calls[1]["response_bytes"], "redactions": echo.redactions,
               "outcome": "ok"}),
        json!({"type": "proxy_call", "grant_id": grant, "method": "GET",
               "url": format!("{origin}/redirect"), "status": 302,
               "response_bytes": 5, "redactions": moved.redactions, "outcome": "ok"}),
        json!({"type": "proxy_call", "grant_id": grant, "method": "DELETE",
               "url": format!("{origin}/v1/hello"), "status": null,
               "response_bytes": 0, "redactions": 0,
               "outcome": "method is not allowed for this secret"}),
        json!({"type": "proxy_call", "grant_id": grant, "method": "GET",
               "url": format!("{origin}/echo"), "status": 200,
               "response_bytes": calls[4]["response_bytes"], "redactions": rotated.redactions,
               "outcome": "ok"}),
        json!({"type": "proxy_call", "grant_id": grant, "method": "GET",
               "url": format!("{origin}/v1/hello"), "status": null,
               "response_bytes": 0, "redactions": 0,
               "outcome": "policy changed; request access again"}),
    ];
    assert_eq!(calls, expected);
    assert!(echo.redactions > 0);

    // Each call that went out was recorded as started before it was sent;
    // refused calls never started.
    let events = audit_events(&s.broker, &["proxy_call_started", "proxy_call"]);
    let types: Vec<&str> = events.iter().map(|e| e["type"].as_str().unwrap()).collect();
    assert_eq!(
        types,
        [
            "proxy_call_started",
            "proxy_call",
            "proxy_call_started",
            "proxy_call",
            "proxy_call_started",
            "proxy_call",
            "proxy_call",
            "proxy_call_started",
            "proxy_call",
            "proxy_call",
        ]
    );
    assert_eq!(
        events[0],
        json!({"type": "proxy_call_started", "grant_id": grant, "method": "GET",
               "url": format!("{origin}/v1/hello")})
    );

    let log = std::fs::read_to_string(s.broker.audit_path()).unwrap();
    assert!(!log.contains("agent-query-value"));
    assert_clean(&log, SECRET, "audit log");
    assert_clean(&log, ROTATED, "audit log");
    audit::verify(s.broker.audit_path()).unwrap();
}

#[tokio::test]
async fn proxy_refused_when_audit_unwritable() {
    let s = setup().await;
    // Another writer holds the audit log's lock: the pre-flight entry
    // cannot be written, so nothing may be sent.
    let holder = std::fs::File::open(s.broker.audit_path()).unwrap();
    holder.lock().unwrap();
    let resp = get(&s, "/v1/hello").await;
    holder.unlock().unwrap();
    assert_eq!(
        resp.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        resp.body
    );
    assert_eq!(resp.body, r#"{"error":"internal error"}"#);
    assert!(s.upstream.received().is_empty());
    assert_eq!(
        audit_events(&s.broker, &["proxy_call_started", "proxy_call"]),
        [] as [serde_json::Value; 0]
    );

    // Once the log is writable again, calls go through.
    let (proxied, _) = proxied(&get(&s, "/v1/hello").await);
    assert_eq!(proxied.status, 200);
}

/// A revocation that has reported access stopped holds for a call still waiting
/// to record its start: it must not go out once the log answers.
#[tokio::test]
async fn revoked_while_a_call_waits_to_record_its_start_sends_nothing() {
    let s = setup().await;
    let holder = std::fs::File::open(s.broker.audit_path()).unwrap();
    holder.lock().unwrap();
    let call = get(&s, "/delayed");
    let revoke = async {
        while s
            .broker
            .state()
            .requests
            .proxy_calls()
            .snapshot()
            .is_empty()
        {
            tokio::task::yield_now().await;
        }
        let outcome = s
            .broker
            .state()
            .requests
            .revoke_grant(&s.grant, "owner")
            .await
            .unwrap();
        drop(holder);
        outcome
    };
    let (resp, outcome) = tokio::join!(call, revoke);
    assert_eq!(outcome, warden_broker::requests::AuditOutcome::Missing);
    // Refused as revoked or, had the wait for the log run out first, as unrecorded.
    assert_ne!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(s.upstream.received().is_empty());
}

/// A call whose URL is too long to record is listed on the owner's grants
/// page under the audit's marker while it runs, never with its path.
#[tokio::test]
async fn overlong_path_is_listed_as_invalid() {
    let s = setup().await;
    let long = format!("/delayed/{}", "a".repeat(4096));
    let call = get(&s, &long);
    let live = async {
        let reached = tokio::time::timeout(Duration::from_secs(5), async {
            while s.upstream.received().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(reached.is_ok(), "the upstream never received the call");
        s.broker.get("/grants/live").await
    };
    let (resp, live) = tokio::join!(call, live);
    let (proxied, _) = proxied(&resp);
    assert_eq!(proxied.status, 200);
    assert_eq!(live.status, StatusCode::OK, "{}", live.body);
    let listed = &live.json()["grants"][0]["proxy_calls"];
    assert_eq!(listed[0]["path"], "invalid", "{}", live.body);
    assert_eq!(listed.as_array().map(Vec::len), Some(1), "{}", live.body);
    assert!(!live.body.contains("aaaa"), "{}", live.body);
    assert!(live.body.len() < 512, "{}", live.body.len());
    assert_eq!(proxy_calls(&s.broker)[0]["url"], "invalid");
}
