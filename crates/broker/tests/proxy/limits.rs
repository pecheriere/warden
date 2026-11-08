//! Concurrent call limits, per agent and overall.

use std::time::{Duration, Instant};

use axum::http::StatusCode;
use serde_json::Value;
use warden_broker::proxy::ProxyLimits;
use warden_broker::testkit::TestResponse;

use super::{Setup, approve_api, call_as, get, proxied, proxy_calls, setup_with};

const TOO_MANY: &str = r#"{"error":"too many concurrent calls"}"#;

fn limited(max_calls_per_agent: usize, max_calls: usize) -> ProxyLimits {
    ProxyLimits {
        max_calls_per_agent,
        max_calls,
        ..ProxyLimits::default()
    }
}

/// Assert that exactly `refused` of `responses` were refused for too many
/// calls and the rest succeeded, and that each refusal was audited without
/// reaching the upstream.
fn assert_refusals(s: &Setup, responses: &[TestResponse], refused: usize) {
    let (slow, others): (Vec<_>, Vec<_>) =
        responses.iter().partition(|r| r.status == StatusCode::OK);
    assert_eq!(others.len(), refused, "{responses:?}");
    for r in &others {
        assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{}", r.body);
        assert_eq!(r.body, TOO_MANY);
    }
    assert_eq!(s.upstream.received().len(), slow.len());
    let calls = proxy_calls(&s.broker);
    let audited = calls
        .iter()
        .filter(|c| c["outcome"] == "too many concurrent calls")
        .collect::<Vec<_>>();
    assert_eq!(audited.len(), refused);
    for c in audited {
        assert_eq!(c["status"], Value::Null);
        assert_eq!(c["response_bytes"], 0);
    }
}

#[tokio::test]
async fn per_agent_limit_refuses_excess() {
    let s = setup_with(limited(1, 16), |_| {}).await;
    let (a, b) = tokio::join!(get(&s, "/delayed"), get(&s, "/delayed"));
    assert_refusals(&s, &[a, b], 1);

    // Another agent is not held up by the first one's calls.
    let other_key = s.broker.add_agent("other").await;
    let other_grant = approve_api(&s.broker, "other", "svc").await;
    let url = s.upstream.url("/delayed");
    let (mine, theirs) = tokio::join!(
        get(&s, "/delayed"),
        call_as(&s.broker, &other_key, &other_grant, "GET", &url, None)
    );
    assert_eq!(mine.status, StatusCode::OK, "{}", mine.body);
    assert_eq!(theirs.status, StatusCode::OK, "{}", theirs.body);
}

#[tokio::test]
async fn overall_limit_refuses_excess() {
    let s = setup_with(limited(1, 2), |_| {}).await;
    let url = s.upstream.url("/delayed");
    let mut agents = vec![(s.key.clone(), s.grant.clone())];
    for name in ["second", "third"] {
        let key = s.broker.add_agent(name).await;
        let grant = approve_api(&s.broker, name, "svc").await;
        agents.push((key, grant));
    }
    let call = |i: usize| call_as(&s.broker, &agents[i].0, &agents[i].1, "GET", &url, None);
    let (a, b, c) = tokio::join!(call(0), call(1), call(2));
    assert_refusals(&s, &[a, b, c], 1);
}

#[tokio::test]
async fn slot_released_after_error_and_disconnect() {
    let s = setup_with(limited(1, 1), |_| {}).await;

    // A refused call and an upstream failure each give the slot back.
    let url = s.upstream.url("/v1/hello");
    let refused = call_as(&s.broker, &s.key, &s.grant, "DELETE", &url, None).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    let failed = get(&s, "/gzip").await;
    assert_eq!(failed.status, StatusCode::BAD_GATEWAY, "{}", failed.body);
    let (ok, _) = proxied(&get(&s, "/v1/hello").await);
    assert_eq!(ok.status, 200);

    // An agent that hangs up leaves its call running, still holding the
    // slot, and the slot is free again once that call is over. The agent
    // hangs up only once the call has reached the upstream, so the slot is
    // certainly taken.
    let mut call = Box::pin(get(&s, "/delayed"));
    let reached = tokio::time::timeout(Duration::from_secs(5), async {
        while !s
            .upstream
            .received()
            .iter()
            .any(|r| r.path_and_query == "/delayed")
        {
            tokio::select! {
                resp = &mut call => panic!("the call ended early: {}", resp.status),
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
    })
    .await;
    assert!(reached.is_ok(), "the upstream never received the call");
    drop(call);
    let busy = get(&s, "/v1/hello").await;
    assert_eq!(busy.status, StatusCode::TOO_MANY_REQUESTS, "{}", busy.body);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let resp = get(&s, "/v1/hello").await;
        if resp.status == StatusCode::OK {
            break;
        }
        assert_eq!(resp.status, StatusCode::TOO_MANY_REQUESTS, "{}", resp.body);
        assert!(Instant::now() < deadline, "slot never released");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
