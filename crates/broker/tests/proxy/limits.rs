//! Concurrent call limits, per agent and overall.

use std::time::{Duration, Instant};

use axum::http::StatusCode;
use serde_json::Value;
use warden_broker::proxy::ProxyLimits;
use warden_broker::requests::Clock as _;
use warden_broker::testkit::TestResponse;
use warden_broker::testkit::wait::{self, HANG};

use super::{
    Setup, approve_api, audit_events, call_as, get, proxied, proxy_calls, setup_daily, setup_with,
};

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

/// Wait until the upstream has received `count` calls to `path`.
async fn reached(s: &Setup, path: &str, count: usize) {
    wait::until("the upstream receiving the held calls", || {
        s.upstream
            .received()
            .iter()
            .filter(|r| r.path_and_query == path)
            .count()
            >= count
    })
    .await;
}

#[tokio::test]
async fn per_agent_limit_refuses_excess() {
    let s = setup_with(limited(1, 16), |_| {}).await;
    let other_key = s.broker.add_agent("other").await;
    let other_grant = approve_api(&s.broker, "other", "svc").await;
    let url = s.upstream.url("/v1/hello");
    // The agent's first call holds its only place until the upstream answers.
    // Meanwhile its second call is refused, and another agent is not held up
    // by the first one's calls.
    // A held call that ends early was wrongly refused: fail with its status rather
    // than waiting out `reached`.
    let mut held = Box::pin(get(&s, "/held"));
    let others = async {
        reached(&s, "/held", 1).await;
        let excess = get(&s, "/v1/hello").await;
        let theirs = call_as(&s.broker, &other_key, &other_grant, "GET", &url, None).await;
        s.upstream.release_held();
        (excess, theirs)
    };
    let (excess, theirs) = tokio::select! {
        resp = &mut held => panic!("the held call ended early: {} {}", resp.status, resp.body),
        done = others => done,
    };
    let held = held.await;
    assert_eq!(
        excess.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        excess.body
    );
    assert_eq!(theirs.status, StatusCode::OK, "{}", theirs.body);
    assert_refusals(&s, &[held, excess, theirs], 1);
}

#[tokio::test]
async fn overall_limit_refuses_excess() {
    let s = setup_with(limited(1, 2), |_| {}).await;
    let mut agents = vec![(s.key.clone(), s.grant.clone())];
    for name in ["second", "third"] {
        let key = s.broker.add_agent(name).await;
        let grant = approve_api(&s.broker, name, "svc").await;
        agents.push((key, grant));
    }
    let s = &s;
    let agents = &agents;
    let call = |i: usize, path: &str| {
        let url = s.upstream.url(path);
        let (key, grant) = &agents[i];
        async move { call_as(&s.broker, key, grant, "GET", &url, None).await }
    };
    // Two agents' calls take both places until the upstream answers; a third
    // agent, under its own limit, is refused meanwhile.
    // A held call that ends early was wrongly refused: fail with its status rather
    // than waiting out `reached`.
    let mut a = Box::pin(call(0, "/held"));
    let mut b = Box::pin(call(1, "/held"));
    let third = async {
        reached(s, "/held", 2).await;
        let refused = call(2, "/v1/hello").await;
        s.upstream.release_held();
        refused
    };
    let c = tokio::select! {
        resp = &mut a => panic!("the first held call ended early: {} {}", resp.status, resp.body),
        resp = &mut b => panic!("the second held call ended early: {} {}", resp.status, resp.body),
        refused = third => refused,
    };
    let (a, b) = (a.await, b.await);
    assert_eq!(c.status, StatusCode::TOO_MANY_REQUESTS, "{}", c.body);
    assert_refusals(s, &[a, b, c], 1);
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
    let mut call = Box::pin(get(&s, "/held"));
    tokio::select! {
        resp = &mut call => panic!("the call ended early: {}", resp.status),
        () = reached(&s, "/held", 1) => {}
    }
    drop(call);
    let busy = get(&s, "/v1/hello").await;
    assert_eq!(busy.status, StatusCode::TOO_MANY_REQUESTS, "{}", busy.body);
    s.upstream.release_held();
    let deadline = Instant::now() + HANG;
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

const OVER_THE_DAY: &str = r#"{"error":"this grant made 2 calls today, its limit; calls fail until 00:00 UTC, and the owner was told"}"#;

#[tokio::test]
async fn a_grant_stops_at_its_daily_call_limit_and_the_owner_hears_once() {
    let s = setup_daily(2).await;
    // A grant of its own, made a minute before a UTC midnight: it lasts past the
    // start of the next day, which its window could not otherwise reach.
    let now = s.broker.clock.now();
    s.broker.clock.advance(86_400 - 60 - now.rem_euclid(86_400));
    let key = s.broker.add_agent("late").await;
    let grant = approve_api(&s.broker, "late", "svc").await;
    let url = s.upstream.url("/v1/hello");
    let call = || call_as(&s.broker, &key, &grant, "GET", &url, None);
    let other_key = s.broker.add_agent("other").await;
    let other_grant = approve_api(&s.broker, "other", "svc").await;
    proxied(&call().await);
    proxied(&call().await);
    assert_eq!(s.upstream.received().len(), 2);

    let resp = call().await;
    assert_eq!(resp.status, StatusCode::TOO_MANY_REQUESTS, "{}", resp.body);
    assert_eq!(resp.body, OVER_THE_DAY);
    assert_eq!(s.upstream.received().len(), 2, "nothing was sent");
    let bell = s.broker.capture.next().await;
    assert_eq!(bell.title, "warden: late reached its API call limit");
    assert_eq!(
        bell.message,
        "It made 2 calls with svc today, so its calls fail until 00:00 UTC. If you do not \
         expect this many, revoke its grant."
    );
    assert_eq!(call().await.status, StatusCode::TOO_MANY_REQUESTS);
    let reached = audit_events(&s.broker, &["proxy_call_limit_reached"]);
    assert_eq!(reached.len(), 1, "once a day");
    assert_eq!(reached[0]["grant_id"], grant.as_str());
    assert_eq!(reached[0]["limit"], 2);
    // The refused calls are in the log, and none of them started.
    assert_eq!(audit_events(&s.broker, &["proxy_call_started"]).len(), 2);
    assert_eq!(proxy_calls(&s.broker).len(), 4);

    // Per grant: another agent's calls go on.
    let theirs = call_as(&s.broker, &other_key, &other_grant, "GET", &url, None).await;
    assert_eq!(theirs.status, StatusCode::OK, "{}", theirs.body);

    // The next UTC day starts again, and can be told about again.
    s.broker.clock.advance(120);
    proxied(&call().await);
    proxied(&call().await);
    assert_eq!(call().await.status, StatusCode::TOO_MANY_REQUESTS);
    let reached = audit_events(&s.broker, &["proxy_call_limit_reached"]);
    assert_eq!(reached.len(), 2);
}

#[tokio::test]
async fn concurrent_calls_at_the_daily_limit_pass_exactly_the_limit() {
    let s = setup_daily(3).await;
    let responses = tokio::join!(
        get(&s, "/v1/hello"),
        get(&s, "/v1/hello"),
        get(&s, "/v1/hello"),
        get(&s, "/v1/hello"),
        get(&s, "/v1/hello"),
    );
    let responses = [
        responses.0,
        responses.1,
        responses.2,
        responses.3,
        responses.4,
    ];
    let ok = responses
        .iter()
        .filter(|r| r.status == StatusCode::OK)
        .count();
    assert_eq!(ok, 3);
    assert_eq!(s.upstream.received().len(), 3);
}

#[tokio::test]
async fn refused_calls_do_not_use_the_budget() {
    let s = setup_daily(2).await;
    let url = s.upstream.url("/v1/hello");
    for _ in 0..5 {
        let refused = call_as(&s.broker, &s.key, &s.grant, "DELETE", &url, None).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    }
    proxied(&get(&s, "/v1/hello").await);
    proxied(&get(&s, "/v1/hello").await);
    assert_eq!(s.upstream.received().len(), 2);
}
