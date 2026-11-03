//! A proxied call already out when its grant ends: against a real upstream that
//! never finishes by itself, the call stops, the connection closes, the agent
//! gets a fixed message and the audit log says how far it came. Everything here
//! waits on a condition; `WAIT` only stops a broken build from hanging, and is
//! shorter than the 30 s after which a call would time out by itself.

use std::future::Future;
use std::time::Duration;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use warden_broker::audit::AuditEvent;
use warden_broker::proxy::{CallEnd, CallInfo};
use warden_broker::requests::{AuditOutcome, Clock as _, unwritten_entries};
use warden_broker::testkit::{HttpsUpstream, TestBroker, TestResponse};
use warden_broker_proto::{AgentName, Id, RequestStatus, Window};

const SECRET: &str = "pr0xy-Cred/+=en&tial~42";

const WAIT: Duration = Duration::from_secs(20);

struct Setup {
    broker: TestBroker,
    upstream: HttpsUpstream,
    key: String,
    grant: Id,
}

async fn setup() -> Setup {
    let broker = TestBroker::new().await;
    let upstream = HttpsUpstream::start().await;
    broker
        .backend
        .set_api_secret(upstream.policy("svc"), SECRET);
    let key = broker.add_agent("bot").await;
    let grant = approve(&broker, "bot").await;
    Setup {
        broker,
        upstream,
        key,
        grant,
    }
}

async fn approve(broker: &TestBroker, agent: &str) -> Id {
    let req = TestBroker::api_request("svc", "call the test api", Window::M30);
    let (created, token) = broker.create_request(agent, req).await;
    let done = broker.approve(&token, Window::M30).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    let agent = AgentName::try_from(agent.to_owned()).unwrap();
    match broker
        .state()
        .requests
        .status(&agent, &created.id, Duration::ZERO)
        .await
        .unwrap()
    {
        RequestStatus::Approved(view) => view.grant_id,
        other => panic!("expected approved, got {other:?}"),
    }
}

async fn call(broker: &TestBroker, key: &str, grant: &Id, url: &str) -> TestResponse {
    broker
        .api_post_json(
            key,
            &format!("/v1/grants/{grant}/http"),
            &json!({"method": "GET", "url": url, "headers": [], "body_b64": null}),
        )
        .await
}

async fn get(s: &Setup, path: &str) -> TestResponse {
    call(&s.broker, &s.key, &s.grant, &s.upstream.url(path)).await
}

async fn within<T>(what: &str, work: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, work)
        .await
        .unwrap_or_else(|_| panic!("{what} did not happen"))
}

/// Wait until the upstream has `count` requests.
async fn reached(s: &Setup, count: usize) {
    within("the call reaching the upstream", async {
        while s.upstream.received().len() < count {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

fn audit_events(broker: &TestBroker, kind: &str) -> Vec<Value> {
    std::fs::read_to_string(broker.audit_path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["event"].clone())
        .filter(|event| event["type"] == kind)
        .collect()
}

fn the_call(broker: &TestBroker) -> Value {
    let mut calls = audit_events(broker, "proxy_call");
    assert_eq!(calls.len(), 1, "{calls:?}");
    calls.remove(0)
}

/// `text` holds the secret in no form an upstream echoes it in here.
fn assert_clean(text: &str, what: &str) {
    for leak in [
        SECRET.to_owned(),
        STANDARD.encode(SECRET),
        STANDARD.encode(format!("Bearer {SECRET}")),
    ] {
        assert!(!text.contains(&leak), "{what} leaks {leak:?}:\n{text}");
    }
}

/// The revocation returns while the upstream has not answered and never will,
/// so it cannot have waited for it; then the call stops and the connection
/// closes. Nothing had come back, and the audit says so.
#[tokio::test]
async fn revoke_stops_a_call_waiting_for_its_answer() {
    let s = setup().await;
    let (resp, ()) = tokio::join!(within("the call ending", get(&s, "/hang")), async {
        reached(&s, 1).await;
        let revoked = s
            .broker
            .state()
            .requests
            .revoke_grant(&s.grant, "owner")
            .await
            .unwrap();
        assert_eq!(revoked, AuditOutcome::Recorded);
        within("the connection closing", s.upstream.wait_for_abandoned(1)).await;
    });
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"grant revoked during the call"}"#);
    let audited = the_call(&s.broker);
    assert_eq!(audited["outcome"], "grant revoked during the call");
    assert_eq!(audited["aborted"], "revoked");
    assert_eq!(audited["status"], Value::Null);
    assert_eq!(audited["response_bytes"], 0);
    assert_eq!(audited["redactions"], 0);
    assert_eq!(audit_events(&s.broker, "grant_revoked")[0]["by"], "owner");
    assert_eq!(
        s.broker.state().requests.proxy_calls().snapshot(),
        [] as [CallInfo; 0]
    );
}

/// A revocation through this broker tells the calls itself, with no check having
/// to find it: these slots have nothing else running that could.
#[tokio::test]
async fn a_revocation_tells_the_calls_directly() {
    let s = setup().await;
    let requests = &s.broker.state().requests;
    let hold = |agent: &str, grant: &Id| {
        let agent = AgentName::try_from(agent.to_owned()).unwrap();
        let info = CallInfo::new(grant.clone(), "GET".to_owned(), "/".to_owned(), 0);
        requests.proxy_calls().try_acquire(&agent, info).unwrap()
    };

    let slot = hold("bot", &s.grant);
    requests.revoke_grant(&s.grant, "owner").await.unwrap();
    let end = within("the grant's call", slot.ended()).await;
    assert_eq!(end, CallEnd::Revoked);

    // Revoked already by another process: revoking again here tells the calls.
    s.broker.add_agent("second").await;
    let second = approve(&s.broker, "second").await;
    let slot = hold("second", &second);
    warden_broker::requests::revoke_agent(
        &s.broker.state().pool,
        &AgentName::try_from("second".to_owned()).unwrap(),
        s.broker.clock.now(),
    )
    .await
    .unwrap();
    requests.revoke_grant(&second, "owner").await.unwrap();
    let end = within("the call of a revoked grant", slot.ended()).await;
    assert_eq!(end, CallEnd::Revoked);

    s.broker.add_agent("third").await;
    let third = approve(&s.broker, "third").await;
    let slot = hold("third", &third);
    requests
        .revoke_agent(&AgentName::try_from("third".to_owned()).unwrap())
        .await
        .unwrap();
    let end = within("the agent's call", slot.ended()).await;
    assert_eq!(end, CallEnd::Revoked);
}

/// A response cut part-way never reaches the agent: what had arrived held the
/// secret, unredacted, and is dropped. The audit records how far it came.
#[tokio::test]
async fn revoke_cuts_a_response_still_streaming_and_nothing_of_it_gets_out() {
    let s = setup().await;
    let bearer = format!("Bearer {SECRET}");
    let calls = s.broker.state().requests.proxy_calls();
    let mut seen = 0;
    let (resp, ()) = tokio::join!(within("the call ending", get(&s, "/drip")), async {
        within("the answer arriving", async {
            while calls.response_bytes_in_flight() <= u64::try_from(bearer.len()).unwrap() {
                tokio::task::yield_now().await;
            }
        })
        .await;
        seen = calls.response_bytes_in_flight();
        // Through the agent's own route this time.
        let revoked = s
            .broker
            .api_post(&s.key, &format!("/v1/grants/{}/revoke", s.grant))
            .await;
        assert_eq!(revoked.status, StatusCode::NO_CONTENT, "{}", revoked.body);
        within("the connection closing", s.upstream.wait_for_abandoned(1)).await;
    });
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"grant revoked during the call"}"#);
    assert_clean(&resp.body, "the agent's answer");
    for (name, value) in &resp.headers {
        assert_clean(
            &format!("{name}: {}", String::from_utf8_lossy(value.as_bytes())),
            "a header of the agent's answer",
        );
    }

    let audited = the_call(&s.broker);
    assert_eq!(audited["aborted"], "revoked");
    assert_eq!(audited["status"], 200);
    assert!(
        audited["response_bytes"].as_u64().unwrap() >= seen,
        "{audited}"
    );
    assert_eq!(audited["redactions"], 0);
    assert_clean(
        &std::fs::read_to_string(s.broker.audit_path()).unwrap(),
        "the audit log",
    );
}

/// Revoking an agent stops its calls and leaves other agents' alone.
#[tokio::test]
async fn revoking_an_agent_stops_its_calls_only() {
    let s = setup().await;
    let other_key = s.broker.add_agent("other").await;
    let other_grant = approve(&s.broker, "other").await;
    let delayed = s.upstream.url("/delayed");
    let (mine, theirs, ()) = tokio::join!(
        within("the call ending", get(&s, "/hang")),
        async {
            reached(&s, 1).await;
            call(&s.broker, &other_key, &other_grant, &delayed).await
        },
        async {
            reached(&s, 2).await;
            s.broker
                .state()
                .requests
                .revoke_agent(&AgentName::try_from("bot".to_owned()).unwrap())
                .await
                .unwrap();
        },
    );
    assert_eq!(mine.status, StatusCode::CONFLICT, "{}", mine.body);
    assert_eq!(theirs.status, StatusCode::OK, "{}", theirs.body);
    let audited = audit_events(&s.broker, "proxy_call");
    assert_eq!(audited.len(), 2, "{audited:?}");
    let aborted: Vec<_> = audited.iter().map(|c| c["aborted"].clone()).collect();
    assert!(aborted.contains(&json!("revoked")), "{audited:?}");
    assert!(aborted.contains(&Value::Null), "{audited:?}");
    within("the connection closing", s.upstream.wait_for_abandoned(1)).await;
}

/// A revocation this broker made nothing of (`warden-server agent revoke` is
/// another process, and only changes the database) is found by the call's check.
#[tokio::test]
async fn a_revocation_by_another_process_stops_the_call() {
    let s = setup().await;
    let (resp, ()) = tokio::join!(within("the call ending", get(&s, "/hang")), async {
        reached(&s, 1).await;
        warden_broker::requests::revoke_agent(
            &s.broker.state().pool,
            &AgentName::try_from("bot".to_owned()).unwrap(),
            s.broker.clock.now(),
        )
        .await
        .unwrap();
    });
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"grant revoked during the call"}"#);
    assert_eq!(the_call(&s.broker)["aborted"], "revoked");
    within("the connection closing", s.upstream.wait_for_abandoned(1)).await;
}

/// An answer that arrives after a revocation no slot heard of is checked once
/// more, and withheld. The upstream answers only once the database says revoked.
#[tokio::test]
async fn an_answer_after_a_revocation_is_withheld() {
    let s = setup().await;
    let (resp, ()) = tokio::join!(within("the call ending", get(&s, "/held")), async {
        reached(&s, 1).await;
        warden_broker::requests::revoke_agent(
            &s.broker.state().pool,
            &AgentName::try_from("bot".to_owned()).unwrap(),
            s.broker.clock.now(),
        )
        .await
        .unwrap();
        s.upstream.release_held();
    });
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"grant revoked during the call"}"#);
    assert_eq!(
        the_call(&s.broker)["outcome"],
        "grant revoked during the call"
    );
}

/// The end of the window stops a call too, with no revocation.
#[tokio::test]
async fn expiry_stops_the_call() {
    let s = setup().await;
    let (resp, ()) = tokio::join!(within("the call ending", get(&s, "/hang")), async {
        reached(&s, 1).await;
        s.broker.clock.advance(30 * 60);
    });
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"grant expired during the call"}"#);
    let audited = the_call(&s.broker);
    assert_eq!(audited["outcome"], "grant expired during the call");
    assert_eq!(audited["aborted"], "expired");
    within("the connection closing", s.upstream.wait_for_abandoned(1)).await;
}

/// With nothing able to say the grant still holds, the call stops. This waits
/// for the real limit of 10 s.
#[tokio::test]
async fn a_grant_state_that_stays_unreadable_stops_the_call() {
    let s = setup().await;
    let (resp, ()) = tokio::join!(within("the call ending", get(&s, "/hang")), async {
        reached(&s, 1).await;
        s.broker.state().pool.close().await;
    });
    assert_eq!(
        resp.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        resp.body
    );
    assert_eq!(
        resp.body,
        r#"{"error":"grant state unavailable during the call"}"#
    );
    assert_eq!(the_call(&s.broker)["aborted"], "grant_state_unavailable");
    within("the connection closing", s.upstream.wait_for_abandoned(1)).await;
}

/// The call is told before the revocation goes near the log, which here does not
/// answer, so a revocation can still be waiting for it when the slot hears. Polling
/// the revocation first catches an order that tells the call only after the log:
/// on this single-threaded runtime it would then be finished by the time the slot
/// wakes.
#[tokio::test]
async fn a_stalled_log_cannot_delay_telling_the_calls() {
    let s = setup().await;
    let requests = &s.broker.state().requests;
    let hold = |agent: &str, grant: &Id| {
        let agent = AgentName::try_from(agent.to_owned()).unwrap();
        let info = CallInfo::new(grant.clone(), "GET".to_owned(), "/".to_owned(), 0);
        requests.proxy_calls().try_acquire(&agent, info).unwrap()
    };
    s.broker.add_agent("other").await;
    let other_grant = approve(&s.broker, "other").await;
    let by_grant = hold("bot", &s.grant);
    let by_agent = hold("other", &other_grant);
    let holder = std::fs::File::open(s.broker.audit_path()).unwrap();
    holder.lock().unwrap();

    let revoking = requests.revoke_grant(&s.grant, "owner");
    tokio::pin!(revoking);
    tokio::select! {
        biased;
        _ = &mut revoking => panic!("the revocation finished before telling the call"),
        end = by_grant.ended() => assert_eq!(end, CallEnd::Revoked),
    }
    assert_eq!(revoking.await.unwrap(), AuditOutcome::Missing);

    let other = AgentName::try_from("other".to_owned()).unwrap();
    let revoking = requests.revoke_agent(&other);
    tokio::pin!(revoking);
    tokio::select! {
        biased;
        _ = &mut revoking => panic!("the revocation finished before telling the call"),
        end = by_agent.ended() => assert_eq!(end, CallEnd::Revoked),
    }
    assert_eq!(revoking.await.unwrap(), AuditOutcome::Missing);
    drop(holder);
}

/// A log that does not answer holds up neither the end of the call nor its answer,
/// and the entry of how it ended is not lost: it waits in the database, and
/// reaches the log once the log works.
#[tokio::test]
async fn a_stalled_log_does_not_keep_a_call_going_or_lose_its_end() {
    let s = setup().await;
    let (resp, holder) = tokio::join!(within("the call ending", get(&s, "/hang")), async {
        reached(&s, 1).await;
        let holder = std::fs::File::open(s.broker.audit_path()).unwrap();
        holder.lock().unwrap();
        let revoked = s
            .broker
            .state()
            .requests
            .revoke_grant(&s.grant, "owner")
            .await
            .unwrap();
        assert_eq!(revoked, AuditOutcome::Missing);
        within("the connection closing", s.upstream.wait_for_abandoned(1)).await;
        holder
    });
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    assert_eq!(resp.body, r#"{"error":"grant revoked during the call"}"#);

    // The log has not moved: the agent's answer did not wait for it.
    assert_eq!(audit_events(&s.broker, "proxy_call"), [] as [Value; 0]);
    let waiting = unwritten_entries(&s.broker.state().pool).await.unwrap();
    assert!(
        waiting.iter().any(|entry| matches!(
            entry,
            AuditEvent::ProxyCall {
                aborted: Some(CallEnd::Revoked),
                ..
            }
        )),
        "{waiting:?}"
    );
    assert_ne!(
        s.broker
            .state()
            .requests
            .unwritten_entry_count()
            .await
            .unwrap(),
        0
    );

    drop(holder);
    within("the entry reaching the log", async {
        while s
            .broker
            .state()
            .requests
            .unwritten_entry_count()
            .await
            .unwrap()
            > 0
        {
            s.broker.state().requests.flush_waiting_entries().await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert_eq!(the_call(&s.broker)["aborted"], "revoked");
}

/// A call that ends by itself is not affected, and its entry has no `aborted`.
#[tokio::test]
async fn a_call_that_finishes_has_no_abort_in_its_entry() {
    let s = setup().await;
    let resp = get(&s, "/delayed").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let audited = the_call(&s.broker);
    assert_eq!(audited["outcome"], "ok");
    assert_eq!(audited.get("aborted"), None, "{audited}");
    assert_eq!(s.upstream.abandoned(), 0);
}

/// An agent never sees an answer the audit log has no record of: if the entry for
/// a finished call cannot be written, the answer stays with the broker.
#[tokio::test]
async fn an_answer_is_withheld_when_its_entry_cannot_be_written() {
    let s = setup().await;
    let log = s.broker.audit_path().to_owned();
    let (resp, good) = tokio::join!(within("the call ending", get(&s, "/held")), async {
        reached(&s, 1).await;
        let good = std::fs::read(&log).unwrap();
        let mut corrupt = good.clone();
        corrupt.extend_from_slice(b"not an audit line\n");
        std::fs::write(&log, corrupt).unwrap();
        s.upstream.release_held();
        good
    });
    assert_eq!(
        resp.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        resp.body
    );
    assert!(!resp.body.contains("late answer"), "{}", resp.body);
    std::fs::write(&log, good).unwrap();
    assert_eq!(audit_events(&s.broker, "proxy_call_started").len(), 1);
    assert_eq!(audit_events(&s.broker, "proxy_call").len(), 0);
}

/// The scope of a call comes from the stored grant. One that can no longer be read
/// limits nothing, so the secret is not used for the call at all.
#[tokio::test]
async fn a_damaged_grant_sends_nothing() {
    let s = setup().await;
    let pool = &s.broker.state().pool;
    let view: String = sqlx::query_scalar("SELECT view FROM grants WHERE id = ?")
        .bind(s.grant.as_str())
        .fetch_one(pool)
        .await
        .unwrap();
    let damaged = view.replace(r#""GET""#, r#""NOT A METHOD""#);
    assert_ne!(damaged, view);
    sqlx::query("UPDATE grants SET view = ? WHERE id = ?")
        .bind(damaged)
        .bind(s.grant.as_str())
        .execute(pool)
        .await
        .unwrap();

    let resp = get(&s, "/plain").await;
    assert_eq!(
        resp.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        resp.body
    );
    assert!(!resp.body.contains("METHOD"), "{}", resp.body);
    assert!(s.upstream.received().is_empty());
}
