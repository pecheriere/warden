//! Ending access does not wait for the audit log, however long the log takes.
//!
//! An append here is held until the test lets it go, with no time limit, as on a
//! disk that has stalled. What a change has done is read from the database while
//! the append is still held. The timeouts only stop a test from hanging when the
//! code under test is wrong: they are far beyond anything correct code waits for.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use warden_broker::requests::{
    self, AuditOutcome, Clock, RequestError, RequestLimits, SystemClock,
};
use warden_broker::testkit::{FakeBackend, TestBroker};
use warden_broker_proto::{AgentName, Id, RequestStatus, Window};

/// Longer than anything here should take. Not what is being tested.
const HANG: Duration = Duration::from_secs(30);

fn bot() -> AgentName {
    AgentName::try_from("bot".to_owned()).unwrap()
}

/// Wait until `query`, which counts rows, finds one.
async fn until_row(broker: &TestBroker, query: &'static str, what: &str) {
    tokio::time::timeout(HANG, async {
        while sqlx::query_scalar::<_, i64>(query)
            .fetch_one(&broker.state().pool)
            .await
            .unwrap()
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}, with an append held"));
}

async fn until_recorded(broker: &TestBroker, kind: &str) {
    tokio::time::timeout(HANG, async {
        while !broker.audit_types().iter().any(|t| t == kind) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {kind} entry"));
}

/// A broker with agent `bot` (its key returned too), holding an approved API grant.
async fn api_grant() -> (TestBroker, String, Id) {
    let broker = TestBroker::new().await;
    broker
        .backend
        .set_api_secret(FakeBackend::example_api_secret(), "not-a-real-secret");
    let key = broker.add_agent("bot").await;
    broker.enroll_soft_passkey().await;
    let (created, token) = broker
        .create_request(
            "bot",
            TestBroker::api_request("github", "list issues", Window::M15),
        )
        .await;
    until_recorded(&broker, "notified").await;
    let approved = broker.approve(&token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let status = broker
        .state()
        .requests
        .status(&bot(), &created.id, Duration::ZERO)
        .await
        .unwrap();
    let RequestStatus::Approved(view) = status else {
        panic!("expected approved");
    };
    (broker, key, view.grant_id)
}

/// Start a change that writes its entry first, and wait until its append is held:
/// the writer a revocation must get past.
async fn other_writer_held(broker: &TestBroker, stall: &warden_broker::audit::AppendStall) {
    let passkeys = broker.state().passkeys.clone();
    let now = broker.clock.now();
    drop(tokio::spawn(async move {
        passkeys.create_enrollment_code(now).await
    }));
    stall.until_holding(1).await;
}

#[tokio::test]
async fn revoking_a_grant_commits_and_answers_with_appends_held() {
    let (broker, key, grant) = api_grant().await;
    let audit = broker.state().audit.clone();
    let stall = audit.stall_appends(|_| true);
    other_writer_held(&broker, &stall).await;

    let revoke = {
        let requests = broker.state().requests.clone();
        let grant = grant.clone();
        tokio::spawn(async move { requests.revoke_grant(&grant, "owner").await })
    };
    // Committed, with the other writer's append and this one's own held.
    until_row(
        &broker,
        "SELECT COUNT(*) FROM grants WHERE revoked_at IS NOT NULL",
        "the grant was not revoked",
    )
    .await;
    stall.until_holding(2).await;
    let refused = broker
        .api_post_json(
            &key,
            &format!("/v1/grants/{grant}/http"),
            &serde_json::json!({"method": "GET", "url": "https://api.example.com/x", "headers": []}),
        )
        .await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);

    // And the owner gets an answer while they are still held.
    let outcome = tokio::time::timeout(HANG, revoke)
        .await
        .expect("revoking waited for the audit log")
        .unwrap()
        .unwrap();
    assert_eq!(outcome, AuditOutcome::Missing);
    assert!(stall.holding() >= 2);

    // The entry follows once the log answers.
    drop(stall);
    until_recorded(&broker, "grant_revoked").await;
}

#[tokio::test]
async fn revoking_an_agent_commits_and_answers_with_appends_held() {
    let (broker, key, _grant) = api_grant().await;
    let audit = broker.state().audit.clone();
    let stall = audit.stall_appends(|_| true);
    other_writer_held(&broker, &stall).await;

    let revoke = {
        let requests = broker.state().requests.clone();
        tokio::spawn(async move { requests.revoke_agent(&bot()).await })
    };
    until_row(
        &broker,
        "SELECT COUNT(*) FROM agents WHERE revoked_at IS NOT NULL",
        "the agent was not revoked",
    )
    .await;
    until_row(
        &broker,
        "SELECT COUNT(*) FROM grants WHERE revoked_at IS NOT NULL",
        "its grant was not revoked",
    )
    .await;
    stall.until_holding(2).await;
    let refused = broker.api_get(&key, "/v1/grants").await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{}", refused.body);

    let outcome = tokio::time::timeout(HANG, revoke)
        .await
        .expect("revoking waited for the audit log")
        .unwrap()
        .unwrap();
    assert_eq!(outcome, AuditOutcome::Missing);
    assert!(stall.holding() >= 2);

    drop(stall);
    until_recorded(&broker, "agent_revoked").await;
}

/// What `warden-server agent revoke` does, from a process of its own.
#[tokio::test]
async fn the_agent_revoke_command_path_commits_and_answers_with_appends_held() {
    let (broker, key, _grant) = api_grant().await;
    let audit = broker.state().audit.clone();
    let stall = audit.stall_appends(|_| true);
    other_writer_held(&broker, &stall).await;

    let pool = &broker.state().pool;
    tokio::time::timeout(
        HANG,
        requests::revoke_agent(pool, &bot(), broker.clock.now()),
    )
    .await
    .expect("revoking waited for the audit log")
    .unwrap();
    let refused = broker.api_get(&key, "/v1/grants").await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{}", refused.body);

    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let written = tokio::time::timeout(HANG, requests::write_entries(pool, &audit, &clock))
        .await
        .expect("writing the entries waited for the audit log");
    assert_eq!(written.outcome, AuditOutcome::Missing);
    assert!(stall.holding() >= 2);
    assert_ne!(requests::unwritten_entries(pool).await.unwrap().len(), 0);

    drop(stall);
    until_recorded(&broker, "agent_revoked").await;
}

#[tokio::test]
async fn denying_commits_and_answers_with_appends_held() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let (_, to_deny) = broker
        .create_request("bot", TestBroker::pi_request("first", Window::M15))
        .await;
    until_recorded(&broker, "notified").await;
    let audit = broker.state().audit.clone();
    let stall = audit.stall_appends(|_| true);
    other_writer_held(&broker, &stall).await;

    let deny = {
        let requests = broker.state().requests.clone();
        tokio::spawn(async move { requests.deny(&to_deny).await })
    };
    until_row(
        &broker,
        "SELECT COUNT(*) FROM requests WHERE status = 'denied'",
        "the request was not denied",
    )
    .await;
    let outcome = tokio::time::timeout(HANG, deny)
        .await
        .expect("denying waited for the audit log")
        .unwrap()
        .unwrap();
    assert_eq!(outcome, AuditOutcome::Missing);
    drop(stall);
    until_recorded(&broker, "denied").await;
}

/// The sweep drives expiry and the writing of waiting entries: a refusal count that
/// cannot be written must hold up neither.
#[tokio::test]
async fn the_sweep_goes_on_while_a_refusal_count_is_held() {
    let broker = TestBroker::with_request_limits(RequestLimits {
        max_pending: 1,
        max_new: 10,
        window_secs: 600,
    })
    .await;
    broker.add_agent("bot").await;
    broker
        .create_request("bot", TestBroker::pi_request("restart", Window::M15))
        .await;
    until_recorded(&broker, "notified").await;
    broker
        .backend
        .set_api_secret(FakeBackend::example_api_secret(), "not-a-real-secret");
    // The first refusal is recorded at once, and the second is counted.
    for _ in 0..2 {
        let refused = TestBroker::api_request("github", "list issues", Window::M15);
        let got = broker.state().requests.create(&bot(), refused).await;
        assert!(matches!(got, Err(RequestError::Limited(_))));
    }
    let audit = broker.state().audit.clone();
    let stall = audit.stall_appends(|event| {
        matches!(
            event,
            warden_broker::audit::AuditEvent::RequestLimited { .. }
        )
    });

    // The count is due, and the sweep gets held writing it.
    broker.clock.advance(60);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let sweeper = tokio::spawn(requests::sweep_loop(
        broker.state().requests.clone(),
        Duration::from_millis(10),
        stopped,
    ));
    stall.until_holding(1).await;

    // Later ticks still expire a request and write its entry.
    broker.clock.advance(600);
    until_row(
        &broker,
        "SELECT COUNT(*) FROM requests WHERE status = 'expired'",
        "the sweep did not expire the request",
    )
    .await;
    until_recorded(&broker, "expired").await;
    tokio::time::timeout(HANG, async {
        while broker
            .state()
            .requests
            .unwritten_entry_count()
            .await
            .unwrap()
            > 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the sweep did not write the waiting entry");
    assert_eq!(stall.holding(), 1);

    drop(stall);
    stop.send(true).unwrap();
    sweeper.await.unwrap();
}
