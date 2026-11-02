//! Per-agent request limits, through the agent API. Time only moves through
//! the broker's manual clock.

use axum::http::StatusCode;
use serde_json::{Value, json};
use warden_broker::notify::Doorbell;
use warden_broker::requests::RequestLimits;
use warden_broker::testkit::{CapturingNotifier, TestBroker, TestResponse};
use warden_broker_proto::Window;

const LIMITS: RequestLimits = RequestLimits {
    max_pending: 2,
    max_new: 3,
    window_secs: 300,
};

/// The body of a request with a dedupe slot of its own.
fn body(slot: u32) -> Value {
    serde_json::to_value(TestBroker::api_request(
        "github",
        "triage issue 42",
        Window::M15,
    ))
    .map(|mut v| {
        v["access"]["path_prefix"] = json!(format!("/repos/{slot}"));
        v
    })
    .unwrap()
}

async fn create(broker: &TestBroker, key: &str, slot: u32) -> TestResponse {
    broker.api_post_json(key, "/v1/requests", &body(slot)).await
}

async fn created_id(broker: &TestBroker, key: &str, slot: u32) -> String {
    let resp = create(broker, key, slot).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.body);
    resp.json()["id"].as_str().unwrap().to_owned()
}

async fn cancel(broker: &TestBroker, key: &str, id: &str) {
    let resp = broker
        .api_post(key, &format!("/v1/requests/{id}/cancel"))
        .await;
    assert_eq!(resp.status, StatusCode::NO_CONTENT, "{}", resp.body);
}

async fn broker() -> TestBroker {
    let broker = TestBroker::with_request_limits(LIMITS).await;
    broker.backend.set_api_secret(
        warden_broker::testkit::FakeBackend::example_api_secret(),
        "not-a-real-secret",
    );
    broker
}

async fn request_count(broker: &TestBroker) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM requests")
        .fetch_one(&broker.state().pool)
        .await
        .unwrap()
}

/// The notices that an agent is over its limit, among the doorbells rung.
fn limit_notices(broker: &TestBroker) -> Vec<Doorbell> {
    broker
        .capture
        .rung()
        .into_iter()
        .filter(|bell| bell.title == "warden: build-agent is over its request limit")
        .collect()
}

/// The `request_limited` entries of the audit log, as (agent, pending, rate).
fn limited_entries(broker: &TestBroker) -> Vec<(String, u64, u64)> {
    std::fs::read_to_string(broker.audit_path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|line| line["event"]["type"] == "request_limited")
        .map(|line| {
            let event = &line["event"];
            (
                event["agent"].as_str().unwrap().to_owned(),
                event["pending"].as_u64().unwrap(),
                event["rate"].as_u64().unwrap(),
            )
        })
        .collect()
}

#[tokio::test]
async fn pending_limit_refuses_clearly_stores_nothing_and_audits() {
    let broker = broker().await;
    let key = broker.add_agent("build-agent").await;
    for slot in 0..2 {
        created_id(&broker, &key, slot).await;
    }
    broker.clock.advance(100);
    let refused = create(&broker, &key, 2).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    // The first of the two still at the limit expires 500 s from now.
    assert_eq!(refused.header("retry-after"), "500");
    assert_eq!(
        refused.json()["error"],
        "too many pending requests: at most 2 per agent. Cancel one or wait for the owner; a slot frees within 500 s"
    );
    assert_eq!(request_count(&broker).await, 2);
    assert_eq!(limited_entries(&broker), [("build-agent".to_owned(), 1, 0)]);
}

#[tokio::test]
async fn cancelling_frees_a_pending_slot_but_still_counts_as_a_new_request() {
    let broker = broker().await;
    let key = broker.add_agent("build-agent").await;
    let first = created_id(&broker, &key, 0).await;
    let second = created_id(&broker, &key, 1).await;
    cancel(&broker, &key, &first).await;
    created_id(&broker, &key, 2).await;
    cancel(&broker, &key, &second).await;
    // Only one is pending now, but three were made in the window.
    broker.clock.advance(100);
    let refused = create(&broker, &key, 3).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.header("retry-after"), "200");
    assert_eq!(
        refused.json()["error"],
        "too many new requests: at most 3 every 300 s, cancelled ones included. Try again in 200 s"
    );
    assert_eq!(limited_entries(&broker), [("build-agent".to_owned(), 0, 1)]);

    // The limit ends with the window, exactly when the agent was told.
    broker.clock.advance(199);
    let refused = create(&broker, &key, 3).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.header("retry-after"), "1");
    broker.clock.advance(1);
    created_id(&broker, &key, 3).await;
}

#[tokio::test]
async fn the_limits_survive_a_restart() {
    let broker = broker().await;
    let key = broker.add_agent("build-agent").await;
    let first = created_id(&broker, &key, 0).await;
    created_id(&broker, &key, 1).await;
    cancel(&broker, &key, &first).await;
    created_id(&broker, &key, 2).await;
    let broker = broker.restart().await;
    assert_eq!(
        create(&broker, &key, 3).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn expiry_frees_pending_slots_even_before_any_sweep() {
    let broker = TestBroker::with_request_limits(RequestLimits {
        max_pending: 1,
        max_new: 100,
        window_secs: 60,
    })
    .await;
    broker.backend.set_api_secret(
        warden_broker::testkit::FakeBackend::example_api_secret(),
        "not-a-real-secret",
    );
    let key = broker.add_agent("build-agent").await;
    created_id(&broker, &key, 0).await;
    broker.clock.advance(599);
    let refused = create(&broker, &key, 1).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.header("retry-after"), "1");
    broker.clock.advance(1);
    created_id(&broker, &key, 1).await;
}

#[tokio::test]
async fn a_duplicate_of_a_pending_request_is_answered_at_the_limit() {
    let broker = broker().await;
    let key = broker.add_agent("build-agent").await;
    let first = created_id(&broker, &key, 0).await;
    created_id(&broker, &key, 1).await;
    assert_eq!(
        create(&broker, &key, 2).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    // It stores nothing and rings nobody, so it has no limit to hit.
    assert_eq!(created_id(&broker, &key, 0).await, first);
    assert_eq!(request_count(&broker).await, 2);
}

#[tokio::test]
async fn one_agent_at_its_limits_blocks_neither_another_agent_nor_the_owner() {
    let broker = broker().await;
    broker.enroll_soft_passkey().await;
    let flooding = broker.add_agent("flooding").await;
    let other = broker.add_agent("other").await;
    created_id(&broker, &flooding, 0).await;
    let first_bell = broker.capture.next().await;
    created_id(&broker, &flooding, 1).await;
    let second_bell = broker.capture.next().await;
    assert_eq!(
        create(&broker, &flooding, 2).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    let notice = broker.capture.next().await;
    assert!(notice.title.contains("flooding"), "{notice:?}");

    // The other agent has its whole allowance.
    created_id(&broker, &other, 0).await;
    let other_bell = broker.capture.next().await;
    created_id(&broker, &other, 1).await;

    // The owner can decide all of them, which also frees the flooding agent's
    // pending slots.
    let token = CapturingNotifier::token(&other_bell);
    let approved = broker.approve(&token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let token = CapturingNotifier::token(&first_bell);
    assert_eq!(
        broker.approve(&token, Window::M15).await.status,
        StatusCode::OK
    );
    assert_eq!(
        broker
            .deny(&CapturingNotifier::token(&second_bell))
            .await
            .status,
        StatusCode::OK
    );
    created_id(&broker, &flooding, 2).await;
}

#[tokio::test]
async fn the_owner_is_told_once_and_refusals_cannot_fill_the_audit_log() {
    let broker = broker().await;
    let key = broker.add_agent("build-agent").await;
    created_id(&broker, &key, 0).await;
    created_id(&broker, &key, 1).await;
    for _ in 0..5 {
        assert_eq!(
            create(&broker, &key, 2).await.status,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    let rung = limit_notices(&broker);
    assert_eq!(rung.len(), 1, "{rung:?}");
    assert!(!rung[0].message.contains("triage"), "{rung:?}");
    assert_eq!(rung[0].url.path(), "/history");
    assert_eq!(limited_entries(&broker), [("build-agent".to_owned(), 1, 0)]);
    let types = broker.audit_types();
    assert_eq!(
        types.iter().filter(|t| *t == "limit_notified").count(),
        1,
        "{types:?}"
    );

    // Refusals held back come out with the next entry, a minute on.
    broker.clock.advance(60);
    assert_eq!(
        create(&broker, &key, 2).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        limited_entries(&broker),
        [
            ("build-agent".to_owned(), 1, 0),
            ("build-agent".to_owned(), 5, 0)
        ]
    );
    assert_eq!(limit_notices(&broker).len(), 1);
    warden_broker::audit::verify(broker.audit_path()).unwrap();
}

#[tokio::test]
async fn refusals_held_back_are_written_by_the_sweep_even_if_the_agent_stops() {
    let broker = broker().await;
    let key = broker.add_agent("build-agent").await;
    created_id(&broker, &key, 0).await;
    created_id(&broker, &key, 1).await;
    for _ in 0..2 {
        assert_eq!(
            create(&broker, &key, 2).await.status,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    broker.state().requests.flush_refusals(false).await;
    assert_eq!(limited_entries(&broker).len(), 1);
    broker.clock.advance(60);
    broker.state().requests.flush_refusals(false).await;
    assert_eq!(
        limited_entries(&broker),
        [
            ("build-agent".to_owned(), 1, 0),
            ("build-agent".to_owned(), 1, 0)
        ]
    );
}

#[tokio::test]
async fn a_failed_audit_write_still_refuses_and_the_count_is_written_later() {
    let broker = broker().await;
    let key = broker.add_agent("build-agent").await;
    created_id(&broker, &key, 0).await;
    created_id(&broker, &key, 1).await;
    // Notifications are recorded in the background: wait for them, so that the
    // audit log stays as it is saved here.
    wait_for_audit_entries(&broker, "notified", 2).await;

    let good = std::fs::read(broker.audit_path()).unwrap();
    let mut corrupt = good.clone();
    corrupt.extend_from_slice(b"not an audit line\n");
    std::fs::write(broker.audit_path(), &corrupt).unwrap();
    assert_eq!(
        create(&broker, &key, 2).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(request_count(&broker).await, 2);

    // During the outage, further refusals are counted and not retried at once.
    assert_eq!(
        create(&broker, &key, 2).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    std::fs::write(broker.audit_path(), &good).unwrap();
    assert_eq!(limited_entries(&broker), []);

    broker.clock.advance(60);
    assert_eq!(
        create(&broker, &key, 2).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(limited_entries(&broker), [("build-agent".to_owned(), 3, 0)]);
}

/// Wait until the audit log holds `count` entries of `kind`.
async fn wait_for_audit_entries(broker: &TestBroker, kind: &str, count: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while broker.audit_types().iter().filter(|t| *t == kind).count() < count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("audit entries within 5 s");
}

#[tokio::test]
async fn a_clock_set_back_does_not_hold_the_rate_limit_past_its_window() {
    let broker = broker().await;
    let key = broker.add_agent("build-agent").await;
    let first = created_id(&broker, &key, 0).await;
    let second = created_id(&broker, &key, 1).await;
    cancel(&broker, &key, &first).await;
    let third = created_id(&broker, &key, 2).await;
    cancel(&broker, &key, &second).await;
    cancel(&broker, &key, &third).await;
    assert_eq!(
        create(&broker, &key, 3).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );

    // Requests dated ahead of the clock do not count, so nothing outlasts the
    // wait the agent is told, and requests made from here on count as usual.
    broker.clock.advance(-1000);
    for slot in 3..5 {
        let id = created_id(&broker, &key, slot).await;
        cancel(&broker, &key, &id).await;
    }
    created_id(&broker, &key, 5).await;
    let refused = create(&broker, &key, 6).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.header("retry-after"), "300");
    broker.clock.advance(300);
    created_id(&broker, &key, 6).await;
}

#[tokio::test]
async fn after_a_clock_set_back_the_pending_wait_is_stated_as_it_is() {
    let broker = broker().await;
    let key = broker.add_agent("build-agent").await;
    let first = created_id(&broker, &key, 0).await;
    created_id(&broker, &key, 1).await;
    broker.clock.advance(-1000);
    let refused = create(&broker, &key, 2).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    // They expire 600 s after they were made, 1600 s from this clock's now.
    assert_eq!(refused.header("retry-after"), "1600");
    // Cancelling frees a slot at once, whatever the clock says.
    cancel(&broker, &key, &first).await;
    created_id(&broker, &key, 2).await;
}
