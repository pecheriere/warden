//! Approval UI: passkey enrollment and approval ceremonies driven through the
//! real routes with software passkeys, plus page and request hardening.
//!
//! Shared fixtures live here; each area of the UI has its own module.

mod api;
mod approve;
mod counters;
mod enrollment;
mod grants;
mod hardening;
mod relay;

use std::time::Duration;

use sqlx::Row as _;
use warden_broker::testkit::TestBroker;
use warden_broker_proto::{AgentName, CreatedResponse, Id, RequestStatus, Window};

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
                   connect-src 'self'; form-action 'self'; frame-ancestors 'none'";

fn bot() -> AgentName {
    AgentName::try_from("bot".to_owned()).unwrap()
}

/// A broker with agent `bot` and one pending 30m request for `pi`.
async fn pending() -> (TestBroker, CreatedResponse, String) {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let (created, token) = broker
        .create_request(
            "bot",
            TestBroker::pi_request("restart the backup job", Window::M30),
        )
        .await;
    (broker, created, token)
}

async fn status(broker: &TestBroker, id: &Id) -> RequestStatus {
    broker
        .state()
        .requests
        .status(&bot(), id, Duration::ZERO)
        .await
        .unwrap()
}

async fn grant_count(broker: &TestBroker) -> i64 {
    sqlx::query("SELECT COUNT(*) FROM grants")
        .fetch_one(&broker.state().pool)
        .await
        .unwrap()
        .get(0)
}

async fn stored_credentials(broker: &TestBroker) -> Vec<String> {
    sqlx::query("SELECT credential FROM passkeys ORDER BY created_at, id")
        .fetch_all(&broker.state().pool)
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

async fn stored_counters(broker: &TestBroker) -> Vec<i64> {
    sqlx::query("SELECT counter FROM passkeys ORDER BY created_at, id")
        .fetch_all(&broker.state().pool)
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}
