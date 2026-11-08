//! The nonce table: only verified requests insert, concurrent replays, and
//! expiry.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use ssh_key::{Algorithm, PrivateKey};
use warden_broker::requests;
use warden_broker::signed::NONCE_RETENTION_SECS;
use warden_broker::testkit::TestBroker;

use super::{again, head, nonce_rows};

#[tokio::test]
async fn unauthenticated_cannot_insert_nonces() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let _legacy = broker.add_agent("legacy").await;
    let stranger = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();

    for _ in 0..20 {
        for (agent, signer) in [
            ("bot", &stranger),
            ("ghost", &stranger),
            ("legacy", &stranger),
        ] {
            let resp = broker
                .api_signed(signer, agent, "GET", "/v1/grants", b"")
                .await;
            assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
        }
        // Validly signed but stale.
        let stale = broker.signed_request(&key, "bot", "GET", "/v1/grants", Vec::new());
        broker.clock.advance(61);
        assert_eq!(
            broker.api_send(stale).await.status,
            StatusCode::UNAUTHORIZED
        );
        broker.clock.advance(-61);
    }
    assert_eq!(nonce_rows(&broker).await, 0);

    let resp = broker
        .api_signed(&key, "bot", "GET", "/v1/grants", b"")
        .await;
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(nonce_rows(&broker).await, 1);
}

#[tokio::test]
async fn nonces_expire() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let parts = head(broker.signed_request(&key, "bot", "GET", "/v1/grants", Vec::new()));
    let resp = broker.api_send(again(&parts, b"")).await;
    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(nonce_rows(&broker).await, 1);

    broker.clock.advance(599);
    assert_eq!(broker.state().requests.sweep_nonces().await.unwrap(), 0);
    assert_eq!(nonce_rows(&broker).await, 1);
    broker.clock.advance(1);
    assert_eq!(broker.state().requests.sweep_nonces().await.unwrap(), 1);
    assert_eq!(nonce_rows(&broker).await, 0);

    // Forgotten, but long stale: the replay is still refused.
    let resp = broker.api_send(again(&parts, b"")).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_replays_accept_exactly_one() {
    const COPIES: usize = 16;
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let urls = broker.spawn().await;
    let parts = head(broker.signed_request(&key, "bot", "GET", "/v1/grants", Vec::new()));
    let url = urls.api.join("v1/grants").unwrap();
    let client = reqwest::Client::new();

    let start = Arc::new(tokio::sync::Barrier::new(COPIES));
    let mut sends = tokio::task::JoinSet::new();
    for _ in 0..COPIES {
        let request = client.get(url.clone()).headers(parts.headers.clone());
        let start = start.clone();
        sends.spawn(async move {
            start.wait().await;
            request.send().await.unwrap().status()
        });
    }
    let statuses = sends.join_all().await;
    let ok = statuses.iter().filter(|s| **s == StatusCode::OK).count();
    let refused = statuses
        .iter()
        .filter(|s| **s == StatusCode::UNAUTHORIZED)
        .count();
    assert_eq!((ok, refused), (1, COPIES - 1), "{statuses:?}");
    assert_eq!(nonce_rows(&broker).await, 1);
}

#[tokio::test]
async fn sweep_loop_forgets_expired_nonces() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let resp = broker
        .api_signed(&key, "bot", "GET", "/v1/grants", b"")
        .await;
    assert_eq!(resp.status, StatusCode::OK);

    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let sweeper = tokio::spawn(requests::sweep_loop(
        broker.state().requests.clone(),
        Duration::from_millis(10),
        stop_rx,
    ));
    // Several sweeps run while the nonce is still within its retention.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(nonce_rows(&broker).await, 1);

    broker.clock.advance(NONCE_RETENTION_SECS);
    let deadline = Instant::now() + Duration::from_secs(5);
    while nonce_rows(&broker).await != 0 {
        assert!(Instant::now() < deadline, "the sweeper kept the nonce");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    stop.send_replace(true);
    sweeper.await.unwrap();
}
