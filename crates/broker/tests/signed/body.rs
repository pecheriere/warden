//! Bodies refused before verification: oversized, or never arriving.

use std::convert::Infallible;
use std::num::NonZeroU64;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use http_body_util::channel::Channel;
use ssh_key::{Algorithm, HashAlg, PrivateKey};
use warden_broker::signed::BodyReadTimeout;
use warden_broker::testkit::TestBroker;
use warden_broker_proto::signing::NAMESPACE;

use super::{BODY_LIMIT, again, head, nonce_rows, set_signature, sign_with};

#[tokio::test]
async fn oversized_body_refused_before_verification() {
    let broker = TestBroker::new().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let big = vec![b' '; BODY_LIMIT + 1];

    // Validly signed, too large: 413.
    let resp = broker
        .api_signed(&key, "bot", "POST", "/v1/requests", &big)
        .await;
    assert_eq!(resp.status, StatusCode::PAYLOAD_TOO_LARGE, "{}", resp.body);

    // Badly signed and too large: 413 too, the body is read first.
    let mut parts = head(broker.signed_request(&key, "bot", "POST", "/v1/requests", Vec::new()));
    let stranger = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
    set_signature(
        &mut parts,
        &sign_with(&stranger, NAMESPACE, HashAlg::Sha512, "x"),
    );
    let resp = broker.api_send(again(&parts, &big)).await;
    assert_eq!(resp.status, StatusCode::PAYLOAD_TOO_LARGE, "{}", resp.body);

    // Exactly the limit is read and checked (and is not a valid request).
    let resp = broker
        .api_signed(&key, "bot", "POST", "/v1/requests", &big[1..])
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    assert_eq!(nonce_rows(&broker).await, 1);
}

/// Send a validly signed `method target` whose body never arrives; the
/// response and how long it took.
async fn send_stalled(
    broker: &TestBroker,
    key: &PrivateKey,
    target: &str,
) -> (StatusCode, String, Duration) {
    let parts = head(broker.signed_request(key, "bot", "POST", target, Vec::new()));
    // A body whose sender stays open and never sends anything.
    let (sender, stalled) = Channel::<Bytes, Infallible>::new(1);
    let mut req = Request::post(target).body(Body::new(stalled)).unwrap();
    *req.headers_mut() = parts.headers.clone();
    let started = Instant::now();
    // Far past any limit under test, so only a request that never times out
    // gets here; how far past a limit it answers depends on the machine.
    let resp = tokio::time::timeout(Duration::from_secs(60), broker.api_send(req))
        .await
        .expect("the stalled request never timed out");
    let waited = started.elapsed();
    drop(sender);
    (resp.status, resp.body, waited)
}

#[tokio::test]
async fn stalled_body_times_out_before_verification() {
    // At 4 MiB/s, a 16 KiB limit takes 4 ms (so the 100 ms floor applies)
    // and the 2 MiB limit of a proxied call 500 ms.
    let timeout = BodyReadTimeout {
        floor: Duration::from_millis(100),
        bytes_per_sec: NonZeroU64::new(4 * 1024 * 1024).unwrap(),
    };
    let broker = TestBroker::with_body_read_timeout(timeout).await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;

    for (target, expected) in [
        ("/v1/requests", Duration::from_millis(100)),
        (
            "/v1/grants/0b8f4c1e9d2a47f3a5c6e7d8f9a0b1c2/http",
            Duration::from_millis(500),
        ),
    ] {
        let (status, body, waited) = send_stalled(&broker, &key, target).await;
        assert_eq!(status, StatusCode::REQUEST_TIMEOUT, "{target}: {body}");
        assert_eq!(body, r#"{"error":"request body timed out"}"#);
        assert!(waited >= expected, "{target}: {waited:?}");
    }
    assert_eq!(nonce_rows(&broker).await, 0);
}
