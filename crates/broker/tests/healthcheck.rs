//! The `healthcheck` probe used by the container orchestrator: succeeds
//! against a live agent API and fails when nothing is listening.

use std::net::SocketAddr;

use warden_broker::health;
use warden_broker::testkit::TestBroker;

#[tokio::test]
async fn probe_succeeds_against_a_live_api() {
    let broker = TestBroker::new().await;
    let urls = broker.spawn().await;
    let addr: SocketAddr = format!(
        "{}:{}",
        urls.api.host_str().unwrap(),
        urls.api.port().unwrap()
    )
    .parse()
    .unwrap();
    health::probe(addr).await.unwrap();
}

#[tokio::test]
async fn probe_fails_when_nothing_listens() {
    // Bind then drop to obtain a loopback port with no listener.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    assert!(health::probe(addr).await.is_err());
}

#[test]
fn listen_address_defaults_and_validates() {
    assert_eq!(
        health::api_listen(|_| None).unwrap(),
        "127.0.0.1:8080".parse().unwrap()
    );
    assert_eq!(
        health::api_listen(|_| Some("0.0.0.0:9000".to_owned())).unwrap(),
        "0.0.0.0:9000".parse().unwrap()
    );
    assert!(health::api_listen(|_| Some("nonsense".to_owned())).is_err());
}

#[test]
fn unspecified_listen_address_is_probed_over_loopback() {
    assert_eq!(
        health::probe_target("0.0.0.0:9000".parse().unwrap()),
        "127.0.0.1:9000".parse().unwrap()
    );
    assert_eq!(
        health::probe_target("[::]:9000".parse().unwrap()),
        "[::1]:9000".parse().unwrap()
    );
    assert_eq!(
        health::probe_target("10.1.2.3:9000".parse().unwrap()),
        "10.1.2.3:9000".parse().unwrap()
    );
}
