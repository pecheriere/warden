//! Bounds on what agent API callers can hold at once: waiting long-polls per
//! agent, bodies read before their signature is verified, and connections per
//! listener. Each test holds the places itself and checks what is refused; none
//! waits on real time.

use std::convert::Infallible;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use axum::routing::get;
use http_body_util::channel::Channel;
use serde_json::json;
use ssh_key::Algorithm;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc};
use warden_broker::load::{MAX_WAITS_PER_AGENT, PRE_SIGNATURE_BODY_BUDGET};
use warden_broker::serve::{HEADER_READ_TIMEOUT, ServeLimits, serve};
use warden_broker::testkit::{FakeBackend, TestBroker};
use warden_broker_proto::{AgentName, Window};

fn agent(name: &str) -> AgentName {
    AgentName::try_from(name.to_owned()).unwrap()
}

/// A broker that knows the example API secret.
async fn broker() -> TestBroker {
    let broker = TestBroker::new().await;
    broker
        .backend
        .set_api_secret(FakeBackend::example_api_secret(), "not-a-real-secret");
    broker
}

/// A request by the agent holding `key`, cancelled at once, so that a status
/// call on it answers without waiting whatever `wait` it asks for.
async fn cancelled_request(broker: &TestBroker, key: &str) -> String {
    let body = serde_json::to_value(TestBroker::api_request(
        "github",
        "triage issue 42",
        Window::M15,
    ))
    .unwrap();
    let resp = broker.api_post_json(key, "/v1/requests", &body).await;
    assert_eq!(resp.status, StatusCode::CREATED, "{}", resp.body);
    let id = resp.json()["id"].as_str().unwrap().to_owned();
    let resp = broker
        .api_post(key, &format!("/v1/requests/{id}/cancel"))
        .await;
    assert_eq!(resp.status, StatusCode::NO_CONTENT, "{}", resp.body);
    id
}

#[tokio::test]
async fn waiting_long_polls_are_capped_per_agent() {
    let broker = broker().await;
    let key = broker.add_agent("build-agent").await;
    let other = broker.add_agent("other-agent").await;
    let id = cancelled_request(&broker, &key).await;
    let other_id = cancelled_request(&broker, &other).await;
    let waits = &broker.api_load().waits;
    let mut held: Vec<_> = (0..MAX_WAITS_PER_AGENT)
        .map(|_| waits.try_acquire(&agent("build-agent")).unwrap())
        .collect();

    // One more wait is refused, before anything is read.
    let resp = broker
        .api_get(&key, &format!("/v1/requests/{id}?wait=30"))
        .await;
    assert_eq!(resp.status, StatusCode::TOO_MANY_REQUESTS, "{}", resp.body);
    assert_eq!(
        resp.json(),
        json!({"error": "too many status requests waiting; try again"})
    );
    // A call that does not wait holds no place.
    let resp = broker
        .api_get(&key, &format!("/v1/requests/{id}?wait=0"))
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    // Another agent has places of its own.
    let resp = broker
        .api_get(&other, &format!("/v1/requests/{other_id}?wait=30"))
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);

    // A place given back can be used, and is given back after the call.
    drop(held.pop());
    let resp = broker
        .api_get(&key, &format!("/v1/requests/{id}?wait=30"))
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    let last = waits.try_acquire(&agent("build-agent"));
    assert!(last.is_some());
    assert!(waits.try_acquire(&agent("build-agent")).is_none());
}

#[tokio::test]
async fn unverified_bodies_share_one_budget() {
    let broker = broker().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    let body = br#"{"not":"a request"}"#;
    let all = broker
        .api_load()
        .bodies
        .try_reserve(PRE_SIGNATURE_BODY_BUDGET)
        .unwrap();

    // A body is refused while the budget is used up, before it is read.
    let resp = broker
        .api_signed(&key, "bot", "POST", "/v1/requests", body)
        .await;
    assert_eq!(
        resp.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        resp.body
    );
    assert_eq!(resp.json(), json!({"error": "broker busy; try again"}));
    // An empty body takes nothing.
    let resp = broker
        .api_signed(&key, "bot", "GET", "/v1/requests", b"")
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);

    drop(all);
    let resp = broker
        .api_signed(&key, "bot", "POST", "/v1/requests", body)
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
}

#[tokio::test]
async fn a_body_of_unknown_length_reserves_the_route_limit() {
    let broker = broker().await;
    let key = broker.add_signing_agent("bot", Algorithm::Ed25519).await;
    // Leave 8 KiB: less than the 16 KiB limit of `/v1/requests`.
    let _most = broker
        .api_load()
        .bodies
        .try_reserve(PRE_SIGNATURE_BODY_BUDGET - 8 * 1024)
        .unwrap();

    // A streamed body says no length, so it needs the route's whole limit.
    let signed = broker.signed_request(&key, "bot", "POST", "/v1/requests", Vec::new());
    let (sender, streamed) = Channel::<Bytes, Infallible>::new(1);
    let mut req = Request::post("/v1/requests")
        .body(Body::new(streamed))
        .unwrap();
    *req.headers_mut() = signed.headers().clone();
    let resp = broker.api_send(req).await;
    drop(sender);
    assert_eq!(
        resp.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        resp.body
    );

    // A body whose length fits what is left is read and checked.
    let resp = broker
        .api_signed(&key, "bot", "POST", "/v1/requests", br#"{"short":1}"#)
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
}

/// The bytes the server sends on `stream` until it closes it, or `None` if it
/// reset the connection.
async fn read_all(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    match stream.read_to_end(&mut buf).await {
        Ok(_) => Some(buf),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => None,
        Err(e) => panic!("reading the response: {e}"),
    }
}

#[tokio::test]
async fn connections_beyond_the_cap_are_closed_unanswered() {
    let (entered_tx, mut entered) = mpsc::channel::<()>(1);
    let release = Arc::new(Notify::new());
    let held = Arc::clone(&release);
    let router = Router::new()
        .route(
            "/hold",
            get(move || {
                let (entered_tx, held) = (entered_tx.clone(), Arc::clone(&held));
                async move {
                    entered_tx.send(()).await.unwrap();
                    held.notified().await;
                    "held"
                }
            }),
        )
        .route("/ok", get(|| async { "ok" }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let limits = ServeLimits {
        max_connections: 1,
        header_read_timeout: HEADER_READ_TIMEOUT,
    };
    let server = tokio::spawn(serve(
        "test",
        listener,
        router,
        limits,
        std::future::pending(),
    ));

    // The one connection allowed is in a handler.
    let mut first = TcpStream::connect(addr).await.unwrap();
    first
        .write_all(b"GET /hold HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    entered.recv().await.unwrap();

    // A second one is closed without an answer, though its route answers at once.
    let mut second = TcpStream::connect(addr).await.unwrap();
    // The write fails if the server has closed the connection already.
    let _ = second
        .write_all(b"GET /ok HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await;
    if let Some(answer) = read_all(&mut second).await {
        assert!(answer.is_empty(), "{}", String::from_utf8_lossy(&answer));
    }

    // The first is still served.
    release.notify_one();
    let answer = read_all(&mut first).await.expect("an answer");
    let answer = String::from_utf8(answer).unwrap();
    assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
    assert!(answer.ends_with("held"), "{answer}");
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn unfinished_headers_are_dropped_after_the_timeout() {
    let router = Router::new().route("/ok", get(|| async { "ok" }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve(
        "test",
        listener,
        router,
        ServeLimits::API,
        std::future::pending(),
    ));

    let started = tokio::time::Instant::now();
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /ok HTTP/1.1\r\nHost: test\r\n")
        .await
        .unwrap();
    // The paused clock moves on only while every task waits, so the server
    // closes the connection exactly when the timeout has passed.
    let answer = read_all(&mut stream).await.unwrap_or_default();
    assert!(
        !String::from_utf8_lossy(&answer).contains("200 OK"),
        "{}",
        String::from_utf8_lossy(&answer)
    );
    assert!(started.elapsed() >= HEADER_READ_TIMEOUT);
    server.abort();
}

#[tokio::test]
async fn serving_ends_on_shutdown() {
    let router = Router::new().route("/ok", get(|| async { "ok" }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve("test", listener, router, ServeLimits::API, async {
        let _ = stopped.await;
    }));

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /ok HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let answer = String::from_utf8(read_all(&mut stream).await.unwrap()).unwrap();
    assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");

    // With no connection left open, serving ends once shutdown is asked.
    stop.send(()).unwrap();
    server.await.unwrap();
}
