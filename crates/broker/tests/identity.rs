use std::io;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;
use warden_broker::agents;
use warden_broker::identity::{AuthedAgent, Owner};
use warden_broker::testkit::{TEST_OWNER, TestBroker};
use warden_broker_proto::AgentName;

const OWNER: &str = TEST_OWNER;

/// Extractor probes on the state of an in-process test broker.
async fn app() -> (Router, TestBroker) {
    let broker = TestBroker::new().await;
    let router = Router::new()
        .route("/owner", get(|_: Owner| async { "ok" }))
        .route(
            "/agent",
            get(|AuthedAgent(name): AuthedAgent| async move { format!("hello {name}") }),
        )
        .with_state(broker.state().clone());
    (router, broker)
}

async fn call(router: &Router, headers: &[(&str, &str)], path: &str) -> (StatusCode, String) {
    let mut req = Request::builder().uri(path);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = router
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn owner_header_required() {
    let (router, _broker) = app().await;

    let (status, body) = call(&router, &[], "/owner").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, r#"{"error":"forbidden"}"#);

    let (status, _) = call(
        &router,
        &[("Tailscale-User-Login", "mallory@example.com")],
        "/owner",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Exact comparison: no case folding, no prefix or suffix matches.
    let (status, _) = call(
        &router,
        &[("Tailscale-User-Login", "OWNER@example.com")],
        "/owner",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(
        &router,
        &[("Tailscale-User-Login", "owner@example.com ")],
        "/owner",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = call(&router, &[("Tailscale-User-Login", OWNER)], "/owner").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn agent_bearer_required() {
    let (router, broker) = app().await;
    let state = broker.state();
    let name: AgentName = "bot".parse().unwrap();
    let key = agents::add(&state.pool, &name).await.unwrap();
    let bearer = format!("Bearer {}", key.expose());
    let owner = ("Tailscale-User-Login", OWNER);

    let (status, body) = call(&router, &[owner], "/agent").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, r#"{"error":"unauthorized"}"#);

    let (status, _) = call(
        &router,
        &[owner, ("Authorization", "Bearer wdn_nope")],
        "/agent",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = call(&router, &[owner, ("Authorization", key.expose())], "/agent").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A valid key without the owner identity is forbidden.
    let (status, body) = call(&router, &[("Authorization", &bearer)], "/agent").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, r#"{"error":"forbidden"}"#);

    let (status, body) = call(&router, &[owner, ("Authorization", &bearer)], "/agent").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "hello bot");

    agents::revoke(&state.pool, &name, 1).await.unwrap();
    let (status, _) = call(&router, &[owner, ("Authorization", &bearer)], "/agent").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn error_bodies_do_not_echo_presented_key() {
    let (router, broker) = app().await;
    let state = broker.state();
    let name: AgentName = "bot".parse().unwrap();
    let key = agents::add(&state.pool, &name).await.unwrap();
    agents::revoke(&state.pool, &name, 1).await.unwrap();
    let revoked = key.expose().to_owned();
    let unknown = "wdn_unknownunknownunknownunknownunknownunknown0";
    for presented in [revoked.as_str(), unknown] {
        let bearer = format!("Bearer {presented}");
        let (status, body) = call(
            &router,
            &[("Tailscale-User-Login", OWNER), ("Authorization", &bearer)],
            "/agent",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(!body.contains(presented));
        assert_eq!(body, r#"{"error":"unauthorized"}"#);
    }
}

/// A `tracing` writer that keeps everything written to it.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn database_failure_is_500_and_logged_without_the_key() {
    let (router, broker) = app().await;
    let state = broker.state();
    let key = agents::add(&state.pool, &"bot".parse().unwrap())
        .await
        .unwrap();
    let bearer = format!("Bearer {}", key.expose());
    state.pool.close().await;

    let logs = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer({
            let logs = logs.clone();
            move || logs.clone()
        })
        .with_ansi(false)
        .finish();
    // The test runtime is single-threaded, so the whole request runs under
    // this thread-local subscriber.
    let _guard = tracing::subscriber::set_default(subscriber);
    let (status, body) = call(
        &router,
        &[("Tailscale-User-Login", OWNER), ("Authorization", &bearer)],
        "/agent",
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, r#"{"error":"internal error"}"#);
    let logs = logs.text();
    assert!(logs.contains("ERROR"), "{logs}");
    assert!(logs.contains("closed"), "{logs}");
    assert!(!logs.contains(key.expose()), "{logs}");
}
