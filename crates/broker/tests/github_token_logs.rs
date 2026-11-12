//! The GitHub token, the JWT and what GitHub says stay out of the logs. In a test
//! binary of its own, with this as its only test: `tracing` decides once per log
//! statement, for the whole process, whether anything listens, and other tests
//! running beside this one would make that decision for it.

use std::io;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use serde_json::json;
use warden_broker::github_app::GithubApi;
use warden_broker::requests::Clock as _;
use warden_broker::testkit::upstream::Scripted;
use warden_broker::testkit::{HttpsUpstream, TestBroker, github_app_key};
use warden_broker_proto::Window;

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A mint, an upstream failure that echoes a token and a JWT, and a backend outage, with everything logged.
#[tokio::test]
async fn the_token_stays_out_of_the_logs() {
    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer({
            let logs = logs.clone();
            move || logs.clone()
        })
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    // The test runtime is single-threaded, so all of it runs under this subscriber.
    let _guard = tracing::subscriber::set_default(subscriber);

    let upstream = HttpsUpstream::start().await;
    let api = GithubApi::pinned(
        upstream.origin().parse().unwrap(),
        upstream.origin().parse().unwrap(),
        upstream.ca_pem().as_bytes().to_vec(),
    );
    let broker = TestBroker::with_github_api(api).await;
    broker.backend.set_github_app(Some(github_app_key().0));
    let key = broker.add_agent("bot").await;
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::github_token_request(
                "push the fix",
                Window::D30,
                &["example-owner/example-repo"],
            ),
        )
        .await;
    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);

    let mint = || async {
        broker
            .api_post_json(&key, "/v1/github-token", &json!({}))
            .await
    };
    let expires = jiff::Timestamp::from_second(broker.clock.now() + 3600).unwrap();
    upstream.script_github_token(Scripted::with_body(
        201,
        json!({"token": "ghs_logged_secret", "expires_at": expires.to_string()}).to_string(),
    ));
    assert_eq!(mint().await.status, StatusCode::OK);
    upstream.script_github_token(Scripted::with_body(
        401,
        r#"{"message":"ghs_echoed_secret eyJechoedjwt"}"#,
    ));
    assert_eq!(mint().await.status, StatusCode::SERVICE_UNAVAILABLE);
    broker
        .backend
        .set_github_app_outage(Some("the vault is unreachable"));
    assert_eq!(mint().await.status, StatusCode::SERVICE_UNAVAILABLE);

    // The JWT was sent, so it could have been logged.
    let sent = upstream.received();
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|call| {
        call.headers["authorization"]
            .to_str()
            .unwrap()
            .contains("eyJ")
    }));

    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logged.contains("GitHub token minted"), "{logged}");
    assert!(logged.contains("minting a GitHub token failed"), "{logged}");
    for forbidden in ["ghs_", "eyJ"] {
        let line = logged.lines().find(|line| line.contains(forbidden));
        assert!(line.is_none(), "{forbidden} in the logs: {line:?}");
    }
}
