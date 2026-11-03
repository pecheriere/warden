//! The commit signing key stays out of the logs. In a test binary of its own, with
//! this as its only test: `tracing` decides once per log statement, for the whole
//! process, whether anything listens, and other tests running beside this one would
//! make that decision for it.

use std::io;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;
use ssh_key::LineEnding;
use warden_broker::testkit::{TestBroker, TestResponse};
use warden_broker_proto::Window;

const TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
const WHO: &str = "build-agent <build-agent@example.com> 1800000000 +0000";

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

async fn sign(broker: &TestBroker, key: &str, payload: &str) -> TestResponse {
    let body = json!({"namespace": "git", "payload_b64": STANDARD.encode(payload)});
    broker
        .api_post_json(key, "/v1/commit-signing/sign", &body)
        .await
}

/// Signing, a refusal and a backend outage, with everything logged.
#[tokio::test]
async fn the_key_stays_out_of_the_logs() {
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

    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::commit_signing_request("sign my commits", Window::D30),
        )
        .await;
    let approved = broker.approve(&token, Window::D30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);

    let commit = format!("tree {TREE}\nauthor {WHO}\ncommitter {WHO}\n\nm\n");
    assert_eq!(sign(&broker, &key, &commit).await.status, StatusCode::OK);
    let tag = format!("object {TREE}\ntype commit\ntag v1\ntagger {WHO}\n\nm\n");
    assert_eq!(
        sign(&broker, &key, &tag).await.status,
        StatusCode::BAD_REQUEST
    );
    broker.backend.set_commit_signing_outage(Some("out"));
    assert_eq!(
        sign(&broker, &key, &commit).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );

    let written = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(written.contains("commit signed"), "{written}");
    assert!(written.contains("commit signing refused"), "{written}");
    let pem = broker
        .backend
        .commit_signing_private_key()
        .to_openssh(LineEnding::LF)
        .unwrap();
    for line in pem.lines().filter(|l| !l.starts_with("-----")) {
        assert!(!written.contains(line), "the key is in the logs");
    }
    assert!(
        !written.contains("SSH SIGNATURE"),
        "a signature is in the logs"
    );
}
