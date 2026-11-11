//! What GitHub says stays out of the logs and out of the release client's
//! errors. In a test binary of its own, with this as its only test: `tracing`
//! decides once per log statement, for the whole process, whether anything
//! listens, and other tests running beside this one would make that decision for
//! it.

use std::io;
use std::sync::{Arc, Mutex};

use serde_json::json;
use warden_broker::github_app::GithubApi;
use warden_broker::github_release::{installation_for, release_token};
use warden_broker::policy::ReleaseAppKey;
use warden_broker::testkit::HttpsUpstream;
use warden_broker::testkit::github_app::RSA2048_PKCS8;
use warden_broker::testkit::github_release::{INSTALLATION_ID, TOKEN_EXPIRES_AT};
use warden_broker::testkit::upstream::Scripted;
use warden_broker_proto::release::RepoName;

/// 2026-11-08T12:00:00Z.
const NOW: i64 = 1_794_139_200;
const MARKER: &str = "marker-github-said-this";

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

/// Failing, malformed and over-wide answers that repeat a marker, and a
/// connection to a GitHub nobody trusts, with everything logged.
#[tokio::test]
async fn what_github_says_stays_out_of_the_logs_and_errors() {
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

    let repo: RepoName = "example-owner/example-repo".to_owned().try_into().unwrap();
    let app = ReleaseAppKey::new(
        "987654".to_owned(),
        std::str::from_utf8(RSA2048_PKCS8).unwrap(),
    )
    .unwrap();
    let upstream = HttpsUpstream::start().await;
    upstream.github_release().install(&repo);
    let origin: url::Url = upstream.origin().parse().unwrap();
    let api = GithubApi::pinned(
        origin.clone(),
        origin,
        upstream.ca_pem().as_bytes().to_vec(),
    );

    let exact = json!({"contents": "write", "metadata": "read"});
    let wider = json!({"contents": "write", "metadata": "read", "administration": MARKER});
    let answers = [
        Scripted::with_body(500, format!("{{\"message\":\"{MARKER}\"}}")),
        Scripted::with_body(200, format!("{{\"id\": \"{MARKER}\"}}")),
        Scripted::with_body(201, format!("not json {MARKER}")),
        Scripted::with_body(
            201,
            json!({"token": MARKER, "expires_at": MARKER, "permissions": exact}).to_string(),
        ),
        Scripted::with_body(
            201,
            json!({
                "token": MARKER,
                "expires_at": TOKEN_EXPIRES_AT,
                "permissions": wider,
                "repository_selection": "selected",
                "repositories": [{"name": "example-repo"}],
            })
            .to_string(),
        ),
        Scripted::with_body(200, json!({"id": 1}).to_string()).header("content-encoding", MARKER),
    ];
    let mut results = Vec::new();
    for answer in answers {
        upstream.github_release().answer_everything_with(answer);
        results.push(installation_for(&api, &app, &repo, NOW).await.map(drop));
        results.push(
            release_token(&api, &app, INSTALLATION_ID, &repo, NOW)
                .await
                .map(drop),
        );
    }
    // A GitHub nobody trusts: the failure is logged, without the URL.
    let stranger = HttpsUpstream::start().await;
    let stranger_origin: url::Url = stranger.origin().parse().unwrap();
    let untrusted = GithubApi::pinned(
        stranger_origin.clone(),
        stranger_origin,
        upstream.ca_pem().as_bytes().to_vec(),
    );
    results.push(
        installation_for(&untrusted, &app, &repo, NOW)
            .await
            .map(drop),
    );
    for result in results {
        let err = result.unwrap_err();
        assert!(!err.to_string().contains(MARKER));
        assert!(!format!("{err:?}").contains(MARKER));
    }

    // The JWT was sent, so it could have been logged.
    let sent = upstream.github_release().record();
    assert_eq!(sent.len(), 12);
    assert!(sent.iter().all(|call| {
        call.headers["authorization"]
            .to_str()
            .unwrap()
            .contains("eyJ")
    }));

    let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logged.contains("the GitHub call failed"), "{logged}");
    for forbidden in [MARKER, "ghs_", "eyJ"] {
        let line = logged.lines().find(|line| line.contains(forbidden));
        assert!(line.is_none(), "{forbidden} in the logs: {line:?}");
    }
}
