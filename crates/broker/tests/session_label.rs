//! A session label and a link on a request, through the real routes: who may send
//! them, what the owner's pages and notification show, and that the audit log holds
//! the label and neither holds nor passes on the link.

use axum::http::StatusCode;
use serde_json::{Value, json};
use warden_broker::testkit::TestBroker;
use warden_broker_proto::{AgentName, CreateRequest, Window, fingerprint};

/// A label that would run if it reached a page as it is.
const HOSTILE: &str = "<script>x()</script>";
const ESCAPED: &str = "&lt;script&gt;x()&lt;/script&gt;";

fn bot() -> AgentName {
    AgentName::try_from("bot".to_owned()).unwrap()
}

fn body(session: Option<&str>, link: Option<&str>) -> Value {
    let mut value =
        serde_json::to_value(TestBroker::pi_request("restart the job", Window::M15)).unwrap();
    if let Some(session) = session {
        value["session"] = json!(session);
    }
    if let Some(link) = link {
        value["link"] = json!(link);
    }
    value
}

/// Agent `bot` on a broker that accepts links to `git.example.com`, and its key.
async fn broker() -> (TestBroker, String) {
    let broker = TestBroker::with_link_hosts("git.example.com").await;
    let key = broker.add_agent("bot").await;
    (broker, key)
}

/// The `session` of every `request_created` audit entry, oldest first.
fn audit_session(broker: &TestBroker) -> Vec<Option<String>> {
    std::fs::read_to_string(broker.audit_path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|entry| entry["event"]["type"] == "request_created")
        .map(|entry| entry["event"]["session"].as_str().map(ToOwned::to_owned))
        .collect()
}

#[tokio::test]
async fn the_label_and_link_reach_every_page_and_the_fingerprint() {
    let (broker, key) = broker().await;
    let sent = body(Some(HOSTILE), Some("https://git.example.com/o/r/pull/7"));
    let response = broker.api_post_json(&key, "/v1/requests", &sent).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.body);
    let created = response.json();
    let request: CreateRequest = serde_json::from_value(sent).unwrap();
    assert_eq!(
        created["fingerprint"],
        json!(fingerprint(&bot(), &request).as_str()),
        "what the agent computes covers both"
    );
    let bell = broker.capture.next().await;
    let token = bell.url.path_segments().unwrap().next_back().unwrap();
    for path in [
        format!("/approve/{token}"),
        "/pending".to_owned(),
        "/history".to_owned(),
    ] {
        let html = broker.get(&path).await.body;
        assert!(html.contains(ESCAPED), "{path}: {html}");
        assert!(!html.contains(HOSTILE), "{path}");
        assert!(
            html.contains(r#"href="https://git.example.com/o/r/pull/7" target="_blank" rel="noopener noreferrer""#),
            "{path}: {html}"
        );
    }
}

#[tokio::test]
async fn the_notification_has_the_label_as_a_claim_and_never_the_link() {
    let (broker, key) = broker().await;
    let sent = body(
        Some("release-work"),
        Some("https://git.example.com/o/r/pull/7"),
    );
    let response = broker.api_post_json(&key, "/v1/requests", &sent).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.body);
    let bell = broker.capture.next().await;
    assert_eq!(
        bell.message,
        "Session stated by the agent: release-work\nrestart the job"
    );
    for text in [&bell.title, &bell.message, &bell.url.to_string()] {
        assert!(!text.contains("git.example.com"), "{text}");
    }
}

#[tokio::test]
async fn the_audit_log_has_the_label_and_not_the_link() {
    let (broker, key) = broker().await;
    let sent = body(
        Some("release-work"),
        Some("https://git.example.com/o/r/pull/7"),
    );
    let response = broker.api_post_json(&key, "/v1/requests", &sent).await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.body);
    assert_eq!(audit_session(&broker), [Some("release-work".to_owned())]);
    let log = std::fs::read_to_string(broker.audit_path()).unwrap();
    assert!(log.contains(r#""session":"release-work""#), "{log}");
    assert!(!log.contains("git.example.com"), "{log}");
}

/// What an older CLI sends, and what is in an older database and log.
#[tokio::test]
async fn a_request_without_them_looks_as_it_did() {
    let (broker, key) = broker().await;
    let response = broker
        .api_post_json(&key, "/v1/requests", &body(None, None))
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.body);
    let bell = broker.capture.next().await;
    assert_eq!(bell.message, "restart the job");
    assert_eq!(audit_session(&broker), [None]);
    let log = std::fs::read_to_string(broker.audit_path()).unwrap();
    assert!(!log.contains("session"), "{log}");
    assert!(
        !broker
            .get("/pending")
            .await
            .body
            .contains("stated by the agent")
    );
}

#[tokio::test]
async fn a_link_to_a_host_off_the_list_refuses_the_request() {
    let (broker, key) = broker().await;
    for link in [
        "https://evil.example.org/x",
        "https://sub.git.example.com/x",
        "https://git.example.com.evil.example/x",
    ] {
        let response = broker
            .api_post_json(&key, "/v1/requests", &body(Some("s"), Some(link)))
            .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{link}");
        assert!(response.body.contains("link refused"), "{}", response.body);
    }
    assert_eq!(broker.capture.rung().len(), 0, "the owner was not asked");
    assert_eq!(audit_session(&broker).len(), 0);
    assert!(!broker.get("/history").await.body.contains("evil.example"));
}

#[tokio::test]
async fn links_are_off_by_default() {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    let response = broker
        .api_post_json(
            &key,
            "/v1/requests",
            &body(None, Some("https://git.example.com/x")),
        )
        .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(broker.capture.rung().len(), 0);
    // A label needs no setting.
    let response = broker
        .api_post_json(&key, "/v1/requests", &body(Some("s"), None))
        .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.body);
}

#[tokio::test]
async fn a_malformed_label_or_link_is_refused_without_being_quoted() {
    let (broker, key) = broker().await;
    for (session, link) in [
        (Some("a\u{202E}b"), None),
        (Some("a\nb"), None),
        (None, Some("https://user:hunter2@git.example.com/")),
        (None, Some("http://git.example.com/hunter2")),
        (None, Some("https://git.example.com/?token=hunter2")),
    ] {
        let response = broker
            .api_post_json(&key, "/v1/requests", &body(session, link))
            .await;
        assert!(
            response.status.is_client_error(),
            "{session:?} {link:?}: {}",
            response.status
        );
        assert!(!response.body.contains("hunter2"), "{}", response.body);
    }
    assert_eq!(broker.capture.rung().len(), 0);
}

/// Today's rule: one request per agent and target. A second session's different
/// label gets the first request back, and its fingerprint shows it is not its own.
#[tokio::test]
async fn a_label_does_not_open_a_second_pending_slot() {
    let (broker, key) = broker().await;
    let first = serde_json::to_value(TestBroker::api_request("github", "read", Window::M15))
        .map(|mut value| {
            value["session"] = json!("one");
            value
        })
        .unwrap();
    let mut second = first.clone();
    second["session"] = json!("two");
    let first_created = broker
        .api_post_json(&key, "/v1/requests", &first)
        .await
        .json();
    let second_created = broker
        .api_post_json(&key, "/v1/requests", &second)
        .await
        .json();
    assert_eq!(first_created["id"], second_created["id"]);
    let request: CreateRequest = serde_json::from_value(second).unwrap();
    assert_ne!(
        second_created["fingerprint"],
        json!(fingerprint(&bot(), &request).as_str())
    );
}
