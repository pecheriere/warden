//! API secrets: scoped requests, their approval pages and grants.

use axum::http::{HeaderName, Method, StatusCode};
use serde_json::json;
use sqlx::Row as _;
use warden_broker::policy::{ApiSecretPolicy, ValueFormat};
use warden_broker::requests::{Clock as _, RequestError};
use warden_broker::testkit::{CapturingNotifier, FakeBackend, TestBroker};
use warden_broker_proto::{
    Access, ApiGrant, CreateRequest, CreatedResponse, Goal, GrantAccess, RequestStatus, SecretName,
    Window,
};

use super::{bot, grant_count, status};

/// Value of the `github` API secret in these tests.
const API_CREDENTIAL: &str = "api-credential-0123456789abcdef";

/// A broker with agent `bot`, API secret `github` (see
/// [`FakeBackend::example_api_secret`]) and one pending 30m request for it.
async fn api_pending() -> (TestBroker, CreatedResponse, String) {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    broker
        .backend
        .set_api_secret(FakeBackend::example_api_secret(), API_CREDENTIAL);
    let (created, token) = broker
        .create_request(
            "bot",
            TestBroker::api_request("github", "list the open pull requests", Window::M30),
        )
        .await;
    (broker, created, token)
}

/// A broker with agent `bot` and API secret `github` allowing GET, HEAD and
/// POST under `/v1/`.
async fn scoped_broker() -> TestBroker {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let mut policy = FakeBackend::example_api_secret();
    policy.methods = vec![Method::POST, Method::GET, Method::HEAD];
    "/v1/".clone_into(&mut policy.path_prefix);
    broker.backend.set_api_secret(policy, API_CREDENTIAL);
    broker
}

fn scoped_request(methods: Option<&[&str]>, path_prefix: Option<&str>) -> CreateRequest {
    CreateRequest {
        session: None,
        link: None,
        goal: Goal::try_from("list the open pull requests".to_owned()).unwrap(),
        access: Access::Api {
            secret: SecretName::try_from("github".to_owned()).unwrap(),
            methods: methods.map(|m| m.iter().map(|s| (*s).to_owned()).collect()),
            path_prefix: path_prefix.map(str::to_owned),
        },
        window: Window::M15,
    }
}

async fn create_scoped(
    broker: &TestBroker,
    req: CreateRequest,
) -> Result<CreatedResponse, RequestError> {
    broker.state().requests.create(&bot(), req).await
}

async fn dedupe_keys(broker: &TestBroker) -> Vec<String> {
    sqlx::query("SELECT dedupe_key FROM requests ORDER BY created_at, rowid")
        .fetch_all(&broker.state().pool)
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

#[tokio::test]
async fn scope_violations_are_rejected_without_notifying() {
    let broker = scoped_broker().await;
    let cases = [
        (
            scoped_request(Some(&["DELETE"]), None),
            "secret github does not allow DELETE",
        ),
        (
            scoped_request(None, Some("/v1")),
            "secret github: path prefix must be under /v1/",
        ),
        (
            scoped_request(Some(&["GET"]), Some("/v1/../admin")),
            "secret github: path prefix must not contain . or .. segments",
        ),
    ];
    for (req, expected) in cases {
        let err = create_scoped(&broker, req).await.unwrap_err();
        let RequestError::Rejected(message) = err else {
            panic!("expected Rejected, got {err:?}");
        };
        assert_eq!(message, expected);
    }
    assert_eq!(
        broker.capture.rung(),
        [] as [warden_broker::notify::Doorbell; 0]
    );
    assert_eq!(dedupe_keys(&broker).await, [] as [std::string::String; 0]);
    assert!(!broker.audit_types().contains(&"request_created".to_owned()));
}

#[tokio::test]
async fn read_and_write_requests_do_not_dedupe() {
    let broker = scoped_broker().await;
    let read = create_scoped(&broker, scoped_request(None, None))
        .await
        .unwrap();
    let write = create_scoped(&broker, scoped_request(Some(&["GET", "POST"]), None))
        .await
        .unwrap();
    let narrower = create_scoped(&broker, scoped_request(None, Some("/v1/repos")))
        .await
        .unwrap();
    assert_ne!(read.id, write.id);
    assert_ne!(read.id, narrower.id);
    // The same request again is the dedupe path, as before.
    let again = create_scoped(
        &broker,
        scoped_request(Some(&["HEAD", "GET"]), Some("/v1/")),
    )
    .await
    .unwrap();
    assert_eq!(again.id, read.id);
    assert_eq!(
        dedupe_keys(&broker).await,
        [
            "bot|api|github|GET,HEAD|/v1/",
            "bot|api|github|GET,POST|/v1/",
            "bot|api|github|GET,HEAD|/v1/repos",
        ]
    );
}

#[tokio::test]
async fn api_request_notifies_and_approves() {
    let (broker, created, token) = api_pending().await;
    let bells = broker.capture.rung();
    assert_eq!(bells.len(), 1);
    assert_eq!(bells[0].title, "warden: bot wants api github (read-only)");
    assert_eq!(bells[0].message, "list the open pull requests");
    broker.clock.advance(7);

    let approved = broker.approve(&token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert_eq!(approved.body, r#"{"message":"Approved for 15m."}"#);

    let RequestStatus::Approved(view) = status(&broker, &created.id).await else {
        panic!("expected approved");
    };
    let now = broker.clock.now();
    assert_eq!(view.not_before, now);
    assert_eq!(view.not_after, now + 900);
    assert_eq!(
        view.access,
        GrantAccess::Api(ApiGrant {
            secret: SecretName::try_from("github".to_owned()).unwrap(),
            origin: "https://api.example.com".to_owned(),
            methods: vec!["GET".to_owned()],
            path_prefix: "/".to_owned(),
            header: "authorization".to_owned(),
            digest: FakeBackend::example_api_secret().destination_digest(),
        })
    );

    // Approved and audited, with no certificate involved; the secret value
    // is nowhere: not in the grant, the database or the audit log.
    let types = broker.audit_types();
    assert!(types.contains(&"approved".to_owned()), "{types:?}");
    assert!(!types.contains(&"cert_issued".to_owned()), "{types:?}");
    let audit = std::fs::read_to_string(broker.audit_path()).unwrap();
    assert!(!audit.contains(API_CREDENTIAL));
    let stored: Vec<String> = sqlx::query("SELECT view FROM grants")
        .fetch_all(&broker.state().pool)
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(stored.len(), 1);
    assert!(!stored[0].contains(API_CREDENTIAL));

    // The grant is listed among the active ones and can be revoked there.
    let page = broker.get("/grants").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains(view.grant_id.as_str()), "{}", page.body);
    assert!(
        page.body.contains("https://api.example.com/"),
        "{}",
        page.body
    );
    let revoke = broker
        .post_json(
            &format!("/grants/{}/revoke", view.grant_id.as_str()),
            &json!({}),
        )
        .await;
    assert_eq!(revoke.status, StatusCode::OK, "{}", revoke.body);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Revoked);
}

#[tokio::test]
async fn api_approval_rejected_when_policy_changes() {
    let (broker, created, token) = api_pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    let edits: [fn(&mut ApiSecretPolicy); 5] = [
        |p| {
            p.origin = url::Url::parse("https://evil.example.com")
                .unwrap()
                .origin();
        },
        |p| p.path_prefix = "/admin/".to_owned(),
        |p| p.methods.push(Method::DELETE),
        |p| p.header = HeaderName::from_static("x-api-key"),
        |p| p.ca_pem = Some("-----BEGIN CERTIFICATE-----".to_owned()),
    ];
    let original = FakeBackend::example_api_secret();
    for edit in edits {
        // Changed between begin and finish.
        let begin = broker.begin_approval(&token, Window::M15).await;
        let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
        let mut changed = original.clone();
        edit(&mut changed);
        broker
            .backend
            .set_api_secret(changed.clone(), API_CREDENTIAL);
        let finish = broker.finish_approval(&token, &ceremony, &credential).await;
        assert_eq!(finish.status, StatusCode::CONFLICT, "{}", finish.body);
        assert_eq!(
            finish.body,
            r#"{"error":"policy changed; reload and review"}"#
        );
        assert_eq!(grant_count(&broker).await, 0);
        assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);

        // Changed between page load and begin.
        broker
            .backend
            .set_api_secret(original.clone(), API_CREDENTIAL);
        let shown = broker.page_target_digest(&token).await;
        assert_eq!(shown.len(), 64, "page should embed a SHA-256 digest");
        broker.backend.set_api_secret(changed, API_CREDENTIAL);
        let begin = broker.begin_approval_for(&token, Window::M15, &shown).await;
        assert_eq!(begin.status, StatusCode::CONFLICT, "{}", begin.body);
        broker
            .backend
            .set_api_secret(original.clone(), API_CREDENTIAL);
    }

    // A smaller max window is re-checked at finish too.
    let begin = broker.begin_approval(&token, Window::H1).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    let mut shrunk = original.clone();
    shrunk.max_window = Window::M30;
    broker.backend.set_api_secret(shrunk, API_CREDENTIAL);
    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(finish.status, StatusCode::CONFLICT, "{}", finish.body);
    assert!(
        finish
            .body
            .contains("window 1h exceeds max 30m for secret github"),
        "{}",
        finish.body
    );
    assert_eq!(grant_count(&broker).await, 0);

    // A rotated credential is not a destination change.
    broker.backend.set_api_secret(original, API_CREDENTIAL);
    let begin = broker.begin_approval(&token, Window::M15).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    broker.backend.set_api_secret(
        FakeBackend::example_api_secret(),
        "rotated-credential-0123456789",
    );
    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(finish.status, StatusCode::OK, "{}", finish.body);
}

#[tokio::test]
async fn api_page_shows_origin_methods_prefix_header_format_and_ca() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let mut policy = FakeBackend::example_api_secret();
    policy.origin = url::Url::parse("https://api.example.com:8443")
        .unwrap()
        .origin();
    policy.methods = vec![Method::GET, Method::POST];
    policy.path_prefix = "/v1/repos/".to_owned();
    policy.header = HeaderName::from_static("x-api-key");
    policy.format = ValueFormat::parse("token=<{{secret}}>;").unwrap();
    broker.backend.set_api_secret(policy, API_CREDENTIAL);
    let goal = "triage <b>issues</b> & \u{5e9}\u{5dc}\u{5d5}\u{5dd}";
    let (created, token) = broker
        .create_request("bot", TestBroker::api_request("github", goal, Window::M30))
        .await;

    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    let html = &page.body;
    assert!(html.contains(created.fingerprint.as_str()), "{html}");
    assert!(html.contains("<bdi>bot</bdi>"), "{html}");
    assert!(
        html.contains(
            "<bdi>triage &lt;b&gt;issues&lt;/b&gt; &amp; \u{5e9}\u{5dc}\u{5d5}\u{5dd}</bdi>"
        ),
        "{html}"
    );
    assert!(
        html.contains(
            "use secret <code><bdi>github</bdi></code> for <code><bdi>GET</bdi></code> \
             on <code><bdi>https://api.example.com:8443/v1/repos/</bdi></code> \
             (header <code><bdi>x-api-key</bdi></code>)"
        ),
        "{html}"
    );
    // How the secret is written, never the secret itself, and whether the
    // upstream's certificate must chain to a pinned CA.
    assert!(
        html.contains("value <code><bdi>token=&lt;…&gt;;</bdi></code>, pinned CA: no"),
        "{html}"
    );
    assert!(!html.contains(API_CREDENTIAL), "{html}");
    // Window picker capped at the secret's 1h max, requested 30m preselected.
    assert!(
        html.contains(r#"name="window" value="30m" checked>"#),
        "{html}"
    );
    assert!(html.contains(r#"name="window" value="1h">"#), "{html}");
    assert!(!html.contains(r#"value="4h""#), "{html}");
    // The page binds the policy digest, and begin enforces the max.
    broker.enroll_soft_passkey().await;
    let begin = broker.begin_approval(&token, Window::H4).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
    assert!(
        begin
            .body
            .contains("window 4h exceeds max 1h for secret github"),
        "{}",
        begin.body
    );
    let begin = broker.begin_approval(&token, Window::H1).await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
}

#[tokio::test]
async fn api_page_shows_a_pinned_ca() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let mut policy = FakeBackend::example_api_secret();
    policy.ca_pem = Some("-----BEGIN CERTIFICATE-----".to_owned());
    broker.backend.set_api_secret(policy, API_CREDENTIAL);
    let (_, token) = broker
        .create_request(
            "bot",
            TestBroker::api_request("github", "call", Window::M30),
        )
        .await;
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body
            .contains("value <code><bdi>Bearer …</bdi></code>, pinned CA: yes"),
        "{}",
        page.body
    );
}

#[tokio::test]
async fn dedupe_is_per_kind() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let mut pi_secret = FakeBackend::example_api_secret();
    pi_secret.name = SecretName::try_from("pi".to_owned()).unwrap();
    broker.backend.set_api_secret(pi_secret, API_CREDENTIAL);

    let (ssh, _) = broker
        .create_request("bot", TestBroker::pi_request("ssh in", Window::M15))
        .await;
    let (api, _) = broker
        .create_request("bot", TestBroker::api_request("pi", "call", Window::M15))
        .await;
    assert_ne!(ssh.id, api.id);
    assert_eq!(status(&broker, &ssh.id).await, RequestStatus::Pending);
    assert_eq!(status(&broker, &api.id).await, RequestStatus::Pending);

    // A repeat of either returns its own pending request without ringing.
    let again = broker
        .state()
        .requests
        .create(&bot(), TestBroker::api_request("pi", "call", Window::M15))
        .await
        .unwrap();
    assert_eq!(again, api);
    let again = broker
        .state()
        .requests
        .create(&bot(), TestBroker::pi_request("ssh in", Window::M15))
        .await
        .unwrap();
    assert_eq!(again.id, ssh.id);
    assert_eq!(broker.capture.rung().len(), 2);
}

/// An item edited to drop a requested method after the page loaded cannot
/// be approved, and no grant is issued.
#[tokio::test]
async fn approval_refused_when_item_drops_requested_method() {
    let broker = scoped_broker().await;
    let (created, token) = broker
        .create_request("bot", scoped_request(Some(&["POST"]), None))
        .await;
    let mut auth = broker.enroll_soft_passkey().await;
    let begin = broker.begin_approval(&token, Window::M15).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    let mut narrowed = FakeBackend::example_api_secret();
    narrowed.methods = vec![Method::GET, Method::HEAD];
    "/v1/".clone_into(&mut narrowed.path_prefix);
    broker.backend.set_api_secret(narrowed, API_CREDENTIAL);
    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    // The destination digest changed with the methods, so that guard fires;
    // the scope re-check in `check_policy` is a second line of defence.
    assert_eq!(finish.status, StatusCode::CONFLICT, "{}", finish.body);
    assert_eq!(
        finish.json(),
        json!({"error": "policy changed; reload and review"})
    );
    assert_eq!(grant_count(&broker).await, 0);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);
}

#[tokio::test]
async fn grants_page_labels_api_grants() {
    let (broker, _created, token) = api_pending().await;
    let approved = broker.approve(&token, Window::M30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let page = broker.get("/grants").await;
    assert!(
        page.body.contains("</svg> Read-only</strong>"),
        "{}",
        page.body
    );

    let broker = scoped_broker().await;
    let (_, token) = broker
        .create_request("bot", scoped_request(Some(&["POST", "GET"]), None))
        .await;
    let approved = broker.approve(&token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let page = broker.get("/grants").await;
    assert!(
        page.body.contains("</svg> Can modify: POST</strong>"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("Read-only"), "{}", page.body);
}

#[tokio::test]
async fn page_marks_read_only() {
    let (broker, _created, token) = api_pending().await;
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body.contains("</svg> Read-only</strong>"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("Can modify"), "{}", page.body);
}

#[tokio::test]
async fn page_warns_can_modify() {
    let broker = scoped_broker().await;
    let mut policy = FakeBackend::example_api_secret();
    policy.methods = vec![Method::GET, Method::POST, Method::PUT];
    "/v1/".clone_into(&mut policy.path_prefix);
    broker.backend.set_api_secret(policy, API_CREDENTIAL);
    create_scoped(&broker, scoped_request(Some(&["PUT", "GET", "POST"]), None))
        .await
        .unwrap();
    let bell = broker.capture.rung().pop().unwrap();
    let token = CapturingNotifier::token(&bell);
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body.contains("</svg> Can modify: POST, PUT</strong>"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("Read-only"), "{}", page.body);
}

#[tokio::test]
async fn notification_says_can_modify() {
    let broker = scoped_broker().await;
    create_scoped(&broker, scoped_request(Some(&["POST", "GET"]), None))
        .await
        .unwrap();
    create_scoped(&broker, scoped_request(None, Some("/v1/repos")))
        .await
        .unwrap();
    let titles: Vec<String> = broker.capture.rung().into_iter().map(|b| b.title).collect();
    assert_eq!(
        titles,
        [
            "warden: bot wants api github (CAN MODIFY: POST)",
            "warden: bot wants api github (read-only)",
        ]
    );
}

#[tokio::test]
async fn audit_summary_includes_scope() {
    let broker = scoped_broker().await;
    create_scoped(&broker, scoped_request(Some(&["POST", "GET"]), None))
        .await
        .unwrap();
    create_scoped(&broker, scoped_request(None, None))
        .await
        .unwrap();
    assert_eq!(
        broker.audit_summaries(),
        [
            "api github (CAN MODIFY: POST) for 15m: list the open pull requests",
            "api github (read-only) for 15m: list the open pull requests",
        ]
    );
}
