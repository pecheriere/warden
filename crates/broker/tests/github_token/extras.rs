//! A GitHub token request may name extra permissions beyond the owner's default,
//! within the owner's allowlist; a sensitive one only for a short window; and an
//! agent has one pending request per repositories, whatever extras it names.

use axum::http::StatusCode;
use serde_json::{Value, json};
use warden_broker::policy::GithubPermissionPolicy;
use warden_broker::requests::RequestError;
use warden_broker::testkit::upstream::HttpsUpstream;
use warden_broker::testkit::{CapturingNotifier, TestBroker};
use warden_broker_proto::github_token::{
    EXTRA_NOT_ALLOWED, OTHER_PERMISSIONS_PENDING, SENSITIVE_WINDOW,
};
use warden_broker_proto::{CreateRequest, Window};

use super::permissions::{WITH_CHECKS, set};
use super::{active_for, approve, configured_on_fake, entries, installation, resolved};

pub(super) const REPO: &str = "example-owner/example-repo";

/// The legacy set, which is the default of a broker whose owner set none.
pub(super) const LEGACY: &str = "contents:write,issues:write,metadata:read,pull_requests:write";

/// Make `default` the owner's default and `allowed` what agents may add to it.
pub(super) fn allow(broker: &TestBroker, default: &str, allowed: &str) {
    broker
        .backend
        .set_github_permissions(Some(GithubPermissionPolicy {
            default: set(default),
            allowed_extras: set(allowed),
        }));
}

pub(super) fn with_extras(window: Window, extras: &str) -> CreateRequest {
    TestBroker::github_token_request_with_extras("push the fix", window, &[REPO], extras)
}

fn without_extras(window: Window) -> CreateRequest {
    TestBroker::github_token_request("push the fix", window, &[REPO])
}

async fn post(broker: &TestBroker, key: &str, request: &CreateRequest) -> (StatusCode, String) {
    let resp = broker
        .api_post_json(key, "/v1/requests", &serde_json::to_value(request).unwrap())
        .await;
    (resp.status, resp.body)
}

/// What a tool sends: no extras, `automatic` set.
async fn post_automatic(broker: &TestBroker, key: &str) -> (StatusCode, String) {
    let mut body = serde_json::to_value(without_extras(Window::D30)).unwrap();
    body["access"]["automatic"] = json!({"by": "git_credential"});
    let resp = broker.api_post_json(key, "/v1/requests", &body).await;
    (resp.status, resp.body)
}

/// What the App's installation holds when it holds the legacy set and `more`.
pub(super) fn installation_with(
    more: &[(&str, &str)],
) -> warden_broker::testkit::upstream::Scripted {
    let mut held = vec![
        ("contents", "write"),
        ("issues", "write"),
        ("metadata", "read"),
        ("pull_requests", "write"),
    ];
    held.extend_from_slice(more);
    installation(&held)
}

/// Ask for `REPO` as `bot` with `extras` for `window`, approve it, and return the
/// grant. The installation holds the legacy set and `more`, which the caller names
/// for the extras it asks.
pub(super) async fn approve_with_extras(
    broker: &TestBroker,
    upstream: &HttpsUpstream,
    window: Window,
    extras: &str,
    more: &[(&str, &str)],
) -> String {
    let (_, token) = broker
        .create_request("bot", with_extras(window, extras))
        .await;
    upstream.answer_github_installation(Some(installation_with(more)));
    upstream.script_github_token(resolved(broker, &[(1001, REPO)]));
    let approved = broker.approve(&token, window).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    active_for(broker, "bot", REPO)
        .await
        .expect("a grant for the repository")
        .grant_id
        .to_string()
}

fn created_id(body: &str) -> String {
    let value: Value = serde_json::from_str(body).unwrap();
    value["id"].as_str().unwrap().to_owned()
}

async fn pending_count(broker: &TestBroker) -> usize {
    broker
        .state()
        .requests
        .pending_requests()
        .await
        .unwrap()
        .len()
}

#[tokio::test]
async fn extra_outside_allowlist_refused() {
    let (broker, key, _upstream) = configured_on_fake().await;
    let (status, body) = post(&broker, &key, &with_extras(Window::D7, "checks:read")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.contains(&format!("{EXTRA_NOT_ALLOWED}checks")),
        "{body}"
    );
    assert!(broker.capture.rung().is_empty(), "nobody is rung");
    assert_eq!(pending_count(&broker).await, 0);
    // The refusal is in the audit log, with the known permission name only.
    let refused = entries(&broker, "github_token_refused");
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(
        refused[0]["reason"],
        format!("{EXTRA_NOT_ALLOWED}checks"),
        "{refused:?}"
    );
}

#[tokio::test]
async fn extra_not_in_allowlist_refused_before_prompt() {
    let (broker, key, _upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "checks:read");
    let (status, body) = post(&broker, &key, &with_extras(Window::H1, "workflows:write")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.contains(&format!("{EXTRA_NOT_ALLOWED}workflows")),
        "{body}"
    );
    assert!(broker.capture.rung().is_empty(), "nobody is rung");
    assert_eq!(pending_count(&broker).await, 0);
}

#[tokio::test]
async fn extra_above_allowed_level_refused() {
    let (broker, key, _upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "checks:read");
    let (status, body) = post(&broker, &key, &with_extras(Window::D7, "checks:write")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.contains(&format!(
            "{EXTRA_NOT_ALLOWED}checks:write (only read is allowed)"
        )),
        "{body}"
    );
    let (status, body) = post(&broker, &key, &with_extras(Window::D7, "checks:read")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn full_set_is_default_plus_extras() {
    let (broker, key, upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "actions:read,checks:read");
    let (status, body) = post(&broker, &key, &with_extras(Window::D7, "checks:read")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let bell = broker.capture.next().await;
    let id = created_id(&body).parse().unwrap();
    let stored = broker
        .state()
        .requests
        .stored_permissions(&id)
        .await
        .unwrap();
    assert_eq!(stored.full, set(WITH_CHECKS));
    assert_eq!(
        stored
            .beyond_default
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["checks:read"]
    );
    upstream.script_github_token(resolved(&broker, &[(1001, REPO)]));
    let approved = broker
        .approve(&CapturingNotifier::token(&bell), Window::D7)
        .await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let grant = active_for(&broker, "bot", REPO).await.unwrap().grant;
    assert_eq!(grant.permissions.known().unwrap(), set(WITH_CHECKS));
    assert_eq!(
        grant.extra_permissions.unwrap().known().unwrap(),
        set("checks:read")
    );
}

#[tokio::test]
async fn extra_covered_by_default_not_marked() {
    let (broker, key, _upstream) = configured_on_fake().await;
    allow(&broker, WITH_CHECKS, "checks:read");
    let (status, body) = post(&broker, &key, &with_extras(Window::D7, "checks:read")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = created_id(&body).parse().unwrap();
    let stored = broker
        .state()
        .requests
        .stored_permissions(&id)
        .await
        .unwrap();
    assert_eq!(stored.full, set(WITH_CHECKS));
    assert_eq!(stored.beyond_default, Vec::new());
}

#[tokio::test]
async fn pending_with_other_extras_is_409() {
    let (broker, key, _upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "actions:read,checks:read");
    let (status, body) = post(&broker, &key, &with_extras(Window::D7, "checks:read")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let waiting = created_id(&body);
    for other in [
        with_extras(Window::D7, "actions:read"),
        without_extras(Window::D7),
    ] {
        let (status, body) = post(&broker, &key, &other).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body.contains(OTHER_PERMISSIONS_PENDING), "{body}");
        assert!(body.contains(&waiting), "{body}");
    }
    // A tool's automatic request asks for no extras: the credential helper is told.
    let (status, body) = post_automatic(&broker, &key).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.contains(OTHER_PERMISSIONS_PENDING), "{body}");
    assert_eq!(pending_count(&broker).await, 1);
    // Each refusal is in the audit log: the fixed text and the waiting request's id.
    let refused = entries(&broker, "github_token_refused");
    assert_eq!(refused.len(), 3, "{refused:?}");
    for entry in &refused {
        assert_eq!(
            entry["reason"],
            format!("{OTHER_PERMISSIONS_PENDING}: {waiting}"),
            "{entry}"
        );
    }
}

#[tokio::test]
async fn pending_automatic_blocks_a_request_with_extras() {
    let (broker, key, _upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "checks:read");
    let (status, body) = post_automatic(&broker, &key).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = post(&broker, &key, &with_extras(Window::D30, "checks:read")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.contains(OTHER_PERMISSIONS_PENDING), "{body}");
    assert_eq!(pending_count(&broker).await, 1);
}

#[tokio::test]
async fn pending_with_same_extras_returns_it() {
    let (broker, key, _upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "checks:read");
    let (status, first) = post(&broker, &key, &with_extras(Window::D7, "checks:read")).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let (status, second) = post(&broker, &key, &with_extras(Window::D7, "checks:read")).await;
    assert_eq!(status, StatusCode::CREATED, "{second}");
    assert_eq!(created_id(&first), created_id(&second));
    assert_eq!(
        serde_json::from_str::<Value>(&second).unwrap()["created"],
        false
    );
    assert_eq!(pending_count(&broker).await, 1);
}

#[tokio::test]
async fn renewal_finding_a_request_with_extras_is_409() {
    let (broker, _key, upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "checks:read");
    let grant = approve(&broker, &upstream, "bot", Window::D7).await;
    broker
        .create_request("bot", with_extras(Window::D7, "checks:read"))
        .await;
    let error = broker
        .state()
        .requests
        .renew_grant(&grant.parse().unwrap())
        .await
        .unwrap_err();
    assert!(
        matches!(error, RequestError::OtherPermissionsPending(_)),
        "{error}"
    );
}

#[tokio::test]
async fn the_owners_renew_button_says_what_is_waiting() {
    let (broker, _key, upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "checks:read");
    let grant = approve(&broker, &upstream, "bot", Window::D7).await;
    broker
        .create_request("bot", with_extras(Window::D7, "checks:read"))
        .await;
    let resp = broker
        .post_json(&format!("/grants/{grant}/renew"), &json!({}))
        .await;
    assert_eq!(resp.status, StatusCode::CONFLICT, "{}", resp.body);
    let says = resp.json()["error"].as_str().unwrap().to_owned();
    assert!(says.contains("approve or deny that one first"), "{says}");
    assert!(!says.contains("cancel"), "{says}");
}

#[tokio::test]
async fn summary_names_extras() {
    let (broker, _key, _upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "actions:read,checks:read");
    broker
        .create_request("bot", with_extras(Window::D7, "checks:read,actions:read"))
        .await;
    let created = entries(&broker, "request_created");
    let summary = created[0]["summary"].as_str().unwrap();
    assert!(
        summary.starts_with(&format!(
            "github token for {REPO} +actions:read,checks:read for "
        )),
        "{summary}"
    );
}

#[tokio::test]
async fn sensitive_extra_needs_a_short_window() {
    let (broker, key, _upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "workflows:write");
    for window in [Window::D1, Window::D7, Window::D30, Window::H4] {
        let (status, body) = post(&broker, &key, &with_extras(window, "workflows:write")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{window:?}: {body}");
        assert!(body.contains(SENSITIVE_WINDOW), "{window:?}: {body}");
    }
    assert!(broker.capture.rung().is_empty(), "nobody is rung");
    // Each refusal is in the audit log, with its fixed text.
    let refused = entries(&broker, "github_token_refused");
    assert_eq!(refused.len(), 4, "{refused:?}");
    for entry in &refused {
        assert_eq!(entry["reason"], SENSITIVE_WINDOW, "{entry}");
    }
    let (status, body) = post(&broker, &key, &with_extras(Window::H1, "workflows:write")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn sensitive_extra_allows_short_window_only_then() {
    let (broker, key, _upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "checks:read,workflows:write");
    let mut waiting: Option<String> = None;
    // The short windows are for a sensitive extra, and for nothing else.
    for window in [Window::M15, Window::M30, Window::H1] {
        for request in [without_extras(window), with_extras(window, "checks:read")] {
            let (status, body) = post(&broker, &key, &request).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{window:?}: {body}");
            assert!(body.contains("1d, 7d or 30d"), "{window:?}: {body}");
        }
        // The first of them stores the request; the others find that one waiting,
        // as they name the same extras, and return it.
        let (status, body) = post(&broker, &key, &with_extras(window, "workflows:write")).await;
        assert_eq!(status, StatusCode::CREATED, "{window:?}: {body}");
        match &waiting {
            None => waiting = Some(created_id(&body)),
            Some(id) => assert_eq!(&created_id(&body), id, "{window:?}: {body}"),
        }
    }
    assert_eq!(pending_count(&broker).await, 1);
}

#[tokio::test]
async fn long_windows_stay_for_extras_that_are_not_sensitive() {
    let (broker, key, _upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "checks:read");
    let (status, body) = post(&broker, &key, &with_extras(Window::D30, "checks:read")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn approving_a_sensitive_request_takes_a_short_window_only() {
    let (broker, key, upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "workflows:write");
    let (status, body) = post(&broker, &key, &with_extras(Window::H1, "workflows:write")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let bell = broker.capture.next().await;
    let token = CapturingNotifier::token(&bell);
    broker.enroll_soft_passkey().await;
    upstream.answer_github_installation(Some(installation(&[
        ("contents", "write"),
        ("issues", "write"),
        ("metadata", "read"),
        ("pull_requests", "write"),
        ("workflows", "write"),
    ])));
    upstream.script_github_token(resolved(&broker, &[(1001, REPO)]));
    // Whatever the owner chooses on the page, the long windows are refused.
    for window in [Window::D1, Window::D30] {
        let begin = broker.begin_approval(&token, window).await;
        assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
        assert!(begin.body.contains(SENSITIVE_WINDOW), "{}", begin.body);
    }
    let approved = broker.approve(&token, Window::H1).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let active = active_for(&broker, "bot", REPO).await.unwrap();
    assert_eq!(
        active.grant.extra_permissions.unwrap().known().unwrap(),
        set("workflows:write")
    );
}

/// The approval page of `request` under a policy that allows `workflows:write` and
/// `checks:read` beyond the legacy default.
async fn extras_page(request: CreateRequest) -> String {
    let (broker, _key, upstream) = configured_on_fake().await;
    allow(&broker, LEGACY, "checks:read,workflows:write");
    let (_, token) = broker.create_request("bot", request).await;
    upstream.script_github_token(resolved(&broker, &[(1001, REPO)]));
    upstream.answer_github_installation(Some(installation(&[
        ("checks", "read"),
        ("contents", "write"),
        ("issues", "write"),
        ("metadata", "read"),
        ("pull_requests", "write"),
        ("workflows", "write"),
    ])));
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    page.body
}

fn offered(body: &str) -> Vec<&'static str> {
    ["15m", "30m", "1h", "4h", "1d", "7d", "30d"]
        .into_iter()
        .filter(|w| body.contains(&format!("value=\"{w}\"")))
        .collect()
}

#[tokio::test]
async fn sensitive_request_page_offers_short_windows_only() {
    let body = extras_page(with_extras(Window::M30, "workflows:write")).await;
    assert_eq!(offered(&body), ["15m", "30m", "1h"], "{body}");
    assert!(body.contains(r#"value="30m" checked"#), "{body}");
    assert!(
        body.contains(r#"<code class="perm sensitive">workflows: write</code>"#),
        "{body}"
    );
    // The same extras that are not sensitive keep the long windows.
    let body = extras_page(with_extras(Window::D7, "checks:read")).await;
    assert_eq!(offered(&body), ["1d", "7d", "30d"], "{body}");
    assert!(body.contains(r#"value="7d" checked"#), "{body}");
}
