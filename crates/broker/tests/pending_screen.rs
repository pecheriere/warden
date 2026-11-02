//! The pending screen: who can reach it, what replacing an approval link does to
//! the old one, that nothing there approves without the passkey, and that a request
//! no longer pending cannot be acted on. Driven through the real routes with
//! software passkeys.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use serde_json::{Value, json};
use sqlx::Row as _;
use ssh_key::Algorithm;
use warden_broker::audit::AuditEvent;
use warden_broker::requests::Clock as _;
use warden_broker::requests::{RequestError, sha256_hex};
use warden_broker::testkit::{TEST_ORIGIN, TEST_OWNER, TestBroker, TestResponse};
use warden_broker_proto::{
    AgentName, CreatedResponse, GrantAccess, GrantView, Id, RequestStatus, SshGrant, UnixUser,
    Window,
};
use webauthn_rs::prelude::{Passkey, RequestChallengeResponse};

fn bot() -> AgentName {
    AgentName::try_from("bot".to_owned()).unwrap()
}

/// A broker with agent `bot` and one pending 30m request for `pi`.
async fn pending() -> (TestBroker, CreatedResponse, String) {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    let (created, token) = broker
        .create_request(
            "bot",
            TestBroker::pi_request("restart the backup job", Window::M30),
        )
        .await;
    (broker, created, token)
}

async fn status(broker: &TestBroker, id: &Id) -> RequestStatus {
    broker
        .state()
        .requests
        .status(&bot(), id, Duration::ZERO)
        .await
        .unwrap()
}

async fn grant_count(broker: &TestBroker) -> i64 {
    sqlx::query("SELECT COUNT(*) FROM grants")
        .fetch_one(&broker.state().pool)
        .await
        .unwrap()
        .get(0)
}

async fn stored_hash(broker: &TestBroker, id: &Id) -> String {
    sqlx::query("SELECT approval_token_hash FROM requests WHERE id = ?")
        .bind(id.as_str())
        .fetch_one(&broker.state().pool)
        .await
        .unwrap()
        .get(0)
}

async fn open(broker: &TestBroker, id: &Id) -> TestResponse {
    broker
        .post_json(&format!("/pending/{id}/open"), &json!({}))
        .await
}

async fn deny(broker: &TestBroker, id: &Id) -> TestResponse {
    broker
        .post_json(&format!("/pending/{id}/deny"), &json!({}))
        .await
}

/// Open request `id` from the screen, and return the token of its new link.
async fn opened_token(broker: &TestBroker, id: &Id) -> String {
    let opened = open(broker, id).await;
    assert_eq!(opened.status, StatusCode::OK, "{}", opened.body);
    let link = opened.json()["link"].as_str().unwrap().to_owned();
    let (origin, token) = link.rsplit_once("/approve/").unwrap();
    assert_eq!(origin, TEST_ORIGIN.trim_end_matches('/'), "{link}");
    token.to_owned()
}

fn audit_text(broker: &TestBroker) -> String {
    std::fs::read_to_string(broker.audit_path()).unwrap()
}

fn replacements(broker: &TestBroker) -> usize {
    broker
        .audit_types()
        .iter()
        .filter(|t| *t == "approval_link_replaced")
        .count()
}

/// Wait until the entry saying the owner was notified is written: it is the last
/// thing a new request writes, and it comes from a task of its own.
async fn until_notified(broker: &TestBroker) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while !broker.audit_types().iter().any(|t| t == "notified") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the request was notified");
}

/// Make every append to the audit log fail, once nothing else is writing to it.
async fn break_audit_log(broker: &TestBroker) {
    until_notified(broker).await;
    let mut corrupt = std::fs::read(broker.audit_path()).unwrap();
    corrupt.extend_from_slice(b"not an audit line\n");
    std::fs::write(broker.audit_path(), &corrupt).unwrap();
}

// --- who can reach it -------------------------------------------------------

#[tokio::test]
async fn only_the_owner_reaches_the_screen() {
    let (broker, created, _) = pending().await;
    let hash = stored_hash(&broker, &created.id).await;
    let id = &created.id;
    for login in [None, Some("mallory@example.com"), Some("OWNER@example.com")] {
        for (method, path) in [
            (Method::GET, "/pending".to_owned()),
            (Method::GET, "/pending/live".to_owned()),
            (Method::POST, format!("/pending/{id}/open")),
            (Method::POST, format!("/pending/{id}/deny")),
        ] {
            let mut req = Request::builder()
                .method(&method)
                .uri(&path)
                .header("Origin", TEST_ORIGIN)
                .header("Content-Type", "application/json");
            if let Some(login) = login {
                req = req.header("Tailscale-User-Login", login);
            }
            let resp = broker.send(req.body(Body::from("{}")).unwrap()).await;
            assert_eq!(resp.status, StatusCode::FORBIDDEN, "{path} as {login:?}");
            assert!(!resp.body.contains("backup job"), "{}", resp.body);
        }
    }
    assert_eq!(status(&broker, id).await, RequestStatus::Pending);
    assert_eq!(stored_hash(&broker, id).await, hash);
}

#[tokio::test]
async fn an_agent_cannot_reach_the_screen() {
    let (broker, created, _) = pending().await;
    let key = broker.add_agent("other").await;
    let hash = stored_hash(&broker, &created.id).await;
    let open_path = format!("/pending/{}/open", created.id);
    let deny_path = format!("/pending/{}/deny", created.id);

    // The routes do not exist on the agent API, whoever asks.
    let page = broker.api_get(&key, "/pending").await;
    assert_eq!(page.status, StatusCode::NOT_FOUND, "{}", page.body);
    assert!(!page.body.contains("backup job"), "{}", page.body);
    for path in [&open_path, &deny_path] {
        let resp = broker.api_post(&key, path).await;
        assert_eq!(resp.status, StatusCode::NOT_FOUND, "{path}: {}", resp.body);
    }

    // On the approval listener a valid agent credential is not an identity:
    // neither a bearer key nor a signature stands in for the owner's login.
    let agent_key = broker.add_signing_agent("signer", Algorithm::Ed25519).await;
    let signed = broker.signed_request(&agent_key, "signer", "GET", "/pending", Vec::new());
    assert_eq!(broker.send(signed).await.status, StatusCode::FORBIDDEN);
    let signed = broker.signed_request(&agent_key, "signer", "POST", &open_path, b"{}".to_vec());
    assert_eq!(broker.send(signed).await.status, StatusCode::FORBIDDEN);
    for (method, path) in [
        (Method::GET, "/pending"),
        (Method::POST, open_path.as_str()),
        (Method::POST, deny_path.as_str()),
    ] {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("Authorization", format!("Bearer {key}"))
            .header("Origin", TEST_ORIGIN)
            .header("Content-Type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let resp = broker.send(req).await;
        assert_eq!(resp.status, StatusCode::FORBIDDEN, "{path}: {}", resp.body);
    }

    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);
    assert_eq!(stored_hash(&broker, &created.id).await, hash);
    assert_eq!(replacements(&broker), 0);
}

#[tokio::test]
async fn state_changes_need_a_same_origin_json_post() {
    let (broker, created, token) = pending().await;
    let hash = stored_hash(&broker, &created.id).await;
    for action in ["open", "deny"] {
        let path = format!("/pending/{}/{action}", created.id);
        // A cross-site page can reach none of these.
        let req = |origin: Option<&str>, content_type: &str| {
            let mut req = Request::post(&path)
                .header("Tailscale-User-Login", TEST_OWNER)
                .header("Content-Type", content_type);
            if let Some(origin) = origin {
                req = req.header("Origin", origin);
            }
            req.body(Body::from("{}")).unwrap()
        };
        let cases = [
            (Some("https://evil.example"), "application/json"),
            (None, "application/json"),
        ];
        for (origin, content_type) in cases {
            let resp = broker.send(req(origin, content_type)).await;
            assert_eq!(resp.status, StatusCode::FORBIDDEN, "{path} from {origin:?}");
        }
        let form = broker
            .send(req(Some(TEST_ORIGIN), "application/x-www-form-urlencoded"))
            .await;
        assert_eq!(form.status, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{path}");
        // A link or an image cannot change anything.
        let get = broker.get(&path).await;
        assert_eq!(get.status, StatusCode::METHOD_NOT_ALLOWED, "{path}");
    }
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);
    assert_eq!(stored_hash(&broker, &created.id).await, hash);
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
}

// --- the list ---------------------------------------------------------------

#[tokio::test]
async fn lists_what_is_pending_with_enough_to_judge_it() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    broker.add_agent("bot-2").await;
    let empty = broker.get("/pending").await;
    assert_eq!(empty.status, StatusCode::OK, "{}", empty.body);
    assert!(empty.body.contains("Nothing waiting"), "{}", empty.body);
    assert!(
        empty.body.contains(r#"data-pending="empty""#),
        "{}",
        empty.body
    );

    let goal = "fix <script>alert(1)</script> now";
    let (first, _) = broker
        .create_request("bot", TestBroker::pi_request(goal, Window::M30))
        .await;
    broker.clock.advance(10);
    let (second, second_token) = broker
        .create_request("bot-2", TestBroker::pi_request("second", Window::H1))
        .await;

    let page = broker.get("/pending").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    let csp = page.header("content-security-policy");
    assert!(csp.contains("script-src 'self'"), "{csp}");
    let html = &page.body;
    for needle in [
        first.fingerprint.as_str(),
        second.fingerprint.as_str(),
        "<bdi>bot</bdi>",
        "<bdi>bot-2</bdi>",
        "<bdi>fix &lt;script&gt;alert(1)&lt;/script&gt; now</bdi>",
        "ssh alice@pi (",
        "Asks for 30 min",
        "Asks for 1 h",
        r#"<span class="remaining" data-remaining="600">(in 10 min)</span>"#,
        r#"<a href="/pending" aria-current="page">"#,
    ] {
        assert!(html.contains(needle), "{needle} missing from {html}");
    }
    assert!(!html.contains("<script>alert"), "{html}");
    // Soonest expiry first, and no token on the page.
    let at = |id: &Id| html.find(&format!(r#"data-request="{id}""#)).unwrap();
    assert!(at(&first.id) < at(&second.id), "{html}");
    assert!(!html.contains(&second_token), "{html}");
    assert!(!html.contains("/approve/"), "{html}");

    // Every page of the UI links to it.
    let history = broker.get("/history").await;
    assert!(history.body.contains(r#"<a href="/pending">"#));
}

#[tokio::test]
async fn the_list_survives_a_policy_outage_and_denial_still_works() {
    let (broker, created, _) = pending().await;
    broker
        .backend
        .set_target_outage(Some("connect at http://192.0.2.7:8080 refused"));
    let page = broker.get("/pending").await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains("<bdi>bot</bdi>"), "{}", page.body);
    assert!(page.body.contains("could not be read"), "{}", page.body);
    assert!(!page.body.contains("192.0.2.7"), "{}", page.body);

    // Approving waits for the policy; the new link says so rather than guessing.
    let token = opened_token(&broker, &created.id).await;
    let approval = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(approval.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        broker
            .begin_approval_for(&token, Window::M15, "any")
            .await
            .status,
        StatusCode::SERVICE_UNAVAILABLE,
    );

    let denied = deny(&broker, &created.id).await;
    assert_eq!(denied.status, StatusCode::OK, "{}", denied.body);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Denied);
}

#[tokio::test]
async fn an_unreadable_stored_request_fails_the_page_closed() {
    let (broker, created, _) = pending().await;
    sqlx::query("UPDATE requests SET body = 'not json' WHERE id = ?")
        .bind(created.id.as_str())
        .execute(&broker.state().pool)
        .await
        .unwrap();
    let page = broker.get("/pending").await;
    assert_eq!(page.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!page.body.contains("not json"), "{}", page.body);
    assert!(page.body.contains("Something went wrong"), "{}", page.body);
    // The link it can still get leads nowhere near a grant either.
    let token = opened_token(&broker, &created.id).await;
    let begin = broker.begin_approval_for(&token, Window::M15, "any").await;
    assert_eq!(begin.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(grant_count(&broker).await, 0);
}

#[tokio::test]
async fn refreshing_the_list_changes_nothing_and_shows_no_token() {
    let (broker, created, token) = pending().await;
    until_notified(&broker).await;
    broker.clock.advance(30);
    let hash = stored_hash(&broker, &created.id).await;
    let log = audit_text(&broker);

    for path in ["/pending", "/pending/live", "/pending", "/pending/live"] {
        let resp = broker.get(path).await;
        assert_eq!(resp.status, StatusCode::OK, "{path}: {}", resp.body);
        assert_eq!(resp.header("cache-control"), "no-store", "{path}");
        assert!(!resp.body.contains(&token), "{path}: {}", resp.body);
        assert!(!resp.body.contains(&hash), "{path}: {}", resp.body);
    }
    assert_eq!(stored_hash(&broker, &created.id).await, hash);
    assert_eq!(audit_text(&broker), log, "reading writes nothing");
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "the link still works");

    let live = broker.get("/pending/live").await;
    assert_eq!(
        live.json(),
        json!({"requests": [{"id": created.id, "remaining": 570}]})
    );

    // New requests appear in the answer, and ended ones leave it.
    broker.add_agent("bot-2").await;
    let (second, _) = broker
        .create_request("bot-2", TestBroker::pi_request("second", Window::M15))
        .await;
    let ids = |live: &Value| -> Vec<String> {
        live["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_owned())
            .collect()
    };
    let live = broker.get("/pending/live").await.json();
    assert_eq!(
        ids(&live),
        [created.id.to_string(), second.id.to_string()],
        "the page's order"
    );
    assert_eq!(deny(&broker, &created.id).await.status, StatusCode::OK);
    let live = broker.get("/pending/live").await.json();
    assert_eq!(ids(&live), [second.id.to_string()]);
    broker.clock.advance(600);
    let live = broker.get("/pending/live").await.json();
    assert!(ids(&live).is_empty(), "{live}");
}

#[tokio::test]
async fn refreshing_the_list_reads_no_policy() {
    let (broker, created, _) = pending().await;
    // With the backend out, a refresh that read it would have to say so.
    broker.backend.set_target_outage(Some("connect refused"));
    let live = broker.get("/pending/live").await;
    assert_eq!(live.status, StatusCode::OK, "{}", live.body);
    assert_eq!(live.json()["requests"][0]["id"], json!(created.id));
}

// --- replacing the link -----------------------------------------------------

#[tokio::test]
async fn opening_replaces_the_link_and_the_old_one_dies() {
    let (broker, created, old) = pending().await;
    let details = broker.get(&format!("/approve/{old}")).await;
    assert_eq!(details.status, StatusCode::OK, "{}", details.body);

    let new = opened_token(&broker, &created.id).await;
    assert_ne!(new, old);
    assert_eq!(
        stored_hash(&broker, &created.id).await,
        sha256_hex(&new),
        "only the new token's hash is kept"
    );
    assert_eq!(new.len(), old.len());

    // The old link ends in the not-pending outcome, on every route.
    let page = broker.get(&format!("/approve/{old}")).await;
    assert_eq!(page.status, StatusCode::NOT_FOUND);
    assert_eq!(
        page.body,
        broker.get("/approve/not-a-real-token").await.body,
        "says nothing a made-up link would not"
    );
    assert!(page.body.contains(r#"href="/pending""#), "{}", page.body);
    let begin = broker.begin_approval_for(&old, Window::M15, "any").await;
    assert_eq!(begin.status, StatusCode::NOT_FOUND, "{}", begin.body);
    let denied = broker.deny(&old).await;
    assert_eq!(denied.status, StatusCode::NOT_FOUND, "{}", denied.body);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);

    // The new link shows the same details page.
    let page = broker.get(&format!("/approve/{new}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert_eq!(
        page.body, details.body,
        "the same page as from the notification"
    );

    // Opening again leaves one link again: the one before it dies too.
    let newest = opened_token(&broker, &created.id).await;
    let page = broker.get(&format!("/approve/{new}")).await;
    assert_eq!(page.status, StatusCode::NOT_FOUND);
    let page = broker.get(&format!("/approve/{newest}")).await;
    assert_eq!(page.status, StatusCode::OK);

    // On the record, without any token, and with no decision made. The request
    // keeps its id, fingerprint and expiry, and nobody was notified again.
    assert_eq!(replacements(&broker), 2);
    let log = audit_text(&broker);
    for token in [&old, &new, &newest] {
        assert!(!log.contains(token.as_str()), "{log}");
        assert!(!log.contains(&sha256_hex(token)), "{log}");
    }
    assert!(!log.contains(r#""type":"approved""#), "{log}");
    warden_broker::audit::verify(broker.audit_path()).unwrap();
    assert_eq!(broker.capture.rung().len(), 1);
    assert!(
        page.body.contains(r#"data-remaining="600""#),
        "{}",
        page.body
    );
}

#[tokio::test]
async fn a_page_open_on_the_old_link_fails_safely() {
    let (broker, created, old) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    // The old page began its passkey prompt before the link was replaced. Opening
    // drops the prompt, so tapping again says why nothing can happen.
    let begin = broker.begin_approval(&old, Window::H1).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    let new = opened_token(&broker, &created.id).await;
    let finish = broker.finish_approval(&old, &ceremony, &credential).await;
    assert_eq!(finish.status, StatusCode::GONE, "{}", finish.body);
    let again = broker.begin_approval_for(&old, Window::H1, "any").await;
    assert_eq!(again.status, StatusCode::NOT_FOUND, "{}", again.body);
    assert!(again.body.contains("newer link"), "{}", again.body);
    assert_eq!(grant_count(&broker).await, 0);

    // A prompt that outlives the replacement (it began as the link was being
    // replaced) is refused as such, not as a cloned passkey.
    let begin = broker.begin_approval(&new, Window::H1).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    let next = replaced_without_dropping_ceremonies(&broker, &created.id).await;
    let finish = broker.finish_approval(&new, &ceremony, &credential).await;
    assert_eq!(finish.status, StatusCode::CONFLICT, "{}", finish.body);
    assert!(finish.body.contains("newer link"), "{}", finish.body);
    assert!(
        !finish.body.contains("open the request"),
        "does not claim it is still waiting: {}",
        finish.body
    );
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);
    assert!(
        !broker
            .audit_types()
            .contains(&"passkey_counter_regressed".to_owned()),
    );

    // It does not carry over to the new link either, even with a signature made
    // before the replacement.
    let begin = broker.begin_approval(&next, Window::H1).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    let newest = replaced_without_dropping_ceremonies(&broker, &created.id).await;
    let finish = broker
        .finish_approval(&newest, &ceremony, &credential)
        .await;
    assert_eq!(finish.status, StatusCode::BAD_REQUEST, "{}", finish.body);
    assert_eq!(grant_count(&broker).await, 0);

    // The link in hand still works, and the owner's choice of window on it is
    // what applies.
    let approved = broker.approve_with(&mut auth, &newest, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert!(matches!(
        status(&broker, &created.id).await,
        RequestStatus::Approved(_)
    ));
    assert_eq!(grant_count(&broker).await, 1);
}

/// The store's replacement alone, as when a `begin` on the old link lands just after
/// the route dropped that link's ceremonies. Returns the new token.
async fn replaced_without_dropping_ceremonies(broker: &TestBroker, id: &Id) -> String {
    let link = broker.state().requests.replace_link(id).await.unwrap();
    link.path().rsplit('/').next().unwrap().to_owned()
}

fn test_grant(now: i64) -> GrantView {
    GrantView {
        grant_id: Id::random(),
        not_before: now,
        not_after: now + 900,
        access: GrantAccess::Ssh(SshGrant {
            certificate: "ssh-ed25519-cert-v01@openssh.com AAAA".to_owned(),
            host: "192.0.2.10".to_owned(),
            port: 22,
            user: UnixUser::try_from("alice".to_owned()).unwrap(),
            host_keys: vec![],
        }),
    }
}

/// `mark_approved` for `token`, held with its entry being written: past its check
/// of the token, not yet applied.
async fn approval_past_its_check(
    broker: &TestBroker,
    token: &str,
) -> (
    warden_broker::audit::AppendStall,
    tokio::task::JoinHandle<Result<(), RequestError>>,
) {
    let stall = broker
        .state()
        .audit
        .stall_appends(|event| matches!(event, AuditEvent::Approved { .. }));
    let approving = {
        let requests = broker.state().requests.clone();
        let (token, grant) = (token.to_owned(), test_grant(broker.clock.now()));
        tokio::spawn(async move {
            requests
                .mark_approved(&token, Window::M15, grant, "passkey")
                .await
        })
    };
    stall.until_holding(1).await;
    (stall, approving)
}

#[tokio::test]
async fn an_approval_past_its_check_does_not_apply_on_a_replaced_token() {
    let (broker, created, old) = pending().await;
    let (stall, approving) = approval_past_its_check(&broker, &old).await;
    // Only the database's own check is left to catch this. The replacement route
    // cannot land here, as the next test shows, so write the hash directly.
    sqlx::query("UPDATE requests SET approval_token_hash = ? WHERE id = ?")
        .bind(sha256_hex("a newer token"))
        .bind(created.id.as_str())
        .execute(&broker.state().pool)
        .await
        .unwrap();
    drop(stall);
    let refused = approving.await.unwrap();
    assert!(
        matches!(refused, Err(RequestError::AlreadyDecided)),
        "{refused:?}"
    );
    assert_eq!(grant_count(&broker).await, 0);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);
    assert!(audit_text(&broker).contains("did not take effect"));
}

#[tokio::test]
async fn a_replacement_waits_for_an_approval_past_its_check() {
    let (broker, created, old) = pending().await;
    let (stall, approving) = approval_past_its_check(&broker, &old).await;
    let replacing = {
        let requests = broker.state().requests.clone();
        let id = created.id.clone();
        tokio::spawn(async move { requests.replace_link(&id).await })
    };
    drop(stall);
    approving.await.unwrap().unwrap();
    // Whichever way the two were scheduled, the approval stands and no entry says
    // its link was replaced under it.
    assert!(matches!(
        replacing.await.unwrap(),
        Err(RequestError::NotFound)
    ));
    assert_eq!(grant_count(&broker).await, 1);
    assert_eq!(replacements(&broker), 0);
}

#[tokio::test]
async fn cancelling_after_a_replacement_says_so_on_the_new_link_only() {
    let (broker, created, old) = pending().await;
    let new = opened_token(&broker, &created.id).await;
    broker
        .state()
        .requests
        .cancel(&bot(), &created.id)
        .await
        .unwrap();
    let page = broker.get(&format!("/approve/{new}")).await;
    assert_eq!(page.status, StatusCode::NOT_FOUND);
    assert!(
        page.body.contains("Cancelled by the agent"),
        "{}",
        page.body
    );
    let page = broker.get(&format!("/approve/{old}")).await;
    assert_eq!(page.status, StatusCode::NOT_FOUND);
    assert!(page.body.contains("no longer pending"), "{}", page.body);
}

#[tokio::test]
async fn no_link_is_replaced_without_its_audit_entry() {
    let (broker, created, old) = pending().await;
    let hash = stored_hash(&broker, &created.id).await;
    break_audit_log(&broker).await;
    let opened = open(&broker, &created.id).await;
    assert_eq!(
        opened.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        opened.body
    );
    assert!(!opened.body.contains("approve/"), "{}", opened.body);
    assert_eq!(stored_hash(&broker, &created.id).await, hash);
    let page = broker.get(&format!("/approve/{old}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
}

// --- approving --------------------------------------------------------------

#[tokio::test]
async fn approving_from_the_screen_still_needs_the_passkey() {
    let (broker, created, _) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    let opened = open(&broker, &created.id).await;
    assert_eq!(opened.status, StatusCode::OK, "{}", opened.body);
    // A link and nothing more: no grant, no decision, no challenge.
    let answer: Value = opened.json();
    assert_eq!(answer.as_object().unwrap().len(), 1, "{answer}");
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);
    assert_eq!(grant_count(&broker).await, 0);

    // The screen has no way to approve.
    for action in ["approve", "begin", "finish"] {
        let resp = broker
            .post_json(&format!("/pending/{}/{action}", created.id), &json!({}))
            .await;
        assert_eq!(resp.status, StatusCode::NOT_FOUND, "{action}");
    }

    // On the new link, an assertion from a passkey that is not enrolled, or none
    // at all, approves nothing.
    let token = opened_token(&broker, &created.id).await;
    let begin = broker.begin_approval(&token, Window::M15).await;
    let (ceremony, _) = TestBroker::sign(&mut auth, &begin);
    let bare = broker
        .post_json(
            &format!("/approve/{token}/finish"),
            &json!({"ceremony": ceremony}),
        )
        .await;
    assert!(bare.status.is_client_error(), "{}", bare.body);
    assert_eq!(grant_count(&broker).await, 0);
    // A real passkey enrolled elsewhere signs this broker's real challenge.
    let elsewhere = TestBroker::new().await;
    let mut stranger = elsewhere.enroll_soft_passkey().await;
    let row = sqlx::query("SELECT credential FROM passkeys")
        .fetch_one(&elsewhere.state().pool)
        .await
        .unwrap();
    let stranger_cred: Passkey = serde_json::from_str(row.get(0)).unwrap();
    let begin = broker.begin_approval(&token, Window::M15).await;
    let body = begin.json();
    let mut options = body["options"].clone();
    options["publicKey"]["allowCredentials"] = json!([{
        "type": "public-key",
        "id": serde_json::to_value(stranger_cred.cred_id()).unwrap(),
    }]);
    let options: RequestChallengeResponse = serde_json::from_value(options).unwrap();
    let credential = stranger
        .do_authentication(url::Url::parse(TEST_ORIGIN).unwrap(), options)
        .unwrap();
    let finish = broker
        .finish_approval(&token, &body["ceremony"], &credential)
        .await;
    assert_eq!(finish.status, StatusCode::FORBIDDEN, "{}", finish.body);
    assert_eq!(grant_count(&broker).await, 0);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);

    // The enrolled passkey approves, and the audit names it.
    let approved = broker.approve_with(&mut auth, &token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert!(matches!(
        status(&broker, &created.id).await,
        RequestStatus::Approved(_)
    ));
    assert!(audit_text(&broker).contains(r#""passkey_id":""#));
}

// --- denying ----------------------------------------------------------------

#[tokio::test]
async fn deny_behaves_like_the_existing_deny() {
    let (broker, created, token) = pending().await;
    let denied = deny(&broker, &created.id).await;
    assert_eq!(denied.status, StatusCode::OK, "{}", denied.body);
    assert_eq!(denied.json()["message"], "Denied.");
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Denied);
    assert!(broker.audit_types().contains(&"denied".to_owned()));
    assert!(
        audit_text(&broker).contains(&format!(r#""type":"denied","id":"{}""#, created.id)),
        "the same entry as from the approval page"
    );
    assert_eq!(replacements(&broker), 0, "denying needs no new link");
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::NOT_FOUND);
    let list = broker.get("/pending").await;
    assert!(list.body.contains("Nothing waiting"), "{}", list.body);
}

#[tokio::test]
async fn deny_does_not_wait_for_the_audit_log() {
    let (broker, created, _) = pending().await;
    break_audit_log(&broker).await;
    let denied = deny(&broker, &created.id).await;
    assert_eq!(denied.status, StatusCode::OK, "{}", denied.body);
    assert!(denied.body.contains("not on record yet"), "{}", denied.body);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Denied);
}

// --- requests no longer pending ---------------------------------------------

/// What every way a request stops being pending must leave behind: it is off the
/// list, and neither action can touch it.
async fn cannot_be_acted_on(broker: &TestBroker, id: &Id, what: &str) {
    let hash = stored_hash(broker, id).await;
    let replaced = replacements(broker);
    let grants = grant_count(broker).await;
    let list = broker.get("/pending").await;
    assert_eq!(list.status, StatusCode::OK, "{what}");
    assert!(
        !list.body.contains(&format!(r#"data-request="{id}""#)),
        "{what}: {}",
        list.body
    );
    for resp in [open(broker, id).await, deny(broker, id).await] {
        assert_eq!(resp.status, StatusCode::NOT_FOUND, "{what}: {}", resp.body);
        assert_eq!(resp.json()["error"], "this request is no longer pending");
    }
    assert_eq!(stored_hash(broker, id).await, hash, "{what}");
    assert_eq!(replacements(broker), replaced, "{what}");
    assert_eq!(grant_count(broker).await, grants, "{what}");
}

#[tokio::test]
async fn a_decided_or_cancelled_request_cannot_be_acted_on() {
    let (broker, created, token) = pending().await;
    assert_eq!(broker.deny(&token).await.status, StatusCode::OK);
    cannot_be_acted_on(&broker, &created.id, "denied").await;

    let (created, token) = broker
        .create_request("bot", TestBroker::pi_request("second", Window::M30))
        .await;
    assert_eq!(
        broker.approve(&token, Window::M15).await.status,
        StatusCode::OK
    );
    cannot_be_acted_on(&broker, &created.id, "approved").await;
    assert!(matches!(
        status(&broker, &created.id).await,
        RequestStatus::Approved(_)
    ));

    broker.add_agent("bot-b").await;
    let (created, _) = broker
        .create_request("bot-b", TestBroker::pi_request("third", Window::M30))
        .await;
    let agent = AgentName::try_from("bot-b".to_owned()).unwrap();
    broker
        .state()
        .requests
        .cancel(&agent, &created.id)
        .await
        .unwrap();
    cannot_be_acted_on(&broker, &created.id, "cancelled").await;

    let unknown = Id::random();
    for resp in [open(&broker, &unknown).await, deny(&broker, &unknown).await] {
        assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);
    }
}

#[tokio::test]
async fn an_expired_request_cannot_be_acted_on_even_before_a_sweep() {
    let (broker, created, _) = pending().await;
    let token = opened_token(&broker, &created.id).await;
    let mut auth = broker.enroll_soft_passkey().await;
    let begin = broker.begin_approval(&token, Window::M15).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);

    broker.clock.advance(600);
    cannot_be_acted_on(&broker, &created.id, "expired").await;
    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    assert!(finish.status.is_client_error(), "{}", finish.body);
    assert_eq!(grant_count(&broker).await, 0);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Expired);
    assert!(!audit_text(&broker).contains(r#""type":"approved""#));
}

#[tokio::test]
async fn a_decision_in_another_tab_wins_over_a_link_from_the_screen() {
    let (broker, created, _) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    let token = opened_token(&broker, &created.id).await;
    let begin = broker.begin_approval(&token, Window::M15).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);

    let denied = deny(&broker, &created.id).await;
    assert_eq!(denied.status, StatusCode::OK, "{}", denied.body);

    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(finish.status, StatusCode::CONFLICT, "{}", finish.body);
    assert!(finish.body.contains("already decided"), "{}", finish.body);
    assert_eq!(grant_count(&broker).await, 0);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Denied);
}

#[tokio::test]
async fn a_revoked_agents_request_cannot_be_acted_on() {
    let (broker, created, _) = pending().await;
    broker.state().requests.revoke_agent(&bot()).await.unwrap();
    cannot_be_acted_on(&broker, &created.id, "revoked agent").await;
    assert_eq!(grant_count(&broker).await, 0);
}
