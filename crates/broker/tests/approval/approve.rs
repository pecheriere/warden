//! The approval page and the passkey ceremonies that decide a request.

use std::time::Duration;

use axum::http::StatusCode;
use serde_json::json;
use sqlx::Row as _;
use ssh_key::Certificate;
use warden_broker::requests::Clock as _;
use warden_broker::testkit::{PI_HOST, SoftAuthenticator, TEST_ORIGIN, TEST_START, TestBroker};
use warden_broker_proto::{AgentName, GrantAccess, RequestStatus, Window};
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{Passkey, RequestChallengeResponse};

use super::{grant_count, pending, status, stored_counters, stored_credentials};

#[tokio::test]
async fn approve_page_shows_fingerprint_goal_target() {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    // Right-to-left text is allowed (bidi controls are not; see proto).
    let goal = "fix <script>alert(1)</script> & \u{5e9}\u{5dc}\u{5d5}\u{5dd}.exe";
    let (created, token) = broker
        .create_request("bot", TestBroker::pi_request(goal, Window::M30))
        .await;

    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.header("content-type").starts_with("text/html"));
    let html = &page.body;
    assert!(html.contains(created.fingerprint.as_str()), "{html}");
    assert!(html.contains("<bdi>bot</bdi>"), "{html}");
    assert!(
        html.contains(
            "<bdi>fix &lt;script&gt;alert(1)&lt;/script&gt; &amp; \u{5e9}\u{5dc}\u{5d5}\u{5dd}.exe</bdi>"
        ),
        "{html}"
    );
    assert!(!html.contains("<script>alert"), "{html}");
    assert!(
        html.contains(&format!("ssh alice@pi ({PI_HOST}:22)")),
        "{html}"
    );
    // Window picker: only windows up to the target's 1h max, requested 30m preselected.
    assert!(html.contains(r#"name="window" value="15m">"#), "{html}");
    assert!(
        html.contains(r#"name="window" value="30m" checked>"#),
        "{html}"
    );
    assert!(html.contains(r#"name="window" value="1h">"#), "{html}");
    assert!(!html.contains(r#"value="4h""#), "{html}");
    // Countdown data, external script only.
    assert!(html.contains(r#"data-remaining="600""#), "{html}");
    assert!(html.contains(r#"<script src="/static/warden.js" defer></script>"#));
    assert_eq!(html.matches("<script").count(), 1, "{html}");

    // Unknown or decided tokens get a page that says so, nothing more.
    let unknown = broker.get("/approve/not-a-real-token").await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert!(
        unknown.body.contains("no longer pending"),
        "{}",
        unknown.body
    );
    let denied = broker.deny(&token).await;
    assert_eq!(denied.status, StatusCode::OK, "{}", denied.body);
    let decided = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(decided.status, StatusCode::NOT_FOUND);
    assert_eq!(decided.body, unknown.body);
}

#[tokio::test]
async fn approve_applies_window_chosen_at_begin() {
    let (broker, created, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    let before = stored_credentials(&broker).await;
    broker.clock.advance(42);

    let begin = broker.begin_approval(&token, Window::M15).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    // A window smuggled into finish is ignored.
    let finish = broker
        .post_json(
            &format!("/approve/{token}/finish"),
            &json!({"ceremony": ceremony, "credential": credential, "window": "1h"}),
        )
        .await;
    assert_eq!(finish.status, StatusCode::OK, "{}", finish.body);

    let RequestStatus::Approved(view) = status(&broker, &created.id).await else {
        panic!("expected approved");
    };
    let now = broker.clock.now();
    assert_eq!(now, TEST_START + 42);
    assert_eq!(view.not_before, now);
    assert_eq!(view.not_after, now + 900);
    let GrantAccess::Ssh(ssh) = &view.access else {
        panic!("expected an ssh grant");
    };
    assert_eq!(ssh.host, PI_HOST);
    assert_eq!(ssh.port, 22);
    assert_eq!(ssh.user.as_str(), "alice");
    assert_eq!(ssh.host_keys.len(), 1);
    let window: i64 = sqlx::query("SELECT window_secs FROM grants")
        .fetch_one(&broker.state().pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(window, 900);

    let cert = Certificate::from_openssh(&ssh.certificate).unwrap();
    assert_eq!(cert.valid_before(), u64::try_from(now + 900).unwrap());
    assert_eq!(cert.valid_principals(), ["warden:pi:alice"]);
    assert_eq!(
        cert.key_id(),
        format!("warden:bot:{}", view.grant_id.as_str())
    );
    let ca = broker
        .backend
        .ca_public_key()
        .fingerprint(ssh_key::HashAlg::Sha256);
    cert.validate_at(u64::try_from(now).unwrap(), &[ca])
        .unwrap();

    let types = broker.audit_types();
    assert!(types.contains(&"approved".to_owned()), "{types:?}");
    assert!(types.contains(&"cert_issued".to_owned()), "{types:?}");
    // The signature counter was stored back.
    assert_ne!(stored_credentials(&broker).await, before);
    // The counter column mirrors the one inside the stored credential.
    let mirrored: i64 = sqlx::query(
        "SELECT COUNT(*) FROM passkeys WHERE counter > 0 \
         AND counter = json_extract(credential, '$.cred.counter')",
    )
    .fetch_one(&broker.state().pool)
    .await
    .unwrap()
    .get(0);
    assert_eq!(mirrored, 1);
}

#[tokio::test]
async fn approve_rejects_window_over_target_max() {
    let (broker, created, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;

    let begin = broker.begin_approval(&token, Window::H4).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
    assert!(begin.body.contains("exceeds"), "{}", begin.body);

    // The policy shrinks between begin and finish: the stored window is
    // re-checked against the target fetched at approval time.
    let begin = broker.begin_approval(&token, Window::H1).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    let mut pi = broker.backend.target("pi");
    pi.max_window = Window::M30;
    broker.backend.set_target(pi);
    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(finish.status, StatusCode::CONFLICT, "{}", finish.body);
    assert!(finish.body.contains("exceeds"), "{}", finish.body);
    assert_eq!(grant_count(&broker).await, 0);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);

    // So does a user removed from the target.
    let begin = broker.begin_approval(&token, Window::M30).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    let mut pi = broker.backend.target("pi");
    pi.users.retain(|u| u.as_str() != "alice");
    broker.backend.set_target(pi);
    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(finish.status, StatusCode::CONFLICT, "{}", finish.body);
    assert_eq!(grant_count(&broker).await, 0);
}

#[tokio::test]
async fn backend_outage_during_approval_is_503_without_detail() {
    let (broker, created, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    let fixed = r#"{"error":"secret backend unavailable"}"#;

    broker
        .backend
        .set_target_outage(Some("connect at http://10.9.8.7:8080 refused"));
    let begin = broker.begin_approval(&token, Window::M30).await;
    assert_eq!(
        begin.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        begin.body
    );
    assert_eq!(begin.body, fixed);
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!page.body.contains("10.9.8.7"), "{}", page.body);
    broker.backend.set_target_outage(None);

    let begin = broker.begin_approval(&token, Window::M30).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    broker
        .backend
        .set_ca_outage(Some("item \"warden-ssh-ca\": field private_key unreadable"));
    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(
        finish.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        finish.body
    );
    assert_eq!(finish.body, fixed);
    assert_eq!(grant_count(&broker).await, 0);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);
}

#[tokio::test]
async fn approval_rejected_when_target_host_changes() {
    let (broker, created, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    let changes: [fn(&mut warden_broker::policy::SshTarget); 3] = [
        |t| t.host = "10.6.6.6".to_owned(),
        |t| t.port = 2222,
        |t| {
            t.host_keys = vec![
                ssh_key::PrivateKey::random(
                    &mut ssh_key::rand_core::OsRng,
                    ssh_key::Algorithm::Ed25519,
                )
                .unwrap()
                .public_key()
                .clone(),
            ];
        },
    ];
    for change in changes {
        let original = broker.backend.target("pi");
        let begin = broker.begin_approval(&token, Window::M15).await;
        let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
        let mut pi = original.clone();
        change(&mut pi);
        broker.backend.set_target(pi);
        let finish = broker.finish_approval(&token, &ceremony, &credential).await;
        assert_eq!(finish.status, StatusCode::CONFLICT, "{}", finish.body);
        assert_eq!(
            finish.body,
            r#"{"error":"policy changed; reload and review"}"#
        );
        assert_eq!(grant_count(&broker).await, 0);
        assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);
        broker.backend.set_target(original);
    }
}

#[tokio::test]
async fn begin_rejected_when_target_changed_since_page_load() {
    let (broker, _created, token) = pending().await;
    broker.enroll_soft_passkey().await;
    let shown = broker.page_target_digest(&token).await;
    assert_eq!(shown.len(), 64, "page should embed a SHA-256 digest");
    let mut pi = broker.backend.target("pi");
    pi.host = "10.6.6.6".to_owned();
    broker.backend.set_target(pi);
    let begin = broker.begin_approval_for(&token, Window::M15, &shown).await;
    assert_eq!(begin.status, StatusCode::CONFLICT, "{}", begin.body);
    assert_eq!(
        begin.body,
        r#"{"error":"policy changed; reload and review"}"#
    );
    // A reloaded page shows the new destination and can be approved.
    let reloaded = broker.page_target_digest(&token).await;
    assert_ne!(reloaded, shown);
    let page = broker.get(&format!("/approve/{token}")).await;
    assert!(page.body.contains("(10.6.6.6:22)"), "{}", page.body);
    let begin = broker
        .begin_approval_for(&token, Window::M15, &reloaded)
        .await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
}

#[tokio::test]
async fn approve_is_single_use_under_concurrency() {
    let (broker, created, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    let first = broker.begin_approval(&token, Window::M15).await;
    let second = broker.begin_approval(&token, Window::M30).await;
    let (c1, a1) = TestBroker::sign(&mut auth, &first);
    let (c2, a2) = TestBroker::sign(&mut auth, &second);

    let (r1, r2) = tokio::join!(
        broker.finish_approval(&token, &c1, &a1),
        broker.finish_approval(&token, &c2, &a2),
    );
    // Exactly one wins. The loser is refused either as already decided or,
    // when it gets past the pending check before the winner is approved but
    // stores its counter after the winner's higher one, as a counter
    // regression: storing the counter and approving are separate steps, so
    // two finishes landing at the same moment can look like a cloned
    // authenticator. The sequential case is never refused that way
    // (`decided_request_refused_before_passkey_check`).
    let mut codes = [r1.status, r2.status];
    codes.sort();
    assert!(
        codes == [StatusCode::OK, StatusCode::FORBIDDEN]
            || codes == [StatusCode::OK, StatusCode::CONFLICT],
        "{r1:?} {r2:?}"
    );
    let loser = if r1.status == StatusCode::OK {
        &r2
    } else {
        &r1
    };
    let expected = if loser.status == StatusCode::CONFLICT {
        "this request was already decided"
    } else {
        "passkey refused: its signature counter went backwards"
    };
    assert_eq!(loser.json()["error"], expected, "{}", loser.body);
    assert_eq!(grant_count(&broker).await, 1);
    assert!(matches!(
        status(&broker, &created.id).await,
        RequestStatus::Approved(_)
    ));
    let approved = broker
        .audit_types()
        .iter()
        .filter(|t| *t == "approved")
        .count();
    assert_eq!(approved, 1);

    // A ceremony is single use: replaying a finished one is refused.
    let replay = broker.finish_approval(&token, &c1, &a1).await;
    assert_eq!(replay.status, StatusCode::GONE, "{}", replay.body);
}

#[tokio::test]
async fn decided_request_refused_before_passkey_check() {
    let (broker, created, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    let first = broker.begin_approval(&token, Window::M15).await;
    let second = broker.begin_approval(&token, Window::M30).await;
    let (c1, older) = TestBroker::sign(&mut auth, &first);
    let (c2, newer) = TestBroker::sign(&mut auth, &second);

    // The newer assertion approves the request; the older one arrives after
    // that and is refused as already decided, not as a counter regression.
    let done = broker.finish_approval(&token, &c2, &newer).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    let late = broker.finish_approval(&token, &c1, &older).await;
    assert_eq!(late.status, StatusCode::CONFLICT, "{}", late.body);
    assert_eq!(late.json()["error"], "this request was already decided");
    assert_eq!(grant_count(&broker).await, 1);
    assert!(matches!(
        status(&broker, &created.id).await,
        RequestStatus::Approved(_)
    ));
    assert_eq!(stored_counters(&broker).await, [2]);
    let types = broker.audit_types();
    assert!(
        !types.contains(&"passkey_counter_regressed".to_owned()),
        "{types:?}"
    );
    // The refused ceremony was used up all the same.
    let replay = broker.finish_approval(&token, &c1, &older).await;
    assert_eq!(replay.status, StatusCode::GONE, "{}", replay.body);
}

#[tokio::test]
async fn assertion_from_unenrolled_key_rejected() {
    let (broker, created, token) = pending().await;
    broker.enroll_soft_passkey().await;

    // A real passkey enrolled elsewhere (same origin, other broker).
    let elsewhere = TestBroker::new().await;
    let mut stranger = elsewhere.enroll_soft_passkey().await;
    let stranger_cred: Passkey =
        serde_json::from_str(&stored_credentials(&elsewhere).await[0]).unwrap();

    // It signs this broker's real challenge, aimed at its own credential.
    let begin = broker.begin_approval(&token, Window::M15).await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
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

    // Enrollment asks for user verification: the options say "required", so
    // a soft passkey that cannot verify the user declines to register. This
    // is the client honouring the request; the server's own enforcement is
    // tested in `server_rejects_assertion_without_user_verification`.
    let mut no_uv: SoftAuthenticator = WebauthnAuthenticator::new(SoftPasskey::new(false));
    let code = broker.enrollment_code().await;
    let begin = broker
        .post_json("/enroll/begin", &json!({"code": code, "label": "no-uv"}))
        .await
        .json();
    assert_eq!(
        begin["options"]["publicKey"]["authenticatorSelection"]["userVerification"], "required",
        "{begin}"
    );
    assert!(
        no_uv
            .do_registration(
                url::Url::parse(TEST_ORIGIN).unwrap(),
                serde_json::from_value(begin["options"].clone()).unwrap(),
            )
            .is_err()
    );
}

#[tokio::test]
async fn server_rejects_assertion_without_user_verification() {
    let (broker, created, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;

    // The authenticator is told UV is discouraged, so it signs the real
    // challenge with user presence only: a validly signed assertion whose
    // UV flag is clear, as a passkey that skipped Face ID would send.
    let begin = broker.begin_approval(&token, Window::M15).await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
    let body = begin.json();
    assert_eq!(body["options"]["publicKey"]["userVerification"], "required");
    let mut options = body["options"].clone();
    options["publicKey"]["userVerification"] = json!("discouraged");
    let options: RequestChallengeResponse = serde_json::from_value(options).unwrap();
    let credential = auth
        .do_authentication(url::Url::parse(TEST_ORIGIN).unwrap(), options)
        .unwrap();
    let flags = credential.response.authenticator_data.as_ref()[32];
    assert_eq!(
        flags & 0b101,
        0b001,
        "assertion must have UP set and UV clear"
    );

    let finish = broker
        .finish_approval(&token, &body["ceremony"], &credential)
        .await;
    assert_eq!(finish.status, StatusCode::FORBIDDEN, "{}", finish.body);
    assert_eq!(grant_count(&broker).await, 0);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);

    // Control: the same passkey with user verification is accepted.
    let done = broker.approve_with(&mut auth, &token, Window::M15).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    assert_eq!(grant_count(&broker).await, 1);
}

#[tokio::test]
async fn ceremony_is_bound_to_its_request() {
    let (broker, first, token_a) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    broker.add_agent("other").await;
    let (second, token_b) = broker
        .create_request(
            "other",
            TestBroker::pi_request("rotate the logs", Window::M15),
        )
        .await;

    let begin = broker.begin_approval(&token_a, Window::M15).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    let finish = broker
        .finish_approval(&token_b, &ceremony, &credential)
        .await;
    assert_eq!(finish.status, StatusCode::BAD_REQUEST, "{}", finish.body);
    assert_eq!(grant_count(&broker).await, 0);
    assert_eq!(status(&broker, &first.id).await, RequestStatus::Pending);
    let other = broker
        .state()
        .requests
        .status(
            &AgentName::try_from("other".to_owned()).unwrap(),
            &second.id,
            Duration::ZERO,
        )
        .await
        .unwrap();
    assert_eq!(other, RequestStatus::Pending);
}

#[tokio::test]
async fn ceremony_expires_after_120s() {
    let (broker, created, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;

    let begin = broker.begin_approval(&token, Window::M15).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    broker.clock.advance(120);
    let late = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(late.status, StatusCode::GONE, "{}", late.body);
    assert!(late.body.contains("tap"), "{}", late.body);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);

    let begin = broker.begin_approval(&token, Window::M15).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    broker.clock.advance(119);
    let in_time = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(in_time.status, StatusCode::OK, "{}", in_time.body);
}

#[tokio::test]
async fn finish_after_request_expiry_says_expired() {
    let (broker, created, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    broker.clock.advance(550);
    let begin = broker.begin_approval(&token, Window::M15).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);
    broker.clock.advance(50);
    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(finish.status, StatusCode::GONE, "{}", finish.body);
    assert!(finish.body.contains("expired"), "{}", finish.body);
    assert_eq!(grant_count(&broker).await, 0);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Expired);
}
