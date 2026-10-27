//! Approval UI: passkey enrollment and approval ceremonies driven through the
//! real routes with software passkeys, plus page and request hardening.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderName, Method, Request, StatusCode};
use serde_json::json;
use sqlx::Row as _;
use ssh_key::{Certificate, PublicKey};
use warden_broker::approval::passkeys;
use warden_broker::policy::{ApiSecretPolicy, RelayCredential, ValueFormat};
use warden_broker::requests::{Clock as _, RequestError};
use warden_broker::testkit::{
    CapturingNotifier, FakeBackend, NAS_HOST, PI_HOST, RELAY_PUBLIC_HOST, RELAY_PUBLIC_PORT,
    SoftAuthenticator, TEST_ORIGIN, TEST_OWNER, TEST_START, TestBroker,
};
use warden_broker_proto::{
    Access, AgentName, ApiGrant, CreateRequest, CreatedResponse, Goal, GrantAccess, Id,
    RequestStatus, SecretName, TargetName, Window,
};
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{Passkey, RequestChallengeResponse};
use zeroize::Zeroizing;

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                   connect-src 'self'; form-action 'self'; frame-ancestors 'none'";

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

async fn stored_credentials(broker: &TestBroker) -> Vec<String> {
    sqlx::query("SELECT credential FROM passkeys ORDER BY created_at, id")
        .fetch_all(&broker.state().pool)
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}

// --- enrollment -------------------------------------------------------------

#[tokio::test]
async fn enroll_with_code_then_code_is_spent() {
    let broker = TestBroker::new().await;
    let code = broker.enrollment_code().await;
    assert_eq!(code.len(), 12, "{code}");
    assert!(
        code.chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)),
        "{code}"
    );
    // Only a hash of the code is stored.
    let stored: String = sqlx::query("SELECT code_hash FROM enrollment_codes")
        .fetch_one(&broker.state().pool)
        .await
        .unwrap()
        .get(0);
    assert_ne!(stored, code);
    assert!(!stored.contains(&code));

    let mut auth = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let begin = broker
        .post_json("/enroll/begin", &json!({"code": code, "label": "phone"}))
        .await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
    let begin = begin.json();
    let credential = auth
        .do_registration(
            url::Url::parse(TEST_ORIGIN).unwrap(),
            serde_json::from_value(begin["options"].clone()).unwrap(),
        )
        .unwrap();
    let finish = broker
        .post_json(
            "/enroll/finish",
            &json!({"ceremony": begin["ceremony"], "credential": credential}),
        )
        .await;
    assert_eq!(finish.status, StatusCode::OK, "{}", finish.body);
    let passkey_id = finish.json()["passkey_id"].as_str().unwrap().to_owned();

    let listed = passkeys::list(&broker.state().pool).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, passkey_id);
    assert_eq!(listed[0].label, "phone");
    assert_eq!(listed[0].created_at, TEST_START);
    // The counter column mirrors the one inside the credential from the start.
    let mirrored: i64 = sqlx::query(
        "SELECT COUNT(*) FROM passkeys WHERE counter = json_extract(credential, '$.cred.counter')",
    )
    .fetch_one(&broker.state().pool)
    .await
    .unwrap()
    .get(0);
    assert_eq!(mirrored, 1);
    assert!(
        broker
            .audit_types()
            .contains(&"passkey_enrolled".to_owned())
    );

    // The code is single use, even for a different authenticator.
    let again = broker
        .post_json("/enroll/begin", &json!({"code": code, "label": "laptop"}))
        .await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST, "{}", again.body);
    assert!(again.json()["error"].as_str().unwrap().contains("code"));

    // The enrolled passkey can approve.
    let (created, token) = broker_request(&broker).await;
    let approved = broker.approve_with(&mut auth, &token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert!(matches!(
        status(&broker, &created.id).await,
        RequestStatus::Approved(_)
    ));
}

async fn broker_request(broker: &TestBroker) -> (CreatedResponse, String) {
    broker.add_agent("bot").await;
    broker
        .create_request(
            "bot",
            TestBroker::pi_request("restart the backup job", Window::M30),
        )
        .await
}

#[tokio::test]
async fn enroll_code_expires_after_600s() {
    let broker = TestBroker::new().await;
    let early = broker.enrollment_code().await;
    broker.clock.advance(599);
    let ok = broker
        .post_json("/enroll/begin", &json!({"code": early, "label": "phone"}))
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);

    let late = broker.enrollment_code().await;
    broker.clock.advance(600);
    let expired = broker
        .post_json("/enroll/begin", &json!({"code": late, "label": "phone"}))
        .await;
    assert_eq!(expired.status, StatusCode::BAD_REQUEST, "{}", expired.body);
}

#[tokio::test]
async fn enroll_rejects_bad_label_and_unknown_code() {
    let broker = TestBroker::new().await;
    let code = broker.enrollment_code().await;
    for label in ["", "   ", "tab\there", &"x".repeat(65)] {
        let resp = broker
            .post_json("/enroll/begin", &json!({"code": code, "label": label}))
            .await;
        assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{label:?}");
    }
    let resp = broker
        .post_json(
            "/enroll/begin",
            &json!({"code": "AAAAAAAAAAAA", "label": "phone"}),
        )
        .await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    // A rejected label does not spend the code; codes are case-insensitive.
    let resp = broker
        .post_json(
            "/enroll/begin",
            &json!({"code": code.to_lowercase(), "label": "phone"}),
        )
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
}

#[tokio::test]
async fn removed_passkey_can_no_longer_approve() {
    let (broker, _, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    let id = passkeys::list(&broker.state().pool).await.unwrap()[0]
        .id
        .clone();
    let begin = broker.begin_approval(&token, Window::M15).await;
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);

    passkeys::remove(&broker.state().pool, &broker.state().audit, &id)
        .await
        .unwrap();
    assert!(broker.audit_types().contains(&"passkey_removed".to_owned()));
    assert!(matches!(
        passkeys::remove(&broker.state().pool, &broker.state().audit, &id).await,
        Err(passkeys::PasskeyError::NotFound)
    ));

    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(finish.status, StatusCode::FORBIDDEN, "{}", finish.body);
    let begin = broker.begin_approval(&token, Window::M15).await;
    assert_eq!(begin.status, StatusCode::CONFLICT, "{}", begin.body);
    assert!(begin.body.contains("enroll"), "{}", begin.body);
    assert_eq!(grant_count(&broker).await, 0);
}

// --- approval page ----------------------------------------------------------

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
    assert!(html.contains(r#"<option value="15m">"#), "{html}");
    assert!(html.contains(r#"<option value="30m" selected>"#), "{html}");
    assert!(html.contains(r#"<option value="1h">"#), "{html}");
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

// --- approval ceremonies ----------------------------------------------------

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
    let mut codes = [r1.status, r2.status];
    codes.sort();
    assert_eq!(
        codes,
        [StatusCode::OK, StatusCode::CONFLICT],
        "{r1:?} {r2:?}"
    );
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

// --- deny, grants, history --------------------------------------------------

#[tokio::test]
async fn deny_marks_denied_and_wakes_cli() {
    let (broker, created, token) = pending().await;
    let broker = Arc::new(broker);
    let poller = {
        let broker = broker.clone();
        let id = created.id.clone();
        tokio::spawn(async move {
            broker
                .state()
                .requests
                .status(&bot(), &id, Duration::from_secs(30))
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        while broker.state().requests.bus().receiver_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("long-poll never subscribed");

    let denied = broker.deny(&token).await;
    assert_eq!(denied.status, StatusCode::OK, "{}", denied.body);
    let woke = tokio::time::timeout(Duration::from_secs(5), poller)
        .await
        .expect("long-poll not woken")
        .unwrap();
    assert_eq!(woke.unwrap(), RequestStatus::Denied);
    assert!(broker.audit_types().contains(&"denied".to_owned()));

    let again = broker.deny(&token).await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{}", again.body);
    let unknown = broker.deny("no-such-token").await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND, "{}", unknown.body);
}

#[tokio::test]
async fn cancelled_request_cannot_be_approved() {
    let (broker, created, token) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    // The ceremony starts while the request is still pending.
    let begin = broker.begin_approval(&token, Window::M15).await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);

    broker
        .state()
        .requests
        .cancel(&bot(), &created.id)
        .await
        .unwrap();
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Cancelled);

    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::NOT_FOUND);
    assert!(
        page.body.contains("Cancelled by the agent."),
        "{}",
        page.body
    );
    let again = broker.begin_approval(&token, Window::M15).await;
    assert_eq!(again.status, StatusCode::NOT_FOUND, "{}", again.body);
    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    assert_eq!(finish.status, StatusCode::CONFLICT, "{}", finish.body);
    assert_eq!(grant_count(&broker).await, 0);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Cancelled);
    let denied = broker.deny(&token).await;
    assert_eq!(denied.status, StatusCode::CONFLICT, "{}", denied.body);

    let history = broker.get("/history").await;
    assert!(history.body.contains("cancelled"), "{}", history.body);
}

#[tokio::test]
async fn grants_page_lists_and_revokes() {
    let (broker, created, token) = pending().await;
    let approved = broker.approve(&token, Window::M30).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let RequestStatus::Approved(view) = status(&broker, &created.id).await else {
        panic!("expected approved");
    };

    let page = broker.get("/grants").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains(view.grant_id.as_str()), "{}", page.body);
    assert!(page.body.contains("<bdi>bot</bdi>"), "{}", page.body);
    assert!(page.body.contains(created.fingerprint.as_str()));

    let revoke = broker
        .post_json(
            &format!("/grants/{}/revoke", view.grant_id.as_str()),
            &json!({}),
        )
        .await;
    assert_eq!(revoke.status, StatusCode::OK, "{}", revoke.body);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Revoked);
    let page = broker.get("/grants").await;
    assert!(!page.body.contains(view.grant_id.as_str()), "{}", page.body);
    assert!(broker.audit_types().contains(&"grant_revoked".to_owned()));

    let unknown = broker
        .post_json(
            &format!("/grants/{}/revoke", Id::random().as_str()),
            &json!({}),
        )
        .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn history_lists_decided_requests_newest_first() {
    let (broker, denied, token) = pending().await;
    let deny = broker.deny(&token).await;
    assert_eq!(deny.status, StatusCode::OK, "{}", deny.body);
    broker.clock.advance(10);
    let (approved, token) = broker
        .create_request("bot", TestBroker::pi_request("second", Window::M30))
        .await;
    assert_eq!(
        broker.approve(&token, Window::M15).await.status,
        StatusCode::OK
    );
    broker.clock.advance(10);
    let (expired, _) = broker
        .create_request("bot", TestBroker::pi_request("third", Window::H1))
        .await;
    broker.clock.advance(600);
    broker.state().requests.sweep_expired().await.unwrap();

    let page = broker.get("/history").await;
    assert_eq!(page.status, StatusCode::OK);
    let html = &page.body;
    let at = |needle: &str| {
        html.find(needle)
            .unwrap_or_else(|| panic!("{needle} missing from {html}"))
    };
    let (e, a, d) = (
        at(expired.fingerprint.as_str()),
        at(approved.fingerprint.as_str()),
        at(denied.fingerprint.as_str()),
    );
    assert!(e < a && a < d, "not newest first: {html}");
    for needle in [
        "expired",
        "approved",
        "denied",
        "<bdi>second</bdi>",
        "alice@pi",
        "15m",
        "2027-01-15 08:00:00 UTC",
    ] {
        at(needle);
    }
}

// --- hardening --------------------------------------------------------------

fn every_route(token: &str) -> Vec<(&'static str, String)> {
    let grant = Id::random();
    vec![
        ("GET", format!("/approve/{token}")),
        ("POST", format!("/approve/{token}/begin")),
        ("POST", format!("/approve/{token}/finish")),
        ("POST", format!("/approve/{token}/deny")),
        ("GET", "/grants".to_owned()),
        ("POST", format!("/grants/{}/revoke", grant.as_str())),
        ("GET", "/history".to_owned()),
        ("GET", "/enroll".to_owned()),
        ("POST", "/enroll/begin".to_owned()),
        ("POST", "/enroll/finish".to_owned()),
        ("GET", "/static/warden.js".to_owned()),
        ("GET", "/no-such-page".to_owned()),
    ]
}

#[tokio::test]
async fn non_owner_gets_403_everywhere() {
    let (broker, created, token) = pending().await;
    for login in [None, Some("mallory@example.com"), Some("OWNER@example.com")] {
        for (method, path) in every_route(&token) {
            let mut req = Request::builder()
                .method(method)
                .uri(&path)
                .header("Origin", TEST_ORIGIN)
                .header("Content-Type", "application/json");
            if let Some(login) = login {
                req = req.header("Tailscale-User-Login", login);
            }
            let resp = broker
                .send(req.body(Body::from(r#"{"window":"15m"}"#)).unwrap())
                .await;
            assert_eq!(
                resp.status,
                StatusCode::FORBIDDEN,
                "{method} {path} as {login:?}"
            );
            assert_eq!(resp.header("content-security-policy"), CSP);
        }
    }
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);
}

#[tokio::test]
async fn cross_origin_post_rejected() {
    let (broker, created, token) = pending().await;
    let post = |origin: Option<&'static str>, content_type: &'static str, path: String| {
        let mut req = Request::post(path)
            .header("Tailscale-User-Login", TEST_OWNER)
            .header("Content-Type", content_type);
        if let Some(origin) = origin {
            req = req.header("Origin", origin);
        }
        req.body(Body::from("{}")).unwrap()
    };
    for (_, path) in every_route(&token)
        .into_iter()
        .filter(|(m, _)| *m == "POST")
    {
        for origin in [
            None,
            Some("https://evil.test"),
            Some("null"),
            Some("http://warden.test"),
            Some("https://warden.test:8443"),
            Some("https://sub.warden.test"),
        ] {
            let resp = broker
                .send(post(origin, "application/json", path.clone()))
                .await;
            assert_eq!(resp.status, StatusCode::FORBIDDEN, "{path} from {origin:?}");
        }
        for content_type in [
            "text/plain",
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=x",
        ] {
            let resp = broker
                .send(post(Some(TEST_ORIGIN), content_type, path.clone()))
                .await;
            assert_eq!(
                resp.status,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{path} as {content_type}"
            );
        }
    }
    // A charset parameter is fine.
    let resp = broker
        .send(post(
            Some(TEST_ORIGIN),
            "application/json; charset=utf-8",
            format!("/approve/{token}/deny"),
        ))
        .await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Denied);
}

#[tokio::test]
async fn csp_header_present() {
    let (broker, _, token) = pending().await;
    let responses = vec![
        broker.get(&format!("/approve/{token}")).await,
        broker.get("/approve/unknown").await,
        broker.get("/grants").await,
        broker.get("/history").await,
        broker.get("/enroll").await,
        broker.get("/static/warden.js").await,
        broker.get("/no-such-page").await,
        broker.begin_approval(&token, Window::M15).await,
        broker.deny(&token).await,
        broker
            .send(Request::get("/grants").body(Body::empty()).unwrap())
            .await,
    ];
    for resp in &responses {
        assert_eq!(resp.header("content-security-policy"), CSP, "{resp:?}");
        assert_eq!(resp.header("referrer-policy"), "no-referrer");
        assert_eq!(resp.header("cache-control"), "no-store");
        assert_eq!(resp.header("x-content-type-options"), "nosniff");
    }
    let js = &responses[5];
    assert_eq!(js.status, StatusCode::OK);
    assert_eq!(js.header("content-type"), "text/javascript; charset=utf-8");
    assert!(js.body.contains("navigator.credentials"));
}

// --- api access -------------------------------------------------------------

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
    assert!(broker.capture.rung().is_empty());
    assert!(dedupe_keys(&broker).await.is_empty());
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
    assert!(html.contains(r#"<option value="30m" selected>"#), "{html}");
    assert!(html.contains(r#"<option value="1h">"#), "{html}");
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

// --- relay targets ----------------------------------------------------------

/// A broker with agent `bot`, relay target `nas` and one pending 30m relay
/// request for `backup@nas`; also returns the request's bound public key.
async fn relay_pending(broker: TestBroker) -> (TestBroker, CreatedResponse, String, PublicKey) {
    broker.add_agent("bot").await;
    broker.backend.set_relay_target(
        FakeBackend::relay_target(),
        RelayCredential::Password(Zeroizing::new("onward-password".to_owned())),
    );
    let request = TestBroker::relay_request("copy the backups", Window::M30);
    let Access::Ssh { public_key, .. } = &request.access else {
        panic!("expected an ssh request");
    };
    let public_key = PublicKey::from_openssh(public_key).unwrap();
    let (created, token) = broker.create_request("bot", request).await;
    (broker, created, token, public_key)
}

#[tokio::test]
async fn relay_request_approves_without_certificate() {
    let (broker, created, token, _) = relay_pending(TestBroker::new().await).await;
    broker.clock.advance(7);

    let approved = broker.approve(&token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);

    let RequestStatus::Approved(view) = status(&broker, &created.id).await else {
        panic!("expected approved");
    };
    let now = broker.clock.now();
    assert_eq!(view.not_before, now);
    assert_eq!(view.not_after, now + 900);
    let GrantAccess::Relay(relay) = &view.access else {
        panic!("expected a relay grant, got {:?}", view.access);
    };
    assert_eq!(relay.target.as_str(), "nas");
    assert_eq!(relay.user.as_str(), "backup");
    assert_eq!(relay.relay_host, RELAY_PUBLIC_HOST);
    assert_eq!(relay.relay_port, RELAY_PUBLIC_PORT);
    let endpoint = broker.state().requests.relay().expect("relay configured");
    assert_eq!(relay.relay_host_key, endpoint.host_key);
    let host_key = PublicKey::from_openssh(&relay.relay_host_key).unwrap();
    assert_eq!(host_key.algorithm(), ssh_key::Algorithm::Ed25519);
    // Nothing in the grant is (or contains) a certificate.
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("cert"), "{json}");

    let types = broker.audit_types();
    assert!(types.contains(&"approved".to_owned()), "{types:?}");
    assert!(!types.contains(&"cert_issued".to_owned()), "{types:?}");

    // The grants page names the relay.
    let page = broker.get("/grants").await;
    assert!(page.body.contains("via the warden relay"), "{}", page.body);
}

#[tokio::test]
async fn relay_page_says_via_relay() {
    let (broker, created, token, _) = relay_pending(TestBroker::new().await).await;
    let page = broker.get(&format!("/approve/{token}")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    let html = &page.body;
    assert!(html.contains(created.fingerprint.as_str()), "{html}");
    assert!(
        html.contains(&format!(
            "<code>ssh backup@nas ({NAS_HOST}:22)</code> via the warden relay"
        )),
        "{html}"
    );

    // A cert target's page does not mention the relay.
    let (_, token) = broker
        .create_request("bot", TestBroker::pi_request("look around", Window::M30))
        .await;
    let page = broker.get(&format!("/approve/{token}")).await;
    assert!(!page.body.contains("relay"), "{}", page.body);
}

#[tokio::test]
async fn relay_mode_change_invalidates_the_page() {
    let (broker, _, token) = pending().await;
    let digest = broker.page_target_digest(&token).await;
    // Same host, port and keys, but now relayed: not what the owner saw.
    let mut pi = broker.backend.target("pi");
    pi.mode = warden_broker::policy::SshMode::Relay;
    broker.backend.set_relay_target(
        pi,
        RelayCredential::Password(Zeroizing::new("onward-password".to_owned())),
    );
    let begin = broker
        .begin_approval_for(&token, Window::M15, &digest)
        .await;
    assert_eq!(begin.status, StatusCode::CONFLICT, "{}", begin.body);
    assert_eq!(grant_count(&broker).await, 0);
}

#[tokio::test]
async fn relay_approval_refused_when_relay_not_configured() {
    let (broker, created, token, _) = relay_pending(TestBroker::new().await).await;
    let mut auth = broker.enroll_soft_passkey().await;
    let begin = broker.begin_approval(&token, Window::M15).await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
    let (ceremony, credential) = TestBroker::sign(&mut auth, &begin);

    // The broker comes back without WARDEN_RELAY_PUBLIC_ADDR.
    let broker = broker.restart_without_relay().await;
    assert!(broker.state().requests.relay().is_none());
    let finish = broker.finish_approval(&token, &ceremony, &credential).await;
    // The ceremony was in memory and is gone; a fresh begin is refused.
    assert_ne!(finish.status, StatusCode::OK, "{}", finish.body);
    let begin = broker.begin_approval(&token, Window::M15).await;
    assert_eq!(begin.status, StatusCode::BAD_REQUEST, "{}", begin.body);
    assert!(
        begin.json()["error"]
            .as_str()
            .unwrap()
            .contains("relay is not configured"),
        "{}",
        begin.body
    );
    assert_eq!(grant_count(&broker).await, 0);
    assert_eq!(status(&broker, &created.id).await, RequestStatus::Pending);
}

#[tokio::test]
async fn active_relay_grant_matches_bound_key_and_target_only() {
    let (broker, _, token, bound) = relay_pending(TestBroker::new().await).await;
    let requests = &broker.state().requests;
    let nas = TargetName::try_from("nas".to_owned()).unwrap();
    // Nothing before approval.
    assert!(
        requests
            .active_relay_grant(&nas, &bound)
            .await
            .unwrap()
            .is_none()
    );

    let approved = broker.approve(&token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);

    let found = requests
        .active_relay_grant(&nas, &bound)
        .await
        .unwrap()
        .expect("active relay grant for the bound key");
    assert_eq!(found.agent.as_str(), "bot");
    assert_eq!(found.target, nas);
    assert_eq!(found.user.as_str(), "backup");
    assert_eq!(found.not_after, broker.clock.now() + 900);

    // Another key, or the right key on another target, finds nothing.
    let other =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone();
    assert!(
        requests
            .active_relay_grant(&nas, &other)
            .await
            .unwrap()
            .is_none()
    );
    let pi = TargetName::try_from("pi".to_owned()).unwrap();
    assert!(
        requests
            .active_relay_grant(&pi, &bound)
            .await
            .unwrap()
            .is_none()
    );
    // A comment on the offered key does not matter, only the key itself.
    let mut commented = bound.clone();
    commented.set_comment("someone@example.com");
    assert!(
        requests
            .active_relay_grant(&nas, &commented)
            .await
            .unwrap()
            .is_some()
    );

    // Expired: nothing.
    broker.clock.advance(900);
    assert!(
        requests
            .active_relay_grant(&nas, &bound)
            .await
            .unwrap()
            .is_none()
    );
    broker.clock.advance(-900);

    // Revoked: nothing.
    let revoke = broker
        .post_json(
            &format!("/grants/{}/revoke", found.grant_id.as_str()),
            &json!({}),
        )
        .await;
    assert_eq!(revoke.status, StatusCode::OK, "{}", revoke.body);
    assert!(
        requests
            .active_relay_grant(&nas, &bound)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn cert_grant_is_never_an_active_relay_grant() {
    let (broker, _, token) = pending().await;
    let approved = broker.approve(&token, Window::M15).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    let grants = broker.state().requests.active_grants().await.unwrap();
    let Access::Ssh { public_key, .. } = &grants[0].request.access else {
        panic!("expected an ssh request");
    };
    let key = PublicKey::from_openssh(public_key).unwrap();
    let pi = TargetName::try_from("pi".to_owned()).unwrap();
    assert!(
        broker
            .state()
            .requests
            .active_relay_grant(&pi, &key)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn bound_key_reuse_is_409_on_the_api() {
    let broker = TestBroker::new().await;
    let bot = broker.add_agent("bot").await;
    let other = broker.add_agent("other").await;
    let request = TestBroker::pi_request("look around", Window::M30);
    let body = serde_json::to_value(&request).unwrap();
    let first = broker.api_post_json(&bot, "/v1/requests", &body).await;
    assert_eq!(first.status, StatusCode::CREATED, "{}", first.body);
    let second = broker.api_post_json(&other, "/v1/requests", &body).await;
    assert_eq!(second.status, StatusCode::CONFLICT, "{}", second.body);
    assert_eq!(
        second.json(),
        json!({"error": "this public key is already bound to another request or grant"})
    );
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
        page.body
            .contains(r#"<strong class="readonly">Read-only</strong>"#),
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
        page.body
            .contains(r#"<strong class="warning">Can modify: POST</strong>"#),
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
        page.body
            .contains(r#"<strong class="readonly">Read-only</strong>"#),
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
        page.body
            .contains(r#"<strong class="warning">Can modify: POST, PUT</strong>"#),
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

#[tokio::test]
async fn counter_regression_refused() {
    let (broker, first, token_a) = pending().await;
    let mut auth = broker.enroll_soft_passkey().await;
    broker.add_agent("other").await;
    let (_second, token_b) = broker
        .create_request(
            "other",
            TestBroker::pi_request("rotate the logs", Window::M15),
        )
        .await;

    // Both ceremonies begin while the stored counter is 0; the authenticator
    // signs the first with counter 1 and the second with counter 2.
    let begin_a = broker.begin_approval(&token_a, Window::M15).await;
    let begin_b = broker.begin_approval(&token_b, Window::M15).await;
    let (ceremony_a, older) = TestBroker::sign(&mut auth, &begin_a);
    let (ceremony_b, newer) = TestBroker::sign(&mut auth, &begin_b);

    // The newer assertion arrives first and is stored.
    let done = broker.finish_approval(&token_b, &ceremony_b, &newer).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    let stored = stored_counters(&broker).await;
    assert_eq!(stored, [2]);
    let credential = stored_credentials(&broker).await;

    // The older one arrives late: refused as a possible cloned authenticator,
    // with a fixed message, no grant, and the stored counter untouched.
    let late = broker.finish_approval(&token_a, &ceremony_a, &older).await;
    assert_eq!(late.status, StatusCode::FORBIDDEN, "{}", late.body);
    assert_eq!(
        late.json()["error"],
        "passkey refused: its signature counter went backwards"
    );
    assert_eq!(grant_count(&broker).await, 1);
    assert_eq!(status(&broker, &first.id).await, RequestStatus::Pending);
    assert_eq!(stored_counters(&broker).await, [2]);
    assert_eq!(stored_credentials(&broker).await, credential);
    let types = broker.audit_types();
    assert!(
        types.contains(&"passkey_counter_regressed".to_owned()),
        "{types:?}"
    );
}

async fn stored_counters(broker: &TestBroker) -> Vec<i64> {
    sqlx::query("SELECT counter FROM passkeys ORDER BY created_at, id")
        .fetch_all(&broker.state().pool)
        .await
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect()
}
