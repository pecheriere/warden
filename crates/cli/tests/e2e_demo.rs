//! The demo end to end: the real `warden` binary, set up by sourcing the file
//! the demo writes, against the real listeners of `warden_demo::Demo`, as its
//! documentation describes. Only the person is replaced, by a software
//! passkey with the demo's `http://localhost` origin.

use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};
use warden_broker_proto::Window;
use warden_demo::{Demo, SECRET_NAME};
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

/// `warden <args>` in a shell that sourced the demo's settings, and nothing
/// else from this process's environment that could point it elsewhere.
fn agent(demo: &Demo, args: &[&str]) -> Command {
    let mut cmd = Command::new("sh");
    cmd.args(["-c", r#". "$1"; shift; exec "$@""#, "sh"])
        .arg(demo.agent_env())
        .arg(env!("CARGO_BIN_EXE_warden"))
        .args(args)
        .env_remove("WARDEN_AGENT_KEY")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .stdin(Stdio::null());
    cmd
}

/// A browser on the approval origin: right `Origin`, JSON bodies.
struct Browser {
    http: reqwest::Client,
    origin: url::Url,
}

impl Browser {
    fn new(demo: &Demo) -> Self {
        Self {
            http: reqwest::Client::new(),
            origin: demo.approval_url().clone(),
        }
    }

    async fn page(&self, path: &str) -> (reqwest::StatusCode, String) {
        let resp = self
            .http
            .get(self.origin.join(path).unwrap())
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.text().await.unwrap())
    }

    async fn post(&self, path: &str, body: &Value) -> (reqwest::StatusCode, Value) {
        let origin = self.origin.origin().ascii_serialization();
        let resp = self
            .http
            .post(self.origin.join(path).unwrap())
            .header("Origin", origin)
            .json(body)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap())
    }
}

/// Enroll a software passkey with `code`, the way the enrollment page does.
async fn enroll(browser: &Browser, code: &str) -> WebauthnAuthenticator<SoftPasskey> {
    let mut passkey = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (status, begin) = browser
        .post("/enroll/begin", &json!({"code": code, "label": "soft"}))
        .await;
    assert!(status.is_success(), "{status}: {begin}");
    let options: CreationChallengeResponse =
        serde_json::from_value(begin["options"].clone()).unwrap();
    let credential = passkey
        .do_registration(browser.origin.clone(), options)
        .unwrap();
    let (status, finish) = browser
        .post(
            "/enroll/finish",
            &json!({"ceremony": begin["ceremony"], "credential": credential}),
        )
        .await;
    assert!(status.is_success(), "{status}: {finish}");
    passkey
}

/// The destination digest the approval page at `link` embeds.
async fn destination_digest(browser: &Browser, link: &str) -> String {
    let (status, page) = browser.page(link).await;
    assert!(status.is_success(), "{status}: {page}");
    page.split_once(r#"data-target=""#)
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(digest, _)| digest.to_owned())
        .expect("the approval page embeds the destination digest")
}

/// Approve `link`, the way the approval page does.
async fn approve(browser: &Browser, passkey: &mut WebauthnAuthenticator<SoftPasskey>, link: &str) {
    let digest = destination_digest(browser, link).await;
    let (status, begin) = browser
        .post(
            &format!("{link}/begin"),
            &json!({"window": Window::M15, "target": digest}),
        )
        .await;
    assert!(status.is_success(), "{status}: {begin}");
    let options: RequestChallengeResponse =
        serde_json::from_value(begin["options"].clone()).unwrap();
    let credential = passkey
        .do_authentication(browser.origin.clone(), options)
        .unwrap();
    let (status, finish) = browser
        .post(
            &format!("{link}/finish"),
            &json!({"ceremony": begin["ceremony"], "credential": credential}),
        )
        .await;
    assert!(status.is_success(), "{status}: {finish}");
}

fn text(output: &Output) -> String {
    format!(
        "status {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn the_documented_flow_works_with_real_checks() {
    let mut demo = Demo::start().await.unwrap();
    let target = demo.target_url().to_string();
    let browser = Browser::new(&demo);
    let call = ["http", SECRET_NAME, "GET", target.as_str()];

    // The settings the demo writes are a working setup, as `warden doctor` sees it.
    let doctor = agent(&demo, &["doctor"]).output().unwrap();
    assert!(doctor.status.success(), "{}", text(&doctor));
    assert!(!text(&doctor).contains("wdn_"), "{}", text(&doctor));

    // Nothing has been approved, so the agent can call nothing.
    let refused = agent(&demo, &call).output().unwrap();
    assert!(!refused.status.success(), "{}", text(&refused));

    // The agent asks, and waits.
    let goal = "try the warden demo";
    let waiting = agent(
        &demo,
        &[
            "request",
            "api",
            SECRET_NAME,
            "--for",
            "15m",
            "--goal",
            goal,
        ],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    let bell = demo.next_doorbell().await.unwrap();
    assert!(bell.message.contains(goal), "{}", bell.message);
    let origin = demo.approval_url().origin();
    assert_eq!(bell.url.origin(), origin, "the link must open the UI");

    // Until a passkey is enrolled nothing can approve, and a wrong code does
    // not enroll one.
    let link = bell.url.path().to_owned();
    let (status, _) = browser
        .post(
            &format!("{link}/begin"),
            &json!({"window": Window::M15, "target": destination_digest(&browser, &link).await}),
        )
        .await;
    assert!(!status.is_success(), "{status}");
    let (status, _) = browser
        .post(
            "/enroll/begin",
            &json!({"code": "AAAAAAAAAAAA", "label": "soft"}),
        )
        .await;
    assert!(status.is_client_error(), "{status}");

    let mut passkey = enroll(&browser, demo.enrollment_code()).await;

    // Another origin cannot drive a ceremony.
    let (status, _) = {
        let resp = browser
            .http
            .post(browser.origin.join("/enroll/begin").unwrap())
            .header("Origin", "http://evil.example")
            .json(&json!({"code": "AAAAAAAAAAAA", "label": "soft"}))
            .send()
            .await
            .unwrap();
        (resp.status(), resp.bytes().await.unwrap())
    };
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);

    approve(&browser, &mut passkey, &link).await;

    let decided = tokio::task::spawn_blocking(move || waiting.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(decided.status.success(), "{}", text(&decided));

    // The agent's call reaches the API with the secret; the agent cannot see it.
    let used = agent(&demo, &call).output().unwrap();
    assert!(used.status.success(), "{}", text(&used));
    let body: Value = serde_json::from_slice(&used.stdout).unwrap();
    assert_eq!(body["message"], "hello from the demo API");
    assert_eq!(body["authorization_received"], "[REDACTED]");

    // Only GET is in the grant.
    let post = agent(&demo, &["http", SECRET_NAME, "POST", target.as_str()])
        .output()
        .unwrap();
    assert!(!post.status.success(), "{}", text(&post));

    // The audit log shows it all, and the chain holds.
    let log = std::fs::read_to_string(demo.audit_path()).unwrap();
    for event in [
        "request_created",
        "passkey_enrolled",
        "\"approved\"",
        "\"proxy_call\"",
    ] {
        assert!(log.contains(event), "{event} is missing from:\n{log}");
    }
    assert!(
        !log.contains("demo-token-"),
        "the secret is in the audit log"
    );
    let dir = demo.dir().to_owned();
    let entries = demo.finish().await.unwrap();
    assert!(entries >= 4, "{entries}");
    assert!(!dir.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn only_its_own_address_gets_the_owner_identity() {
    let demo = Demo::start().await.unwrap();
    let port = demo.approval_url().port().unwrap();
    let client = reqwest::Client::new();

    let own = client
        .get(demo.approval_url().join("/history").unwrap())
        .send()
        .await
        .unwrap();
    assert!(own.status().is_success(), "{}", own.status());

    // As a page after DNS rebinding, or a plain IP that WebAuthn cannot use.
    for host in ["evil.example".to_owned(), format!("127.0.0.1:{port}")] {
        let other = client
            .get(format!("http://127.0.0.1:{port}/history"))
            .header("Host", &host)
            .send()
            .await
            .unwrap();
        assert_eq!(other.status(), reqwest::StatusCode::FORBIDDEN, "{host}");
    }
    demo.finish().await.unwrap();
}
