//! Passkey enrollment and approval of requests on a [`TestBroker`].

use axum::http::StatusCode;
use serde_json::{Value, json};
use url::Url;
use warden_broker_proto::Window;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RequestChallengeResponse,
};

use super::{TestBroker, TestResponse};
use crate::requests::Clock;
use crate::testkit::{SoftAuthenticator, TEST_ORIGIN};

impl TestBroker {
    /// A fresh enrollment code.
    ///
    /// # Panics
    /// If the code cannot be created.
    pub async fn enrollment_code(&self) -> String {
        self.state
            .passkeys
            .create_enrollment_code(self.clock.now())
            .await
            .expect("create enrollment code")
    }

    /// Enroll a new software passkey through the enrollment routes.
    ///
    /// # Panics
    /// If any step fails.
    pub async fn enroll_soft_passkey(&self) -> SoftAuthenticator {
        let code = self.enrollment_code().await;
        let mut auth = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let begin = self
            .post_json("/enroll/begin", &json!({"code": code, "label": "soft"}))
            .await;
        assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
        let begin = begin.json();
        let options: CreationChallengeResponse =
            serde_json::from_value(begin["options"].clone()).expect("creation options");
        let credential = auth
            .do_registration(origin(), options)
            .expect("soft passkey registration");
        let finish = self
            .post_json(
                "/enroll/finish",
                &json!({"ceremony": begin["ceremony"], "credential": credential}),
            )
            .await;
        assert_eq!(finish.status, StatusCode::OK, "{}", finish.body);
        auth
    }

    /// The destination digest the approval page for `token` embeds (as the
    /// browser script reads it), or an empty string if the page has none.
    pub async fn page_target_digest(&self, token: &str) -> String {
        let page = self.get(&format!("/approve/{token}")).await;
        page.body
            .split_once(r#"data-target=""#)
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(digest, _)| digest.to_owned())
            .unwrap_or_default()
    }

    /// `POST /approve/<token>/begin` for `window`, as the page's script sends
    /// it: with the destination digest the page was rendered with.
    pub async fn begin_approval(&self, token: &str, window: Window) -> TestResponse {
        let target = self.page_target_digest(token).await;
        self.begin_approval_for(token, window, &target).await
    }

    /// `POST /approve/<token>/begin` for `window`, claiming the page showed
    /// the destination with digest `target`.
    pub async fn begin_approval_for(
        &self,
        token: &str,
        window: Window,
        target: &str,
    ) -> TestResponse {
        self.post_json(
            &format!("/approve/{token}/begin"),
            &json!({ "window": window, "target": target }),
        )
        .await
    }

    /// Sign the challenge in a successful `begin` response.
    ///
    /// # Panics
    /// If `begin` is not a challenge or the authenticator refuses.
    #[must_use]
    pub fn sign(
        auth: &mut SoftAuthenticator,
        begin: &TestResponse,
    ) -> (Value, PublicKeyCredential) {
        assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
        let begin = begin.json();
        let options: RequestChallengeResponse =
            serde_json::from_value(begin["options"].clone()).expect("request options");
        let credential = auth
            .do_authentication(origin(), options)
            .expect("soft passkey assertion");
        (begin["ceremony"].clone(), credential)
    }

    /// `POST /approve/<token>/finish`.
    pub async fn finish_approval(
        &self,
        token: &str,
        ceremony: &Value,
        credential: &PublicKeyCredential,
    ) -> TestResponse {
        self.post_json(
            &format!("/approve/{token}/finish"),
            &json!({"ceremony": ceremony, "credential": credential}),
        )
        .await
    }

    /// Approve with `auth`: begin, sign, finish.
    ///
    /// # Panics
    /// If `begin` fails.
    pub async fn approve_with(
        &self,
        auth: &mut SoftAuthenticator,
        token: &str,
        window: Window,
    ) -> TestResponse {
        let begin = self.begin_approval(token, window).await;
        let (ceremony, credential) = Self::sign(auth, &begin);
        self.finish_approval(token, &ceremony, &credential).await
    }

    /// Approve with this broker's own passkey, enrolling it on first use.
    ///
    /// # Panics
    /// If enrollment or `begin` fails.
    pub async fn approve(&self, token: &str, window: Window) -> TestResponse {
        let mut slot = self.default_passkey.lock().await;
        if slot.is_none() {
            *slot = Some(self.enroll_soft_passkey().await);
        }
        let auth = slot.as_mut().expect("default passkey enrolled");
        self.approve_with(auth, token, window).await
    }

    /// `POST /approve/<token>/deny`.
    pub async fn deny(&self, token: &str) -> TestResponse {
        self.post_json(&format!("/approve/{token}/deny"), &json!({}))
            .await
    }
}

fn origin() -> Url {
    Url::parse(TEST_ORIGIN).expect("test origin is a URL")
}
