//! Agents, access requests and calls to a [`TestBroker`]'s two routers.

use axum::body::Body;
use axum::http::Request;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http_body_util::BodyExt as _;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use ssh_encoding::Encode as _;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, PrivateKey};
use tower::ServiceExt as _;
use warden_broker_proto::signing::{
    AGENT_HEADER, NAMESPACE, NONCE_HEADER, Nonce, SIGNATURE_HEADER, SignedRequestParts,
    TIMESTAMP_HEADER, canonical_message,
};
use warden_broker_proto::{
    Access, AgentName, CreateRequest, CreatedResponse, Goal, SecretName, TargetName, UnixUser,
    Window,
};

use super::{TestBroker, TestResponse};
use crate::agents;
use crate::requests::Clock;
use crate::testkit::{CapturingNotifier, TEST_ORIGIN, TEST_OWNER};

impl TestBroker {
    /// Add an agent and return its key.
    ///
    /// # Panics
    /// If the agent cannot be added.
    pub async fn add_agent(&self, name: &str) -> String {
        let name = AgentName::try_from(name.to_owned()).expect("valid agent name");
        agents::add(&self.state.pool, &name)
            .await
            .expect("add agent")
            .expose()
            .to_owned()
    }

    /// Add a key-signed agent with a fresh signing key of `algorithm`
    /// (Ed25519 or ECDSA P-256) and return the key.
    ///
    /// # Panics
    /// If the key cannot be generated or the agent cannot be added.
    pub async fn add_signing_agent(&self, name: &str, algorithm: Algorithm) -> PrivateKey {
        let key = crate::test_keys::random_key(algorithm);
        let line = key.public_key().to_openssh().expect("encode public key");
        let public = agents::AgentPublicKey::parse(&line).expect("acceptable signing key");
        let name = AgentName::try_from(name.to_owned()).expect("valid agent name");
        agents::add_key_audited(&self.state.pool, &self.state.audit, &name, &public)
            .await
            .expect("add key-signed agent");
        key
    }

    /// A request to the agent API signed by `key` as `agent`, with a fresh
    /// nonce, the broker clock's current time and this broker's audience,
    /// and no `Tailscale-User-Login`. A non-empty body is sent as JSON.
    ///
    /// # Panics
    /// If the request cannot be signed or built.
    #[must_use]
    pub fn signed_request(
        &self,
        key: &PrivateKey,
        agent: &str,
        method: &str,
        target: &str,
        body: Vec<u8>,
    ) -> Request<Body> {
        let agent_name = AgentName::try_from(agent.to_owned()).expect("valid agent name");
        let nonce = Nonce::random();
        let timestamp = self.clock.now();
        let signature = request_signature(
            key,
            &SignedRequestParts {
                audience: &self.state.audience,
                agent: &agent_name,
                method,
                target,
                timestamp,
                nonce: &nonce,
                body_sha256: Sha256::digest(&body).into(),
            },
        );
        let mut builder = Request::builder()
            .method(method)
            .uri(target)
            .header(AGENT_HEADER, agent)
            .header(TIMESTAMP_HEADER, timestamp.to_string())
            .header(NONCE_HEADER, nonce.as_str())
            .header(SIGNATURE_HEADER, signature);
        if !body.is_empty() {
            builder = builder.header("Content-Type", "application/json");
        }
        builder.body(Body::from(body)).expect("request")
    }

    /// Send [`TestBroker::signed_request`] to the agent API.
    ///
    /// # Panics
    /// If the request cannot be signed or the router fails.
    pub async fn api_signed(
        &self,
        key: &PrivateKey,
        agent: &str,
        method: &str,
        target: &str,
        body: &[u8],
    ) -> TestResponse {
        self.api_send(self.signed_request(key, agent, method, target, body.to_vec()))
            .await
    }

    /// An SSH request for `alice@pi` with a fresh Ed25519 key.
    ///
    /// # Panics
    /// If no key can be generated.
    #[must_use]
    pub fn pi_request(goal: &str, window: Window) -> CreateRequest {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .expect("subject key generation")
            .public_key()
            .to_openssh()
            .expect("encode public key");
        CreateRequest {
            session: None,
            link: None,
            goal: Goal::try_from(goal.to_owned()).expect("valid goal"),
            access: Access::Ssh {
                target: TargetName::try_from("pi".to_owned()).expect("valid target"),
                user: UnixUser::try_from("alice".to_owned()).expect("valid user"),
                public_key: key,
            },
            window,
        }
    }

    /// An SSH request for `backup@nas` (see [`FakeBackend::relay_target`](crate::testkit::FakeBackend::relay_target))
    /// with a fresh Ed25519 key.
    ///
    /// # Panics
    /// If no key can be generated or `goal` is not valid.
    #[must_use]
    pub fn relay_request(goal: &str, window: Window) -> CreateRequest {
        let mut request = Self::pi_request(goal, window);
        if let Access::Ssh { target, user, .. } = &mut request.access {
            *target = TargetName::try_from("nas".to_owned()).expect("valid target");
            *user = UnixUser::try_from("backup".to_owned()).expect("valid user");
        }
        request
    }

    /// A request for commit signing.
    ///
    /// # Panics
    /// If `goal` is not a valid goal.
    #[must_use]
    pub fn commit_signing_request(goal: &str, window: Window) -> CreateRequest {
        CreateRequest {
            goal: Goal::try_from(goal.to_owned()).expect("valid goal"),
            access: Access::CommitSigning {},
            window,
            session: None,
            link: None,
        }
    }

    /// A request to use API secret `secret`.
    ///
    /// # Panics
    /// If `secret` or `goal` is not valid.
    #[must_use]
    pub fn api_request(secret: &str, goal: &str, window: Window) -> CreateRequest {
        CreateRequest {
            session: None,
            link: None,
            goal: Goal::try_from(goal.to_owned()).expect("valid goal"),
            access: Access::Api {
                secret: SecretName::try_from(secret.to_owned()).expect("valid secret name"),
                methods: None,
                path_prefix: None,
            },
            window,
        }
    }

    /// Create a request as `agent` and return it with the approval token
    /// from its doorbell.
    ///
    /// # Panics
    /// If creation fails or no doorbell arrives.
    pub async fn create_request(
        &self,
        agent: &str,
        req: CreateRequest,
    ) -> (CreatedResponse, String) {
        let agent = AgentName::try_from(agent.to_owned()).expect("valid agent name");
        let created = self
            .state
            .requests
            .create(&agent, req)
            .await
            .expect("create request");
        let bell = self.capture.next().await;
        (created, CapturingNotifier::token(&bell))
    }

    /// Send a raw request to the approval router.
    ///
    /// # Panics
    /// If the router or body fails.
    pub async fn send(&self, req: Request<Body>) -> TestResponse {
        read(
            self.router
                .clone()
                .oneshot(req)
                .await
                .expect("router is infallible"),
        )
        .await
    }

    /// `GET path` as the owner.
    ///
    /// # Panics
    /// If the request cannot be built.
    pub async fn get(&self, path: &str) -> TestResponse {
        let req = Request::get(path)
            .header("Tailscale-User-Login", TEST_OWNER)
            .body(Body::empty())
            .expect("request");
        self.send(req).await
    }

    /// `POST path` with a JSON body as the owner, from the public origin.
    ///
    /// # Panics
    /// If the request cannot be built.
    pub async fn post_json(&self, path: &str, body: &Value) -> TestResponse {
        let req = Request::post(path)
            .header("Tailscale-User-Login", TEST_OWNER)
            .header("Origin", TEST_ORIGIN)
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        self.send(req).await
    }

    /// Send a raw request to the agent API router.
    ///
    /// # Panics
    /// If the router or body fails.
    pub async fn api_send(&self, req: Request<Body>) -> TestResponse {
        read(
            self.api_router
                .clone()
                .oneshot(req)
                .await
                .expect("router is infallible"),
        )
        .await
    }

    /// `GET path` on the agent API as the owner, authenticated as the agent
    /// holding `key`.
    ///
    /// # Panics
    /// If the request cannot be built.
    pub async fn api_get(&self, key: &str, path: &str) -> TestResponse {
        let req = Request::get(path)
            .header("Tailscale-User-Login", TEST_OWNER)
            .header("Authorization", format!("Bearer {key}"))
            .body(Body::empty())
            .expect("request");
        self.api_send(req).await
    }

    /// `POST path` with no body on the agent API, authenticated like
    /// [`TestBroker::api_get`].
    ///
    /// # Panics
    /// If the request cannot be built.
    pub async fn api_post(&self, key: &str, path: &str) -> TestResponse {
        let req = Request::post(path)
            .header("Tailscale-User-Login", TEST_OWNER)
            .header("Authorization", format!("Bearer {key}"))
            .body(Body::empty())
            .expect("request");
        self.api_send(req).await
    }

    /// `POST path` with a JSON body on the agent API, authenticated like
    /// [`TestBroker::api_get`].
    ///
    /// # Panics
    /// If the request cannot be built.
    pub async fn api_post_json(&self, key: &str, path: &str, body: &Value) -> TestResponse {
        let req = Request::post(path)
            .header("Tailscale-User-Login", TEST_OWNER)
            .header("Authorization", format!("Bearer {key}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        self.api_send(req).await
    }
}

/// The `Warden-Signature` value for `parts`: an SSHSIG by `key` (namespace
/// `warden-request-v1`, hash `sha512`) over their canonical message, as
/// standard base64 of the binary blob.
///
/// # Panics
/// If `parts` cannot be signed.
#[must_use]
pub fn request_signature(key: &PrivateKey, parts: &SignedRequestParts<'_>) -> String {
    let message = canonical_message(parts).expect("signable request");
    let signature = crate::test_keys::sign(key, NAMESPACE, HashAlg::Sha512, message.as_bytes());
    let mut blob = Vec::new();
    signature.encode(&mut blob).expect("encode signature");
    STANDARD.encode(blob)
}

async fn read(resp: axum::response::Response) -> TestResponse {
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes();
    TestResponse {
        status,
        headers,
        body: String::from_utf8(bytes.to_vec()).expect("body is UTF-8"),
    }
}
