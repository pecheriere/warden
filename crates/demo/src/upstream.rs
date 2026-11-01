//! The demo's target: a small HTTPS API on loopback that wants a bearer token.
//!
//! It is HTTPS because the proxy and the `warden` CLI only speak HTTPS, and
//! that does not change for a demo. Its throwaway CA is pinned in the secret's
//! policy, exactly as a real item can pin one.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::aws_lc_rs;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use url::Url;
use warden_broker::policy::{ApiSecretPolicy, ValueFormat};
use warden_broker_proto::Window;
use zeroize::Zeroizing;

/// The demo API: its keys, its token and where it is.
pub struct Target {
    origin: Url,
    ca_pem: String,
    tls: TlsAcceptor,
    secret: Zeroizing<String>,
}

impl Target {
    /// A fresh CA, certificate and token, for `origin`, which must be on
    /// `localhost`, the name the certificate holds.
    pub fn generate(origin: Url) -> Result<Self> {
        let (ca_pem, chain, key) = certificates()?;
        let config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .context("choosing TLS versions")?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .context("setting the demo API's certificate")?;
        let mut token = [0_u8; 32];
        getrandom::fill(&mut token).context("generating the demo token")?;
        Ok(Self {
            origin,
            ca_pem,
            tls: TlsAcceptor::from(Arc::new(config)),
            secret: Zeroizing::new(format!("demo-token-{}", hex::encode(token))),
        })
    }

    /// The token the broker will send.
    pub fn secret(&self) -> Zeroizing<String> {
        self.secret.clone()
    }

    /// What the vault says about this API: the origin, the pinned CA,
    /// `Authorization: Bearer {{secret}}`, `GET` only, any path.
    pub fn policy(&self, name: &str) -> Result<ApiSecretPolicy> {
        Ok(ApiSecretPolicy {
            name: name.to_owned().try_into()?,
            origin: self.origin.origin(),
            header: header::AUTHORIZATION,
            format: ValueFormat::default(),
            methods: vec![http::Method::GET],
            path_prefix: "/".to_owned(),
            ca_pem: Some(self.ca_pem.clone()),
            max_window: Window::H1,
        })
    }

    /// Serve on `listener` until aborted.
    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        let router = Router::new()
            .route("/v1/hello", get(hello))
            .with_state(Arc::new(self.secret));
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = accepted.context("accepting on the demo API")?;
                    let (acceptor, router) = (self.tls.clone(), router.clone());
                    connections.spawn(async move {
                        // A failed handshake or a broken connection only ends
                        // that connection.
                        let Ok(tls) = acceptor.accept(stream).await else { return };
                        let service = hyper_util::service::TowerToHyperService::new(router);
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                            .await;
                    });
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    }
}

/// `200` with the token it received, so the demo can show the broker's
/// redaction: an API that echoes what it is sent, as some do on an error page.
/// Without the right token, `401`.
async fn hello(State(secret): State<Arc<Zeroizing<String>>>, headers: HeaderMap) -> Response {
    let received = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let expected = format!("Bearer {}", secret.as_str());
    match received {
        Some(value) if value == expected => Json(json!({
            "message": "hello from the demo API",
            "authorization_received": value,
        }))
        .into_response(),
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "missing or wrong token"})),
        )
            .into_response(),
    }
}

/// The CA certificate PEM, and the server's chain and key.
fn certificates() -> Result<(String, Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "warden demo CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate()?;
    let ca = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_params = CertificateParams::new(vec!["localhost".to_owned()])?;
    let leaf_key = KeyPair::generate()?;
    let leaf = leaf_params.signed_by(&leaf_key, &issuer)?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    Ok((ca.pem(), vec![leaf.der().clone()], key))
}
