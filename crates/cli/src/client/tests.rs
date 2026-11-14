//! Tests of the broker client.

use warden_broker_proto::{Id, RequestStatus};
use zeroize::Zeroizing;

use super::{Auth, CallError, Client};

fn bearer(key: &str) -> Auth {
    Auth::Bearer(Zeroizing::new(key.to_owned()))
}

#[test]
fn debug_redacts_the_agent_key() {
    let key = format!("wdn_{}", "S".repeat(43));
    let client = Client::new(
        &url::Url::parse("https://warden.example/api").unwrap(),
        bearer(&key),
    )
    .unwrap();
    let shown = format!("{client:?}");
    assert!(!shown.contains(&key), "{shown}");
    assert!(shown.contains("redacted"));
    assert_eq!(
        client.url("v1/grants").unwrap().as_str(),
        "https://warden.example/api/v1/grants"
    );
}

/// A broker that answers every request with `status` and `body`.
async fn answering(status: u16, body: &'static str) -> url::Url {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let mut buf = [0_u8; 4096];
            let _ = conn.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = conn.write_all(resp.as_bytes()).await;
        }
    });
    url::Url::parse(&format!("http://{addr}/")).unwrap()
}

fn client(url: &url::Url) -> Client {
    Client::new(url, bearer(&format!("wdn_{}", "S".repeat(43)))).unwrap()
}

#[tokio::test]
async fn a_broker_too_old_to_list_requests_is_told_apart_from_a_refusal() {
    let old = client(&answering(405, "").await);
    assert_eq!(old.pending().await, Ok(None));
    let current = client(&answering(200, "[]").await);
    assert_eq!(current.pending().await, Ok(Some(Vec::new())));
    let refused = client(&answering(401, r#"{"error":"agent revoked"}"#).await);
    assert!(matches!(
        refused.pending().await,
        Err(CallError::Refused(_))
    ));
}

#[tokio::test]
async fn only_the_stopped_call_503_is_told_apart_from_an_outage() {
    let stopped = client(
        &answering(
            503,
            r#"{"error":"grant state unavailable during the call"}"#,
        )
        .await,
    );
    assert!(matches!(
        stopped.revoke(&Id::random()).await,
        Err(CallError::CallStopped(_))
    ));
    let outage = client(&answering(503, r#"{"error":"connect down"}"#).await);
    assert!(matches!(
        outage.revoke(&Id::random()).await,
        Err(CallError::Unavailable(_))
    ));
}

#[tokio::test]
async fn too_many_waits_is_unavailable_only_for_a_status_call() {
    let id = Id::random();
    let busy = client(
        &answering(
            429,
            r#"{"error":"too many status requests waiting; try again"}"#,
        )
        .await,
    );
    assert_eq!(
        busy.status(&id, 30).await,
        Err(CallError::Unavailable(
            "broker refused (429 Too Many Requests): too many status requests waiting; try again"
                .to_owned()
        ))
    );
    // Elsewhere a 429 is a limit that waiting a moment does not lift.
    assert!(matches!(busy.revoke(&id).await, Err(CallError::Refused(_))));
}

#[tokio::test]
async fn server_errors_and_unreachable_broker_are_unavailable() {
    let id = Id::random();
    let five = client(&answering(503, r#"{"error":"connect down"}"#).await);
    assert_eq!(
        five.status(&id, 0).await,
        Err(CallError::Unavailable(
            "broker error (503 Service Unavailable): connect down".to_owned()
        ))
    );

    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        url::Url::parse(&format!("http://{}/", l.local_addr().unwrap())).unwrap()
    };
    assert!(matches!(
        client(&closed).status(&id, 0).await,
        Err(CallError::Unavailable(_))
    ));
}

#[tokio::test]
async fn client_errors_and_garbage_are_refused() {
    let id = Id::random();
    let four = client(&answering(404, r#"{"error":"not found"}"#).await);
    assert_eq!(
        four.status(&id, 0).await,
        Err(CallError::Refused(
            "broker refused (404 Not Found): not found".to_owned()
        ))
    );
    let garbage = client(&answering(200, r#"{"status":"nope"}"#).await);
    assert!(matches!(
        garbage.status(&id, 0).await,
        Err(CallError::Refused(_))
    ));
}

#[tokio::test]
async fn revoked_grant_is_told_apart_from_other_conflicts() {
    let call = warden_broker_proto::ProxyRequest {
        method: "GET".to_owned(),
        url: "https://api.example.com/".to_owned(),
        headers: Vec::new(),
        body_b64: None,
    };
    let id = Id::random();
    for (message, body) in [
        ("grant revoked", r#"{"error":"grant revoked"}"#),
        (
            "grant revoked during the call",
            r#"{"error":"grant revoked during the call"}"#,
        ),
    ] {
        assert_eq!(
            client(&answering(409, body).await).proxy(&id, &call).await,
            Err(CallError::Revoked(format!(
                "broker refused (409 Conflict): {message}"
            )))
        );
    }
    for (message, body) in [
        ("grant expired", r#"{"error":"grant expired"}"#),
        (
            "grant expired during the call",
            r#"{"error":"grant expired during the call"}"#,
        ),
    ] {
        assert_eq!(
            client(&answering(409, body).await).proxy(&id, &call).await,
            Err(CallError::Expired(format!(
                "broker refused (409 Conflict): {message}"
            )))
        );
    }
    let changed = client(&answering(409, r#"{"error":"policy changed"}"#).await);
    assert!(matches!(
        changed.proxy(&id, &call).await,
        Err(CallError::Refused(_))
    ));
}

/// A grant at its daily call limit gets a 429 that waiting a moment does not lift: it
/// is a refusal with the broker's words, never an outage to retry.
#[tokio::test]
async fn a_proxied_call_over_the_daily_limit_is_refused_not_retried() {
    let call = warden_broker_proto::ProxyRequest {
        method: "GET".to_owned(),
        url: "https://api.example.com/".to_owned(),
        headers: Vec::new(),
        body_b64: None,
    };
    let body = r#"{"error":"this grant made 2 calls today, its limit; calls fail until 00:00 UTC, and the owner was told"}"#;
    assert_eq!(
        client(&answering(429, body).await)
            .proxy(&Id::random(), &call)
            .await,
        Err(CallError::Refused(
            "broker refused (429 Too Many Requests): this grant made 2 calls today, its limit; \
             calls fail until 00:00 UTC, and the owner was told"
                .to_owned()
        ))
    );
}

/// The broker's words reach the terminal only with control, format and
/// separator characters replaced.
#[tokio::test]
async fn broker_messages_are_sanitized() {
    let id = Id::random();
    let refused =
        client(&answering(400, r#"{"error":"bad\u001b[2J\u202ething\u2028x\u0085y"}"#).await);
    assert_eq!(
        refused.status(&id, 0).await,
        Err(CallError::Refused(
            "broker refused (400 Bad Request): bad?[2J?thing?x?y".to_owned()
        ))
    );
    let failed = client(
        &answering(
            200,
            r#"{"status":"error","message":"no\u009bnotifier\u200b\u2029"}"#,
        )
        .await,
    );
    assert_eq!(
        failed.status(&id, 0).await,
        Ok(RequestStatus::Error {
            message: "no?notifier??".to_owned()
        })
    );
}

#[test]
fn cleartext_remote_server_is_refused() {
    let url = url::Url::parse("http://warden.example/").unwrap();
    assert!(Client::new(&url, bearer("")).is_err());
}

/// One request as it arrived on the wire.
struct Captured {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A broker that records each raw request and answers `status` and
/// `body`.
async fn recording(
    status: u16,
    body: &'static str,
) -> (url::Url, tokio::sync::mpsc::UnboundedReceiver<Captured>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let mut raw = Vec::new();
            let mut buf = [0_u8; 4096];
            let head_end = loop {
                let n = conn.read(&mut buf).await.unwrap();
                assert!(n > 0, "connection closed mid-request");
                raw.extend_from_slice(&buf[..n]);
                if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i;
                }
            };
            let head = String::from_utf8(raw[..head_end].to_vec()).unwrap();
            let mut lines = head.split("\r\n");
            let mut line = lines.next().unwrap().split(' ');
            let method = line.next().unwrap().to_owned();
            let target = line.next().unwrap().to_owned();
            let headers: Vec<(String, String)> = lines
                .map(|l| {
                    let (n, v) = l.split_once(':').unwrap();
                    (n.to_owned(), v.trim().to_owned())
                })
                .collect();
            let len: usize = headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
                .map_or(0, |(_, v)| v.parse().unwrap());
            let mut received = raw[head_end + 4..].to_vec();
            while received.len() < len {
                let n = conn.read(&mut buf).await.unwrap();
                received.extend_from_slice(&buf[..n]);
            }
            tx.send(Captured {
                method,
                target,
                headers,
                body: received,
            })
            .unwrap();
            let resp = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = conn.write_all(resp.as_bytes()).await;
        }
    });
    (url::Url::parse(&format!("http://{addr}/")).unwrap(), rx)
}

/// In key mode the signature covers the method, the request target and
/// the body exactly as they went on the wire, with no `Authorization`;
/// every call carries a fresh nonce.
#[tokio::test]
async fn signed_calls_sign_what_is_sent() {
    use sha2::{Digest as _, Sha256};
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey};
    use warden_broker_proto::signing::{
        Audience, NAMESPACE, Nonce, SignedRequestParts, canonical_message, parse_timestamp,
    };

    use crate::sign::testing::TestAgent;
    use crate::sign::{Signer, parse_signing_key};

    let agent = TestAgent::start();
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    agent.add(&key);
    let audience = Audience::random();
    let signer = Signer::new(
        "bot".parse().unwrap(),
        audience.clone(),
        parse_signing_key(&key.public_key().to_openssh().unwrap()).unwrap(),
        agent.socket.clone(),
    );
    let (url, mut seen) = recording(200, r#"{"status":"pending"}"#).await;
    let client = Client::new(&url, Auth::Signed(Box::new(signer))).unwrap();

    let id = Id::random();
    assert_eq!(client.status(&id, 30).await, Ok(RequestStatus::Pending));
    assert_eq!(client.status(&id, 30).await, Ok(RequestStatus::Pending));
    let call = warden_broker_proto::ProxyRequest {
        method: "POST".to_owned(),
        url: "https://api.example.com/a b?q=é".to_owned(),
        headers: vec![("X-A".to_owned(), "1".to_owned())],
        body_b64: Some("eyJ4IjoxfQ==".to_owned()),
    };
    // The answer is not a proxy response: only the request matters.
    assert!(client.proxy(&id, &call).await.is_err());

    let mut nonces = Vec::new();
    for expected in [
        ("GET", format!("/v1/requests/{id}?wait=30")),
        ("GET", format!("/v1/requests/{id}?wait=30")),
        ("POST", format!("/v1/grants/{id}/http")),
    ] {
        let got = seen.recv().await.unwrap();
        assert_eq!(
            (got.method.as_str(), got.target.clone()),
            (expected.0, expected.1)
        );
        assert_eq!(got.header("authorization"), None);
        assert_eq!(got.header("warden-agent"), Some("bot"));
        let nonce = Nonce::try_from(got.header("warden-nonce").unwrap().to_owned()).unwrap();
        let message = canonical_message(&SignedRequestParts {
            audience: &audience,
            agent: &"bot".parse().unwrap(),
            method: &got.method,
            target: &got.target,
            timestamp: parse_timestamp(got.header("warden-timestamp").unwrap()).unwrap(),
            nonce: &nonce,
            body_sha256: Sha256::digest(&got.body).into(),
        })
        .unwrap();
        let blob = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            got.header("warden-signature").unwrap(),
        )
        .unwrap();
        let sig = <ssh_key::SshSig as ssh_encoding::Decode>::decode(&mut blob.as_slice()).unwrap();
        key.public_key()
            .verify(NAMESPACE, message.as_bytes(), &sig)
            .unwrap();
        if got.method == "POST" {
            assert_eq!(got.header("content-type"), Some("application/json"));
            assert_eq!(got.body, serde_json::to_vec(&call).unwrap());
        } else {
            assert_eq!(got.body, [] as [u8; 0]);
        }
        nonces.push(nonce);
    }
    assert_ne!(nonces[0], nonces[1]);
}

/// A bearer client sends its key and no `Warden-*` header.
#[tokio::test]
async fn bearer_calls_are_unsigned() {
    let (url, mut seen) = recording(200, "[]").await;
    let key = format!("wdn_{}", "S".repeat(43));
    let client = Client::new(&url, bearer(&key)).unwrap();
    assert_eq!(client.grants().await, Ok(Vec::new()));
    let got = seen.recv().await.unwrap();
    assert_eq!(
        got.header("authorization"),
        Some(format!("Bearer {key}").as_str())
    );
    assert!(
        !got.headers
            .iter()
            .any(|(n, _)| n.to_ascii_lowercase().starts_with("warden-"))
    );
}

/// A signing client refuses a server URL with a path: the API is at the
/// root and the path is signed.
#[test]
fn signed_client_needs_a_root_url() {
    let signer = crate::sign::Signer::new(
        "bot".parse().unwrap(),
        warden_broker_proto::signing::Audience::random(),
        crate::sign::parse_signing_key(
            &ssh_key::PrivateKey::random(
                &mut ssh_key::rand_core::OsRng,
                ssh_key::Algorithm::Ed25519,
            )
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap(),
        )
        .unwrap(),
        "/s".into(),
    );
    let url = url::Url::parse("https://warden.example/api/").unwrap();
    let err = Client::new(&url, Auth::Signed(Box::new(signer))).unwrap_err();
    assert!(err.to_string().contains("no path"), "{err}");
}
