//! Signatures made by OpenSSH's `ssh-keygen -Y sign`, from a key file or an
//! `ssh-agent`.

use std::path::Path;
use std::time::Duration;

use axum::http::StatusCode;
use sha2::{Digest as _, Sha256};
use warden_broker::agents::{self, AgentPublicKey};
use warden_broker::requests::Clock as _;
use warden_broker::testkit::TestBroker;
use warden_broker_proto::signing::{
    AGENT_HEADER, Audience, NONCE_HEADER, Nonce, SIGNATURE_HEADER, TIMESTAMP_HEADER,
};

use super::{create_body, name};

/// Run `ssh-keygen` with `args`; `None` if it is not installed.
async fn ssh_keygen(args: &[&str], auth_sock: Option<&Path>, stdin: &[u8]) -> Option<Vec<u8>> {
    use tokio::io::AsyncWriteExt as _;
    let mut cmd = tokio::process::Command::new("ssh-keygen");
    cmd.args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    match auth_sock {
        Some(sock) => cmd.env("SSH_AUTH_SOCK", sock),
        None => cmd.env_remove("SSH_AUTH_SOCK"),
    };
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("ssh-keygen: {e}"),
    };
    let mut input = child.stdin.take().unwrap();
    input.write_all(stdin).await.unwrap();
    drop(input);
    let out = child.wait_with_output().await.unwrap();
    assert!(
        out.status.success(),
        "ssh-keygen {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(out.stdout)
}

/// The canonical message, written out by hand from the protocol document.
fn message_by_hand(
    audience: &Audience,
    agent: &str,
    method: &str,
    target: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> String {
    format!(
        "warden-request-v1\naudience:{audience}\nagent:{agent}\nmethod:{method}\ntarget:{target}\n\
         timestamp:{timestamp}\nnonce:{nonce}\nbody-sha256:{}\n",
        hex::encode(Sha256::digest(body))
    )
}

/// An agent whose key `ssh-keygen` holds: in a file, or in an `ssh-agent`.
struct OpenSshSigner<'a> {
    agent: &'a str,
    /// The `.pub` file to enroll.
    public: &'a Path,
    /// What `ssh-keygen -Y sign -f` is given: the private key file, or the
    /// `.pub` file when the key is in the agent at `auth_sock`.
    sign_with: &'a Path,
    auth_sock: Option<&'a Path>,
}

/// Enroll `signer`, sign `method target body` with `ssh-keygen -Y sign` and
/// send it over real HTTP to the API at `api`.
async fn openssh_round_trip(
    broker: &TestBroker,
    api: &url::Url,
    signer: &OpenSshSigner<'_>,
    (method, target, body): (&str, &str, &[u8]),
) -> StatusCode {
    let line = std::fs::read_to_string(signer.public).unwrap();
    let key = AgentPublicKey::parse(&line).unwrap();
    let agent = signer.agent;
    agents::add_key_audited(
        &broker.state().pool,
        &broker.state().audit,
        &name(agent),
        &key,
    )
    .await
    .unwrap();
    let timestamp = broker.clock.now();
    let nonce = Nonce::random();
    let audience = broker.state().audience.clone();
    let message = message_by_hand(
        &audience,
        agent,
        method,
        target,
        timestamp,
        nonce.as_str(),
        body,
    );
    let armored = ssh_keygen(
        &[
            "-Y",
            "sign",
            "-n",
            "warden-request-v1",
            "-f",
            signer.sign_with.to_str().unwrap(),
        ],
        signer.auth_sock,
        message.as_bytes(),
    )
    .await
    .expect("ssh-keygen is installed");
    let armored = String::from_utf8(armored).unwrap();
    // The header value: the armor without its BEGIN/END lines, joined.
    let lines: Vec<&str> = armored.lines().collect();
    assert!(
        lines
            .first()
            .unwrap()
            .starts_with("-----BEGIN SSH SIGNATURE")
    );
    let signature: String = lines[1..lines.len() - 1].concat();

    let url = api.join(target.trim_start_matches('/')).unwrap();
    assert_eq!(&url[url::Position::BeforePath..], target);
    let resp = reqwest::Client::new()
        .request(method.parse().unwrap(), url)
        .header(AGENT_HEADER, agent)
        .header(TIMESTAMP_HEADER, timestamp.to_string())
        .header(NONCE_HEADER, nonce.as_str())
        .header(SIGNATURE_HEADER, signature)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .unwrap();
    resp.status()
}

#[tokio::test]
async fn openssh_ssh_keygen_signature_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| dir.path().join(name);
    let keygen = |kind: &'static [&'static str], file: std::path::PathBuf| async move {
        let file = file.to_str().unwrap().to_owned();
        let mut args = vec!["-q", "-N", "", "-C", "interop-test"];
        args.extend_from_slice(kind);
        args.extend_from_slice(&["-f", &file]);
        ssh_keygen(&args, None, b"").await
    };
    if keygen(&["-t", "ed25519"], path("ed")).await.is_none() {
        eprintln!("ssh-keygen not installed; skipping the OpenSSH interop test");
        return;
    }
    keygen(&["-t", "ecdsa", "-b", "256"], path("p256"))
        .await
        .unwrap();
    keygen(&["-t", "ecdsa", "-b", "256"], path("p256-agent"))
        .await
        .unwrap();

    let broker = TestBroker::new().await;
    let urls = broker.spawn().await;

    // Ed25519 key file, a POST with a body.
    let signer = OpenSshSigner {
        agent: "ed-bot",
        public: &path("ed.pub"),
        sign_with: &path("ed"),
        auth_sock: None,
    };
    let body = create_body("interop");
    let status =
        openssh_round_trip(&broker, &urls.api, &signer, ("POST", "/v1/requests", &body)).await;
    assert_eq!(status, StatusCode::CREATED);

    // ECDSA P-256 key file, a GET with a query.
    let signer = OpenSshSigner {
        agent: "p256-bot",
        public: &path("p256.pub"),
        sign_with: &path("p256"),
        auth_sock: None,
    };
    let status = openssh_round_trip(
        &broker,
        &urls.api,
        &signer,
        ("GET", "/v1/grants?interop=1", b""),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // ECDSA P-256 held only by an ssh-agent (as a Secure Enclave or TPM key
    // is): ssh-keygen is given the public key and asks the agent.
    let sock = path("agent.sock");
    let mut agent = tokio::process::Command::new("ssh-agent")
        .args(["-D", "-a", sock.to_str().unwrap()])
        .stdout(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("ssh-agent ships with ssh-keygen");
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let added = tokio::process::Command::new("ssh-add")
        .arg(path("p256-agent"))
        .env("SSH_AUTH_SOCK", &sock)
        .output()
        .await
        .unwrap();
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    // No private key file beside the .pub: only the agent can sign.
    std::fs::remove_file(path("p256-agent")).unwrap();
    let signer = OpenSshSigner {
        agent: "enclave-bot",
        public: &path("p256-agent.pub"),
        sign_with: &path("p256-agent.pub"),
        auth_sock: Some(&sock),
    };
    let status = openssh_round_trip(&broker, &urls.api, &signer, ("GET", "/v1/grants", b"")).await;
    assert_eq!(status, StatusCode::OK);
    agent.kill().await.unwrap();
}
