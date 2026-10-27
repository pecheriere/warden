//! Signing agent API requests with an SSH key held by an `ssh-agent`
//! (protocol `warden-request-v1`, `docs/agent-protocol.md` section 3).
//!
//! The CLI never reads a private key: it asks the agent at the configured
//! socket (or `$SSH_AUTH_SOCK`) to sign the SSHSIG preimage of each
//! request's canonical message, then wraps the agent's signature into the
//! SSHSIG blob sent in `Warden-Signature`.

use std::fmt;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest as _, Sha256};
use ssh_agent_lib::agent::Session as _;
use ssh_agent_lib::proto::{PublicCredential, SignRequest};
use ssh_encoding::Encode as _;
use ssh_key::{HashAlg, PublicKey, SshSig};
use warden_broker_proto::AgentName;
use warden_broker_proto::signing::{
    AGENT_HEADER, Audience, NAMESPACE, NONCE_HEADER, Nonce, SIGNATURE_HEADER, SignedRequestParts,
    SigningKeyError, SigningPublicKey, TIMESTAMP_HEADER, canonical_message,
};
use zeroize::Zeroizing;

/// Environment variable naming the default `ssh-agent` socket.
pub const SSH_AUTH_SOCK: &str = "SSH_AUTH_SOCK";

/// Largest public key file read, in bytes; a `.pub` line is far shorter.
const MAX_PUBLIC_KEY_FILE: u64 = 16 * 1024;

/// How long the `ssh-agent` may take to answer. An agent that waits for a
/// touch, a PIN or a biometric prompt would hold every call: such keys
/// cannot sign unattended, so the CLI gives up instead.
const AGENT_TIMEOUT: Duration = Duration::from_secs(20);

/// The SSHSIG hash algorithm the CLI signs with (the `ssh-keygen` default).
const HASH_ALG: HashAlg = HashAlg::Sha512;

/// Validate an OpenSSH public key line as a signing key: `ssh-ed25519` or
/// `ecdsa-sha2-nistp256`, not a security key, certificate or published test
/// key. Returns it without its comment.
///
/// # Errors
/// Why the line is refused. Messages never echo the line.
pub fn parse_signing_key(line: &str) -> Result<PublicKey> {
    match SigningPublicKey::parse(line) {
        Ok(key) => Ok(key.into_public_key()),
        Err(SigningKeyError::Malformed) => bail!(
            "not an OpenSSH public key: expected one line such as 'ssh-ed25519 AAAA… comment'"
        ),
        Err(SigningKeyError::SecurityKey) => bail!(
            "security keys (sk-*) cannot sign requests: they need a touch for every signature, \
             and every API call is signed"
        ),
        Err(SigningKeyError::Certificate) => {
            bail!("certificates cannot sign requests: use the plain public key")
        }
        Err(SigningKeyError::Unsupported(algorithm)) => {
            bail!("unsupported key type {algorithm}; use ssh-ed25519 or ecdsa-sha2-nistp256")
        }
        Err(SigningKeyError::PublishedTestKey) => {
            bail!("this is the published test key from the protocol document; generate your own")
        }
    }
}

/// Read and validate the signing key's public key file (the `.pub`).
///
/// # Errors
/// If the file cannot be read, is too large, holds a private key, or is not
/// an acceptable public key ([`parse_signing_key`]).
pub fn read_signing_key(path: &Path) -> Result<PublicKey> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("cannot open the public key {}", path.display()))?;
    // Zeroized: the path may name a private key by mistake.
    let mut raw = Zeroizing::new(String::new());
    file.take(MAX_PUBLIC_KEY_FILE + 1)
        .read_to_string(&mut raw)
        .with_context(|| format!("cannot read the public key {}", path.display()))?;
    ensure!(
        u64::try_from(raw.len()).is_ok_and(|n| n <= MAX_PUBLIC_KEY_FILE),
        "{} is too large for a public key",
        path.display()
    );
    ensure!(
        !raw.contains("PRIVATE KEY"),
        "{} holds a private key; pass the public key (.pub) instead",
        path.display()
    );
    parse_signing_key(&raw).with_context(|| format!("{}", path.display()))
}

/// The `ssh-agent` socket: `configured`, or else `$SSH_AUTH_SOCK` now.
///
/// # Errors
/// If neither is set.
pub fn agent_socket(configured: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = configured {
        return Ok(path.to_owned());
    }
    match std::env::var_os(SSH_AUTH_SOCK) {
        Some(path) if !path.is_empty() => Ok(PathBuf::from(path)),
        _ => bail!(
            "no ssh-agent: set {SSH_AUTH_SOCK}, or log in again with --ssh-agent-socket <path>"
        ),
    }
}

/// The current time in Unix seconds.
fn unix_now() -> Result<i64> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("the system clock is before 1970")?
        .as_secs();
    i64::try_from(secs).context("the system clock is out of range")
}

/// Signs requests as one agent, for one broker, with one key in an
/// `ssh-agent`. Holds nothing secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Signer {
    agent: AgentName,
    audience: Audience,
    key: PublicKey,
    socket: PathBuf,
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field("agent", &self.agent.as_str())
            .field("audience", &self.audience.as_str())
            .field("key", &self.fingerprint())
            .field("socket", &self.socket)
            .finish()
    }
}

/// The four `Warden-*` headers of one signed request.
pub type SignedHeaders = [(&'static str, String); 4];

impl Signer {
    /// A signer for `agent` at the broker with `audience`, using `key`
    /// through the `ssh-agent` at `socket`.
    #[must_use]
    pub const fn new(
        agent: AgentName,
        audience: Audience,
        key: PublicKey,
        socket: PathBuf,
    ) -> Self {
        Self {
            agent,
            audience,
            key,
            socket,
        }
    }

    /// The pinned audience.
    #[must_use]
    pub const fn audience(&self) -> &Audience {
        &self.audience
    }

    /// The signing key's `SHA256:…` fingerprint, as `ssh-keygen -lf` shows.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.key.fingerprint(HashAlg::Sha256).to_string()
    }

    /// Where the `ssh-agent` is, for messages.
    fn agent_place(&self) -> String {
        format!("the ssh-agent at {}", self.socket.display())
    }

    async fn connect(&self) -> Result<ssh_agent_lib::client::Client<tokio::net::UnixStream>> {
        let stream = tokio::net::UnixStream::connect(&self.socket)
            .await
            .with_context(|| format!("cannot connect to {}", self.agent_place()))?;
        Ok(ssh_agent_lib::client::Client::new(stream))
    }

    /// Check that the `ssh-agent` holds the signing key.
    ///
    /// # Errors
    /// If the agent cannot be reached or does not list the key.
    pub async fn check_key_loaded(&self) -> Result<()> {
        let listed = tokio::time::timeout(AGENT_TIMEOUT, async {
            self.connect()
                .await?
                .request_identities()
                .await
                .map_err(|e| anyhow!("{} cannot list its keys: {e}", self.agent_place()))
        })
        .await
        .map_err(|_| anyhow!("{} did not answer", self.agent_place()))??;
        let wanted = PublicCredential::Key(self.key.key_data().clone());
        ensure!(
            listed.iter().any(|id| id.credential == wanted),
            "{} does not hold the key {}; add it (ssh-add -L lists what it holds)",
            self.agent_place(),
            self.fingerprint()
        );
        Ok(())
    }

    /// The headers for a request `method target` with `body` (empty for
    /// none), signed now with a fresh nonce.
    ///
    /// # Errors
    /// If the method or target cannot be signed or the agent does not sign.
    pub async fn sign_request(
        &self,
        method: &str,
        target: &str,
        body: &[u8],
    ) -> Result<SignedHeaders> {
        self.sign_request_at(method, target, body, unix_now()?, &Nonce::random())
            .await
    }

    async fn sign_request_at(
        &self,
        method: &str,
        target: &str,
        body: &[u8],
        timestamp: i64,
        nonce: &Nonce,
    ) -> Result<SignedHeaders> {
        let message = canonical_message(&SignedRequestParts {
            audience: &self.audience,
            agent: &self.agent,
            method,
            target,
            timestamp,
            nonce,
            body_sha256: Sha256::digest(body).into(),
        })
        .map_err(|e| anyhow!("cannot sign {method} {target}: {e}"))?;
        let signature = self.sign(message.as_bytes()).await?;
        Ok([
            (AGENT_HEADER, self.agent.as_str().to_owned()),
            (TIMESTAMP_HEADER, timestamp.to_string()),
            (NONCE_HEADER, nonce.as_str().to_owned()),
            (SIGNATURE_HEADER, signature),
        ])
    }

    /// `Warden-Signature` for `message`: the agent signs the SSHSIG
    /// preimage, and its signature is wrapped into the SSHSIG blob.
    async fn sign(&self, message: &[u8]) -> Result<String> {
        let preimage = SshSig::signed_data(NAMESPACE, HASH_ALG, message)
            .context("cannot build the SSHSIG preimage")?;
        let request = SignRequest {
            credential: PublicCredential::Key(self.key.key_data().clone()),
            data: preimage,
            flags: 0,
        };
        let refused = |e: &dyn fmt::Display| {
            anyhow!(
                "{} refused to sign with the key {} ({e}); check that it holds the key \
                 (ssh-add -L) and that the key needs no touch, PIN or confirmation per signature",
                self.agent_place(),
                self.fingerprint()
            )
        };
        let signature = tokio::time::timeout(AGENT_TIMEOUT, async {
            self.connect()
                .await?
                .sign(request)
                .await
                .map_err(|e| refused(&e))
        })
        .await
        .map_err(|_| {
            anyhow!(
                "{} did not sign with the key {} within {} s; a key that waits for a touch, \
                 PIN or confirmation cannot sign requests unattended",
                self.agent_place(),
                self.fingerprint(),
                AGENT_TIMEOUT.as_secs()
            )
        })??;
        // An Ed25519 key yields an `ssh-ed25519` signature, a P-256 key an
        // `ecdsa-sha2-nistp256` one (mpint r, mpint s): the agent's
        // signature goes into the blob as is.
        ensure!(
            signature.algorithm() == self.key.algorithm(),
            "{} answered with a {} signature for the {} key {}",
            self.agent_place(),
            signature.algorithm(),
            self.key.algorithm(),
            self.fingerprint()
        );
        let sshsig = SshSig::new(self.key.key_data().clone(), NAMESPACE, HASH_ALG, signature)
            .context("cannot build the SSHSIG")?;
        let mut blob = Vec::new();
        sshsig
            .encode(&mut blob)
            .context("cannot encode the SSHSIG")?;
        Ok(STANDARD.encode(blob))
    }
}

/// A real `ssh-agent` for the tests of this crate.
#[cfg(test)]
pub mod testing {
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use ssh_agent_lib::agent::Session as _;
    use ssh_agent_lib::proto::{AddIdentity, PrivateCredential};
    use ssh_key::PrivateKey;

    /// A throwaway `ssh-agent` in a private directory, killed on drop.
    pub struct TestAgent {
        child: Child,
        /// The agent's socket.
        pub socket: PathBuf,
        _dir: tempfile::TempDir,
    }

    impl Drop for TestAgent {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl TestAgent {
        /// Start one.
        pub fn start() -> Self {
            let dir = tempfile::Builder::new()
                .prefix("wdns")
                .tempdir_in("/tmp")
                .unwrap();
            let socket = dir.path().join("agent.sock");
            let child = Command::new("ssh-agent")
                .arg("-D")
                .arg("-a")
                .arg(&socket)
                .env_remove("SSH_AUTH_SOCK")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("ssh-agent (OpenSSH) is needed for this test");
            let deadline = Instant::now() + Duration::from_secs(10);
            while std::os::unix::net::UnixStream::connect(&socket).is_err() {
                assert!(Instant::now() < deadline, "ssh-agent did not start");
                std::thread::sleep(Duration::from_millis(20));
            }
            Self {
                child,
                socket,
                _dir: dir,
            }
        }

        /// Load `key` into the agent over its socket (no file on disk).
        pub async fn add(&self, key: &PrivateKey) {
            let stream = tokio::net::UnixStream::connect(&self.socket).await.unwrap();
            let mut client = ssh_agent_lib::client::Client::new(stream);
            client
                .add_identity(AddIdentity {
                    credential: PrivateCredential::Key {
                        privkey: key.key_data().clone(),
                        comment: "warden test".to_owned(),
                    },
                })
                .await
                .unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use sha2::{Digest as _, Sha256};
    use ssh_encoding::Decode as _;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, SshSig};
    use warden_broker_proto::signing::{
        Audience, NAMESPACE, Nonce, PUBLISHED_TEST_KEYS, SignedRequestParts, canonical_message,
    };

    use super::testing::TestAgent;
    use super::{Signer, agent_socket, parse_signing_key, read_signing_key};

    fn audience() -> Audience {
        Audience::try_from("40ad20029e94984d193159667b296d8a".to_owned()).unwrap()
    }

    fn signer(key: &PrivateKey, socket: &Path) -> Signer {
        Signer::new(
            "build-bot".parse().unwrap(),
            audience(),
            parse_signing_key(&key.public_key().to_openssh().unwrap()).unwrap(),
            socket.to_owned(),
        )
    }

    /// Verify `header` as the broker does: an SSHSIG in the protocol's
    /// namespace with sha512, by exactly `key`, over `message`.
    fn verify(key: &PrivateKey, header: &str, message: &str) {
        let blob = STANDARD.decode(header).unwrap();
        let mut reader = blob.as_slice();
        let sig = SshSig::decode(&mut reader).unwrap();
        assert!(reader.is_empty(), "trailing bytes");
        assert_eq!(sig.version(), 1);
        assert_eq!(sig.namespace(), NAMESPACE);
        assert!(sig.reserved().is_empty());
        assert_eq!(sig.hash_alg(), HashAlg::Sha512);
        assert_eq!(sig.public_key(), key.public_key().key_data());
        key.public_key()
            .verify(NAMESPACE, message.as_bytes(), &sig)
            .unwrap();
        assert!(
            key.public_key()
                .verify(NAMESPACE, b"another message", &sig)
                .is_err()
        );
    }

    /// Verify `header` with OpenSSH's own `ssh-keygen -Y verify`.
    fn verify_with_ssh_keygen(key: &PrivateKey, header: &str, message: &str) {
        let dir = tempfile::tempdir().unwrap();
        let lines: Vec<&str> = header
            .as_bytes()
            .chunks(70)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let armored = format!(
            "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
            lines.join("\n")
        );
        std::fs::write(dir.path().join("message.sig"), armored).unwrap();
        std::fs::write(
            dir.path().join("allowed_signers"),
            format!("build-bot {}\n", key.public_key().to_openssh().unwrap()),
        )
        .unwrap();
        let mut child = Command::new("ssh-keygen")
            .args(["-Y", "verify", "-f"])
            .arg(dir.path().join("allowed_signers"))
            .args(["-I", "build-bot", "-n", NAMESPACE, "-s"])
            .arg(dir.path().join("message.sig"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), message.as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "ssh-keygen -Y verify: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The CLI signs through a real `ssh-agent`, with an Ed25519 and an
    /// ECDSA P-256 key, and the result verifies as the broker and OpenSSH
    /// check it.
    #[tokio::test]
    async fn sshsig_from_agent_verifies() {
        let agent = TestAgent::start();
        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        ] {
            let key = PrivateKey::random(&mut OsRng, algorithm.clone()).unwrap();
            agent.add(&key).await;
            let signer = signer(&key, &agent.socket);
            signer.check_key_loaded().await.unwrap();

            let body = br#"{"goal":"x"}"#;
            let nonce = Nonce::random();
            let headers = signer
                .sign_request_at("POST", "/v1/requests?x=%2F", body, 1_793_091_600, &nonce)
                .await
                .unwrap();
            let names: Vec<&str> = headers.iter().map(|(n, _)| *n).collect();
            assert_eq!(
                names,
                [
                    "Warden-Agent",
                    "Warden-Timestamp",
                    "Warden-Nonce",
                    "Warden-Signature"
                ]
            );
            assert_eq!(headers[0].1, "build-bot");
            assert_eq!(headers[1].1, "1793091600");
            assert_eq!(headers[2].1, nonce.as_str());
            let message = canonical_message(&SignedRequestParts {
                audience: &audience(),
                agent: &"build-bot".parse().unwrap(),
                method: "POST",
                target: "/v1/requests?x=%2F",
                timestamp: 1_793_091_600,
                nonce: &nonce,
                body_sha256: Sha256::digest(body).into(),
            })
            .unwrap();
            verify(&key, &headers[3].1, &message);
            verify_with_ssh_keygen(&key, &headers[3].1, &message);
            assert!(!headers[3].1.contains('\n'), "{algorithm}");
        }
    }

    /// Every request is signed with a fresh nonce and its own signature.
    #[tokio::test]
    async fn each_request_gets_a_fresh_nonce() {
        let agent = TestAgent::start();
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        agent.add(&key).await;
        let signer = signer(&key, &agent.socket);
        let a = signer.sign_request("GET", "/v1/grants", b"").await.unwrap();
        let b = signer.sign_request("GET", "/v1/grants", b"").await.unwrap();
        assert_ne!(a[2].1, b[2].1);
        assert_ne!(a[3].1, b[3].1);
        assert!(Nonce::try_from(a[2].1.clone()).is_ok());
    }

    /// A key the agent does not hold: a clear error naming the socket and
    /// the key's fingerprint.
    #[tokio::test]
    async fn agent_without_the_key_is_named_in_the_error() {
        let agent = TestAgent::start();
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let signer = signer(&key, &agent.socket);
        let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let socket = agent.socket.display().to_string();
        for err in [
            signer.check_key_loaded().await.unwrap_err(),
            signer
                .sign_request("GET", "/v1/grants", b"")
                .await
                .unwrap_err(),
        ] {
            let err = format!("{err:#}");
            assert!(err.contains(&socket), "{err}");
            assert!(err.contains(&fingerprint), "{err}");
        }

        let gone = signer_at_missing_socket(&key);
        let err = format!(
            "{:#}",
            gone.sign_request("GET", "/v1/grants", b"")
                .await
                .unwrap_err()
        );
        assert!(
            err.contains("cannot connect to the ssh-agent at /nonexistent"),
            "{err}"
        );
    }

    fn signer_at_missing_socket(key: &PrivateKey) -> Signer {
        signer(key, Path::new("/nonexistent/agent.sock"))
    }

    #[test]
    fn signing_key_types() {
        let ed = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let line = format!("{} me@host\n", ed.public_key().to_openssh().unwrap());
        let parsed = parse_signing_key(&line).unwrap();
        assert_eq!(parsed.comment(), "");
        assert_eq!(parsed.key_data(), ed.public_key().key_data());
        let p256 = PrivateKey::random(
            &mut OsRng,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        )
        .unwrap();
        assert!(parse_signing_key(&p256.public_key().to_openssh().unwrap()).is_ok());

        for (line, why) in [
            ("", "not an OpenSSH public key"),
            ("ssh-ed25519", "not an OpenSSH public key"),
            // Named by its written type, as the broker does.
            (
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ",
                "unsupported key type ssh-rsa",
            ),
            ("sk-ssh-ed25519@openssh.com AAAA", "security keys"),
            ("sk-ecdsa-sha2-nistp256@openssh.com AAAA", "security keys"),
            ("ssh-ed25519-cert-v01@openssh.com AAAA", "certificates"),
        ] {
            let err = parse_signing_key(line).unwrap_err().to_string();
            assert!(err.contains(why), "{line:?}: {err}");
        }
        let two_lines = format!("{line}{line}");
        assert!(parse_signing_key(&two_lines).is_err());
        for published in PUBLISHED_TEST_KEYS {
            let err = parse_signing_key(&format!("{published} comment"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("published test key"), "{err}");
        }
    }

    /// RSA and other ECDSA curves, made by OpenSSH itself.
    #[test]
    fn other_key_types_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        for (kind, bits, name) in [
            ("rsa", "2048", "ssh-rsa"),
            ("ecdsa", "384", "ecdsa-sha2-nistp384"),
        ] {
            let path = dir.path().join(kind);
            let status = Command::new("ssh-keygen")
                .args(["-q", "-t", kind, "-b", bits, "-N", "", "-f"])
                .arg(&path)
                .stdout(Stdio::null())
                .status()
                .unwrap();
            assert!(status.success());
            let err = format!(
                "{:#}",
                read_signing_key(&path.with_extension("pub")).unwrap_err()
            );
            assert!(
                err.contains("unsupported key type") && err.contains(name),
                "{err}"
            );
            // The private key file is refused without being echoed.
            let err = format!("{:#}", read_signing_key(&path).unwrap_err());
            assert!(err.contains("holds a private key"), "{err}");
            assert!(!err.contains("BEGIN"), "{err}");
        }
    }

    #[test]
    fn public_key_file_is_read_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let path = dir.path().join("k.pub");
        std::fs::write(
            &path,
            format!("{} c\n", key.public_key().to_openssh().unwrap()),
        )
        .unwrap();
        assert_eq!(
            read_signing_key(&path).unwrap().key_data(),
            key.public_key().key_data()
        );
        std::fs::write(&path, "a".repeat(20_000)).unwrap();
        let err = read_signing_key(&path).unwrap_err().to_string();
        assert!(err.contains("too large"), "{err}");
        assert!(read_signing_key(&dir.path().join("missing.pub")).is_err());
    }

    #[test]
    fn configured_socket_wins() {
        assert_eq!(
            agent_socket(Some(Path::new("/run/agent.sock"))).unwrap(),
            PathBuf::from("/run/agent.sock")
        );
    }

    #[test]
    fn debug_shows_the_fingerprint_not_the_key() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let shown = format!("{:?}", signer(&key, Path::new("/s")));
        assert!(shown.contains("SHA256:"), "{shown}");
    }
}
