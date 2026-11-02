//! A small client for the ssh-agent protocol (`draft-ietf-sshm-ssh-agent`),
//! with only the three requests the CLI makes: list keys, sign, and add an
//! Ed25519 key or certificate with a lifetime.
//!
//! It is written here rather than taken from `ssh-agent-lib` because that
//! crate turns on every key type of `ssh-key`, and with them `rsa` 0.9
//! (RUSTSEC-2023-0071) and `crypto-bigint` 0.5 (RUSTSEC-2026-0387), none of
//! which the CLI uses: every RSA or ECDSA signature is made by the agent, in
//! its own process, and this module only carries the bytes.
//!
//! The agent is not trusted to be well behaved: its messages are bounded, and
//! one that cannot be parsed exactly is an error.

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use ssh_encoding::{Decode, Encode, Reader as _};
use ssh_key::certificate::Certificate;
use ssh_key::private::Ed25519Keypair;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, Signature};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use zeroize::Zeroizing;

const AGENT_FAILURE: u8 = 5;
const AGENT_SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const ADD_ID_CONSTRAINED: u8 = 25;
const CONSTRAIN_LIFETIME: u8 = 1;

/// The largest message accepted from an agent, in bytes: OpenSSH's own limit.
const MAX_MESSAGE: usize = 256 * 1024;

/// What an added identity's frame holds besides its certificate: the length,
/// message type, key type, public and private key, comment and constraint.
const ADD_FRAME_OVERHEAD: usize = 512;

/// A key or certificate to add to an agent.
#[derive(Clone, Copy)]
pub enum NewIdentity<'a> {
    /// A plain Ed25519 key.
    Key(&'a Ed25519Keypair),
    /// An Ed25519 key with its certificate.
    Certificate {
        /// The certified key.
        key: &'a Ed25519Keypair,
        /// Its certificate.
        certificate: &'a Certificate,
    },
}

/// One connection to an agent.
pub struct AgentClient<S> {
    stream: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AgentClient<S> {
    /// A client speaking over `stream`.
    pub const fn new(stream: S) -> Self {
        Self { stream }
    }

    /// The encoded public key or certificate of every identity the agent
    /// holds. They stay opaque, so one of a type this client does not know
    /// cannot make the listing fail.
    ///
    /// # Errors
    /// If the agent cannot be reached, refuses, or answers something else.
    pub async fn identities(&mut self) -> Result<Vec<Vec<u8>>> {
        let reply = self
            .round_trip(&frame(REQUEST_IDENTITIES, 0, |_| Ok(()))?)
            .await?;
        let mut body = expect(&reply, IDENTITIES_ANSWER)?;
        let count = u32::decode(&mut body).map_err(|_| malformed())?;
        let mut identities = Vec::new();
        // Each one is read from the bounded message, so `count` cannot make
        // this allocate more than the message holds.
        for _ in 0..count {
            identities.push(Vec::<u8>::decode(&mut body).map_err(|_| malformed())?);
            // The comment is not used, and need not be UTF-8.
            Vec::<u8>::decode(&mut body).map_err(|_| malformed())?;
        }
        ensure!(body.is_finished(), malformed());
        Ok(identities)
    }

    /// Ask the agent to sign `data` with `key`.
    ///
    /// # Errors
    /// If the agent cannot be reached, refuses, or answers something else.
    pub async fn sign(&mut self, key: &KeyData, data: &[u8]) -> Result<Signature> {
        let request = frame(SIGN_REQUEST, data.len() + 1024, |out| {
            key.encode_prefixed(out)?;
            data.encode(out)?;
            0_u32.encode(out)
        })?;
        let reply = self.round_trip(&request).await?;
        let mut body = expect(&reply, SIGN_RESPONSE)?;
        let blob = Vec::<u8>::decode(&mut body).map_err(|_| malformed())?;
        ensure!(body.is_finished(), malformed());
        let mut blob = blob.as_slice();
        let signature = Signature::decode(&mut blob).map_err(|_| malformed())?;
        ensure!(blob.is_finished(), malformed());
        Ok(signature)
    }

    /// Add `identity` to the agent for `lifetime_secs` seconds. The buffer
    /// holding the private key is zeroized.
    ///
    /// # Errors
    /// If the identity cannot be encoded, the agent cannot be reached,
    /// refuses, or answers something else.
    pub async fn add_constrained(
        &mut self,
        identity: NewIdentity<'_>,
        comment: &str,
        lifetime_secs: u32,
    ) -> Result<()> {
        let extra = match identity {
            NewIdentity::Key(_) => 0,
            NewIdentity::Certificate { certificate, .. } => certificate
                .encoded_len()
                .map_err(|e| anyhow!("cannot encode the certificate: {e}"))?,
        };
        let request = frame(ADD_ID_CONSTRAINED, extra + comment.len(), |out| {
            match identity {
                NewIdentity::Key(key) => {
                    Algorithm::Ed25519.as_str().encode(out)?;
                    key.encode(out)?;
                }
                NewIdentity::Certificate { key, certificate } => {
                    Algorithm::Ed25519.to_certificate_type().encode(out)?;
                    certificate.encode_prefixed(out)?;
                    key.encode(out)?;
                }
            }
            comment.encode(out)?;
            CONSTRAIN_LIFETIME.encode(out)?;
            lifetime_secs.encode(out)
        })?;
        let reply = self.round_trip(&request).await?;
        let body = expect(&reply, AGENT_SUCCESS)?;
        ensure!(body.is_empty(), malformed());
        Ok(())
    }

    /// Send one framed request and read the reply's type and body.
    async fn round_trip(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        self.stream
            .write_all(request)
            .await
            .context("cannot write to the agent")?;
        self.stream
            .flush()
            .await
            .context("cannot write to the agent")?;
        let mut length = [0_u8; 4];
        self.stream
            .read_exact(&mut length)
            .await
            .context("cannot read from the agent")?;
        let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| malformed())?;
        ensure!(
            (1..=MAX_MESSAGE).contains(&length),
            "the agent sent a message of {length} bytes"
        );
        let mut reply = vec![0_u8; length];
        self.stream
            .read_exact(&mut reply)
            .await
            .context("cannot read from the agent")?;
        Ok(reply)
    }
}

/// A request: its length, its type, and what `write` encodes. The space for
/// `extra` bytes plus the overhead is reserved first, so that the buffer is
/// not reallocated (leaving a copy behind) once a private key is in it.
fn frame(
    message_type: u8,
    extra: usize,
    write: impl FnOnce(&mut Vec<u8>) -> ssh_encoding::Result<()>,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(extra + ADD_FRAME_OVERHEAD));
    out.extend_from_slice(&[0; 4]);
    out.push(message_type);
    write(&mut out).map_err(|e| anyhow!("cannot encode the request to the agent: {e}"))?;
    let length = u32::try_from(out.len() - 4).context("the request to the agent is too long")?;
    out[..4].copy_from_slice(&length.to_be_bytes());
    Ok(out)
}

/// The body of `reply`, if it is of type `wanted`.
fn expect(reply: &[u8], wanted: u8) -> Result<&[u8]> {
    match reply.split_first() {
        Some((&message_type, body)) if message_type == wanted => Ok(body),
        Some((&AGENT_FAILURE, _)) => bail!("the agent refused"),
        Some((&message_type, _)) => bail!("the agent answered with message type {message_type}"),
        None => Err(malformed()),
    }
}

fn malformed() -> anyhow::Error {
    anyhow!("the agent sent a malformed message")
}

#[cfg(test)]
mod tests {
    use ssh_encoding::Encode as _;
    use ssh_key::certificate::{Builder, CertType};
    use ssh_key::rand_core::OsRng;
    use ssh_key::{HashAlg, PrivateKey};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

    use super::{AgentClient, Algorithm, MAX_MESSAGE, NewIdentity};
    use crate::sign::testing::TestAgent;

    /// An agent that reads one request and answers `reply` as is, and the
    /// client talking to it. The handle returns the request it read.
    fn fake_agent(
        reply: Vec<u8>,
    ) -> (
        AgentClient<tokio::io::DuplexStream>,
        tokio::task::JoinHandle<Vec<u8>>,
    ) {
        let (ours, mut theirs) = duplex(2 * MAX_MESSAGE);
        let agent = tokio::spawn(async move {
            let mut length = [0_u8; 4];
            theirs.read_exact(&mut length).await.unwrap();
            let mut request = vec![0_u8; u32::from_be_bytes(length).try_into().unwrap()];
            theirs.read_exact(&mut request).await.unwrap();
            theirs.write_all(&reply).await.unwrap();
            request
        });
        (AgentClient::new(ours), agent)
    }

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    fn ed25519() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
    }

    fn certificate(key: &PrivateKey) -> ssh_key::Certificate {
        let ca = ed25519();
        let mut builder = Builder::new_with_random_nonce(
            &mut OsRng,
            key.public_key().key_data().clone(),
            1,
            u64::from(u32::MAX),
        )
        .unwrap();
        builder.cert_type(CertType::User).unwrap();
        builder.key_id("test").unwrap();
        builder.valid_principal("deploy").unwrap();
        builder.sign(&ca).unwrap()
    }

    /// Every message the agent could answer with that is not the expected
    /// one, or not exactly it, is an error.
    #[tokio::test]
    async fn unexpected_replies_are_refused() {
        let mut too_long = 1_u32.to_be_bytes().to_vec();
        too_long.extend_from_slice(&[0; 7]);
        for (reply, why) in [
            (framed(&[5]), "refused"),
            (framed(&[6]), "message type 6"),
            (framed(&[12]), "malformed"),
            // Claims one identity and holds none.
            (framed(&[12, 0, 0, 0, 1]), "malformed"),
            // Claims no identity, and has bytes left over.
            (framed(&[12, 0, 0, 0, 0, 9]), "malformed"),
            // An identity count far larger than the message allocates nothing.
            (framed(&[12, 255, 255, 255, 255]), "malformed"),
            (vec![0, 0, 0, 0], "message of 0 bytes"),
            (
                u32::try_from(MAX_MESSAGE + 1)
                    .unwrap()
                    .to_be_bytes()
                    .to_vec(),
                "message of 262145 bytes",
            ),
            (u32::MAX.to_be_bytes().to_vec(), "message of 4294967295"),
        ] {
            let (mut client, _agent) = fake_agent(reply.clone());
            let err = format!("{:#}", client.identities().await.unwrap_err());
            assert!(err.contains(why), "{reply:?}: {err}");
        }
    }

    /// A signature must be one whole signature blob, and nothing more.
    #[tokio::test]
    async fn sign_response_must_be_exact() {
        let key = ed25519();
        let good = key
            .sign("test", HashAlg::Sha512, b"data")
            .unwrap()
            .signature()
            .clone();
        let mut blob = Vec::new();
        good.encode(&mut blob).unwrap();

        let mut reply = vec![14];
        blob.encode(&mut reply).unwrap();
        let (mut client, agent) = fake_agent(framed(&reply));
        let signature = client
            .sign(key.public_key().key_data(), b"data")
            .await
            .unwrap();
        assert_eq!(signature, good);

        // The request: the key blob, the data and flags of zero.
        let mut wanted = vec![13];
        key.public_key()
            .key_data()
            .encode_prefixed(&mut wanted)
            .unwrap();
        b"data".as_slice().encode(&mut wanted).unwrap();
        0_u32.encode(&mut wanted).unwrap();
        assert_eq!(agent.await.unwrap(), wanted);

        let mut bad = Vec::new();
        let mut trailing_inside = blob.clone();
        trailing_inside.push(0);
        let mut inside = vec![14];
        trailing_inside.encode(&mut inside).unwrap();
        bad.push(inside);
        let mut outside = reply.clone();
        outside.push(0);
        bad.push(outside);
        bad.push(vec![14, 0, 0, 0, 1, 0]);
        for reply in bad {
            let (mut client, _agent) = fake_agent(framed(&reply));
            let err = client
                .sign(key.public_key().key_data(), b"data")
                .await
                .unwrap_err();
            assert!(err.to_string().contains("malformed"), "{reply:?}: {err}");
        }
    }

    /// The bytes of an add request, as the protocol specifies them: the
    /// private key is `k || A`, and the lifetime follows the comment.
    #[tokio::test]
    async fn add_request_is_exactly_the_protocol_message() {
        let key = ed25519();
        let keypair = key.key_data().ed25519().unwrap();
        let (mut client, agent) = fake_agent(framed(&[6]));
        client
            .add_constrained(NewIdentity::Key(keypair), "c", 60)
            .await
            .unwrap();
        let mut wanted = vec![25];
        "ssh-ed25519".encode(&mut wanted).unwrap();
        keypair.public.as_ref().encode(&mut wanted).unwrap();
        let mut private = keypair.private.as_ref().to_vec();
        private.extend_from_slice(keypair.public.as_ref());
        private.as_slice().encode(&mut wanted).unwrap();
        "c".encode(&mut wanted).unwrap();
        wanted.push(1);
        wanted.extend_from_slice(&60_u32.to_be_bytes());
        assert_eq!(agent.await.unwrap(), wanted);
    }

    #[tokio::test]
    async fn refused_add_is_an_error() {
        let key = ed25519();
        let keypair = key.key_data().ed25519().unwrap();
        let (mut client, _agent) = fake_agent(framed(&[5]));
        let err = client
            .add_constrained(NewIdentity::Key(keypair), "c", 60)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("refused"), "{err}");
    }

    /// A real `ssh-agent` takes the key and the certificate, lists them, and
    /// signs with the key.
    #[tokio::test]
    async fn real_agent_accepts_keys_and_certificates() {
        let agent = TestAgent::start();
        let connect = || async {
            AgentClient::new(
                tokio::net::UnixStream::connect(&agent.socket)
                    .await
                    .unwrap(),
            )
        };
        assert_eq!(
            connect().await.identities().await.unwrap(),
            [] as [Vec<u8>; 0]
        );

        let key = ed25519();
        let keypair = key.key_data().ed25519().unwrap();
        connect()
            .await
            .add_constrained(NewIdentity::Key(keypair), "warden test", 60)
            .await
            .unwrap();

        let certified = ed25519();
        let cert = certificate(&certified);
        connect()
            .await
            .add_constrained(
                NewIdentity::Certificate {
                    key: certified.key_data().ed25519().unwrap(),
                    certificate: &cert,
                },
                "warden test",
                60,
            )
            .await
            .unwrap();

        let listed = connect().await.identities().await.unwrap();
        let mut key_blob = Vec::new();
        key.public_key().key_data().encode(&mut key_blob).unwrap();
        let mut cert_blob = Vec::new();
        cert.encode(&mut cert_blob).unwrap();
        assert!(listed.contains(&key_blob), "{listed:?}");
        assert!(listed.contains(&cert_blob), "{listed:?}");

        let signature = connect()
            .await
            .sign(key.public_key().key_data(), b"data")
            .await
            .unwrap();
        assert_eq!(signature.algorithm(), Algorithm::Ed25519);

        let unknown = ed25519();
        let err = connect()
            .await
            .sign(unknown.public_key().key_data(), b"data")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("refused"), "{err}");
    }
}
