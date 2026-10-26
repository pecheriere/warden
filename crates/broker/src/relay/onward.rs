//! The relay's SSH client: connects to a relay target, checks its host key
//! against the pinned ones before anything else, logs in with the target
//! item's credential and opens one session channel. It never requests
//! forwarding and refuses every channel the target tries to open.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use russh::client::{self, AuthResult};
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg, Disconnect};
use warden_broker_proto::UnixUser;

use crate::policy::{RelayCredential, SshTarget};

use super::session::{Cutoff, Program, PtyRequest, with_cutoff};

/// Why the onward connection failed. Messages are fixed: they never carry
/// the credential or anything the target sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum OnwardError {
    /// The target's host key is not one of the pinned `host_keys`, or it
    /// has no host key of a pinned key's type.
    #[error("the target's host key does not match its pinned host keys")]
    HostKeyMismatch,
    /// No pinned host key is of a type the relay can verify.
    #[error("no pinned host key is of a supported type")]
    UnsupportedHostKeys,
    /// The target could not be reached or the SSH handshake failed.
    #[error("the target could not be reached")]
    Unreachable,
    /// The target refused the credential.
    #[error("the target refused the relay's login")]
    LoginRefused,
    /// The credential could not be used (not a valid key).
    #[error("the target's credential cannot be used")]
    BadCredential,
    /// The target did not open the session or refused its pty or command.
    #[error("the target refused the session")]
    SessionRefused,
    /// The target sent more than [`MAX_EARLY_BYTES`] (or
    /// [`MAX_EARLY_MESSAGES`] messages) before accepting the session.
    #[error("the target sent too much before accepting the session")]
    TooMuchEarlyOutput,
}

impl OnwardError {
    /// The `reason` recorded in `relay_session_ended`.
    #[must_use]
    pub(crate) const fn audit_reason(self) -> &'static str {
        match self {
            Self::HostKeyMismatch => "host key mismatch",
            Self::UnsupportedHostKeys => "no supported pinned host key",
            Self::Unreachable => "target unreachable",
            Self::LoginRefused => "onward login refused",
            Self::BadCredential => "credential unusable",
            Self::SessionRefused => "target refused the session",
            Self::TooMuchEarlyOutput => "target output before the start too large",
        }
    }

    /// What the agent is told.
    #[must_use]
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::HostKeyMismatch => {
                "warden relay: the target's host key does not match its pinned host keys; not logging in"
            }
            Self::UnsupportedHostKeys => {
                "warden relay: none of the target's pinned host keys is of a supported type"
            }
            Self::Unreachable => "warden relay: the target could not be reached",
            Self::LoginRefused => "warden relay: the target refused the relay's login",
            Self::BadCredential => "warden relay: the target's credential cannot be used",
            Self::SessionRefused | Self::TooMuchEarlyOutput => {
                "warden relay: the target refused the session"
            }
        }
    }
}

/// Accepts only a pinned host key, and refuses every channel the target
/// opens (forwarded ports, agent, X11, sessions).
struct OnwardHandler {
    pinned: Vec<ssh_key::PublicKey>,
    mismatch: Arc<AtomicBool>,
}

/// `key` (russh's ssh-key) as warden's ssh-key type, via its OpenSSH text.
fn ours(key: &russh::keys::PublicKey) -> Option<ssh_key::PublicKey> {
    let text = key.to_openssh().ok()?;
    ssh_key::PublicKey::from_openssh(&text).ok()
}

impl client::Handler for OnwardHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // Pinned keys only: a host certificate is not trusted here.
        let trusted = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => ours(key).is_some_and(|key| {
                self.pinned
                    .iter()
                    .any(|pinned| pinned.key_data() == key.key_data())
            }),
            PublicKeyOrCertificate::Certificate(_) => false,
        };
        if !trusted {
            self.mismatch.store(true, Ordering::SeqCst);
        }
        Ok(trusted)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<client::Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        // Dropping the reply refuses the channel.
        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: Channel<client::Msg>,
        _socket_path: &str,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        _channel: Channel<client::Msg>,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn server_channel_open_session(
        &mut self,
        _channel: Channel<client::Msg>,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<client::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<client::Msg>,
        _socket_path: &str,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        _channel: Channel<client::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        _reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// The host key algorithms to negotiate with a target: those of its pinned
/// keys, in pinned order, each once, so the target proves the key that is
/// pinned (a target with several host keys would otherwise be asked for
/// the relay's favourite one). RSA keys are asked for as `rsa-sha2-512` then
/// `rsa-sha2-256`, never SHA-1 `ssh-rsa`. (russh 0.64 does not check that
/// the target's signature uses the negotiated hash, so a holder of the
/// pinned key could still sign with SHA-1; the key itself is pinned.) Key
/// types the relay cannot
/// verify (DSA, security keys) are left out.
#[must_use]
fn host_key_algorithms(pinned: &[ssh_key::PublicKey]) -> Vec<russh::keys::Algorithm> {
    use russh::keys::{Algorithm, EcdsaCurve, HashAlg};
    let mut algorithms = Vec::new();
    for key in pinned {
        let wanted: &[Algorithm] = match key.algorithm() {
            ssh_key::Algorithm::Ed25519 => &[Algorithm::Ed25519],
            ssh_key::Algorithm::Ecdsa { curve } => match curve {
                ssh_key::EcdsaCurve::NistP256 => &[Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP256,
                }],
                ssh_key::EcdsaCurve::NistP384 => &[Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP384,
                }],
                ssh_key::EcdsaCurve::NistP521 => &[Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP521,
                }],
            },
            ssh_key::Algorithm::Rsa { .. } => &[
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                },
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                },
            ],
            _ => &[],
        };
        for algorithm in wanted {
            if !algorithms.contains(algorithm) {
                algorithms.push(algorithm.clone());
            }
        }
    }
    algorithms
}

/// A logged-in connection to the target with its session channel open.
pub(crate) struct Onward {
    handle: client::Handle<OnwardHandler>,
    channel: Channel<client::Msg>,
    cut: Arc<Cutoff>,
}

/// Connect to `target`, verify its host key, and log in as `user` with
/// `credential`. Each step (connecting and the handshake, logging in,
/// opening the channel) must finish within `timeout`. The credential is
/// sent only after the host key matched, and dropped (wiped) on return.
pub(crate) async fn connect(
    target: &SshTarget,
    user: &UnixUser,
    credential: RelayCredential,
    timeout: Duration,
) -> Result<Onward, OnwardError> {
    let host_key_algorithms = host_key_algorithms(&target.host_keys);
    if host_key_algorithms.is_empty() {
        return Err(OnwardError::UnsupportedHostKeys);
    }
    let mismatch = Arc::new(AtomicBool::new(false));
    let handler = OnwardHandler {
        pinned: target.host_keys.clone(),
        mismatch: Arc::clone(&mismatch),
    };
    let config = Arc::new(client::Config {
        // Keepalives detect a target that vanished; the session itself has
        // no inactivity limit here (the relay applies its own).
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        preferred: russh::Preferred {
            key: host_key_algorithms.into(),
            ..russh::Preferred::default()
        },
        ..client::Config::default()
    });
    let connected = tokio::time::timeout(timeout, async {
        let socket = tokio::net::TcpStream::connect((target.host.as_str(), target.port))
            .await
            .map_err(|_| OnwardError::Unreachable)?;
        // Small writes (keystrokes) go out at once.
        socket
            .set_nodelay(true)
            .map_err(|_| OnwardError::Unreachable)?;
        let (socket, cut) = with_cutoff(socket).map_err(|_| OnwardError::Unreachable)?;
        Ok::<_, OnwardError>((client::connect_stream(config, socket, handler).await, cut))
    })
    .await;
    let (mut handle, cut) = match connected {
        Ok(Ok((Ok(handle), cut))) => (handle, Arc::new(cut)),
        // The handshake fails when the target has no host key of a pinned
        // type, or when its host key is refused: say so.
        Ok(Ok((
            Err(russh::Error::NoCommonAlgo {
                kind: russh::AlgorithmKind::Key,
                ..
            }),
            _,
        ))) => return Err(OnwardError::HostKeyMismatch),
        Ok(Ok((Err(_), _))) | Err(_) if mismatch.load(Ordering::SeqCst) => {
            return Err(OnwardError::HostKeyMismatch);
        }
        Ok(Err(e)) => return Err(e),
        Ok(Ok((Err(_), _))) | Err(_) => return Err(OnwardError::Unreachable),
    };
    let login = tokio::time::timeout(timeout, async {
        match &credential {
            RelayCredential::Key(text) => {
                let key = russh::keys::PrivateKey::from_openssh(text.as_str())
                    .map_err(|_| OnwardError::BadCredential)?;
                handle
                    .authenticate_publickey(
                        user.as_str(),
                        PrivateKeyWithHashAlg::new(Arc::new(key), None),
                    )
                    .await
                    .map_err(|_| OnwardError::Unreachable)
            }
            RelayCredential::Password(password) => handle
                .authenticate_password(user.as_str(), password.as_str())
                .await
                .map_err(|_| OnwardError::Unreachable),
        }
    })
    .await;
    drop(credential);
    match login {
        Ok(Ok(AuthResult::Success)) => {}
        Ok(Ok(AuthResult::Failure { .. })) => {
            hang_up(&handle).await;
            return Err(OnwardError::LoginRefused);
        }
        Ok(Err(e)) => {
            hang_up(&handle).await;
            return Err(e);
        }
        Err(_) => {
            hang_up(&handle).await;
            return Err(OnwardError::Unreachable);
        }
    }
    let Ok(Ok(channel)) = tokio::time::timeout(timeout, handle.channel_open_session()).await else {
        hang_up(&handle).await;
        return Err(OnwardError::SessionRefused);
    };
    Ok(Onward {
        handle,
        channel,
        cut,
    })
}

/// Longest wait for the target to take the relay's goodbye.
const GOODBYE_WAIT: Duration = Duration::from_secs(2);

async fn hang_up(handle: &client::Handle<OnwardHandler>) {
    // The connection is dropped (or cut) right after; a failed or slow
    // goodbye changes nothing.
    let _ = tokio::time::timeout(
        GOODBYE_WAIT,
        handle.disconnect(Disconnect::ByApplication, "", "en"),
    )
    .await;
}

impl Onward {
    /// Ask for the pty (if any), pass the environment, then start
    /// `program`, waiting for the target to accept each request that needs
    /// an answer. Returns the channel and whatever the target sent meanwhile.
    pub(crate) async fn start(
        mut self,
        pty: Option<&PtyRequest>,
        env: &[(String, String)],
        program: &Program,
        timeout: Duration,
    ) -> Result<Started, OnwardError> {
        let mut early = Early::default();
        let started = tokio::time::timeout(timeout, async {
            if let Some(pty) = pty {
                self.channel
                    .request_pty(
                        true,
                        &pty.term,
                        pty.cols,
                        pty.rows,
                        pty.pix_width,
                        pty.pix_height,
                        &pty.modes,
                    )
                    .await
                    .map_err(|_| OnwardError::SessionRefused)?;
                answer(&mut self.channel, &mut early).await.ok()?;
            }
            for (name, value) in env {
                // No reply wanted: a target that ignores a variable still
                // runs the session, as with OpenSSH's SendEnv.
                self.channel
                    .set_env(false, name.as_str(), value.as_str())
                    .await
                    .map_err(|_| OnwardError::SessionRefused)?;
            }
            match program {
                Program::Shell => self.channel.request_shell(true).await,
                Program::Exec(command) => self.channel.exec(true, command.clone()).await,
            }
            .map_err(|_| OnwardError::SessionRefused)?;
            answer(&mut self.channel, &mut early).await.ok()
        })
        .await;
        match started {
            Ok(Ok(())) => Ok(Started {
                handle: self.handle,
                channel: self.channel,
                cut: self.cut,
                early: early.messages,
            }),
            Ok(Err(e)) => {
                hang_up(&self.handle).await;
                Err(e)
            }
            Err(_) => {
                hang_up(&self.handle).await;
                Err(OnwardError::SessionRefused)
            }
        }
    }
}

/// Most bytes kept from what the target sends before it accepts the
/// session (relayed once it starts).
const MAX_EARLY_BYTES: usize = 1024 * 1024;
/// Most messages kept likewise.
const MAX_EARLY_MESSAGES: usize = 1024;

/// Where replies come from: the target's channel (or, in tests, a list).
trait Inbox {
    fn next(&mut self) -> impl Future<Output = Option<ChannelMsg>> + Send;
}

impl Inbox for Channel<client::Msg> {
    fn next(&mut self) -> impl Future<Output = Option<ChannelMsg>> + Send {
        self.wait()
    }
}

/// What the target sent before it accepted the session, in order.
#[derive(Default)]
struct Early {
    messages: VecDeque<ChannelMsg>,
    bytes: usize,
}

/// The answer to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Accepted,
    Refused,
    /// The target sent too much before answering.
    Flooded,
}

/// Wait for the answer to the last request, keeping anything else that
/// arrives meanwhile in `early`, within its limits.
async fn answer(inbox: &mut impl Inbox, early: &mut Early) -> Answer {
    loop {
        let msg = match inbox.next().await {
            Some(ChannelMsg::Success) => return Answer::Accepted,
            Some(ChannelMsg::Failure | ChannelMsg::Close) | None => return Answer::Refused,
            Some(ChannelMsg::WindowAdjusted { .. }) => continue,
            Some(other) => other,
        };
        if let ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } = &msg {
            early.bytes = early.bytes.saturating_add(data.len());
        }
        early.messages.push_back(msg);
        if early.bytes > MAX_EARLY_BYTES || early.messages.len() > MAX_EARLY_MESSAGES {
            return Answer::Flooded;
        }
    }
}

impl Answer {
    fn ok(self) -> Result<(), OnwardError> {
        match self {
            Self::Accepted => Ok(()),
            Self::Refused => Err(OnwardError::SessionRefused),
            Self::Flooded => Err(OnwardError::TooMuchEarlyOutput),
        }
    }
}

/// A session running on the target.
pub(crate) struct Started {
    handle: client::Handle<OnwardHandler>,
    cut: Arc<Cutoff>,
    /// Its channel.
    pub channel: Channel<client::Msg>,
    /// What the target sent before it accepted the command.
    pub early: VecDeque<ChannelMsg>,
}

impl Started {
    /// Split into the channel, the early messages, the connection's
    /// cutoff, and something that hangs up when the session is over.
    pub(crate) fn into_parts(
        self,
    ) -> (
        Channel<client::Msg>,
        VecDeque<ChannelMsg>,
        Arc<Cutoff>,
        HangUp,
    ) {
        let cut = Arc::clone(&self.cut);
        (
            self.channel,
            self.early,
            cut,
            HangUp {
                handle: self.handle,
                cut: self.cut,
            },
        )
    }
}

/// Hangs up on the target.
pub(crate) struct HangUp {
    handle: client::Handle<OnwardHandler>,
    cut: Arc<Cutoff>,
}

impl HangUp {
    /// Say goodbye to the target (waiting at most 2 s), then cut the
    /// connection, so it ends whatever state the SSH library is in.
    pub(crate) async fn now(self) {
        hang_up(&self.handle).await;
        self.cut.now();
    }
}

#[cfg(test)]
mod tests {
    use russh::keys::{Algorithm, EcdsaCurve, HashAlg};
    use ssh_key::rand_core::OsRng;
    use ssh_key::{PrivateKey, PublicKey};

    use std::collections::VecDeque;

    use russh::ChannelMsg;

    use super::{Answer, Early, Inbox, MAX_EARLY_BYTES, answer, host_key_algorithms};

    impl Inbox for VecDeque<ChannelMsg> {
        fn next(&mut self) -> impl Future<Output = Option<ChannelMsg>> + Send {
            std::future::ready(self.pop_front())
        }
    }

    fn data(len: usize) -> ChannelMsg {
        ChannelMsg::Data {
            data: vec![b'x'; len].into(),
        }
    }

    #[tokio::test]
    async fn early_output_kept_in_order_until_the_answer() {
        let mut inbox: VecDeque<_> = [
            data(3),
            ChannelMsg::WindowAdjusted { new_size: 1 },
            ChannelMsg::ExtendedData {
                data: b"err".to_vec().into(),
                ext: 1,
            },
            ChannelMsg::Success,
            data(1),
        ]
        .into();
        let mut early = Early::default();
        assert_eq!(answer(&mut inbox, &mut early).await, Answer::Accepted);
        assert_eq!(early.messages.len(), 2);
        assert_eq!(early.bytes, 6);
        // What follows the answer is left for the relay loop.
        assert_eq!(inbox.len(), 1);
    }

    #[tokio::test]
    async fn refusal_or_close_is_refused() {
        for end in [Some(ChannelMsg::Failure), Some(ChannelMsg::Close), None] {
            let mut inbox: VecDeque<_> = end.into_iter().collect();
            let mut early = Early::default();
            assert_eq!(answer(&mut inbox, &mut early).await, Answer::Refused);
        }
    }

    #[tokio::test]
    async fn early_output_over_1_mib_is_refused() {
        let mut inbox: VecDeque<_> = [data(MAX_EARLY_BYTES), data(1), ChannelMsg::Success].into();
        let mut early = Early::default();
        assert_eq!(answer(&mut inbox, &mut early).await, Answer::Flooded);
        // Exactly the limit is fine.
        let mut inbox: VecDeque<_> = [data(MAX_EARLY_BYTES), ChannelMsg::Success].into();
        let mut early = Early::default();
        assert_eq!(answer(&mut inbox, &mut early).await, Answer::Accepted);
        // Too many small messages are refused too.
        let mut inbox: VecDeque<_> = (0..2000).map(|_| ChannelMsg::Eof).collect();
        inbox.push_back(ChannelMsg::Success);
        let mut early = Early::default();
        assert_eq!(answer(&mut inbox, &mut early).await, Answer::Flooded);
    }

    /// Throwaway public keys (no private half kept anywhere).
    const RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDA6d7iYsofloqjKz4ox1b4HIcLqlCM530gGr9MTcxqVlaHWSbpo5esI8Tv1i6RNke2Y4Gj/7yXl+F/1ugR8zp5oGZjDPVdGjvMRPXSFkQwayoBia+Mchu9hB0nWOvDlvZmfKSu4e+192Eva09SqSq8MwWCUJ24pXUl/cvCZBobf/IYhhQakLIRr9TnIIfSbJWYXPbDmj7GbFL7HR86H91VJghKMwZ5WrpzEg9UJPOF6k156K6X/VSETJL6xTdZhHTRHsB4iN3Q0p5Zkc13r6JWyj4MAkJQKkXVsO6D+uHk3GVob78cZgGT1x9R7hMognOTR0g+K8kNg1VFRRb0CJyn";
    const ECDSA_P384: &str = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBB+NXTV1fb5U1a0yh41Fv7iOgZ09RpPKLpaXQCKkqAWmSW/sfae/AfKKF44JPLEFsBeuQDNF5WWRHi4MsTLB8yu3tD7kOABuk+mYyPo9AeXNj9OTI2z09ehgmtlKNjSl9Q==";

    fn ed25519() -> PublicKey {
        PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .clone()
    }

    #[test]
    fn pinned_types_in_pinned_order_once_rsa_as_sha2_only() {
        let rsa = PublicKey::from_openssh(RSA).unwrap();
        let ecdsa = PublicKey::from_openssh(ECDSA_P384).unwrap();
        let pinned = [ecdsa.clone(), rsa.clone(), ed25519(), ecdsa, rsa, ed25519()];
        assert_eq!(
            host_key_algorithms(&pinned),
            [
                Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP384
                },
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512)
                },
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256)
                },
                Algorithm::Ed25519,
            ]
        );
        assert!(
            !host_key_algorithms(&pinned).contains(&Algorithm::Rsa { hash: None }),
            "SHA-1 ssh-rsa is never negotiated"
        );
    }

    #[test]
    fn no_pinned_keys_means_nothing_to_negotiate() {
        assert!(host_key_algorithms(&[]).is_empty());
    }
}
