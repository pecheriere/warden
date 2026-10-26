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

use super::session::{Program, PtyRequest};

/// Why the onward connection failed. Messages are fixed: they never carry
/// the credential or anything the target sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum OnwardError {
    /// The target's host key is not one of the pinned `host_keys`.
    #[error("the target's host key does not match its pinned host keys")]
    HostKeyMismatch,
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
}

impl OnwardError {
    /// The `reason` recorded in `relay_session_ended`.
    #[must_use]
    pub(crate) const fn audit_reason(self) -> &'static str {
        match self {
            Self::HostKeyMismatch => "host key mismatch",
            Self::Unreachable => "target unreachable",
            Self::LoginRefused => "onward login refused",
            Self::BadCredential => "credential unusable",
            Self::SessionRefused => "target refused the session",
        }
    }

    /// What the agent is told.
    #[must_use]
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::HostKeyMismatch => {
                "warden relay: the target's host key does not match its pinned host keys; not logging in"
            }
            Self::Unreachable => "warden relay: the target could not be reached",
            Self::LoginRefused => "warden relay: the target refused the relay's login",
            Self::BadCredential => "warden relay: the target's credential cannot be used",
            Self::SessionRefused => "warden relay: the target refused the session",
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

/// A logged-in connection to the target with its session channel open.
pub(crate) struct Onward {
    handle: client::Handle<OnwardHandler>,
    channel: Channel<client::Msg>,
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
        nodelay: true,
        ..client::Config::default()
    });
    let connected = tokio::time::timeout(
        timeout,
        client::connect(config, (target.host.as_str(), target.port), handler),
    )
    .await;
    let mut handle = match connected {
        Ok(Ok(handle)) => handle,
        // The handshake fails when the host key is refused: say so.
        Ok(Err(_)) | Err(_) if mismatch.load(Ordering::SeqCst) => {
            return Err(OnwardError::HostKeyMismatch);
        }
        Ok(Err(_)) | Err(_) => return Err(OnwardError::Unreachable),
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
    Ok(Onward { handle, channel })
}

async fn hang_up(handle: &client::Handle<OnwardHandler>) {
    // The connection is dropped right after; a failed goodbye changes nothing.
    let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
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
        let mut early = VecDeque::new();
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
                if !accepted(&mut self.channel, &mut early).await {
                    return Err(OnwardError::SessionRefused);
                }
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
            if accepted(&mut self.channel, &mut early).await {
                Ok(())
            } else {
                Err(OnwardError::SessionRefused)
            }
        })
        .await;
        match started {
            Ok(Ok(())) => Ok(Started {
                handle: self.handle,
                channel: self.channel,
                early,
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

/// Wait for the answer to the last request on `channel`, keeping anything
/// else that arrives meanwhile in `early`.
async fn accepted(channel: &mut Channel<client::Msg>, early: &mut VecDeque<ChannelMsg>) -> bool {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return true,
            Some(ChannelMsg::Failure | ChannelMsg::Close) | None => return false,
            Some(ChannelMsg::WindowAdjusted { .. }) => {}
            Some(other) => early.push_back(other),
        }
    }
}

/// A session running on the target.
pub(crate) struct Started {
    handle: client::Handle<OnwardHandler>,
    /// Its channel.
    pub channel: Channel<client::Msg>,
    /// What the target sent before it accepted the command.
    pub early: VecDeque<ChannelMsg>,
}

impl Started {
    /// Split into the channel and early messages, and something that hangs
    /// up when the session is over.
    pub(crate) fn into_parts(self) -> (Channel<client::Msg>, VecDeque<ChannelMsg>, HangUp) {
        (self.channel, self.early, HangUp(self.handle))
    }
}

/// Hangs up on the target.
pub(crate) struct HangUp(client::Handle<OnwardHandler>);

impl HangUp {
    /// Disconnect from the target.
    pub(crate) async fn now(self) {
        hang_up(&self.0).await;
    }
}
