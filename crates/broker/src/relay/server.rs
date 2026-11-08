//! The relay's SSH server: agents log in with the ephemeral public key
//! bound into an approved relay request (user name = target name), and get
//! one session channel relayed to the target.
//!
//! Policy, in order:
//! - Before login: at most [`RelayLimits::max_unauthenticated`] connections
//!   (and [`RelayLimits::max_unauthenticated_per_ip`] per address) may be
//!   logging in at once; each has [`RelayLimits::auth_timeout`] and
//!   [`RelayLimits::max_auth_attempts`] public-key attempts. Only public-key
//!   login exists. An unknown target, a key nobody approved and an inactive
//!   grant are all refused the same way, as is an attempt whose grant
//!   lookup takes longer than [`GRANT_QUERY_TIMEOUT`].
//! - After login: at most [`RelayLimits::max_sessions_per_grant`] sessions
//!   per grant and [`RelayLimits::max_sessions`] overall. A connection that
//!   starts no session within [`RelayLimits::start_timeout`] is hung up, as
//!   is one whose session is over and that the agent does not leave within
//!   [`RelayLimits::stall_timeout`]. A connection takes its place in the
//!   limits from login until it is gone.
//! - One session channel per connection. `pty-req`, `env` (`LANG`, `LC_*`,
//!   `TERM`), `window-change`, `signal`, then `shell` or `exec`. Port
//!   forwarding, agent forwarding, X11 and subsystems (sftp included) are
//!   refused with a message on the session's stderr.
//! - Before the session starts, at most 32 messages or 64 KiB of input are
//!   accepted on it; past that the connection is hung up, on record.
//! - When the session starts, the grant and the target's policy are read
//!   again (one read, with the credential); `relay_session_started` is
//!   written before anything reaches the target; `relay_session_ended`
//!   follows when it ends, also when the relay stops mid-setup. The onward
//!   connection negotiates only the host key types of the pinned keys.
//! - A running session ends, both connections cut within seconds, when its
//!   grant or agent is revoked (told at once by the request service; found
//!   by a check every [`GRANT_CHECK_EVERY`] when another process revoked
//!   it), when the grant's window ends, or after
//!   [`RelayLimits::idle_timeout`] with no bytes either way. When no query
//!   of the state of grants has succeeded for [`FAIL_CLOSED_AFTER`], the
//!   relay fails closed: every session ends and none starts until one does.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use russh::server::{self};
use russh::{MethodKind, MethodSet, SshId};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::audit::AuditLog;
use crate::policy::SecretBackend;
use crate::requests::Requests;

use super::host_key::{HostKeyError, RelayHostKey};
use super::read_ahead::AGENT_WINDOW_BYTES;
use super::session::{self, PreAuthLimiter, SessionSlots};

mod conn;
mod grant_check;
mod handler;
mod start;

use conn::connection;
use grant_check::check_grants_every;
use start::Refusal;

pub(crate) use conn::stopping;

/// Told to an agent whose grant or target changed since it logged in.
const NO_LONGER_VALID: &str = "warden relay: this access is no longer valid";
/// Told to an agent when the policy cannot be read.
const UNAVAILABLE: &str = "warden relay: the target's policy cannot be read right now";
/// Told to an agent when the session task failed unexpectedly.
const INTERNAL: &str = "warden relay: internal error";
/// Told to an agent when `relay_session_started` cannot be written.
const UNRECORDED: &str = "warden relay: the session could not be recorded; not starting it";
/// Exit status of a session the relay could not start (OpenSSH's own
/// status for its errors).
const REFUSED_EXIT_STATUS: u32 = 255;
/// Refusal notices, written to the session's stderr.
const NO_FORWARDING: &str = "warden relay: port forwarding is not allowed";
const NO_SUBSYSTEMS: &str = "warden relay: subsystems (such as sftp) are not allowed";
const NO_X11: &str = "warden relay: X11 forwarding is not allowed";
const NO_AGENT: &str = "warden relay: agent forwarding is not allowed";
const ONE_SESSION: &str = "warden relay: one session per connection";
/// Messages (data or requests) a session may receive before it starts.
const MAX_PRE_START_MESSAGES: usize = 32;
/// Bytes of data a session may receive before it starts.
const MAX_PRE_START_BYTES: usize = 64 * 1024;
/// Told to an agent that sent too much before starting its session.
const TOO_MUCH_INPUT: &str = "warden relay: too much input before the session started";
/// Disconnect messages.
const LOGIN_TIMEOUT: &str = "warden relay: login timed out";
const SHUTTING_DOWN: &str = "warden relay: shutting down";
const NOT_STARTED: &str = "warden relay: no session started in time";
const SESSION_OVER: &str = "warden relay: session over";

/// How often the grants of live sessions are checked for revocation (by
/// another process; this one's are told at once) and expiry.
const GRANT_CHECK_EVERY: Duration = Duration::from_secs(1);

/// How long the grant check may go without a successful query before the
/// relay fails closed: every session ends and none starts until one
/// succeeds.
const FAIL_CLOSED_AFTER: Duration = Duration::from_secs(10);

/// Longest a grant query may take; past it, it counts as failed.
const GRANT_QUERY_TIMEOUT: Duration = Duration::from_millis(1500);

/// Longest read of a relay target's item (policy and credential) when a
/// session starts; past it, the session is refused.
const TARGET_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// A session refused because its grant could not be looked up in time.
const GRANT_LOOKUP_FAILED: Refusal =
    Refusal::new("grant lookup failed", session::reason::GRANT_STATE_NOTICE);

/// A session refused because its target is no longer a relay target.
const NOT_A_RELAY_TARGET: Refusal =
    Refusal::new("target is no longer a relay target", NO_LONGER_VALID);

/// How often a run of failed grant queries is logged.
const CHECK_FAILURE_LOG_EVERY: Duration = Duration::from_secs(30);

/// Longest wait for a connection to end after the relay hung up on it.
const GOODBYE_WAIT: Duration = Duration::from_secs(2);
/// Longest pseudo-terminal type name passed on.
const MAX_TERM_LEN: usize = 64;
/// Recorded in `relay_login_refused` for a user name that is not a valid
/// target name.
const INVALID_USER: &str = "<invalid>";

/// The relay's limits. [`RelayLimits::default`] holds the documented values;
/// `max_sessions` comes from `WARDEN_RELAY_MAX_SESSIONS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    /// Sessions open at once, across all grants (16).
    pub max_sessions: usize,
    /// Sessions open at once per grant (4).
    pub max_sessions_per_grant: usize,
    /// Connections not logged in yet, across all peers (10).
    pub max_unauthenticated: usize,
    /// Connections not logged in yet from one IP address (5).
    pub max_unauthenticated_per_ip: usize,
    /// Login attempts per connection (3).
    pub max_auth_attempts: usize,
    /// Time from connecting to being logged in (10 s).
    pub auth_timeout: Duration,
    /// Time for each step of the onward connection: connecting with the
    /// host key check, logging in, opening and starting the session (10 s).
    pub onward_timeout: Duration,
    /// Time a direction of a session may hold data without delivering any
    /// of it (its destination not reading) before the session ends (60 s).
    /// Also the time an agent has, once its session is over, to take the
    /// rest of its output (the exit status included) and leave before the
    /// connection is hung up.
    pub stall_timeout: Duration,
    /// Time both directions of a session may be held up at once with
    /// nothing delivered before the session ends (2 s): the two SSH
    /// connections are then waiting on each other.
    pub wedge_timeout: Duration,
    /// Time a session may carry no bytes either way before it ends (15 min).
    pub idle_timeout: Duration,
    /// Time from login to starting the session (`shell` or `exec`) before
    /// the connection is hung up (30 s).
    pub start_timeout: Duration,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_sessions: 16,
            max_sessions_per_grant: 4,
            max_unauthenticated: 10,
            max_unauthenticated_per_ip: 5,
            max_auth_attempts: 3,
            auth_timeout: Duration::from_secs(10),
            onward_timeout: Duration::from_secs(10),
            stall_timeout: Duration::from_secs(60),
            wedge_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_mins(15),
            start_timeout: Duration::from_secs(30),
        }
    }
}

/// What every connection shares.
struct Shared {
    requests: Requests,
    backend: Arc<dyn SecretBackend>,
    audit: Arc<AuditLog>,
    limits: RelayLimits,
    slots: Arc<SessionSlots>,
    preauth: Arc<PreAuthLimiter>,
    /// Whether the relay failed closed: the state of grants has not been
    /// readable for [`FAIL_CLOSED_AFTER`].
    grant_state_lost: AtomicBool,
}

/// The SSH relay listener.
pub struct RelayServer {
    shared: Arc<Shared>,
    config: Arc<server::Config>,
}

impl std::fmt::Debug for RelayServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayServer")
            .field("limits", &self.shared.limits)
            .finish_non_exhaustive()
    }
}

impl RelayServer {
    /// A relay presenting `host_key`, admitting agents by the relay grants
    /// of `requests`, logging in to targets with credentials from
    /// `backend`, and recording sessions in `audit`.
    ///
    /// # Errors
    /// If the host key cannot be handed to the SSH server.
    pub fn new(
        requests: Requests,
        backend: Arc<dyn SecretBackend>,
        audit: Arc<AuditLog>,
        host_key: &RelayHostKey,
        limits: RelayLimits,
    ) -> Result<Self, HostKeyError> {
        let config = server::Config {
            // No implementation or version in the banner.
            server_id: SshId::Standard("SSH-2.0-warden".into()),
            methods: MethodSet::from(&[MethodKind::PublicKey][..]),
            auth_rejection_time: Duration::from_secs(1),
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![host_key.russh_private_key()?],
            max_auth_attempts: limits.max_auth_attempts,
            // Logins are bounded by `auth_timeout`; live sessions by the
            // keepalives below, which a vanished agent stops answering.
            inactivity_timeout: None,
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_max: 3,
            nodelay: true,
            window_size: AGENT_WINDOW_BYTES,
            ..server::Config::default()
        };
        Ok(Self {
            shared: Arc::new(Shared {
                requests,
                backend,
                audit,
                limits,
                slots: SessionSlots::new(limits.max_sessions, limits.max_sessions_per_grant),
                preauth: PreAuthLimiter::new(
                    limits.max_unauthenticated,
                    limits.max_unauthenticated_per_ip,
                ),
                grant_state_lost: AtomicBool::new(false),
            }),
            config: Arc::new(config),
        })
    }

    /// Accept agents on `listener` until `stop` turns true (or its sender
    /// goes away), then hang up on every connection, end their sessions
    /// (recording `relay_session_ended`) and return once all are gone.
    pub async fn serve(self, listener: TcpListener, mut stop: watch::Receiver<bool>) {
        let mut connections = JoinSet::new();
        let checking = check_grants_every(&self.shared, GRANT_CHECK_EVERY);
        tokio::pin!(checking);
        loop {
            tokio::select! {
                () = stopping(&mut stop) => break,
                () = &mut checking => {}
                accepted = listener.accept() => match accepted {
                    Ok((socket, peer)) => {
                        let Some(permit) = self.shared.preauth.try_admit(peer.ip()) else {
                            tracing::debug!(peer = %peer.ip(), "relay: too many connections logging in; closing");
                            continue;
                        };
                        connections.spawn(connection(
                            Arc::clone(&self.shared),
                            Arc::clone(&self.config),
                            socket,
                            peer,
                            permit,
                            stop.clone(),
                        ));
                    }
                    Err(e) => {
                        // Typically out of file descriptors: back off.
                        tracing::warn!(error = %e, "relay: accepting a connection failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
                Some(joined) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(e) = joined {
                        tracing::error!(error = %e, "relay: connection task failed");
                    }
                }
            }
        }
        drop(listener);
        while let Some(joined) = connections.join_next().await {
            if let Err(e) = joined {
                tracing::error!(error = %e, "relay: connection task failed");
            }
        }
    }
}
