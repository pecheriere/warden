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
//!   grant are all refused the same way.
//! - After login: at most [`RelayLimits::max_sessions_per_grant`] sessions
//!   per grant and [`RelayLimits::max_sessions`] overall. A connection that
//!   starts no session within [`RelayLimits::start_timeout`] is hung up, as
//!   is one whose session is over and that the agent does not leave.
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
//!   [`RelayLimits::idle_timeout`] with no bytes either way. When the
//!   state of grants cannot be read for [`FAIL_CLOSED_AFTER`] in a row, the
//!   relay fails closed: every session ends and none starts until it can.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use russh::server::{self, Auth, Session};
use russh::{
    Channel, ChannelId, ChannelOpenFailure, Disconnect, MethodKind, MethodSet, Pty, Sig, SshId,
};
use ssh_key::Algorithm;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use warden_broker_proto::{Id, TargetName};

use crate::audit::{AuditEvent, AuditLog};
use crate::policy::{PolicyError, SecretBackend, SshMode};
use crate::requests::{GrantEnd, RelayGrantRecord, Requests};

use super::host_key::{HostKeyError, RelayHostKey};
use super::onward;
use super::session::{
    self, Cutoff, Ends, MAX_ENV_VARS, Outcome, PreAuthLimiter, PreAuthPermit, Program, PtyRequest,
    Registration, SessionSlot, SessionSlots, env_allowed, with_cutoff,
};

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

/// How long the grant check may fail in a row before the relay fails
/// closed: every session ends and none starts until a check succeeds.
const FAIL_CLOSED_AFTER: Duration = Duration::from_secs(10);

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
            idle_timeout: Duration::from_secs(15 * 60),
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

/// End the live sessions whose grant was revoked or expired, every
/// `every`; fail closed while the state of grants cannot be read. Never
/// returns.
async fn check_grants_every(shared: &Shared, every: Duration) {
    let mut ticker = tokio::time::interval(every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut outage = Outage::default();
    loop {
        ticker.tick().await;
        let readable = check_grants(&shared.requests).await;
        let lost = outage.record(readable, Instant::now());
        let was_lost = shared.grant_state_lost.swap(lost, Ordering::AcqRel);
        if lost {
            if !was_lost {
                tracing::error!("relay: grant state unreadable for too long; ending every session");
            }
            // Also sessions that started just before the flag was set.
            shared.requests.live_sessions().fail_closed();
        } else if was_lost {
            tracing::info!("relay: grant state readable again");
        }
    }
}

/// Failures of the grant check in a row.
#[derive(Debug, Default)]
struct Outage {
    /// When the current run of failures began.
    since: Option<Instant>,
}

impl Outage {
    /// Record a check made at `now`; whether the state of grants has been
    /// unreadable for [`FAIL_CLOSED_AFTER`] or longer.
    fn record(&mut self, readable: bool, now: Instant) -> bool {
        if readable {
            self.since = None;
            return false;
        }
        now.duration_since(*self.since.get_or_insert(now)) >= FAIL_CLOSED_AFTER
    }
}

/// End the live sessions whose grant is past its window (known without the
/// database) or revoked, in one lookup for all of them. The lookup runs
/// even with no live session, so it also tells whether the state of grants
/// can be read; returns whether it could.
async fn check_grants(requests: &Requests) -> bool {
    let sessions = requests.live_sessions();
    sessions.expire_due(requests.now());
    match requests.ended_grants(&sessions.grant_ids()).await {
        Ok(ended) => {
            for (grant_id, end) in ended {
                match end {
                    GrantEnd::Revoked => sessions.revoke_grant(&grant_id),
                    GrantEnd::Expired => sessions.expire_grant(&grant_id),
                }
            }
            true
        }
        Err(e) => {
            tracing::error!(error = %e, "relay: checking the grants of live sessions failed");
            false
        }
    }
}

/// Refused login attempts on one connection.
#[derive(Debug, Default)]
struct Refusals {
    user: Option<String>,
    attempts: u32,
}

/// What a connection's handler tells its task.
struct Conn {
    logged_in: watch::Sender<bool>,
    refusals: Mutex<Refusals>,
    relayed: Mutex<Relayed>,
    phase: watch::Sender<Phase>,
}

/// Where a connection's session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Not started.
    Waiting,
    /// Its task is running.
    Running,
    /// Its task is done.
    Over,
}

/// Marks a connection's session as over when dropped (also if its task
/// panicked).
struct OverOnDrop(watch::Sender<Phase>);

impl Drop for OverOnDrop {
    fn drop(&mut self) {
        self.0.send_replace(Phase::Over);
    }
}

/// A connection's session task, as its connection task sees it.
#[derive(Debug, Default)]
enum Relayed {
    /// No session started (yet).
    #[default]
    None,
    /// A session task, which records the session's end.
    Running(JoinHandle<()>),
    /// The connection task is done waiting: no session may start now.
    Closed,
}

impl Conn {
    /// Start a session task with `spawn`, unless the connection task has
    /// already stopped waiting for one (then nothing is spawned and `false`
    /// is returned). Under one lock with [`Conn::close`], so every task
    /// that is started is awaited by a stopping relay.
    fn register(&self, spawn: impl FnOnce() -> JoinHandle<()>) -> bool {
        let mut relayed = self.relayed.lock().unwrap_or_else(PoisonError::into_inner);
        if matches!(*relayed, Relayed::Closed) {
            return false;
        }
        *relayed = Relayed::Running(spawn());
        self.phase.send_replace(Phase::Running);
        true
    }

    /// Stop accepting session tasks; the one running, if any, to await.
    fn close(&self) -> Option<JoinHandle<()>> {
        let mut relayed = self.relayed.lock().unwrap_or_else(PoisonError::into_inner);
        match std::mem::replace(&mut *relayed, Relayed::Closed) {
            Relayed::Running(task) => Some(task),
            Relayed::None | Relayed::Closed => None,
        }
    }

    fn refused(&self, user: &str) {
        let mut refusals = self.refusals.lock().unwrap_or_else(PoisonError::into_inner);
        refusals.user = Some(user.to_owned());
        refusals.attempts = refusals.attempts.saturating_add(1);
    }
}

/// Serve one agent connection: the login phase (bounded by the login
/// timeout), then the session until it ends or the relay stops.
async fn connection(
    shared: Arc<Shared>,
    config: Arc<server::Config>,
    socket: TcpStream,
    peer: SocketAddr,
    permit: PreAuthPermit,
    mut stop: watch::Receiver<bool>,
) {
    let deadline = Instant::now() + shared.limits.auth_timeout;
    let (logged_in, mut logged_in_rx) = watch::channel(false);
    let conn = Arc::new(Conn {
        logged_in,
        refusals: Mutex::new(Refusals::default()),
        relayed: Mutex::new(Relayed::None),
        phase: watch::channel(Phase::Waiting).0,
    });
    // A second handle on the socket, to cut the connection off if the peer
    // ignores the relay hanging up on it, or its event loop is stuck.
    let (socket, cut) = match with_cutoff(socket) {
        Ok((socket, cut)) => (socket, Arc::new(cut)),
        Err(e) => {
            tracing::warn!(peer = %peer.ip(), error = %e, "relay: cannot set up a connection");
            return;
        }
    };
    let handler = RelayHandler::new(
        Arc::clone(&shared),
        Arc::clone(&conn),
        permit,
        stop.clone(),
        Arc::clone(&cut),
    );
    // The SSH version exchange is part of logging in, and bounded with it.
    let started = tokio::select! {
        started = tokio::time::timeout_at(deadline, server::run_stream(config, socket, handler)) => started,
        () = stopping(&mut stop) => return,
    };
    let session = match started {
        Ok(Ok(session)) => session,
        Ok(Err(e)) => {
            tracing::debug!(peer = %peer.ip(), error = %e, "relay: connection failed before login");
            return;
        }
        Err(_) => {
            tracing::debug!(peer = %peer.ip(), "relay: no SSH version exchange in time");
            return;
        }
    };
    let handle = session.handle();
    tokio::pin!(session);

    let hang_up = tokio::select! {
        result = &mut session => {
            if let Err(e) = result {
                tracing::debug!(peer = %peer.ip(), error = %e, "relay: connection ended");
            }
            None
        }
        true = became_true(&mut logged_in_rx) => {
            let start_by = Instant::now() + shared.limits.start_timeout;
            let mut phase = conn.phase.subscribe();
            tokio::select! {
                _ = &mut session => None,
                () = stopping(&mut stop) => Some(SHUTTING_DOWN),
                message = no_more_use(&mut phase, start_by) => {
                    if message == NOT_STARTED {
                        tracing::info!(peer = %peer.ip(), "relay: no session started in time; hanging up");
                    }
                    Some(message)
                }
            }
        }
        () = tokio::time::sleep_until(deadline) => Some(LOGIN_TIMEOUT),
        () = stopping(&mut stop) => Some(SHUTTING_DOWN),
    };
    if let Some(message) = hang_up {
        goodbye(&handle, message).await;
        if tokio::time::timeout(GOODBYE_WAIT, &mut session)
            .await
            .is_err()
        {
            // The peer did not leave (it may be mid key exchange, where no
            // goodbye can be sent): cut the connection, which ends the SSH
            // session and frees what it holds.
            cut.now();
            let _ = tokio::time::timeout(GOODBYE_WAIT, &mut session).await;
        }
    }

    // The relayed session records its own end; wait for it, so a stopping
    // relay returns only once every session is recorded.
    // A handler still running (its connection cut but not yet gone) can no
    // longer start one after this.
    if let Some(relayed) = conn.close()
        && let Err(e) = relayed.await
    {
        tracing::error!(error = %e, "relay: session task failed");
    }

    if !*logged_in_rx.borrow() {
        record_refused_login(&shared.audit, &conn, peer).await;
    }
}

/// Record the refused login attempts of a connection that never logged in.
async fn record_refused_login(audit: &AuditLog, conn: &Conn, peer: SocketAddr) {
    let refusals =
        std::mem::take(&mut *conn.refusals.lock().unwrap_or_else(PoisonError::into_inner));
    if refusals.attempts == 0 {
        return;
    }
    let user = refusals.user.unwrap_or_default();
    tracing::info!(peer = %peer.ip(), user, attempts = refusals.attempts, "relay: login refused");
    let event = AuditEvent::RelayLoginRefused {
        user,
        peer: peer.ip().to_string(),
        attempts: refusals.attempts,
    };
    if let Err(e) = audit.append(event).await {
        tracing::error!(error = %e, "relay: could not record a refused login");
    }
}

/// Resolves, with the goodbye, once a logged-in connection has no more use:
/// it started no session by `start_by`, or its session is over and the
/// agent did not leave within [`GOODBYE_WAIT`].
async fn no_more_use(phase: &mut watch::Receiver<Phase>, start_by: Instant) -> &'static str {
    // The sender lives in the connection's `Conn`, which outlives this.
    let started = tokio::time::timeout_at(start_by, phase.wait_for(|p| *p != Phase::Waiting))
        .await
        .map(|seen| seen.is_ok());
    match started {
        Err(_) => return NOT_STARTED,
        Ok(false) => std::future::pending::<()>().await,
        Ok(true) => {}
    }
    let over = phase.wait_for(|p| *p == Phase::Over).await.is_ok();
    if !over {
        std::future::pending::<()>().await;
    }
    tokio::time::sleep(GOODBYE_WAIT).await;
    SESSION_OVER
}

/// Resolves once `stop` is true, or its sender is gone.
pub(crate) async fn stopping(stop: &mut watch::Receiver<bool>) {
    // An error means the sender is gone, which is a stop too.
    let _ = stop.wait_for(|stopping| *stopping).await;
}

/// Whether `flag` became true (`false` if its sender went away first).
async fn became_true(flag: &mut watch::Receiver<bool>) -> bool {
    flag.wait_for(|set| *set).await.is_ok()
}

async fn goodbye(handle: &server::Handle, message: &str) {
    // A connection already gone needs no goodbye, and one whose event loop
    // is held up (its queue full, so even sending this waits) is cut by the
    // caller instead.
    let _ = tokio::time::timeout(
        GOODBYE_WAIT,
        handle.disconnect(
            Disconnect::ByApplication,
            message.to_owned(),
            "en".to_owned(),
        ),
    )
    .await;
}

/// `key` (russh's ssh-key) as warden's ssh-key type, via its OpenSSH text.
fn ours(key: &russh::keys::PublicKey) -> Option<ssh_key::PublicKey> {
    let text = key.to_openssh().ok()?;
    ssh_key::PublicKey::from_openssh(&text).ok()
}

/// Who logged in: the grant matched, and the key it was matched by.
#[derive(Clone)]
struct Login {
    grant: RelayGrantRecord,
    key: ssh_key::PublicKey,
}

/// One connection's SSH event handler.
struct RelayHandler {
    shared: Arc<Shared>,
    conn: Arc<Conn>,
    /// Held until login; dropping it frees a pre-login place.
    preauth: Option<PreAuthPermit>,
    stop: watch::Receiver<bool>,
    login: Option<Login>,
    /// Held from login until the session ends.
    slot: Option<SessionSlot>,
    /// The session channel's id, once the agent opened it.
    session_id: Option<ChannelId>,
    /// The session channel, until its session starts.
    channel: Option<Channel<server::Msg>>,
    pty: Option<PtyRequest>,
    env: Vec<(String, String)>,
    /// Refusals to report on the session's stderr.
    notices: Vec<&'static str>,
    started: bool,
    /// Input that arrived before the session started.
    pre_start_messages: usize,
    pre_start_bytes: usize,
    /// Whether the connection was hung up for too much of it.
    flooded: bool,
    /// Cuts this connection.
    cut: Arc<Cutoff>,
}

impl RelayHandler {
    fn new(
        shared: Arc<Shared>,
        conn: Arc<Conn>,
        permit: PreAuthPermit,
        stop: watch::Receiver<bool>,
        cut: Arc<Cutoff>,
    ) -> Self {
        Self {
            shared,
            conn,
            preauth: Some(permit),
            stop,
            login: None,
            slot: None,
            session_id: None,
            channel: None,
            pty: None,
            env: Vec::new(),
            notices: Vec::new(),
            started: false,
            pre_start_messages: 0,
            pre_start_bytes: 0,
            flooded: false,
            cut,
        }
    }

    fn is_session(&self, channel: ChannelId) -> bool {
        self.session_id == Some(channel)
    }

    /// Queue `notice` for the session's stderr (once).
    fn notice(&mut self, notice: &'static str) {
        if !self.notices.contains(&notice) {
            self.notices.push(notice);
        }
    }

    /// Write queued notices to the stderr of `channel`, a session channel
    /// the agent is using (so it is open).
    fn flush_notices(&mut self, channel: ChannelId, session: &mut Session) {
        if !self.is_session(channel) {
            return;
        }
        let newline = if self.pty.is_some() { "\r\n" } else { "\n" };
        for notice in self.notices.drain(..) {
            // Best effort: the notice is a courtesy; the request it is about
            // is refused regardless.
            let _ = session.extended_data(channel, 1, format!("{notice}{newline}").into_bytes());
        }
    }

    /// Refuse a channel the agent tried to open.
    async fn refuse_open(&mut self, reply: server::ChannelOpenHandle, notice: &'static str) {
        self.notice(notice);
        reply
            .reject(ChannelOpenFailure::Other {
                code: ChannelOpenFailure::AdministrativelyProhibited.code(),
                reason: notice.to_owned(),
            })
            .await;
    }

    /// Refuse request on `channel` with `notice` on stderr.
    fn refuse_request(
        &mut self,
        channel: ChannelId,
        notice: &'static str,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        self.notice(notice);
        self.flush_notices(channel, session);
        session.channel_failure(channel)
    }

    /// Count `bytes` of input (or a request) that arrived on the session
    /// before it started. The SSH library queues it for the session (a
    /// bounded queue whose overflow would stall this connection), so past
    /// [`MAX_PRE_START_MESSAGES`] messages or [`MAX_PRE_START_BYTES`] bytes
    /// the session is refused, on record, and the connection hung up.
    /// Returns whether to go on handling the input.
    async fn admit_before_start(
        &mut self,
        bytes: usize,
        session: &mut Session,
    ) -> Result<bool, russh::Error> {
        if self.started {
            return Ok(!self.flooded);
        }
        self.pre_start_messages = self.pre_start_messages.saturating_add(1);
        self.pre_start_bytes = self.pre_start_bytes.saturating_add(bytes);
        if self.pre_start_messages <= MAX_PRE_START_MESSAGES
            && self.pre_start_bytes <= MAX_PRE_START_BYTES
        {
            return Ok(true);
        }
        self.started = true;
        self.flooded = true;
        self.channel = None;
        self.slot = None;
        if let Some(login) = &self.login {
            refuse_session(
                &self.shared,
                &login.grant.grant_id,
                "too much input before the session started",
                TOO_MUCH_INPUT,
            )
            .await;
        }
        session.disconnect(Disconnect::ByApplication, TOO_MUCH_INPUT, "en")?;
        Ok(false)
    }

    /// Start the session on `channel` with `program`: check the grant and
    /// policy again, record the start, connect to the target, and hand both
    /// ends to a task relaying them. On any failure the agent gets a fixed
    /// message on stderr, a failure reply, and the channel is closed.
    async fn start(
        &mut self,
        channel: ChannelId,
        program: Program,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        self.flush_notices(channel, session);
        if !self.is_session(channel) || self.started {
            return session.channel_failure(channel);
        }
        self.started = true;
        let (Some(login), Some(agent), Some(slot)) =
            (self.login.as_ref(), self.channel.take(), self.slot.take())
        else {
            return session.channel_failure(channel);
        };
        // The session runs on its own task, registered with the connection
        // before anything is recorded: a stopping relay waits for it, so a
        // recorded start always gets its recorded end.
        let (ready, ready_rx) = oneshot::channel();
        let (shared, login, pty, env) = (
            Arc::clone(&self.shared),
            login.clone(),
            self.pty.clone(),
            self.env.clone(),
        );
        let (agent_handle, mut stop) = (session.handle(), self.stop.clone());
        let agent_cut = Arc::clone(&self.cut);
        let over = OverOnDrop(self.conn.phase.clone());
        let newline = if pty.is_some() { "\r\n" } else { "\n" };
        let spawn = move || {
            tokio::spawn(async move {
                let _over = over;
                // Listed before the grant is checked again: a revocation
                // after the check still reaches the session.
                let mut live = shared.requests.live_sessions().register(&login.grant);
                let opened = open_target(
                    &shared,
                    &login,
                    pty.as_ref(),
                    &env,
                    &program,
                    &mut stop,
                    &mut live,
                )
                .await;
                let started = match opened {
                    Ok(started) => started,
                    Err(message) => {
                        // The handler may be gone with its connection; then
                        // nobody needs the answer.
                        let _ = ready.send(Err(message));
                        return;
                    }
                };
                let _ = ready.send(Ok(()));
                let grant = &login.grant;
                tracing::info!(grant = %grant.grant_id, agent = %grant.agent, target = %grant.target, "relay: session started");
                let (target, early, target_cut, hang_up) = started.into_parts();
                let ends = Ends {
                    agent,
                    agent_handle,
                    newline,
                    agent_cut,
                    target,
                    target_cut,
                    early,
                };
                let watch = session::Watch {
                    stall: shared.limits.stall_timeout,
                    wedge: shared.limits.wedge_timeout,
                    idle: shared.limits.idle_timeout,
                };
                let outcome = session::relay(ends, &mut live, stop, watch).await;
                if session::reason::forced(outcome.reason) {
                    // Given its chance to close already.
                    hang_up.cut();
                } else {
                    hang_up.now().await;
                }
                drop(slot);
                record_end(&shared.audit, &grant.grant_id, &outcome).await;
            })
        };
        if !self.conn.register(spawn) {
            // The connection is being hung up: nothing was recorded.
            return self.refuse_start(channel, SHUTTING_DOWN, session);
        }
        // Replies go out before anything the session task relays: they are
        // written here, inside the connection's event loop, which handles
        // the task's output only after this returns.
        match ready_rx.await {
            Ok(Ok(())) => session.channel_success(channel),
            Ok(Err(message)) => self.refuse_start(channel, message, session),
            Err(_) => self.refuse_start(channel, INTERNAL, session),
        }
    }

    /// Answer a session that could not start like one that ran and failed:
    /// OpenSSH clients drop stderr that follows a refused request, but
    /// print it before an exit status.
    fn refuse_start(
        &self,
        channel: ChannelId,
        message: &str,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let newline = if self.pty.is_some() { "\r\n" } else { "\n" };
        session.channel_success(channel)?;
        session.extended_data(channel, 1, format!("{message}{newline}").into_bytes())?;
        session.exit_status_request(channel, REFUSED_EXIT_STATUS)?;
        session.eof(channel)?;
        session.close(channel)
    }
}

/// Record that a session ended.
async fn record_end(audit: &AuditLog, grant_id: &Id, outcome: &Outcome) {
    tracing::info!(grant = %grant_id, reason = outcome.reason, "relay: session ended");
    let event = AuditEvent::RelaySessionEnded {
        grant_id: grant_id.clone(),
        reason: outcome.reason.to_owned(),
        bytes_to_target: outcome.bytes_to_target,
        bytes_from_target: outcome.bytes_from_target,
        exit_status: outcome.exit_status,
    };
    if let Err(e) = audit.append(event).await {
        tracing::error!(grant = %grant_id, error = %e, "relay: could not record a session end");
    }
}

/// Record that a session was refused for `reason`, and give the agent
/// `message`.
async fn refuse_session(
    shared: &Shared,
    grant_id: &Id,
    reason: &str,
    message: &'static str,
) -> &'static str {
    tracing::warn!(grant = %grant_id, reason, "relay: session refused");
    let event = AuditEvent::RelaySessionRefused {
        grant_id: grant_id.clone(),
        reason: reason.to_owned(),
    };
    if let Err(e) = shared.audit.append(event).await {
        tracing::error!(grant = %grant_id, error = %e, "relay: could not record a refused session");
    }
    message
}

/// Everything between the agent's `shell`/`exec` and a running session on
/// the target. Returns the message for the agent on failure.
async fn open_target(
    shared: &Shared,
    login: &Login,
    pty: Option<&PtyRequest>,
    env: &[(String, String)],
    program: &Program,
    stop: &mut watch::Receiver<bool>,
    live: &mut Registration,
) -> Result<onward::Started, &'static str> {
    let grant = &login.grant;
    let refuse = |reason, message| refuse_session(shared, &grant.grant_id, reason, message);
    // Failed closed: no grant can be told revoked, so none is used.
    if shared.grant_state_lost.load(Ordering::Acquire) {
        return Err(refuse(
            session::reason::GRANT_STATE_UNAVAILABLE,
            session::reason::GRANT_STATE_NOTICE,
        )
        .await);
    }
    // The grant may have been revoked or expired since login.
    match shared
        .requests
        .active_relay_grant(&grant.target, &login.key)
        .await
    {
        Ok(Some(now)) if now.grant_id == grant.grant_id => {}
        Ok(_) => return Err(refuse("grant no longer active", NO_LONGER_VALID).await),
        Err(e) => {
            tracing::error!(grant = %grant.grant_id, error = %e, "relay: grant lookup failed");
            return Err(refuse("grant lookup failed", session::reason::GRANT_STATE_NOTICE).await);
        }
    }
    // The policy and the credential, in one read.
    let (target, credential) = match shared
        .backend
        .relay_target_with_credential(&grant.target)
        .await
    {
        Ok(read) => read,
        Err(PolicyError::Invalid { field, .. }) if field == "mode" => {
            return Err(refuse("target is no longer a relay target", NO_LONGER_VALID).await);
        }
        Err(PolicyError::NotFound(_)) => {
            return Err(refuse("target no longer exists", NO_LONGER_VALID).await);
        }
        Err(PolicyError::Unavailable(detail)) => {
            tracing::error!(grant = %grant.grant_id, detail, "relay: secret backend unavailable");
            return Err(refuse("secret backend unavailable", UNAVAILABLE).await);
        }
        Err(e) => {
            tracing::warn!(grant = %grant.grant_id, error = %e, "relay: target policy invalid");
            return Err(refuse("target policy invalid", NO_LONGER_VALID).await);
        }
    };
    if target.mode != SshMode::Relay {
        return Err(refuse("target is no longer a relay target", NO_LONGER_VALID).await);
    }
    if !target.users.contains(&grant.user) {
        return Err(refuse("user no longer allowed on the target", NO_LONGER_VALID).await);
    }
    // Pre-flight: on record before any byte reaches the target.
    let started = AuditEvent::RelaySessionStarted {
        grant_id: grant.grant_id.clone(),
        target: grant.target.clone(),
        user: grant.user.clone(),
        command: program.audited(),
    };
    if let Err(e) = shared.audit.append(started).await {
        tracing::error!(grant = %grant.grant_id, error = %e, "relay: could not record a session start; not starting it");
        return Err(UNRECORDED);
    }
    let ended_early = |reason: &'static str| async move {
        let outcome = Outcome {
            reason,
            bytes_to_target: 0,
            bytes_from_target: 0,
            exit_status: None,
        };
        record_end(&shared.audit, &grant.grant_id, &outcome).await;
    };
    let timeout = shared.limits.onward_timeout;
    let onward = async {
        onward::connect(&target, &grant.user, credential, timeout)
            .await?
            .start(pty, env, program, timeout)
            .await
    };
    // A stopping relay does not wait for a slow target: the session ends
    // now, on record, and dropping the attempt closes its connection.
    tokio::select! {
        opened = onward => match opened {
            Ok(started) => Ok(started),
            Err(e) => {
                ended_early(e.audit_reason()).await;
                Err(e.message())
            }
        },
        () = stopping(stop) => {
            ended_early(session::reason::SHUTDOWN).await;
            Err(SHUTTING_DOWN)
        }
        // Revoked or expired while connecting: ended the same way.
        ending = live.ended() => {
            ended_early(ending).await;
            Err(session::reason::notice(ending).unwrap_or(NO_LONGER_VALID))
        }
    }
}

impl server::Handler for RelayHandler {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        // Approved keys are Ed25519; anything else is not worth a signature.
        Ok(
            if public_key.algorithm() == russh::keys::Algorithm::Ed25519 {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let Ok(target) = TargetName::try_from(user.to_owned()) else {
            self.conn.refused(INVALID_USER);
            return Ok(Auth::reject());
        };
        let key = ours(public_key).filter(|key| key.algorithm() == Algorithm::Ed25519);
        let grant = match &key {
            Some(key) => match self.shared.requests.active_relay_grant(&target, key).await {
                Ok(grant) => grant,
                Err(e) => {
                    tracing::error!(error = %e, "relay: login check failed");
                    None
                }
            },
            None => None,
        };
        if let (Some(grant), Some(key)) = (grant, key) {
            self.login = Some(Login { grant, key });
            return Ok(Auth::Accept);
        }
        self.conn.refused(target.as_str());
        Ok(Auth::reject())
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        self.preauth = None;
        let _ = self.conn.logged_in.send(true);
        let Some(login) = &self.login else {
            return session.disconnect(Disconnect::ByApplication, NO_LONGER_VALID, "en");
        };
        let grant = &login.grant;
        match self.shared.slots.try_acquire(&grant.grant_id) {
            Ok(slot) => {
                tracing::info!(grant = %grant.grant_id, agent = %grant.agent, target = %grant.target, "relay: agent logged in");
                self.slot = Some(slot);
                Ok(())
            }
            Err(refusal) => {
                tracing::warn!(grant = %grant.grant_id, agent = %grant.agent, limit = refusal.message(), "relay: session limit reached");
                session.disconnect(Disconnect::TooManyConnections, refusal.message(), "en")
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.slot.is_none() || self.session_id.is_some() {
            self.refuse_open(reply, ONE_SESSION).await;
        } else {
            self.session_id = Some(channel.id());
            self.channel = Some(channel);
            reply.accept().await;
        }
        Ok(())
    }

    async fn channel_open_x11(
        &mut self,
        _channel: Channel<server::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse_open(reply, NO_X11).await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<server::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse_open(reply, NO_FORWARDING).await;
        Ok(())
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<server::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse_open(reply, NO_FORWARDING).await;
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<server::Msg>,
        _socket_path: &str,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse_open(reply, NO_FORWARDING).await;
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.notice(NO_FORWARDING);
        Ok(false)
    }

    async fn streamlocal_forward(
        &mut self,
        _socket_path: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.notice(NO_FORWARDING);
        Ok(false)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.admit_before_start(0, session).await? {
            return Ok(());
        }
        self.flush_notices(channel, session);
        if !self.is_session(channel)
            || self.started
            || self.pty.is_some()
            || term.len() > MAX_TERM_LEN
        {
            return session.channel_failure(channel);
        }
        self.pty = Some(PtyRequest {
            term: term.to_owned(),
            cols: col_width,
            rows: row_height,
            pix_width,
            pix_height,
            modes: modes.to_vec(),
        });
        session.channel_success(channel)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.admit_before_start(0, session).await? {
            return Ok(());
        }
        self.flush_notices(channel, session);
        if !self.is_session(channel)
            || self.started
            || self.env.len() >= MAX_ENV_VARS
            || !env_allowed(variable_name, variable_value)
        {
            return session.channel_failure(channel);
        }
        self.env
            .push((variable_name.to_owned(), variable_value.to_owned()));
        session.channel_success(channel)
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.admit_before_start(0, session).await? {
            return Ok(());
        }
        self.refuse_request(channel, NO_X11, session)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.admit_before_start(0, session).await? {
            return Ok(());
        }
        self.refuse_request(channel, NO_SUBSYSTEMS, session)
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if !self.admit_before_start(0, session).await? {
            return Ok(false);
        }
        // The library sends the failure reply for `false`.
        self.notice(NO_AGENT);
        self.flush_notices(channel, session);
        Ok(false)
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Carried by the session task once started; counted until then.
        self.admit_before_start(data.len(), session).await?;
        Ok(())
    }

    async fn extended_data(
        &mut self,
        _channel: ChannelId,
        _code: u32,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.admit_before_start(data.len(), session).await?;
        Ok(())
    }

    async fn signal(
        &mut self,
        _channel: ChannelId,
        _signal: Sig,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Forwarded by the session task once started.
        self.admit_before_start(0, session).await?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start(channel, Program::Shell, session).await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start(channel, Program::Exec(data.to_vec()), session)
            .await
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.admit_before_start(0, session).await? {
            return Ok(());
        }
        // A running session gets the change from the relay loop; before the
        // start, the pty to be requested takes the new size.
        if let Some(pty) = &mut self.pty
            && !self.started
        {
            pty.cols = col_width;
            pty.rows = row_height;
            pty.pix_width = pix_width;
            pty.pix_height = pix_height;
        }
        if self.is_session(channel) {
            session.channel_success(channel)
        } else {
            session.channel_failure(channel)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use tokio::sync::watch;
    use tokio::time::Instant;

    use super::{
        Conn, GOODBYE_WAIT, NOT_STARTED, Outage, OverOnDrop, Phase, Refusals, Relayed,
        SESSION_OVER, no_more_use,
    };

    fn conn() -> Conn {
        Conn {
            logged_in: tokio::sync::watch::channel(false).0,
            refusals: Mutex::new(Refusals::default()),
            relayed: Mutex::new(Relayed::None),
            phase: tokio::sync::watch::channel(Phase::Waiting).0,
        }
    }

    #[test]
    fn fails_closed_after_ten_seconds_of_failures_in_a_row() {
        let start = Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        let mut outage = Outage::default();
        assert!(!outage.record(false, at(0)));
        assert!(!outage.record(false, at(9)));
        // One success starts the count again.
        assert!(!outage.record(true, at(10)));
        assert!(!outage.record(false, at(11)));
        assert!(!outage.record(false, at(20)));
        assert!(outage.record(false, at(21)));
        assert!(outage.record(false, at(22)));
        assert!(!outage.record(true, at(23)));
    }

    #[tokio::test(start_paused = true)]
    async fn connection_without_a_session_or_after_it_has_no_more_use() {
        // No session started in time.
        let (phase, mut rx) = watch::channel(Phase::Waiting);
        let start_by = Instant::now() + Duration::from_secs(30);
        assert_eq!(no_more_use(&mut rx, start_by).await, NOT_STARTED);
        assert_eq!(Instant::now(), start_by);

        // A session started in time keeps the connection until it is over,
        // and the agent then gets a while to leave by itself.
        let mut rx = phase.subscribe();
        let start_by = Instant::now() + Duration::from_secs(30);
        let waiting = no_more_use(&mut rx, start_by);
        tokio::pin!(waiting);
        tokio::select! {
            why = &mut waiting => panic!("hung up early: {why}"),
            () = tokio::time::sleep(Duration::from_secs(10)) => {}
        }
        phase.send_replace(Phase::Running);
        tokio::select! {
            why = &mut waiting => panic!("hung up on a running session: {why}"),
            () = tokio::time::sleep(Duration::from_secs(600)) => {}
        }
        drop(OverOnDrop(phase.clone()));
        let over = Instant::now();
        assert_eq!((&mut waiting).await, SESSION_OVER);
        assert_eq!(over.elapsed(), GOODBYE_WAIT);
    }

    #[tokio::test]
    async fn no_session_task_starts_after_the_connection_stopped_waiting() {
        let conn = conn();
        assert!(conn.register(|| tokio::spawn(async {})));
        let task = conn.close().expect("the running task");
        task.await.unwrap();
        // A late start is refused without spawning anything.
        assert!(!conn.register(|| unreachable!("nothing may start now")));
        assert!(conn.close().is_none());
    }
}
