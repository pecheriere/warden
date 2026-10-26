//! One relayed session: how many may run, which are live (so revocation
//! and expiry can end them), what the agent asked for before it started,
//! and the loop that carries bytes, EOF, window changes, signals and the
//! exit status between the agent and the target.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use russh::client;
use russh::server;
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Disconnect, Pty};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use warden_broker_proto::{AgentName, Id};

use crate::requests::RelayGrantRecord;

/// Longest command recorded in the audit log, in characters.
const COMMAND_AUDIT_CHARS: usize = 200;

/// Most environment variables an agent may pass on.
pub(crate) const MAX_ENV_VARS: usize = 16;

/// Longest environment variable value passed on, in bytes.
const MAX_ENV_VALUE: usize = 256;

/// Why a session ended, as recorded in `relay_session_ended`.
pub(crate) mod reason {
    /// The command or shell exited (an exit status or signal came back).
    pub const EXITED: &str = "exited";
    /// The target closed the session without an exit status.
    pub const TARGET_CLOSED: &str = "target closed";
    /// The agent closed the session.
    pub const CLIENT_CLOSED: &str = "client closed";
    /// The relay is stopping.
    pub const SHUTDOWN: &str = "relay shutting down";
    /// Prefix of the reasons below.
    pub const FLOW_CONTROL: &str = "flow control: ";
    /// The agent did not take the target's output.
    pub const DOWNSTREAM_STALLED: &str = "flow control: output to the agent not drained";
    /// The target did not take the agent's input.
    pub const UPSTREAM_STALLED: &str = "flow control: input to the target not drained";
    /// The grant (or its agent) was revoked.
    pub const REVOKED: &str = "revoked";
    /// The grant's window ended.
    pub const EXPIRED: &str = "expired";
    /// No bytes went either way for the idle timeout.
    pub const IDLE: &str = "idle timeout";

    /// Whether the relay ends a session ended for `reason` by force: both
    /// connections are cut after a short grace, whatever their state.
    #[must_use]
    pub fn forced(reason: &str) -> bool {
        reason.starts_with(FLOW_CONTROL) || matches!(reason, REVOKED | EXPIRED | IDLE)
    }

    /// What the agent is told when its session ends for `reason`, if
    /// anything.
    #[must_use]
    pub fn notice(reason: &str) -> Option<&'static str> {
        match reason {
            REVOKED => Some("warden relay: access revoked"),
            EXPIRED => Some("warden relay: access expired"),
            IDLE => Some("warden relay: session idle for too long"),
            _ => None,
        }
    }
}

/// The live relay sessions, so that revoking a grant or an agent, and a
/// grant's expiry, end them at once. Shared by the relay and the request
/// service (whose revocations tell it directly); revocations made by
/// another process and expiry are found by the relay's periodic check.
#[derive(Debug, Default)]
pub(crate) struct LiveSessions {
    entries: Mutex<HashMap<u64, LiveSession>>,
    next: AtomicU64,
}

#[derive(Debug)]
struct LiveSession {
    grant_id: Id,
    agent: AgentName,
    not_after: i64,
    /// Why the relay must end the session, once it must.
    end: watch::Sender<Option<&'static str>>,
}

impl LiveSession {
    /// Tell the session to end for `reason`; the first reason given stands.
    fn end(&self, reason: &'static str) {
        self.end.send_if_modified(|ending| {
            if ending.is_some() {
                return false;
            }
            *ending = Some(reason);
            true
        });
    }
}

impl LiveSessions {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Add a session of `grant`; it is listed until the registration is
    /// dropped.
    pub(crate) fn register(self: &Arc<Self>, grant: &RelayGrantRecord) -> Registration {
        let (end, ended) = watch::channel(None);
        let key = self.next.fetch_add(1, Ordering::Relaxed);
        self.lock().insert(
            key,
            LiveSession {
                grant_id: grant.grant_id.clone(),
                agent: grant.agent.clone(),
                not_after: grant.not_after,
                end,
            },
        );
        Registration {
            sessions: Arc::clone(self),
            key,
            ended,
        }
    }

    /// End the sessions of grant `grant_id`: it was revoked.
    pub(crate) fn revoke_grant(&self, grant_id: &Id) {
        self.end_where(|s| s.grant_id == *grant_id, reason::REVOKED);
    }

    /// End the sessions of every grant of `agent`: it was revoked.
    pub(crate) fn revoke_agent(&self, agent: &AgentName) {
        self.end_where(|s| s.agent == *agent, reason::REVOKED);
    }

    /// End the sessions of grant `grant_id`: its window is over.
    pub(crate) fn expire_grant(&self, grant_id: &Id) {
        self.end_where(|s| s.grant_id == *grant_id, reason::EXPIRED);
    }

    /// End the sessions whose grant's window is over at `now` (Unix
    /// seconds), as known when they started.
    pub(crate) fn expire_due(&self, now: i64) {
        self.end_where(|s| s.not_after <= now, reason::EXPIRED);
    }

    /// The grants with live sessions, each once.
    pub(crate) fn grant_ids(&self) -> Vec<Id> {
        self.lock()
            .values()
            .map(|s| s.grant_id.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect()
    }

    fn end_where(&self, matches: impl Fn(&LiveSession) -> bool, reason: &'static str) {
        for session in self.lock().values().filter(|s| matches(s)) {
            session.end(reason);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, LiveSession>> {
        // Every update is a single insert or removal: a holder that
        // panicked leaves the map consistent.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A session's place in [`LiveSessions`], removed when dropped.
#[derive(Debug)]
pub(crate) struct Registration {
    sessions: Arc<LiveSessions>,
    key: u64,
    ended: watch::Receiver<Option<&'static str>>,
}

impl Registration {
    /// Resolves, with the reason, once the relay must end the session.
    pub(crate) async fn ended(&mut self) -> &'static str {
        // The sender lives in the registry entry, which outlives `self`.
        let ending = self
            .ended
            .wait_for(Option::is_some)
            .await
            .map_or(None, |ending| *ending);
        match ending {
            Some(reason) => reason,
            None => std::future::pending().await,
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.sessions.lock().remove(&self.key);
    }
}

/// What the agent asked the target to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Program {
    /// The user's login shell.
    Shell,
    /// A command line, run by the user's shell.
    Exec(Vec<u8>),
}

impl Program {
    /// The command as recorded in the audit log: `None` for a shell; for a
    /// command, its text (invalid UTF-8 replaced) cut to
    /// [`COMMAND_AUDIT_CHARS`] characters with `…`.
    #[must_use]
    pub(crate) fn audited(&self) -> Option<String> {
        match self {
            Self::Shell => None,
            Self::Exec(bytes) => {
                let command = String::from_utf8_lossy(bytes);
                Some(match command.char_indices().nth(COMMAND_AUDIT_CHARS) {
                    None => command.into_owned(),
                    Some((cut, _)) => format!("{}…", &command[..cut]),
                })
            }
        }
    }
}

/// A pseudo-terminal request, held until the session starts.
#[derive(Debug, Clone)]
pub(crate) struct PtyRequest {
    pub term: String,
    pub cols: u32,
    pub rows: u32,
    pub pix_width: u32,
    pub pix_height: u32,
    pub modes: Vec<(Pty, u32)>,
}

/// Whether an agent may pass environment variable `name` with `value` on
/// to the target: only `LANG`, `TERM` and `LC_*` (upper-case letters and
/// `_` after the prefix), with a value of at most 256 bytes and no NUL.
#[must_use]
pub(crate) fn env_allowed(name: &str, value: &str) -> bool {
    let name_ok = match name.strip_prefix("LC_") {
        Some(rest) => !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'),
        None => name == "LANG" || name == "TERM",
    };
    name_ok && value.len() <= MAX_ENV_VALUE && !value.contains('\0')
}

/// Which limit refused a new session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotRefusal {
    /// The grant already has its maximum of sessions.
    Grant,
    /// The relay as a whole is at its maximum.
    Total,
}

impl SlotRefusal {
    /// What the agent is told (in the SSH disconnect message).
    #[must_use]
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::Grant => "warden relay: too many sessions for this grant",
            Self::Total => "warden relay: too many relay sessions; try again later",
        }
    }
}

#[derive(Debug, Default)]
struct SlotCounts {
    total: usize,
    per_grant: HashMap<Id, usize>,
}

/// Counts live relay sessions, overall and per grant.
#[derive(Debug)]
pub(crate) struct SessionSlots {
    max_total: usize,
    max_per_grant: usize,
    counts: Mutex<SlotCounts>,
}

/// A session's place, given back when dropped.
#[derive(Debug)]
pub(crate) struct SessionSlot {
    slots: Arc<SessionSlots>,
    grant_id: Id,
}

impl SessionSlots {
    pub(crate) fn new(max_total: usize, max_per_grant: usize) -> Arc<Self> {
        Arc::new(Self {
            max_total,
            max_per_grant,
            counts: Mutex::new(SlotCounts::default()),
        })
    }

    /// Take a place for a session of `grant_id`, if both limits allow.
    pub(crate) fn try_acquire(self: &Arc<Self>, grant_id: &Id) -> Result<SessionSlot, SlotRefusal> {
        // The counts stay consistent even if a holder panicked mid-update:
        // every update is a single increment or decrement.
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let held = counts.per_grant.get(grant_id).copied().unwrap_or(0);
        if held >= self.max_per_grant {
            return Err(SlotRefusal::Grant);
        }
        if counts.total >= self.max_total {
            return Err(SlotRefusal::Total);
        }
        counts.total += 1;
        *counts.per_grant.entry(grant_id.clone()).or_insert(0) += 1;
        Ok(SessionSlot {
            slots: Arc::clone(self),
            grant_id: grant_id.clone(),
        })
    }

    #[cfg(test)]
    fn live(&self) -> (usize, usize) {
        let counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        (counts.total, counts.per_grant.len())
    }
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        let mut counts = self
            .slots
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        counts.total = counts.total.saturating_sub(1);
        if let Some(held) = counts.per_grant.get_mut(&self.grant_id) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                counts.per_grant.remove(&self.grant_id);
            }
        }
    }
}

#[derive(Debug, Default)]
struct PreAuthCounts {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

/// Counts connections that have not logged in yet, overall and per peer
/// address, so unauthenticated peers cannot exhaust the relay.
#[derive(Debug)]
pub(crate) struct PreAuthLimiter {
    max_total: usize,
    max_per_ip: usize,
    counts: Mutex<PreAuthCounts>,
}

/// A pre-login place, given back when dropped (at login or disconnect).
#[derive(Debug)]
pub(crate) struct PreAuthPermit {
    limiter: Arc<PreAuthLimiter>,
    ip: IpAddr,
}

impl PreAuthLimiter {
    pub(crate) fn new(max_total: usize, max_per_ip: usize) -> Arc<Self> {
        Arc::new(Self {
            max_total,
            max_per_ip,
            counts: Mutex::new(PreAuthCounts::default()),
        })
    }

    /// Admit a new connection from `ip`, if both limits allow.
    pub(crate) fn try_admit(self: &Arc<Self>, ip: IpAddr) -> Option<PreAuthPermit> {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let from_ip = counts.per_ip.get(&ip).copied().unwrap_or(0);
        if from_ip >= self.max_per_ip || counts.total >= self.max_total {
            return None;
        }
        counts.total += 1;
        *counts.per_ip.entry(ip).or_insert(0) += 1;
        Some(PreAuthPermit {
            limiter: Arc::clone(self),
            ip,
        })
    }
}

impl Drop for PreAuthPermit {
    fn drop(&mut self) {
        let mut counts = self
            .limiter
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        counts.total = counts.total.saturating_sub(1);
        if let Some(held) = counts.per_ip.get_mut(&self.ip) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                counts.per_ip.remove(&self.ip);
            }
        }
    }
}

/// How a relayed session went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub reason: &'static str,
    pub bytes_to_target: u64,
    pub bytes_from_target: u64,
    pub exit_status: Option<u32>,
}

/// Bytes of the agent's input held between the agent's connection and the
/// target's; past it the relay stops reading the agent's connection.
const UPSTREAM_QUEUE_BYTES: usize = 2 * 1024 * 1024;

/// Bytes of the target's output held between the two connections; past it
/// the relay stops reading the target's connection. Larger than
/// [`UPSTREAM_QUEUE_BYTES`] plus the SSH window the relay grants the agent
/// (2 MiB), so a target echoing its input never fills it while the agent's
/// window updates wait behind the input queued ahead of them.
const DOWNSTREAM_QUEUE_BYTES: usize = 8 * 1024 * 1024;

/// What a message other than data counts for in a queue.
const CONTROL_MESSAGE_BYTES: usize = 64;

/// When a session that stopped making progress ends.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Watch {
    /// A direction holding data that nothing delivers for this long (an
    /// agent not reading its output, a target not reading its input).
    pub stall: Duration,
    /// Both directions held up at once (each waiting for room in its
    /// queue) with nothing delivered either way for this long.
    ///
    /// russh stops a connection's whole event loop (its window updates and
    /// outgoing data included) while the relay is not reading it, and it
    /// grants window as data arrives whatever the reader's pace, so reading
    /// less is the only way to hold either side back. With both connections
    /// held back each can wait for the other's window forever: an agent
    /// that feeds input to an echoing command and never reads the output
    /// gets there in seconds. While held back, the agent's connection does
    /// not notice the agent leaving either; this ends such a session.
    pub wedge: Duration,
    /// No bytes read from either side for this long.
    pub idle: Duration,
}

/// How often the session checks for progress.
const WATCH_EVERY: Duration = Duration::from_millis(250);

/// Longest each side gets to take the relay's close at the end before its
/// connection is cut.
const CLOSE_WAIT: Duration = Duration::from_secs(2);

/// Longest a session ended by force (see [`reason::forced`]) gets to close
/// gracefully before both connections are cut.
const FORCED_CLOSE_WAIT: Duration = Duration::from_secs(1);

/// Cuts a connection off: shuts its socket down under the SSH library,
/// whose reads then end, whatever state its event loop is in.
#[derive(Debug)]
pub(crate) struct Cutoff(std::net::TcpStream);

impl Cutoff {
    pub(crate) fn now(&self) {
        // Already closed is as good as cut.
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

/// `socket`, and a cutoff for it.
pub(crate) fn with_cutoff(
    socket: tokio::net::TcpStream,
) -> std::io::Result<(tokio::net::TcpStream, Cutoff)> {
    let socket = socket.into_std()?;
    let cutoff = Cutoff(socket.try_clone()?);
    Ok((tokio::net::TcpStream::from_std(socket)?, cutoff))
}

/// Both ends of a started session.
pub(crate) struct Ends {
    /// The agent's session channel.
    pub agent: Channel<server::Msg>,
    /// The agent connection, for an exit signal and a forced hang-up.
    pub agent_handle: server::Handle,
    /// Line ending of notices on the agent's stderr (`\r\n` with a pty).
    pub newline: &'static str,
    /// Cuts the agent's connection.
    pub agent_cut: Arc<Cutoff>,
    /// The target's session channel, its command started.
    pub target: Channel<client::Msg>,
    /// Cuts the target's connection.
    pub target_cut: Arc<Cutoff>,
    /// What the target sent while the session was being set up, in order.
    pub early: VecDeque<ChannelMsg>,
}

fn len64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// How a direction is doing, for the session's watchdog.
#[derive(Debug, Default)]
struct Progress {
    /// Messages delivered so far.
    delivered: AtomicU64,
    /// Bytes queued and not yet delivered.
    queued: AtomicUsize,
    /// Whether the reader is waiting for room in the queue (so the
    /// connection it reads is held up).
    waiting: AtomicBool,
    /// Data bytes read from the source so far.
    received: AtomicU64,
}

impl Progress {
    /// Count a message read from the source.
    fn read(&self, msg: &ChannelMsg) {
        if let ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } = msg {
            self.received.fetch_add(len64(data.len()), Ordering::AcqRel);
        }
    }
}

/// Marks a reader as waiting for room while it exists (also if the wait is
/// abandoned).
struct Waiting<'a>(&'a Progress);

impl<'a> Waiting<'a> {
    fn new(progress: &'a Progress) -> Self {
        progress.waiting.store(true, Ordering::Release);
        Self(progress)
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.waiting.store(false, Ordering::Release);
    }
}

/// A message on its way, holding its room in the queue until delivered.
struct Queued {
    msg: ChannelMsg,
    size: usize,
    _room: OwnedSemaphorePermit,
}

/// A direction's queue of messages between the two connections, bounded
/// in bytes.
struct Queue {
    room: Arc<Semaphore>,
    capacity: usize,
    progress: Arc<Progress>,
    tx: mpsc::UnboundedSender<Queued>,
}

impl Queue {
    fn new(capacity: usize, progress: Arc<Progress>) -> (Self, mpsc::UnboundedReceiver<Queued>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let queue = Self {
            room: Arc::new(Semaphore::new(capacity)),
            capacity,
            progress,
            tx,
        };
        (queue, rx)
    }

    /// Queue `msg`, waiting for room first. `false` if the other end is gone.
    async fn push(&self, msg: ChannelMsg) -> bool {
        let size = match &msg {
            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => data.len(),
            _ => 0,
        }
        .clamp(CONTROL_MESSAGE_BYTES, self.capacity);
        let Ok(permits) = u32::try_from(size) else {
            return false;
        };
        let room = {
            let _waiting = Waiting::new(&self.progress);
            Arc::clone(&self.room).acquire_many_owned(permits).await
        };
        // The semaphore is never closed.
        let Ok(room) = room else {
            return false;
        };
        self.progress.queued.fetch_add(size, Ordering::AcqRel);
        self.tx
            .send(Queued {
                msg,
                size,
                _room: room,
            })
            .is_ok()
    }
}

impl Queued {
    /// Count this message as delivered (its room is freed on drop).
    fn delivered(&self, progress: &Progress) {
        progress.queued.fetch_sub(self.size, Ordering::AcqRel);
        progress.delivered.fetch_add(1, Ordering::AcqRel);
    }
}

/// Carry the session until either side closes it, it stops making
/// progress or sits idle, the relay must end it (`live`: revoked or
/// expired), or `stop` fires; then close both channels, cutting a
/// connection that does not take its close in time. A session ended by
/// force has both connections cut after [`FORCED_CLOSE_WAIT`]. The agent's
/// data, EOF, window changes and signals go to the target; the target's
/// output, EOF, exit status and exit signal come back.
///
/// Each direction reads its source into a bounded queue and writes the
/// queue out separately, so a slow destination holds back only its own
/// source. The session ends when it stops making progress (see [`Watch`]).
pub(crate) async fn relay(
    ends: Ends,
    live: &mut Registration,
    mut stop: watch::Receiver<bool>,
    limits: Watch,
) -> Outcome {
    let Ends {
        agent,
        agent_handle,
        newline,
        agent_cut,
        target,
        target_cut,
        early,
    } = ends;
    let agent_id = agent.id();
    let (mut from_agent, to_agent) = agent.split();
    let (mut from_target, to_target) = target.split();
    let (up_progress, down_progress) =
        (Arc::new(Progress::default()), Arc::new(Progress::default()));
    let mut up = Delivered::default();
    let mut down = Delivered::default();
    let ended = tokio::select! {
        ended = upstream(&mut from_agent, &to_target, Arc::clone(&up_progress), &mut up) => ended,
        ended = downstream(&mut from_target, early, &to_agent, &agent_handle, agent_id, Arc::clone(&down_progress), &mut down) => ended,
        ended = watchdog(&up_progress, &down_progress, limits) => ended,
        ended = live.ended() => ended,
        () = super::server::stopping(&mut stop) => reason::SHUTDOWN,
    };
    if reason::forced(ended) {
        // Within the grace, a notice and a close for each side, a goodbye
        // to the agent, and each connection given the chance to end; then
        // both are cut, whatever state they are in.
        let agent_side = async {
            if let Some(notice) = reason::notice(ended) {
                let _ = to_agent
                    .extended_data_bytes(1, format!("{notice}{newline}").into_bytes())
                    .await;
            }
            let _ = to_agent.close().await;
            let goodbye = reason::notice(ended).unwrap_or("warden relay: session ended");
            let _ = agent_handle
                .disconnect(
                    Disconnect::ByApplication,
                    goodbye.to_owned(),
                    "en".to_owned(),
                )
                .await;
            while from_agent.wait().await.is_some() {}
        };
        let target_side = async {
            let _ = to_target.close().await;
            while let Some(msg) = from_target.wait().await {
                if matches!(msg, ChannelMsg::Close) {
                    break;
                }
            }
        };
        let _ = tokio::time::timeout(FORCED_CLOSE_WAIT, async {
            tokio::join!(agent_side, target_side)
        })
        .await;
        agent_cut.now();
        target_cut.now();
    } else {
        let (agent_closed, target_closed) = tokio::join!(
            tokio::time::timeout(CLOSE_WAIT, to_agent.close()),
            tokio::time::timeout(CLOSE_WAIT, to_target.close()),
        );
        // A connection whose event loop is held up cannot take the close.
        if agent_closed.is_err() {
            agent_cut.now();
        }
        if target_closed.is_err() {
            target_cut.now();
        }
    }
    Outcome {
        reason: if down.exited && !matches!(ended, reason::SHUTDOWN) && !reason::forced(ended) {
            reason::EXITED
        } else {
            ended
        },
        bytes_to_target: up.bytes,
        bytes_from_target: down.bytes,
        exit_status: down.exit_status,
    }
}

/// Resolves, with the reason, once the session stops making progress or
/// sits idle.
async fn watchdog(up: &Progress, down: &Progress, limits: Watch) -> &'static str {
    // Per direction (upstream, downstream): messages delivered at the last
    // check, and since when the direction has held data without delivering
    // any (`None` while it holds nothing). Quiet time with nothing queued
    // never counts.
    let mut delivered = [0_u64; 2];
    let mut held_since: [Option<tokio::time::Instant>; 2] = [None; 2];
    // Bytes read either way at the last check, and since when none were.
    let mut received = 0_u64;
    let mut quiet_since = tokio::time::Instant::now();
    loop {
        tokio::time::sleep(WATCH_EVERY).await;
        let now = tokio::time::Instant::now();
        let read = up
            .received
            .load(Ordering::Acquire)
            .wrapping_add(down.received.load(Ordering::Acquire));
        if read != received {
            received = read;
            quiet_since = now;
        } else if now.duration_since(quiet_since) >= limits.idle {
            return reason::IDLE;
        }
        let mut held = [Duration::ZERO; 2];
        for (i, progress) in [up, down].into_iter().enumerate() {
            let count = progress.delivered.load(Ordering::Acquire);
            let moved = count != delivered[i];
            delivered[i] = count;
            held_since[i] = if progress.queued.load(Ordering::Acquire) == 0 {
                None
            } else if moved {
                Some(now)
            } else {
                Some(held_since[i].unwrap_or(now))
            };
            held[i] = held_since[i].map_or(Duration::ZERO, |since| now.duration_since(since));
        }
        let both_waiting =
            up.waiting.load(Ordering::Acquire) && down.waiting.load(Ordering::Acquire);
        if both_waiting && held[0] >= limits.wedge && held[1] >= limits.wedge {
            return reason::DOWNSTREAM_STALLED;
        }
        if held[1] >= limits.stall {
            return reason::DOWNSTREAM_STALLED;
        }
        if held[0] >= limits.stall {
            return reason::UPSTREAM_STALLED;
        }
    }
}

/// What one direction delivered.
#[derive(Debug, Default)]
struct Delivered {
    /// Data bytes (stdout and stderr downstream).
    bytes: u64,
    exit_status: Option<u32>,
    /// Whether an exit status or signal came back.
    exited: bool,
}

/// Read the agent's side into its queue until the agent closes, while
/// delivering the queue to the target; returns why it stopped. What was
/// queued when the agent closed is still delivered.
async fn upstream(
    from_agent: &mut ChannelReadHalf,
    to_target: &ChannelWriteHalf<client::Msg>,
    progress: Arc<Progress>,
    delivered: &mut Delivered,
) -> &'static str {
    let (queue, mut queued) = Queue::new(UPSTREAM_QUEUE_BYTES, Arc::clone(&progress));
    let read = async move {
        loop {
            let msg = match from_agent.wait().await {
                Some(
                    msg @ (ChannelMsg::Data { .. }
                    | ChannelMsg::Eof
                    | ChannelMsg::WindowChange { .. }
                    | ChannelMsg::Signal { .. }),
                ) => msg,
                Some(ChannelMsg::Close) | None => return reason::CLIENT_CLOSED,
                // Requests were answered by the relay's handler; anything
                // else (stderr from the agent, window adjustments) means
                // nothing to the target.
                Some(_) => continue,
            };
            queue.progress.read(&msg);
            if !queue.push(msg).await {
                return reason::TARGET_CLOSED;
            }
        }
    };
    let write = async {
        while let Some(queued_msg) = queued.recv().await {
            let sent = match &queued_msg.msg {
                ChannelMsg::Data { data } => {
                    let n = len64(data.len());
                    let sent = to_target.data_bytes(data.clone()).await;
                    if sent.is_ok() {
                        delivered.bytes = delivered.bytes.saturating_add(n);
                    }
                    sent
                }
                ChannelMsg::Eof => to_target.eof().await,
                ChannelMsg::WindowChange {
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                } => {
                    to_target
                        .window_change(*col_width, *row_height, *pix_width, *pix_height)
                        .await
                }
                ChannelMsg::Signal { signal } => to_target.signal(signal.clone()).await,
                _ => Ok(()),
            };
            if sent.is_err() {
                return false;
            }
            queued_msg.delivered(&progress);
        }
        true
    };
    finish(read, write, reason::TARGET_CLOSED).await
}

/// Read the target's side (after what it sent during setup) into its queue
/// until the target closes, while delivering the queue to the agent;
/// returns why it stopped. What was queued when the target closed is still
/// delivered.
async fn downstream(
    from_target: &mut ChannelReadHalf,
    early: VecDeque<ChannelMsg>,
    to_agent: &ChannelWriteHalf<server::Msg>,
    agent_handle: &server::Handle,
    agent_id: ChannelId,
    progress: Arc<Progress>,
    delivered: &mut Delivered,
) -> &'static str {
    let (queue, mut queued) = Queue::new(DOWNSTREAM_QUEUE_BYTES, Arc::clone(&progress));
    let read = async move {
        let mut early = early;
        loop {
            let msg = match early.pop_front() {
                Some(msg) => Some(msg),
                None => from_target.wait().await,
            };
            let msg = match msg {
                Some(
                    msg @ (ChannelMsg::Data { .. }
                    | ChannelMsg::ExtendedData { .. }
                    | ChannelMsg::Eof
                    | ChannelMsg::ExitStatus { .. }
                    | ChannelMsg::ExitSignal { .. }),
                ) => msg,
                Some(ChannelMsg::Close) | None => return reason::TARGET_CLOSED,
                Some(_) => continue,
            };
            queue.progress.read(&msg);
            if !queue.push(msg).await {
                return reason::CLIENT_CLOSED;
            }
        }
    };
    let write = async {
        while let Some(queued_msg) = queued.recv().await {
            let sent = match &queued_msg.msg {
                ChannelMsg::Data { data } => {
                    delivered.bytes = delivered.bytes.saturating_add(len64(data.len()));
                    to_agent.data_bytes(data.clone()).await.is_ok()
                }
                ChannelMsg::ExtendedData { data, ext } => {
                    delivered.bytes = delivered.bytes.saturating_add(len64(data.len()));
                    to_agent
                        .extended_data_bytes(*ext, data.clone())
                        .await
                        .is_ok()
                }
                ChannelMsg::Eof => to_agent.eof().await.is_ok(),
                ChannelMsg::ExitStatus { exit_status } => {
                    delivered.exit_status = Some(*exit_status);
                    delivered.exited = true;
                    to_agent.exit_status(*exit_status).await.is_ok()
                }
                ChannelMsg::ExitSignal {
                    signal_name,
                    core_dumped,
                    error_message,
                    lang_tag,
                } => {
                    delivered.exited = true;
                    agent_handle
                        .exit_signal_request(
                            agent_id,
                            signal_name.clone(),
                            *core_dumped,
                            error_message.clone(),
                            lang_tag.clone(),
                        )
                        .await
                        .is_ok()
                }
                _ => true,
            };
            if !sent {
                return false;
            }
            queued_msg.delivered(&progress);
        }
        true
    };
    finish(read, write, reason::CLIENT_CLOSED).await
}

/// Run a direction's `read` and `write` halves together. When `read` ends
/// (its source closed), `write` delivers what is still queued and the
/// direction ends with `read`'s reason; if `write` fails first (its
/// destination is gone), the direction ends with `write_failed`.
async fn finish(
    read: impl Future<Output = &'static str>,
    write: impl Future<Output = bool>,
    write_failed: &'static str,
) -> &'static str {
    tokio::pin!(read, write);
    tokio::select! {
        ended = &mut read => {
            // `read` owned the queue's sender: with it gone, `write` stops
            // once the queue is empty.
            if (&mut write).await { ended } else { write_failed }
        }
        _ = &mut write => write_failed,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use warden_broker_proto::Id;

    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use std::time::Duration;

    use warden_broker_proto::{AgentName, TargetName, UnixUser};

    use crate::requests::RelayGrantRecord;

    use super::{
        LiveSessions, PreAuthLimiter, Program, Progress, Queue, Registration, SessionSlots,
        SlotRefusal, Watch, env_allowed, reason, watchdog,
    };

    fn data(len: usize) -> russh::ChannelMsg {
        russh::ChannelMsg::Data {
            data: vec![0_u8; len].into(),
        }
    }

    #[tokio::test]
    async fn queue_waits_for_room_and_reports_progress() {
        let progress = Arc::new(Progress::default());
        let (queue, mut rx) = Queue::new(1000, Arc::clone(&progress));
        assert!(queue.push(data(600)).await);
        // Control messages take room too, so they cannot pile up for free.
        assert!(queue.push(russh::ChannelMsg::Eof).await);
        assert_eq!(progress.queued.load(Ordering::Acquire), 664);
        let blocked = tokio::time::timeout(Duration::from_millis(100), queue.push(data(600))).await;
        assert!(blocked.is_err(), "a full queue makes the reader wait");
        // Delivering frees room and counts as progress.
        let first = rx.recv().await.unwrap();
        first.delivered(&progress);
        drop(first);
        assert_eq!(progress.delivered.load(Ordering::Acquire), 1);
        assert!(!progress.waiting.load(Ordering::Acquire));
        assert!(queue.push(data(600)).await);
        // A message larger than the whole queue still fits on its own.
        drop(rx.recv().await.unwrap());
        drop(rx.recv().await.unwrap());
        assert!(queue.push(data(5000)).await);
        drop(rx);
        assert!(!queue.push(data(1)).await, "the other end is gone");
    }

    fn limits(stall_secs: u64) -> Watch {
        Watch {
            stall: Duration::from_secs(stall_secs),
            wedge: Duration::from_secs(2),
            idle: Duration::from_secs(15 * 60),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_is_measured_from_the_last_byte_either_way() {
        let (up, down) = (Progress::default(), Progress::default());
        let limits = Watch {
            idle: Duration::from_secs(10),
            ..limits(60)
        };
        let watching = watchdog(&up, &down, limits);
        tokio::pin!(watching);
        // Bytes one way, then the other, every 8 s: never idle for 10 s.
        for (i, progress) in [&up, &down, &up, &down].into_iter().enumerate() {
            tokio::select! {
                why = &mut watching => panic!("ended after {i} rounds: {why}"),
                () = tokio::time::sleep(Duration::from_secs(8)) => {}
            }
            progress.received.fetch_add(1, Ordering::AcqRel);
        }
        // Then quiet: ended 10 s (and a check) after the last byte.
        let quiet = tokio::time::Instant::now();
        assert_eq!((&mut watching).await, reason::IDLE);
        let after = quiet.elapsed();
        assert!(
            after >= Duration::from_secs(10) && after <= Duration::from_millis(10_500),
            "{after:?}"
        );
    }

    fn grant(agent: &str, not_after: i64) -> RelayGrantRecord {
        RelayGrantRecord {
            grant_id: Id::random(),
            agent: AgentName::try_from(agent.to_owned()).unwrap(),
            target: TargetName::try_from("nas".to_owned()).unwrap(),
            user: UnixUser::try_from("backup".to_owned()).unwrap(),
            not_after,
        }
    }

    /// The reason `live` was told to end for, if it was.
    async fn told(live: &mut Registration) -> Option<&'static str> {
        tokio::time::timeout(Duration::from_millis(10), live.ended())
            .await
            .ok()
    }

    #[tokio::test]
    async fn live_sessions_end_by_grant_agent_or_expiry() {
        let sessions = LiveSessions::new();
        let (a, b, c) = (grant("a", 100), grant("a", 200), grant("c", 300));
        let mut a1 = sessions.register(&a);
        let mut a2 = sessions.register(&a);
        let mut b1 = sessions.register(&b);
        let mut c1 = sessions.register(&c);
        let mut ids = sessions.grant_ids();
        ids.sort_by(|x, y| x.as_str().cmp(y.as_str()));
        let mut want = vec![a.grant_id.clone(), b.grant_id.clone(), c.grant_id.clone()];
        want.sort_by(|x, y| x.as_str().cmp(y.as_str()));
        assert_eq!(ids, want, "each grant once");

        sessions.revoke_grant(&a.grant_id);
        assert_eq!(told(&mut a1).await, Some(reason::REVOKED));
        assert_eq!(told(&mut a2).await, Some(reason::REVOKED));
        assert_eq!(told(&mut b1).await, None, "another grant of the agent");
        assert_eq!(told(&mut c1).await, None);

        // The first reason stands.
        sessions.expire_due(150);
        assert_eq!(told(&mut a1).await, Some(reason::REVOKED));
        assert_eq!(told(&mut b1).await, None, "not past its window");
        sessions.expire_due(200);
        assert_eq!(told(&mut b1).await, Some(reason::EXPIRED));

        sessions.revoke_agent(&AgentName::try_from("c".to_owned()).unwrap());
        assert_eq!(told(&mut c1).await, Some(reason::REVOKED));
        sessions.expire_grant(&c.grant_id);
        assert_eq!(told(&mut c1).await, Some(reason::REVOKED));

        // Dropped registrations are no longer listed.
        drop((a1, a2, b1));
        assert_eq!(sessions.grant_ids(), vec![c.grant_id.clone()]);
        drop(c1);
        assert!(sessions.grant_ids().is_empty());
    }

    #[test]
    fn forced_reasons_and_their_notices() {
        for forced in [
            reason::REVOKED,
            reason::EXPIRED,
            reason::IDLE,
            reason::DOWNSTREAM_STALLED,
            reason::UPSTREAM_STALLED,
        ] {
            assert!(reason::forced(forced), "{forced}");
        }
        for gentle in [
            reason::EXITED,
            reason::TARGET_CLOSED,
            reason::CLIENT_CLOSED,
            reason::SHUTDOWN,
        ] {
            assert!(!reason::forced(gentle), "{gentle}");
            assert_eq!(reason::notice(gentle), None);
        }
        assert_eq!(
            reason::notice(reason::REVOKED),
            Some("warden relay: access revoked")
        );
        assert_eq!(reason::notice(reason::DOWNSTREAM_STALLED), None);
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_ends_wedged_and_stalled_sessions_only() {
        // Both directions held up (a waiting reader means a full queue),
        // nothing delivered: ended after 2 s.
        let (up, down) = (Progress::default(), Progress::default());
        for progress in [&up, &down] {
            progress.waiting.store(true, Ordering::Release);
            progress.queued.store(10, Ordering::Release);
        }
        let started = tokio::time::Instant::now();
        let why = watchdog(&up, &down, limits(60)).await;
        assert_eq!(why, reason::DOWNSTREAM_STALLED);
        assert!(started.elapsed() < Duration::from_secs(3));

        // One direction holding data nothing delivers: ended after the
        // stall timeout, not before.
        let (up, down) = (Progress::default(), Progress::default());
        up.queued.store(10, Ordering::Release);
        up.waiting.store(true, Ordering::Release);
        let started = tokio::time::Instant::now();
        let why = watchdog(&up, &down, limits(60)).await;
        assert_eq!(why, reason::UPSTREAM_STALLED);
        assert!(started.elapsed() >= Duration::from_secs(60));

        // Progress keeps a session alive, even with the other direction
        // held up all along.
        let (up, down) = (Progress::default(), Progress::default());
        for progress in [&up, &down] {
            progress.waiting.store(true, Ordering::Release);
            progress.queued.store(10, Ordering::Release);
        }
        let moving = async {
            for _ in 0..40 {
                tokio::time::sleep(Duration::from_millis(500)).await;
                down.delivered.fetch_add(1, Ordering::AcqRel);
            }
        };
        tokio::select! {
            why = watchdog(&up, &down, limits(60)) => panic!("ended: {why}"),
            () = moving => {}
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_then_prompt_delivery_is_not_stalled() {
        // An idle shell: nothing queued or delivered for over a minute.
        let (up, down) = (Progress::default(), Progress::default());
        let watching = watchdog(&up, &down, limits(60));
        tokio::pin!(watching);
        tokio::select! {
            why = &mut watching => panic!("idle session ended: {why}"),
            () = tokio::time::sleep(Duration::from_secs(61)) => {}
        }
        // A keystroke is queued and delivered 300 ms later.
        up.queued.store(64, Ordering::Release);
        tokio::select! {
            why = &mut watching => panic!("first keystroke ended the session: {why}"),
            () = tokio::time::sleep(Duration::from_millis(300)) => {}
        }
        up.queued.store(0, Ordering::Release);
        up.delivered.fetch_add(1, Ordering::AcqRel);
        tokio::select! {
            why = &mut watching => panic!("ended after delivery: {why}"),
            () = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }

    #[tokio::test(start_paused = true)]
    async fn held_data_without_delivery_still_stalls() {
        // After a long idle spell, data that is then held for the stall
        // timeout without any delivery ends the session, and not before.
        let (up, down) = (Progress::default(), Progress::default());
        let watching = watchdog(&up, &down, limits(60));
        tokio::pin!(watching);
        tokio::select! {
            why = &mut watching => panic!("idle session ended: {why}"),
            () = tokio::time::sleep(Duration::from_secs(120)) => {}
        }
        down.queued.store(4096, Ordering::Release);
        let held = tokio::time::Instant::now();
        tokio::select! {
            why = &mut watching => panic!("ended early: {why}"),
            () = tokio::time::sleep(Duration::from_secs(59)) => {}
        }
        let why = (&mut watching).await;
        assert_eq!(why, reason::DOWNSTREAM_STALLED);
        let after = held.elapsed();
        assert!(
            after >= Duration::from_secs(60) && after < Duration::from_secs(62),
            "{after:?}"
        );
    }

    #[test]
    fn shell_is_audited_without_a_command() {
        assert_eq!(Program::Shell.audited(), None);
    }

    #[test]
    fn commands_are_cut_to_200_characters() {
        let short = Program::Exec(b"echo ok".to_vec());
        assert_eq!(short.audited().as_deref(), Some("echo ok"));
        let exact = "é".repeat(200);
        assert_eq!(
            Program::Exec(exact.clone().into_bytes()).audited(),
            Some(exact)
        );
        let long = Program::Exec("é".repeat(201).into_bytes())
            .audited()
            .unwrap();
        assert_eq!(long, format!("{}…", "é".repeat(200)));
        // Invalid UTF-8 is recorded, replaced, rather than refused.
        let odd = Program::Exec(vec![b'a', 0xff, b'b']).audited().unwrap();
        assert_eq!(odd, "a\u{fffd}b");
    }

    #[test]
    fn only_locale_and_terminal_variables_pass() {
        for name in ["LANG", "TERM", "LC_ALL", "LC_TIME", "LC_MESSAGES"] {
            assert!(env_allowed(name, "C.UTF-8"), "{name}");
        }
        for name in [
            "PATH",
            "LD_PRELOAD",
            "LC_",
            "LC_all",
            "LC_X1",
            "lang",
            "TERMINFO",
            "BASH_ENV",
            "",
        ] {
            assert!(!env_allowed(name, "x"), "{name}");
        }
        assert!(env_allowed("LANG", &"x".repeat(256)));
        assert!(!env_allowed("LANG", &"x".repeat(257)));
        assert!(!env_allowed("TERM", "xterm\0evil"));
    }

    #[test]
    fn sessions_limited_per_grant_and_overall() {
        let slots = SessionSlots::new(3, 2);
        let (a, b) = (Id::random(), Id::random());
        let a1 = slots.try_acquire(&a).unwrap();
        let a2 = slots.try_acquire(&a).unwrap();
        assert_eq!(slots.try_acquire(&a).unwrap_err(), SlotRefusal::Grant);
        let b1 = slots.try_acquire(&b).unwrap();
        assert_eq!(slots.try_acquire(&b).unwrap_err(), SlotRefusal::Total);
        drop(a1);
        let b2 = slots.try_acquire(&b).unwrap();
        assert_eq!(slots.live(), (3, 2));
        drop((a2, b1, b2));
        // Nothing is left behind for grants with no session.
        assert_eq!(slots.live(), (0, 0));
    }

    #[test]
    fn unauthenticated_connections_limited_per_address_and_overall() {
        let limiter = PreAuthLimiter::new(3, 2);
        let ip = |n| IpAddr::V4(Ipv4Addr::new(192, 0, 2, n));
        let first = limiter.try_admit(ip(1)).unwrap();
        let _second = limiter.try_admit(ip(1)).unwrap();
        assert!(limiter.try_admit(ip(1)).is_none());
        let _third = limiter.try_admit(ip(2)).unwrap();
        assert!(limiter.try_admit(ip(3)).is_none());
        drop(first);
        assert!(limiter.try_admit(ip(3)).is_some());
        let again = limiter.try_admit(ip(1));
        assert!(again.is_some());
    }
}
