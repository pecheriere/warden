//! One relayed session: how many may run, what the agent asked for before
//! it started, and the loop that carries bytes, EOF, window changes,
//! signals and the exit status between the agent and the target.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

use russh::client;
use russh::server;
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Pty};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use warden_broker_proto::Id;

/// Longest command recorded in the audit log, in characters.
const COMMAND_AUDIT_CHARS: usize = 200;

/// Most environment variables an agent may pass on.
pub(crate) const MAX_ENV_VARS: usize = 32;

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

/// Both ends of a started session.
pub(crate) struct Ends {
    /// The agent's session channel.
    pub agent: Channel<server::Msg>,
    /// The agent connection, for an exit signal.
    pub agent_handle: server::Handle,
    /// The target's session channel, its command started.
    pub target: Channel<client::Msg>,
    /// What the target sent while the session was being set up, in order.
    pub early: VecDeque<ChannelMsg>,
}

fn len64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Bytes of the agent's input held between the agent's connection and the
/// target's.
const UPSTREAM_QUEUE_BYTES: usize = 2 * 1024 * 1024;
/// Bytes of the target's output held between the two connections. Larger
/// than [`UPSTREAM_QUEUE_BYTES`] plus the SSH window the relay grants the
/// agent (2 MiB), so a target echoing its input never fills it while the
/// agent's window updates wait behind the input queued ahead of them.
const DOWNSTREAM_QUEUE_BYTES: usize = 8 * 1024 * 1024;
/// What a message other than data counts for in a queue.
const CONTROL_MESSAGE_BYTES: usize = 64;

/// A message on its way from one connection to the other, holding its room
/// in the queue until it is delivered.
struct Queued {
    msg: ChannelMsg,
    _room: OwnedSemaphorePermit,
}

/// A queue of messages between the two connections, bounded in bytes.
struct Queue {
    room: Arc<Semaphore>,
    capacity: usize,
    tx: mpsc::UnboundedSender<Queued>,
}

impl Queue {
    fn new(capacity: usize) -> (Self, mpsc::UnboundedReceiver<Queued>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let queue = Self {
            room: Arc::new(Semaphore::new(capacity)),
            capacity,
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
        let Ok(room) = u32::try_from(size) else {
            return false;
        };
        // The semaphore is never closed.
        let Ok(room) = Arc::clone(&self.room).acquire_many_owned(room).await else {
            return false;
        };
        self.tx.send(Queued { msg, _room: room }).is_ok()
    }
}

/// Carry the session until either side closes it or `stop` fires, then
/// close both channels. The agent's data, EOF, window changes and signals
/// go to the target; the target's output, EOF, exit status and exit signal
/// come back.
///
/// Each connection's SSH event loop stops reading (window updates and
/// outgoing data included) while a channel's inbound queue is full, so
/// each direction reads its source into a bounded queue of its own and
/// writes it out separately: reading never waits on the other connection,
/// and the two loops cannot end up waiting on each other.
pub(crate) async fn relay(ends: Ends, mut stop: watch::Receiver<bool>) -> Outcome {
    let Ends {
        agent,
        agent_handle,
        target,
        early,
    } = ends;
    let agent_id = agent.id();
    let (mut from_agent, to_agent) = agent.split();
    let (mut from_target, to_target) = target.split();
    let mut up = Delivered::default();
    let mut down = Delivered::default();
    let ended = tokio::select! {
        ended = upstream(&mut from_agent, &to_target, &mut up) => ended,
        ended = downstream(&mut from_target, early, &to_agent, &agent_handle, agent_id, &mut down) => ended,
        () = super::server::stopping(&mut stop) => reason::SHUTDOWN,
    };
    // Best effort: either side may already be gone.
    let _ = to_agent.close().await;
    let _ = to_target.close().await;
    Outcome {
        reason: if down.exited && ended != reason::SHUTDOWN {
            reason::EXITED
        } else {
            ended
        },
        bytes_to_target: up.bytes,
        bytes_from_target: down.bytes,
        exit_status: down.exit_status,
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

/// Read the agent's side into a queue until the agent closes, while
/// delivering the queue to the target; returns why it stopped. What was
/// queued when the agent closed is still delivered.
async fn upstream(
    from_agent: &mut ChannelReadHalf,
    to_target: &ChannelWriteHalf<client::Msg>,
    delivered: &mut Delivered,
) -> &'static str {
    let (queue, mut queued) = Queue::new(UPSTREAM_QUEUE_BYTES);
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
            if !queue.push(msg).await {
                return reason::TARGET_CLOSED;
            }
        }
    };
    let write = async {
        while let Some(Queued { msg, _room }) = queued.recv().await {
            let sent = match msg {
                ChannelMsg::Data { data } => {
                    let n = len64(data.len());
                    let sent = to_target.data_bytes(data).await;
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
                        .window_change(col_width, row_height, pix_width, pix_height)
                        .await
                }
                ChannelMsg::Signal { signal } => to_target.signal(signal).await,
                _ => Ok(()),
            };
            if sent.is_err() {
                return false;
            }
        }
        true
    };
    finish(read, write, reason::TARGET_CLOSED).await
}

/// Read the target's side (after what it sent during setup) into a queue
/// until the target closes, while delivering the queue to the agent;
/// returns why it stopped. What was queued when the target closed is still
/// delivered.
async fn downstream(
    from_target: &mut ChannelReadHalf,
    early: VecDeque<ChannelMsg>,
    to_agent: &ChannelWriteHalf<server::Msg>,
    agent_handle: &server::Handle,
    agent_id: ChannelId,
    delivered: &mut Delivered,
) -> &'static str {
    let (queue, mut queued) = Queue::new(DOWNSTREAM_QUEUE_BYTES);
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
            if !queue.push(msg).await {
                return reason::CLIENT_CLOSED;
            }
        }
    };
    let write = async {
        while let Some(Queued { msg, _room }) = queued.recv().await {
            let sent = match msg {
                ChannelMsg::Data { data } => {
                    delivered.bytes = delivered.bytes.saturating_add(len64(data.len()));
                    to_agent.data_bytes(data).await.is_ok()
                }
                ChannelMsg::ExtendedData { data, ext } => {
                    delivered.bytes = delivered.bytes.saturating_add(len64(data.len()));
                    to_agent.extended_data_bytes(ext, data).await.is_ok()
                }
                ChannelMsg::Eof => to_agent.eof().await.is_ok(),
                ChannelMsg::ExitStatus { exit_status } => {
                    delivered.exit_status = Some(exit_status);
                    delivered.exited = true;
                    to_agent.exit_status(exit_status).await.is_ok()
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
                            signal_name,
                            core_dumped,
                            error_message,
                            lang_tag,
                        )
                        .await
                        .is_ok()
                }
                _ => true,
            };
            if !sent {
                return false;
            }
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

    use super::{PreAuthLimiter, Program, Queue, SessionSlots, SlotRefusal, env_allowed};

    fn data(len: usize) -> russh::ChannelMsg {
        russh::ChannelMsg::Data {
            data: vec![0_u8; len].into(),
        }
    }

    #[tokio::test]
    async fn queue_waits_for_room_and_frees_it_on_delivery() {
        let (queue, mut rx) = Queue::new(1000);
        assert!(queue.push(data(600)).await);
        // Control messages take room too, so they cannot pile up for free.
        assert!(queue.push(russh::ChannelMsg::Eof).await);
        let blocked =
            tokio::time::timeout(std::time::Duration::from_millis(100), queue.push(data(600)))
                .await;
        assert!(blocked.is_err(), "a full queue makes the reader wait");
        // Delivering the first message frees its room.
        drop(rx.recv().await.unwrap());
        assert!(queue.push(data(600)).await);
        // A message larger than the whole queue still fits on its own.
        drop(rx.recv().await.unwrap());
        drop(rx.recv().await.unwrap());
        assert!(queue.push(data(5000)).await);
        drop(rx);
        assert!(!queue.push(data(1)).await, "the other end is gone");
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
