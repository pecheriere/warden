//! The loop that carries bytes, EOF, window changes, signals and the exit
//! status between the agent and the target, and the watchdog that ends a
//! session that stops making progress.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use russh::client;
use russh::server;
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Disconnect};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};

use crate::requests::Clock;

use crate::relay::read_ahead::AgentGone;

use super::live::Registration;
use super::{Outcome, reason};

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
    /// gets there in seconds.
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

/// How long a session whose agent left goes on while the agent's input is
/// held up with nothing delivered to the target (see [`agent_left`]).
const LEFT_AND_HELD: Duration = Duration::from_secs(2);

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
pub(crate) fn with_cutoff(socket: TcpStream) -> std::io::Result<(TcpStream, Cutoff)> {
    let socket = socket.into_std()?;
    let cutoff = Cutoff(socket.try_clone()?);
    Ok((TcpStream::from_std(socket)?, cutoff))
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
    /// Whether the agent closed its connection.
    pub agent_gone: AgentGone,
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

/// Carry the session until either side closes it (the agent also when it
/// leaves with its input held up, see [`agent_left`]), it stops making
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
    clock: &dyn Clock,
) -> Outcome {
    let Ends {
        agent,
        agent_handle,
        newline,
        agent_cut,
        agent_gone,
        target,
        target_cut,
        early,
    } = ends;
    let agent_id = agent.id();
    let (mut from_agent, to_agent) = agent.split();
    let (mut from_target, to_target) = target.split();
    let (up_progress, down_progress) =
        (Arc::new(Progress::default()), Arc::new(Progress::default()));
    let (to_target_bytes, from_target_bytes) = live.counters();
    let mut up = Delivered::new(to_target_bytes);
    let mut down = Delivered::new(from_target_bytes);
    let moved = {
        let last_activity = Arc::clone(&live.last_activity);
        move || last_activity.store(clock.now(), Ordering::Relaxed)
    };
    let (ended, left) = {
        let own = async {
            tokio::select! {
                ended = upstream(&mut from_agent, &to_target, Arc::clone(&up_progress), &mut up) => (ended, false),
                ended = downstream(&mut from_target, early, &to_agent, &agent_handle, agent_id, Arc::clone(&down_progress), &mut down) => (ended, false),
                ended = watchdog(&up_progress, &down_progress, limits, moved) => (ended, false),
                () = agent_left(agent_gone, &up_progress) => (reason::CLIENT_CLOSED, true),
            }
        };
        // Pinned here, not moved into `first_end`, which would hold it twice.
        tokio::pin!(own);
        first_end(live, &mut stop, own).await
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
    } else if left {
        // Nobody is left to take a close on the agent's side, whose event
        // loop is held up anyway: its connection is cut, the target's
        // closed.
        agent_cut.now();
        if tokio::time::timeout(CLOSE_WAIT, to_target.close())
            .await
            .is_err()
        {
            target_cut.now();
        }
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
        bytes_to_target: up.bytes.load(Ordering::Relaxed),
        bytes_from_target: down.bytes.load(Ordering::Relaxed),
        exit_status: down.exit_status,
    }
}

/// How a session ended: `(reason, whether the agent left)`. Why the relay
/// told it to end (it is stopping, or `live` was revoked, expired or failed
/// closed) when it was told; otherwise `own`, how it ended by itself.
///
/// The told cause is looked at first on every poll. Ending a session cuts
/// its connections (the relay hanging up on the agent when it stops, the
/// session itself otherwise), and whatever follows from that cut (the
/// agent's side closing, see [`agent_left`]) comes after the cause was told,
/// so it is never taken for why the session ended. An agent that leaves by
/// itself before anything is told still ends the session as it did.
pub(super) async fn first_end(
    live: &mut Registration,
    stop: &mut watch::Receiver<bool>,
    own: impl Future<Output = (&'static str, bool)>,
) -> (&'static str, bool) {
    tokio::select! {
        biased;
        () = crate::relay::server::stopping(stop) => (reason::SHUTDOWN, false),
        ended = live.ended() => (ended, false),
        own = own => own,
    }
}

/// Resolves once the agent's connection is closed and the agent's input
/// has been held up, nothing of it delivered to the target, for
/// [`LEFT_AND_HELD`].
///
/// While the relay reads the agent's channel, the SSH library sees the
/// agent leave itself, after what the agent sent before leaving, which is
/// still delivered. But while the relay waits for room in the input's
/// queue (the target not reading), the library's whole event loop is held
/// up and sees nothing; the read-ahead (see [`crate::relay::read_ahead`]) still
/// does. Input still held when the agent leaves is dropped: nobody is left
/// to see what it would have done.
/// Only it and the session's counters are looked at: nothing here waits
/// on either connection.
async fn agent_left(mut gone: AgentGone, up: &Progress) {
    gone.wait().await;
    let mut delivered = up.delivered.load(Ordering::Acquire);
    let mut held_since = tokio::time::Instant::now();
    loop {
        tokio::time::sleep(WATCH_EVERY).await;
        let now = tokio::time::Instant::now();
        let count = up.delivered.load(Ordering::Acquire);
        if count != delivered || !up.waiting.load(Ordering::Acquire) {
            delivered = count;
            held_since = now;
        } else if now.duration_since(held_since) >= LEFT_AND_HELD {
            return;
        }
    }
}

/// Resolves, with the reason, once the session stops making progress or
/// sits idle. Calls `moved` at a check that finds bytes were read either way
/// since the last one: what the owner's view shows as idle time is the time
/// this limit counts, and taking it here costs the path that carries the
/// bytes nothing.
async fn watchdog(up: &Progress, down: &Progress, limits: Watch, moved: impl Fn()) -> &'static str {
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
            moved();
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
            return reason::WEDGED;
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
#[derive(Debug)]
struct Delivered {
    /// Data bytes (stdout and stderr downstream), shared with the live
    /// session's listing.
    bytes: Arc<AtomicU64>,
    exit_status: Option<u32>,
    /// Whether an exit status or signal came back.
    exited: bool,
}

impl Delivered {
    fn new(bytes: Arc<AtomicU64>) -> Self {
        Self {
            bytes,
            exit_status: None,
            exited: false,
        }
    }

    /// Count `n` more data bytes delivered.
    fn add(&self, n: u64) {
        // Saturating, like the totals recorded in the audit log.
        let _ = self
            .bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |b| {
                Some(b.saturating_add(n))
            });
    }
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
                        delivered.add(n);
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
                    delivered.add(len64(data.len()));
                    to_agent.data_bytes(data.clone()).await.is_ok()
                }
                ChannelMsg::ExtendedData { data, ext } => {
                    delivered.add(len64(data.len()));
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
mod tests;
