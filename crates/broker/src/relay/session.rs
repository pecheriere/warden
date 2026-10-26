//! One relayed session: how many may run, what the agent asked for before
//! it started, and the loop that carries bytes, EOF, window changes,
//! signals and the exit status between the agent and the target.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

use russh::client;
use russh::server;
use russh::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Pty};
use tokio::sync::watch;
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

/// Carry the session until either side closes it or `stop` fires, then
/// close both channels. The agent's data, EOF, window changes and signals
/// go to the target; the target's output, EOF, exit status and exit signal
/// come back. Both directions run at once, so a side that is not reading
/// cannot stall the other.
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
    let mut bytes_to_target = 0_u64;
    let mut back = Downstream {
        early,
        bytes: 0,
        exit_status: None,
        exited: false,
    };
    let ended = tokio::select! {
        ended = upstream(&mut from_agent, &to_target, &mut bytes_to_target) => ended,
        ended = back.run(&mut from_target, &to_agent, &agent_handle, agent_id) => ended,
        () = super::server::stopping(&mut stop) => reason::SHUTDOWN,
    };
    // Best effort: either side may already be gone.
    let _ = to_agent.close().await;
    let _ = to_target.close().await;
    Outcome {
        reason: if back.exited && ended != reason::SHUTDOWN {
            reason::EXITED
        } else {
            ended
        },
        bytes_to_target,
        bytes_from_target: back.bytes,
        exit_status: back.exit_status,
    }
}

/// Carry the agent's side to the target until either closes; returns why
/// it stopped. `bytes` counts the data passed on.
async fn upstream(
    from_agent: &mut ChannelReadHalf,
    to_target: &ChannelWriteHalf<client::Msg>,
    bytes: &mut u64,
) -> &'static str {
    loop {
        let sent = match from_agent.wait().await {
            Some(ChannelMsg::Data { data }) => {
                let n = len64(data.len());
                let sent = to_target.data_bytes(data).await;
                if sent.is_ok() {
                    *bytes = bytes.saturating_add(n);
                }
                sent
            }
            Some(ChannelMsg::Eof) => to_target.eof().await,
            Some(ChannelMsg::WindowChange {
                col_width,
                row_height,
                pix_width,
                pix_height,
            }) => {
                to_target
                    .window_change(col_width, row_height, pix_width, pix_height)
                    .await
            }
            Some(ChannelMsg::Signal { signal }) => to_target.signal(signal).await,
            Some(ChannelMsg::Close) | None => return reason::CLIENT_CLOSED,
            // Requests were answered by the relay's handler; anything else
            // (stderr from the agent, window adjustments) means nothing to
            // the target.
            Some(_) => Ok(()),
        };
        if sent.is_err() {
            return reason::TARGET_CLOSED;
        }
    }
}

/// The target's side of a session, carried back to the agent.
struct Downstream {
    /// What the target sent while the session was set up, delivered first.
    early: VecDeque<ChannelMsg>,
    /// Output passed back (stdout and stderr).
    bytes: u64,
    exit_status: Option<u32>,
    /// Whether an exit status or signal came back.
    exited: bool,
}

impl Downstream {
    /// Carry the target's side to the agent until either closes; returns
    /// why it stopped.
    async fn run(
        &mut self,
        from_target: &mut ChannelReadHalf,
        to_agent: &ChannelWriteHalf<server::Msg>,
        agent_handle: &server::Handle,
        agent_id: ChannelId,
    ) -> &'static str {
        loop {
            let msg = match self.early.pop_front() {
                Some(msg) => Some(msg),
                None => from_target.wait().await,
            };
            let delivered = match msg {
                Some(ChannelMsg::Data { data }) => {
                    self.bytes = self.bytes.saturating_add(len64(data.len()));
                    to_agent.data_bytes(data).await.is_ok()
                }
                Some(ChannelMsg::ExtendedData { data, ext }) => {
                    self.bytes = self.bytes.saturating_add(len64(data.len()));
                    to_agent.extended_data_bytes(ext, data).await.is_ok()
                }
                Some(ChannelMsg::Eof) => to_agent.eof().await.is_ok(),
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    self.exit_status = Some(exit_status);
                    self.exited = true;
                    to_agent.exit_status(exit_status).await.is_ok()
                }
                Some(ChannelMsg::ExitSignal {
                    signal_name,
                    core_dumped,
                    error_message,
                    lang_tag,
                }) => {
                    self.exited = true;
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
                Some(ChannelMsg::Close) | None => return reason::TARGET_CLOSED,
                Some(_) => true,
            };
            if !delivered {
                return reason::CLIENT_CLOSED;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use warden_broker_proto::Id;

    use super::{PreAuthLimiter, Program, SessionSlots, SlotRefusal, env_allowed};

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
