//! One relayed session: how many may run, which are live (so revocation
//! and expiry can end them), what the agent asked for before it started,
//! and the loop that carries bytes, EOF, window changes, signals and the
//! exit status between the agent and the target.

use russh::Pty;

mod limits;
mod live;
mod pump;

pub(crate) use limits::{PreAuthLimiter, PreAuthPermit, SessionSlot, SessionSlots};
pub(crate) use live::{LiveSessionInfo, LiveSessions, Registration};
pub(crate) use pump::{Cutoff, Ends, Watch, relay, with_cutoff};

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
    /// Both directions were held up at once with nothing delivered: the
    /// two connections were waiting on each other.
    pub const WEDGED: &str = "flow control: both directions held up";
    /// The grant (or its agent) was revoked.
    pub const REVOKED: &str = "revoked";
    /// The grant's window ended.
    pub const EXPIRED: &str = "expired";
    /// No bytes went either way for the idle timeout.
    pub const IDLE: &str = "idle timeout";
    /// The state of grants could not be read for too long: the relay
    /// cannot tell revoked grants, so it ends every session.
    pub const GRANT_STATE_UNAVAILABLE: &str = "grant state unavailable";

    /// Told to agents whose session ends, or cannot start, while the state
    /// of grants cannot be read.
    pub const GRANT_STATE_NOTICE: &str = "warden relay: access cannot be checked right now";

    /// Whether the relay ends a session ended for `reason` by force: both
    /// connections are cut after a short grace, whatever their state.
    #[must_use]
    pub fn forced(reason: &str) -> bool {
        reason.starts_with(FLOW_CONTROL)
            || matches!(reason, REVOKED | EXPIRED | IDLE | GRANT_STATE_UNAVAILABLE)
    }

    /// What the agent is told when its session ends for `reason`, if
    /// anything.
    #[must_use]
    pub fn notice(reason: &str) -> Option<&'static str> {
        match reason {
            REVOKED => Some("warden relay: access revoked"),
            EXPIRED => Some("warden relay: access expired"),
            IDLE => Some("warden relay: session idle for too long"),
            GRANT_STATE_UNAVAILABLE => Some(GRANT_STATE_NOTICE),
            _ => None,
        }
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

/// How a relayed session went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub reason: &'static str,
    pub bytes_to_target: u64,
    pub bytes_from_target: u64,
    pub exit_status: Option<u32>,
}

impl Outcome {
    /// The outcome to record, given why the relay was told to end the
    /// session (`told`, see [`Registration::told`]) by the time its teardown
    /// completed. A revocation or expiry told by then is the reason on
    /// record, even if the session also ended otherwise (the target exited
    /// in the same instant, say): the owner sees that it was cut off. The
    /// bytes and exit status stay as they were.
    #[must_use]
    pub(crate) fn settled(self, told: Option<&'static str>) -> Self {
        match told {
            Some(ending @ (reason::REVOKED | reason::EXPIRED)) => Self {
                reason: ending,
                ..self
            },
            _ => self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Program, env_allowed, reason};

    #[test]
    fn forced_reasons_and_their_notices() {
        for forced in [
            reason::REVOKED,
            reason::EXPIRED,
            reason::IDLE,
            reason::GRANT_STATE_UNAVAILABLE,
            reason::DOWNSTREAM_STALLED,
            reason::UPSTREAM_STALLED,
            reason::WEDGED,
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
}
