//! One connection's SSH event handler: what the agent asked for before its
//! session starts, and starting it.

use std::sync::Arc;

use russh::server::{self, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, Disconnect};
use tokio::sync::{oneshot, watch};

use crate::requests::RelayGrantRecord;

use crate::relay::read_ahead::{AgentGone, LoggedIn};
use crate::relay::session::{self, Cutoff, Ends, PreAuthPermit, Program, PtyRequest, SessionSlot};

use super::conn::{Conn, OverOnDrop};
use super::start::{open_target, record_end, refuse_session};
use super::{
    INTERNAL, MAX_PRE_START_BYTES, MAX_PRE_START_MESSAGES, REFUSED_EXIT_STATUS, SHUTTING_DOWN,
    Shared, TOO_MUCH_INPUT,
};

mod protocol;

/// Who logged in: the grant matched, and the key it was matched by.
#[derive(Clone)]
pub(super) struct Login {
    pub(super) grant: RelayGrantRecord,
    pub(super) key: ssh_key::PublicKey,
}

/// One connection's SSH event handler.
pub(super) struct RelayHandler {
    shared: Arc<Shared>,
    conn: Arc<Conn>,
    /// Held until login; dropping it frees a pre-login place.
    preauth: Option<PreAuthPermit>,
    stop: watch::Receiver<bool>,
    login: Option<Login>,
    /// Held from login until the connection is gone: an agent still taking
    /// the end of its session counts against the limits.
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
    /// Whether the agent closed this connection.
    gone: AgentGone,
    /// Raises the connection's read-ahead once the agent logged in.
    logged_in: LoggedIn,
}

impl RelayHandler {
    pub(super) fn new(
        shared: Arc<Shared>,
        conn: Arc<Conn>,
        permit: PreAuthPermit,
        stop: watch::Receiver<bool>,
        cut: Arc<Cutoff>,
        gone: AgentGone,
        logged_in: LoggedIn,
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
            gone,
            logged_in,
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
        let (Some(login), Some(agent), Some(_)) =
            (self.login.as_ref(), self.channel.take(), self.slot.as_ref())
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
        let (agent_cut, agent_gone) = (Arc::clone(&self.cut), self.gone.clone());
        let over = OverOnDrop(self.conn.phase.clone());
        let newline = if pty.is_some() { "\r\n" } else { "\n" };
        let spawn = move || {
            tokio::spawn(async move {
                let _over = over;
                // Listed before the grant is checked again: a revocation
                // after the check still reaches the session.
                let mut live = shared
                    .requests
                    .live_sessions()
                    .register(&login.grant, shared.requests.now());
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
                    agent_gone,
                    target,
                    target_cut,
                    early,
                };
                let watch = session::Watch {
                    stall: shared.limits.stall_timeout,
                    wedge: shared.limits.wedge_timeout,
                    idle: shared.limits.idle_timeout,
                };
                let outcome = session::relay(
                    ends,
                    &mut live,
                    stop,
                    watch,
                    shared.requests.clock().as_ref(),
                )
                .await;
                if session::reason::forced(outcome.reason) {
                    // Given its chance to close already.
                    hang_up.cut();
                } else {
                    hang_up.now().await;
                }
                // A revocation or expiry that reached the session while it
                // ended otherwise (or while it was torn down) is what ended
                // it, on record. Still listed until here, so none is missed;
                // unlisted before the end is recorded, so the owner's view
                // never shows a session whose end is on record.
                let outcome = outcome.settled(live.told());
                drop(live);
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
