//! One agent connection: its login phase, how long it may stay, and how
//! its handler and its session task tell its task where they are.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use russh::Disconnect;
use russh::server::{self};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::audit::{AuditEvent, AuditLog};

use crate::relay::read_ahead::read_ahead;
use crate::relay::session::{PreAuthPermit, with_cutoff};

use super::handler::RelayHandler;
use super::{GOODBYE_WAIT, LOGIN_TIMEOUT, NOT_STARTED, SESSION_OVER, SHUTTING_DOWN, Shared};

/// Refused login attempts on one connection.
#[derive(Debug, Default)]
struct Refusals {
    user: Option<String>,
    attempts: u32,
}

/// What a connection's handler tells its task.
pub(super) struct Conn {
    pub(super) logged_in: watch::Sender<bool>,
    refusals: Mutex<Refusals>,
    relayed: Mutex<Relayed>,
    pub(super) phase: watch::Sender<Phase>,
}

/// Where a connection's session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    /// Not started.
    Waiting,
    /// Its task is running.
    Running,
    /// Its task is done.
    Over,
}

/// Marks a connection's session as over when dropped (also if its task
/// panicked).
pub(super) struct OverOnDrop(pub(super) watch::Sender<Phase>);

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
    pub(super) fn register(&self, spawn: impl FnOnce() -> JoinHandle<()>) -> bool {
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

    pub(super) fn refused(&self, user: &str) {
        let mut refusals = self.refusals.lock().unwrap_or_else(PoisonError::into_inner);
        refusals.user = Some(user.to_owned());
        refusals.attempts = refusals.attempts.saturating_add(1);
    }
}

/// Serve one agent connection: the login phase (bounded by the login
/// timeout), then the session until it ends or the relay stops.
pub(super) async fn connection(
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
    // Read ahead of the SSH library, so the agent leaving is seen even
    // while a session holds the library up; stopped with the connection.
    let (socket, gone, logged_in, _read_ahead) = read_ahead(socket);
    let handler = RelayHandler::new(
        Arc::clone(&shared),
        Arc::clone(&conn),
        permit,
        stop.clone(),
        Arc::clone(&cut),
        gone,
        logged_in,
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
                message = no_more_use(&mut phase, start_by, shared.limits.stall_timeout) => {
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
/// agent did not leave within `leave_within`.
///
/// The session being over means the relay handed the end of its output,
/// the exit status and the close to the SSH library, not that the agent has
/// them: up to a channel window of output may still be on its way, or wait
/// in the agent for its reader. The agent closes its end of the channel
/// only once it has taken all of it, and the SSH library does not report
/// that close, so the agent's leaving is what is waited for: as long as it
/// may go without taking any output during the session.
async fn no_more_use(
    phase: &mut watch::Receiver<Phase>,
    start_by: Instant,
    leave_within: Duration,
) -> &'static str {
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
    tokio::time::sleep(leave_within).await;
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
pub(super) fn ours(key: &russh::keys::PublicKey) -> Option<ssh_key::PublicKey> {
    let text = key.to_openssh().ok()?;
    ssh_key::PublicKey::from_openssh(&text).ok()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use tokio::sync::watch;
    use tokio::time::Instant;

    use super::super::{NOT_STARTED, SESSION_OVER};
    use super::{Conn, OverOnDrop, Phase, Refusals, Relayed, no_more_use};

    fn conn() -> Conn {
        Conn {
            logged_in: tokio::sync::watch::channel(false).0,
            refusals: Mutex::new(Refusals::default()),
            relayed: Mutex::new(Relayed::None),
            phase: tokio::sync::watch::channel(Phase::Waiting).0,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn connection_without_a_session_or_after_it_has_no_more_use() {
        // No session started in time.
        let (phase, mut rx) = watch::channel(Phase::Waiting);
        let (start_by, leave_within) = (
            Instant::now() + Duration::from_secs(30),
            Duration::from_secs(60),
        );
        assert_eq!(
            no_more_use(&mut rx, start_by, leave_within).await,
            NOT_STARTED
        );
        assert_eq!(Instant::now(), start_by);

        // A session started in time keeps the connection until it is over,
        // and the agent then gets a while to take the end of its output and
        // leave by itself.
        let mut rx = phase.subscribe();
        let start_by = Instant::now() + Duration::from_secs(30);
        let waiting = no_more_use(&mut rx, start_by, leave_within);
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
        assert_eq!(over.elapsed(), leave_within);
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
