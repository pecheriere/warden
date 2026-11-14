//! One agent connection: its login phase, how long it may stay, and how
//! its handler and its session task tell its task where they are.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use russh::Disconnect;
use russh::server::{self};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::audit::{AuditEvent, AuditLog};
use crate::audit_throttle::{Allowance, AuditThrottles, Summary, Tally, Throttle};

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
        record_refused_login(&shared, &conn, peer).await;
    }
}

/// Refused relay logins written one by one per address (per /64 network for
/// IPv6) per minute.
const LOGIN_REFUSALS_PER_ADDRESS: u32 = 5;
/// Refused relay logins written one by one per minute over all addresses.
const LOGIN_REFUSALS_OVERALL: u32 = 10;
/// The most distinct addresses (or IPv6 networks) held at once for the minute's summary.
const LOGIN_REFUSAL_ADDRESSES: usize = 1024;

/// What is held for refused logins that were not written one by one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct LoginTally {
    connections: u64,
    attempts: u64,
}

impl Tally for LoginTally {
    fn add(&mut self, other: Self) {
        self.connections = self.connections.saturating_add(other.connections);
        self.attempts = self.attempts.saturating_add(other.attempts);
    }
}

/// The limiter for refused logins, registered with `throttles`: 5 entries a
/// minute per address (per /64 network for IPv6) and 10 overall, the rest summed in one entry a minute.
pub(super) fn login_refusal_throttle(
    throttles: &AuditThrottles,
) -> Arc<Throttle<IpAddr, LoginTally>> {
    throttles.throttle(
        "a refused relay login",
        Allowance {
            per_key: LOGIN_REFUSALS_PER_ADDRESS,
            overall: Some(LOGIN_REFUSALS_OVERALL),
        },
        Summary::Aggregate {
            max_keys: LOGIN_REFUSAL_ADDRESSES,
            event: |peers, held| AuditEvent::RelayLoginsRefusedHeld {
                peers,
                connections: held.connections,
                attempts: held.attempts,
            },
        },
    )
}

/// Record the refused login attempts of a connection that never logged in.
async fn record_refused_login(shared: &Shared, conn: &Conn, peer: SocketAddr) {
    let refusals =
        std::mem::take(&mut *conn.refusals.lock().unwrap_or_else(PoisonError::into_inner));
    if refusals.attempts == 0 {
        return;
    }
    let user = refusals.user.unwrap_or_default();
    tracing::info!(peer = %peer.ip(), user, attempts = refusals.attempts, "relay: login refused");
    write_refused_login(
        &shared.login_refusals,
        &shared.audit,
        shared.requests.now(),
        peer.ip(),
        user,
        refusals.attempts,
    )
    .await;
}

/// The key a refused login is counted under: the IPv4 address, or the /64
/// network of an IPv6 address. An IPv4 address that arrives mapped into IPv6 is
/// the IPv4 address.
fn login_key(peer: IpAddr) -> IpAddr {
    match peer.to_canonical() {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(octets.into())
        }
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

/// Record, or hold, one refused login, counted under [`login_key`].
async fn write_refused_login(
    throttle: &Throttle<IpAddr, LoginTally>,
    audit: &AuditLog,
    now: i64,
    peer: IpAddr,
    user: String,
    attempts: u32,
) {
    let event = AuditEvent::RelayLoginRefused {
        user,
        peer: peer.to_string(),
        attempts,
    };
    let tally = LoginTally {
        connections: 1,
        attempts: u64::from(attempts),
    };
    throttle
        .record(audit, &login_key(peer), now, tally, event)
        .await;
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
    use super::{
        Conn, OverOnDrop, Phase, Refusals, Relayed, login_refusal_throttle, no_more_use,
        write_refused_login,
    };
    use crate::audit::AuditLog;
    use crate::audit_throttle::AuditThrottles;

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

    fn events(path: &std::path::Path, kind: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["event"].clone())
            .filter(|event| event["type"] == kind)
            .collect()
    }

    /// Drives the limiter as the relay builds it: [`login_refusal_throttle`]
    /// registered with the relay's [`AuditThrottles`], written as
    /// `record_refused_login` writes.
    #[tokio::test]
    async fn refused_logins_from_many_addresses_write_one_summary_a_minute() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).await.unwrap();
        let throttles = AuditThrottles::default();
        let throttle = login_refusal_throttle(&throttles);
        let now = 1_000_000;
        for n in 0..2000u32 {
            let [a, b] = u16::try_from(n).unwrap().to_be_bytes();
            let peer = std::net::IpAddr::from([198, 51, a, b]);
            write_refused_login(&throttle, &audit, now, peer, "web".to_owned(), 3).await;
        }
        assert_eq!(events(&path, "relay_login_refused").len(), 10);
        assert_eq!(
            events(&path, "relay_logins_refused_held"),
            [] as [serde_json::Value; 0]
        );

        throttles.flush(&audit, now + 61, true).await;
        let held = events(&path, "relay_logins_refused_held");
        assert_eq!(held.len(), 1, "{held:?}");
        assert_eq!(held[0]["peers"], 1025);
        assert_eq!(held[0]["connections"], 1990);
        assert_eq!(held[0]["attempts"], 5970);
        assert_eq!(events(&path, "relay_login_refused").len(), 10);
    }

    #[tokio::test]
    async fn an_address_mapped_into_ipv6_is_the_same_address() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).await.unwrap();
        let throttle = login_refusal_throttle(&AuditThrottles::default());
        let v4 = std::net::IpAddr::from([198, 51, 100, 7]);
        let mapped =
            std::net::IpAddr::V6(std::net::Ipv4Addr::new(198, 51, 100, 7).to_ipv6_mapped());
        for peer in [v4, mapped, v4, mapped, v4, mapped, v4] {
            write_refused_login(&throttle, &audit, 1_000_000, peer, "web".to_owned(), 1).await;
        }
        assert_eq!(events(&path, "relay_login_refused").len(), 5);
    }

    #[tokio::test]
    async fn ipv6_addresses_in_one_64_network_share_an_allowance() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = AuditLog::open(&path).await.unwrap();
        let throttle = login_refusal_throttle(&AuditThrottles::default());
        let in_network = |network: u16, host: u16| {
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                0x2001, 0xdb8, 0, network, 0, 0, 0, host,
            ))
        };
        // Seven logins from seven addresses of one /64 network: five entries.
        for host in 1..=7 {
            let peer = in_network(1, host);
            write_refused_login(&throttle, &audit, 1_000_000, peer, "web".to_owned(), 1).await;
        }
        assert_eq!(events(&path, "relay_login_refused").len(), 5);
        // Another /64 network has an allowance of its own.
        for host in 1..=7 {
            let peer = in_network(2, host);
            write_refused_login(&throttle, &audit, 1_000_000, peer, "web".to_owned(), 1).await;
        }
        assert_eq!(events(&path, "relay_login_refused").len(), 10);
        // The entry names the address itself.
        let written = events(&path, "relay_login_refused");
        assert_eq!(written[0]["peer"], "2001:db8:0:1::1");
    }
}
