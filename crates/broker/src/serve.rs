//! Serving a router on a listener, with a cap on its open connections and a
//! time limit on reading each request's headers.
//!
//! The agent API and the approval UI run in one process and share its file
//! descriptors. Each listener has its own cap, so connections to the agent API
//! cannot use up what the approval UI needs to let the owner decide and
//! revoke. A connection beyond the cap is closed as soon as it is accepted.

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

/// Most connections the agent API listener holds open at once. Behind
/// Tailscale Serve each request in flight is one connection, and an agent holds
/// at most [`crate::load::MAX_WAITS_PER_AGENT`] long-polls. A few agents stay far
/// below this, but the two caps do not compose for many: 16 agents each at that
/// many waits fill it, and idle keep-alive connections count until the header
/// read timeout closes them. A full listener refuses new connections, so it
/// fails closed, and the approval UI has its own cap. With [`APPROVAL_CONNECTIONS`] and the
/// default relay and proxy limits, the process stays within the usual limit of
/// 1024 open files.
pub const API_CONNECTIONS: usize = 256;

/// Most connections the approval UI listener holds open at once: the owner's
/// browsers need a handful.
pub const APPROVAL_CONNECTIONS: usize = 64;

/// How long a connection may take to send a request's headers, counted from
/// when the broker starts waiting for them, so also how long an idle
/// keep-alive connection is kept. Longer than the 90 s after which Go's HTTP
/// client, as used by reverse proxies such as Tailscale Serve, drops its idle
/// connections, so that the proxy usually drops them first.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(120);

/// How a listener is served.
#[derive(Debug, Clone, Copy)]
pub struct ServeLimits {
    /// Most connections open at once; more are closed when accepted.
    pub max_connections: usize,
    /// Longest time to receive a request's headers.
    pub header_read_timeout: Duration,
}

impl ServeLimits {
    /// The agent API listener's limits.
    pub const API: Self = Self {
        max_connections: API_CONNECTIONS,
        header_read_timeout: HEADER_READ_TIMEOUT,
    };

    /// The approval UI listener's limits.
    pub const APPROVAL: Self = Self {
        max_connections: APPROVAL_CONNECTIONS,
        header_read_timeout: HEADER_READ_TIMEOUT,
    };
}

/// Serve `router` over HTTP/1 on `listener` within `limits` until `shutdown`
/// completes, then stop accepting, let the open connections finish their
/// requests and return. Dropping the future closes every connection.
///
/// `name` names the listener in logs. A failed accept is logged and
/// accepting goes on.
pub async fn serve(
    name: &'static str,
    listener: TcpListener,
    router: Router,
    limits: ServeLimits,
    shutdown: impl Future<Output = ()>,
) {
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    let (stop, stopping) = watch::channel(false);
    let mut connections = JoinSet::new();
    // Whether the cap has been logged as reached since the last connection
    // accepted below it: once per episode, not once per connection.
    let mut saturated = false;
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => {
                let stream = match accepted {
                    Ok((stream, _)) => stream,
                    Err(e) => {
                        accept_failed(name, &e).await;
                        continue;
                    }
                };
                let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                    if !saturated {
                        tracing::warn!(
                            listener = name,
                            max = limits.max_connections,
                            "connection cap reached; closing new connections"
                        );
                        saturated = true;
                    }
                    drop(stream);
                    continue;
                };
                saturated = false;
                let service = TowerToHyperService::new(router.clone());
                let mut stopping = stopping.clone();
                connections.spawn(async move {
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder
                        .timer(TokioTimer::new())
                        .header_read_timeout(limits.header_read_timeout);
                    let conn = builder.serve_connection(TokioIo::new(stream), service);
                    let mut conn = std::pin::pin!(conn);
                    // A connection error only ends that connection.
                    tokio::select! {
                        _ = conn.as_mut() => {}
                        _ = stopping.changed() => {
                            conn.as_mut().graceful_shutdown();
                            let _ = conn.await;
                        }
                    }
                    drop(slot);
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    // A send error means no connection is left to tell.
    let _ = stop.send(true);
    while connections.join_next().await.is_some() {}
}

/// After a failed accept: go on at once if only that connection failed;
/// otherwise (out of file descriptors, for one) log it and pause, so the loop
/// does not spin while the condition lasts.
async fn accept_failed(name: &'static str, e: &io::Error) {
    if matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    ) {
        return;
    }
    tracing::error!(listener = name, error = %e, "accepting a connection failed");
    tokio::time::sleep(Duration::from_secs(1)).await;
}
