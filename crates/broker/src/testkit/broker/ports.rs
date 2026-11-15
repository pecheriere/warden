//! The loopback ports a [`TestBroker`](super::TestBroker) serves on, held
//! across [`TestBroker::restart`](super::TestBroker::restart).
//!
//! A restart that closed its listeners and bound the same ports again would
//! leave each port free in between, for any other test or process to take.
//! Instead, the broker keeps its own copy of every listening socket for as
//! long as it lives, and passes them to the broker that replaces it. While
//! that broker is down on a port, a task accepts every connection and resets
//! it at once: clients see the broker gone, as when its process has exited,
//! and nothing else can bind the port.

use std::net::{Ipv4Addr, TcpListener};
use std::sync::Mutex;

use tokio::task::JoinHandle;

/// A listening socket held for the broker's whole life.
struct HeldPort {
    listener: TcpListener,
    /// While the broker is down on this port: the task refusing its
    /// connections.
    refuser: Option<JoinHandle<()>>,
}

/// Every port a broker has served on.
#[derive(Default)]
pub(super) struct Ports(Mutex<Vec<HeldPort>>);

impl Ports {
    /// Bind a new ephemeral loopback port and hold it; returns a listener to
    /// serve on.
    ///
    /// # Panics
    /// If the port cannot be bound.
    pub(super) fn bind(&self) -> tokio::net::TcpListener {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind loopback listener");
        // Shared with every copy: tokio needs it non-blocking.
        listener
            .set_nonblocking(true)
            .expect("non-blocking loopback listener");
        let serving = copy(&listener);
        self.lock().push(HeldPort {
            listener,
            refuser: None,
        });
        serving
    }

    /// Stop refusing connections on `port`, which this broker holds and is
    /// down on; returns a listener to serve on.
    ///
    /// # Panics
    /// If this broker does not hold `port`, is not down on it, or its refuser
    /// failed.
    pub(super) async fn resume(&self, port: u16) -> tokio::net::TcpListener {
        let (refuser, serving) = {
            let mut held = self.lock();
            let held = held
                .iter_mut()
                .find(|held| local_port(&held.listener) == port)
                .unwrap_or_else(|| panic!("port {port} was never served by this broker"));
            let refuser = held.refuser.take().unwrap_or_else(|| {
                panic!("the broker is already serving on port {port} (not restarted since)")
            });
            (refuser, copy(&held.listener))
        };
        // Once the refuser has ended, it accepts nothing more, so every new
        // connection reaches the server.
        refuser.abort();
        if let Err(e) = refuser.await
            && e.is_panic()
        {
            std::panic::resume_unwind(e.into_panic());
        }
        serving
    }

    /// The same ports, down: each refuses every connection until
    /// [`Ports::resume`]. Call it only once nothing serves on them any more.
    pub(super) fn down(mut self) -> Self {
        let held = std::mem::take(self.0.get_mut().expect("ports lock poisoned"));
        let held = held
            .into_iter()
            .map(|held| {
                let refuser = held
                    .refuser
                    .unwrap_or_else(|| tokio::spawn(refuse(copy(&held.listener))));
                HeldPort {
                    listener: held.listener,
                    refuser: Some(refuser),
                }
            })
            .collect();
        Self(Mutex::new(held))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<HeldPort>> {
        self.0.lock().expect("ports lock poisoned")
    }
}

impl Drop for Ports {
    fn drop(&mut self) {
        if let Ok(held) = self.0.get_mut() {
            for refuser in held.iter_mut().filter_map(|held| held.refuser.take()) {
                refuser.abort();
            }
        }
    }
}

/// Accept every connection on `listener` and reset it at once, as a port
/// with nothing listening would refuse it.
async fn refuse(listener: tokio::net::TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            // A connection its peer gave up on before it was accepted needs
            // no refusal, as in `serve`: keep refusing the others.
            tokio::task::yield_now().await;
            continue;
        };
        // Closing with no linger sends a reset rather than an orderly end. If
        // the option cannot be set (the peer reset first), dropping the stream
        // still ends the connection, which is all a refusal needs.
        let _ = stream.set_zero_linger();
    }
}

/// Another handle on the same listening socket, for tokio.
fn copy(listener: &TcpListener) -> tokio::net::TcpListener {
    let copy = listener.try_clone().expect("copy the loopback listener");
    tokio::net::TcpListener::from_std(copy).expect("serve the loopback listener")
}

fn local_port(listener: &TcpListener) -> u16 {
    listener.local_addr().expect("listener address").port()
}
