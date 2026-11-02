//! The in-process bus on which changed request ids are published, so that
//! long-polls wake up.

use tokio::sync::broadcast;
use warden_broker_proto::Id;

/// Messages a slow long-poll may fall behind before it re-reads.
const BUS_CAPACITY: usize = 256;

/// Broadcasts the id of every request whose state may have changed; a
/// receiver re-reads the request to learn what happened.
#[derive(Debug, Clone)]
pub struct StatusBus {
    tx: broadcast::Sender<Id>,
}

impl StatusBus {
    /// A bus with no subscribers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tx: broadcast::channel(BUS_CAPACITY).0,
        }
    }

    /// Receive ids published from now on.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Id> {
        self.tx.subscribe()
    }

    /// Announce that request `id` may have changed.
    pub fn publish(&self, id: &Id) {
        // An error only means nobody is listening, which is fine.
        let _ = self.tx.send(id.clone());
    }

    /// Number of live subscribers.
    #[must_use]
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for StatusBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Wait for a bus message about `id`. `true` means re-read (it changed or
/// messages were missed); `false` means the bus is gone.
pub(super) async fn next_change(rx: &mut broadcast::Receiver<Id>, id: &Id) -> bool {
    loop {
        match rx.recv().await {
            Ok(changed) if changed == *id => return true,
            Ok(_) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => return true,
            Err(broadcast::error::RecvError::Closed) => return false,
        }
    }
}
