//! Test support: hold audit appends until a test lets them go, as a log whose disk
//! has stalled would, for as long as the test needs and with no time limit. Not
//! built without the `testkit` feature.

use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::watch;

use super::AuditEvent;

/// Which entries a stall holds.
type Filter = fn(&AuditEvent) -> bool;

#[derive(Clone)]
struct Stall {
    filter: Filter,
    released: watch::Receiver<bool>,
    waiting: Arc<watch::Sender<usize>>,
}

/// What an [`AuditLog`](super::AuditLog) checks before each append.
#[derive(Default)]
pub(super) struct Gate {
    stall: Mutex<Option<Stall>>,
}

impl Gate {
    /// Wait here if a stall holds `event`.
    pub(super) async fn pass(&self, event: &AuditEvent) {
        let stall = self
            .stall
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(mut stall) = stall.filter(|stall| (stall.filter)(event)) else {
            return;
        };
        stall.waiting.send_modify(|waiting| *waiting += 1);
        // An error means the stall is gone, which also lets the append go.
        drop(stall.released.wait_for(|released| *released).await);
        stall.waiting.send_modify(|waiting| *waiting -= 1);
    }

    /// Hold every append whose entry `filter` picks, until the result is dropped.
    pub(super) fn hold(self: &Arc<Self>, filter: Filter) -> AppendStall {
        let (release, released) = watch::channel(false);
        let waiting = Arc::new(watch::Sender::new(0));
        *self.stall.lock().unwrap_or_else(PoisonError::into_inner) = Some(Stall {
            filter,
            released,
            waiting: Arc::clone(&waiting),
        });
        AppendStall {
            gate: Arc::clone(self),
            release,
            waiting,
        }
    }
}

/// Appends are held while this lives; dropping it lets them all go.
pub struct AppendStall {
    gate: Arc<Gate>,
    release: watch::Sender<bool>,
    waiting: Arc<watch::Sender<usize>>,
}

impl AppendStall {
    /// Wait until `count` appends are being held at once.
    ///
    /// # Panics
    /// Never: this holds the sender it waits on.
    pub async fn until_holding(&self, count: usize) {
        self.waiting
            .subscribe()
            .wait_for(|waiting| *waiting >= count)
            .await
            .expect("the sender lives in self");
    }

    /// How many appends are being held now.
    #[must_use]
    pub fn holding(&self) -> usize {
        *self.waiting.borrow()
    }
}

impl Drop for AppendStall {
    fn drop(&mut self) {
        *self
            .gate
            .stall
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        self.release.send_replace(true);
    }
}
