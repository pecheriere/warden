//! Notifiers for tests: one that records every doorbell, one that always fails.

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::notify::{Doorbell, Notifier, NotifyError};

/// Records every doorbell and always succeeds.
pub struct CapturingNotifier {
    rung: Mutex<Vec<Doorbell>>,
    tx: mpsc::UnboundedSender<Doorbell>,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Doorbell>>,
}

impl CapturingNotifier {
    /// An empty recorder.
    #[must_use]
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            rung: Mutex::new(Vec::new()),
            tx,
            rx: tokio::sync::Mutex::new(rx),
        }
    }

    /// Every doorbell rung so far, oldest first.
    ///
    /// # Panics
    /// If another thread panicked while recording.
    #[must_use]
    pub fn rung(&self) -> Vec<Doorbell> {
        self.rung.lock().expect("capture lock poisoned").clone()
    }

    /// Wait for the next doorbell not yet returned by `next`.
    ///
    /// # Panics
    /// If none arrives within 5 s.
    pub async fn next(&self) -> Doorbell {
        let mut rx = self.rx.lock().await;
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("no doorbell within 5 s")
            .expect("capture channel closed")
    }

    /// The approval token at the end of a doorbell's link.
    ///
    /// # Panics
    /// If the link has no path segment.
    #[must_use]
    pub fn token(d: &Doorbell) -> String {
        d.url
            .path_segments()
            .and_then(|mut s| s.next_back())
            .expect("approval link has a token segment")
            .to_owned()
    }
}

impl Default for CapturingNotifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Notifier for CapturingNotifier {
    fn name(&self) -> &'static str {
        "capture"
    }

    async fn ring(&self, d: &Doorbell) -> Result<&'static str, NotifyError> {
        self.rung
            .lock()
            .expect("capture lock poisoned")
            .push(d.clone());
        // The receiver lives as long as `self`, so sending cannot fail.
        let _ = self.tx.send(d.clone());
        Ok(self.name())
    }
}

/// Fails every delivery with HTTP 503.
pub struct FailingNotifier;

#[async_trait]
impl Notifier for FailingNotifier {
    fn name(&self) -> &'static str {
        "failing"
    }

    async fn ring(&self, _d: &Doorbell) -> Result<&'static str, NotifyError> {
        Err(NotifyError::Status {
            notifier: "failing",
            status: 503,
        })
    }
}
