//! Waiting in tests on a condition rather than for a fixed time.
//!
//! A test waits for what must happen, and returns as soon as it has. The only
//! time limit is [`HANG`], a guard against a test that would otherwise hang
//! forever: it is far longer than anything should take, even on a machine busy
//! with other builds, so reaching it means the awaited thing never happens.

use std::future::Future;
use std::time::Duration;

/// Longest a test waits for something that must happen before it fails.
pub const HANG: Duration = Duration::from_secs(120);

/// How often [`until`] checks its condition.
const POLL: Duration = Duration::from_millis(20);

/// Wait until `done` holds, checking it every few milliseconds.
///
/// # Panics
/// If it still does not hold after [`HANG`], with `what` in the message.
pub async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let waited = tokio::time::timeout(HANG, async {
        while !done() {
            tokio::time::sleep(POLL).await;
        }
    })
    .await;
    assert!(waited.is_ok(), "never happened within {HANG:?}: {what}");
}

/// Wait for `future` to finish and return its output.
///
/// # Panics
/// If it has not finished after [`HANG`], with `what` in the message.
pub async fn within_hang<T>(what: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(HANG, future)
        .await
        .unwrap_or_else(|_elapsed| panic!("did not finish within {HANG:?}: {what}"))
}
