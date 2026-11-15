//! Reading the audit log from a test while the broker may still be appending
//! to it.
//!
//! The broker writes an entry as one line ending in `\n`. A reader that
//! catches the write half-done sees a last line with no terminator, which is
//! not an entry yet. These helpers read only terminated lines, and the
//! `wait_for_*` ones wait for entries the broker writes after its HTTP
//! response, so a test never parses a half-written line or misses a late one.

use std::path::Path;

use serde_json::Value;

use crate::test_wait;

/// The audit log's complete lines, each ending in `\n`, as one string.
///
/// A trailing partial line is a write in progress and is left out. A missing
/// file reads as empty.
///
/// # Panics
/// If the file exists but cannot be read.
#[must_use]
pub fn audit_text(path: &Path) -> String {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => panic!("read audit log {}: {e}", path.display()),
    };
    match raw.rfind('\n') {
        Some(end) => raw[..=end].to_owned(),
        None => String::new(),
    }
}

/// The audit log's complete lines, parsed. Each value is the whole line:
/// the entry's `event` is under `"event"`.
///
/// # Panics
/// If a complete line is not JSON.
#[must_use]
pub fn audit_entries(path: &Path) -> Vec<Value> {
    audit_text(path)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("audit line {line}: {e}")))
        .collect()
}

/// The `event` of every complete entry whose `event.type` is `kind`, oldest first.
#[must_use]
pub fn audit_events(path: &Path, kind: &str) -> Vec<Value> {
    audit_entries(path)
        .into_iter()
        .map(|entry| entry["event"].clone())
        .filter(|event| event["type"] == kind)
        .collect()
}

/// Wait until the log holds a complete entry for which `found` is true, and
/// return all complete entries at that moment.
///
/// # Panics
/// After [`test_wait::HANG`], naming `what`.
pub async fn wait_for_audit(
    path: &Path,
    what: &str,
    mut found: impl FnMut(&[Value]) -> bool,
) -> Vec<Value> {
    test_wait::until(what, || found(&audit_entries(path))).await;
    audit_entries(path)
}

/// Wait until the log holds at least `count` entries of type `kind`, and
/// return their events, oldest first.
///
/// # Panics
/// After [`test_wait::HANG`].
pub async fn wait_for_audit_kind(path: &Path, kind: &str, count: usize) -> Vec<Value> {
    test_wait::until(&format!("{count} audit entries of type {kind}"), || {
        audit_events(path, kind).len() >= count
    })
    .await;
    audit_events(path, kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_half_written_last_line_is_not_an_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(
            &path,
            "{\"event\":{\"type\":\"a\"}}\n{\"event\":{\"type\":\"b\"}}\n{\"event\":{\"typ",
        )
        .unwrap();
        let kinds: Vec<_> = audit_entries(&path)
            .iter()
            .map(|e| e["event"]["type"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(kinds, ["a", "b"]);
        assert_eq!(audit_events(&path, "b").len(), 1);
    }

    #[test]
    fn a_missing_or_unterminated_log_reads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        assert_eq!(audit_entries(&path), [] as [Value; 0]);
        std::fs::write(&path, "{\"event\":").unwrap();
        assert_eq!(audit_text(&path), "");
    }

    #[tokio::test]
    async fn waiting_returns_once_the_entry_is_complete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "{\"event\":{\"typ").unwrap();
        let writer = {
            let path = path.clone();
            tokio::spawn(async move {
                tokio::task::yield_now().await;
                std::fs::write(&path, "{\"event\":{\"type\":\"late\"}}\n").unwrap();
            })
        };
        let found = wait_for_audit_kind(&path, "late", 1).await;
        writer.await.unwrap();
        assert_eq!(found.len(), 1);
    }
}
