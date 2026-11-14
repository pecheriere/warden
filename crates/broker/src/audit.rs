//! Append-only, hash-chained JSONL audit log.
//!
//! Each line is `{"seq","ts","prev","event","hash"}` where
//! `hash = hex(sha256(prev ‖ "\n" ‖ json({seq,ts,event})))` and the first
//! line's `prev` is 64 zeros. Every line must be byte-for-byte the canonical
//! serialization of the record it parses to (field order as written, no extra
//! whitespace, no unknown fields), so the bytes on disk are exactly what the
//! hash covers. Events carry only ids, names, fingerprints and free-text
//! summaries; they must never contain secrets.

use std::fs::{File, TryLockError};
use std::io::Write as _;
use std::os::unix::fs::FileExt as _;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

mod open;
#[cfg(feature = "testkit")]
mod stall;

pub use self::open::verify;
#[cfg(feature = "testkit")]
pub use self::stall::AppendStall;

mod event;

pub use self::event::AuditEvent;

/// `prev` of the first line in a log.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The hashed portion of a line.
#[derive(Serialize)]
struct Body<'a> {
    seq: u64,
    ts: i64,
    event: &'a AuditEvent,
}

/// A full log line.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    seq: u64,
    ts: i64,
    prev: String,
    event: AuditEvent,
    hash: String,
}

/// Audit log failures.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// The file could not be read or written.
    #[error("audit log I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A line is not a valid audit record.
    #[error("audit log line {line} is malformed: {reason}")]
    Malformed {
        /// 1-based line number.
        line: u64,
        /// What is wrong.
        reason: String,
    },
    /// A line's `prev` or `hash` does not match the chain.
    #[error("audit chain broken at seq {seq}")]
    BrokenChain {
        /// Sequence number of the offending line.
        seq: u64,
    },
    /// Sequence numbers are not consecutive from 1.
    #[error("audit sequence gap: expected {expected}, found {found}")]
    SeqGap {
        /// The sequence number that should have appeared.
        expected: u64,
        /// The one that did.
        found: u64,
    },
    /// An event could not be serialised.
    #[error("audit event serialisation failed: {0}")]
    Serialize(#[from] serde_json::Error),
    /// The log ends with a partial line (torn write); opening it repairs it.
    #[error("audit log ends with an unterminated line of {bytes} bytes")]
    UnterminatedTail {
        /// Length of the unterminated tail.
        bytes: usize,
    },
    /// An earlier append failed or was cancelled; restart to repair the log.
    #[error("audit log poisoned by an earlier failed append; restart to repair")]
    Poisoned,
    /// The log was shorter under the file lock than the prefix already verified
    /// without it, or the last line of that prefix changed. Only a torn tail
    /// past the last complete line is ever cut, so something other than warden
    /// changed the log while it was being opened; it is refused, not repaired.
    #[error("audit log's first {verified} bytes changed while it was being opened")]
    PrefixChanged {
        /// Length of the prefix verified before taking the lock.
        verified: u64,
    },
    /// An entry's line would be longer than any line the log reads back. It
    /// was not written, and the log stays usable.
    #[error(
        "audit entry of type {kind} is {bytes} bytes, more than the {MAX_LINE_BYTES} the log can read back; not written"
    )]
    EntryTooLarge {
        /// The event's type, as on its line.
        kind: String,
        /// Length of its line, newline excluded.
        bytes: usize,
    },
    /// Another writer held the file lock for too long.
    #[error("timed out waiting for the audit log lock")]
    LockTimeout,
    /// The last complete line, read to resume after another writer, is not
    /// a valid audit record.
    #[error("audit log's last line is unreadable: {reason}")]
    UnreadableLastLine {
        /// What is wrong.
        reason: String,
    },
    /// The system clock is before 1970 or out of range.
    #[error("system clock unusable")]
    Clock,
    /// The log could not be kept private to warden's user.
    #[error(transparent)]
    Private(#[from] crate::private_files::PrivateFileError),
}

fn compute_hash(prev: &str, body: &Body<'_>) -> Result<String, serde_json::Error> {
    let json = serde_json::to_string(body)?;
    let mut hasher = Sha256::new();
    hasher.update(prev.as_bytes());
    hasher.update(b"\n");
    hasher.update(json.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

/// Parse `raw` as a line, requiring it to be exactly the canonical
/// serialization of the parsed record. Errors describe what is wrong.
fn parse_canonical(raw: &[u8]) -> Result<Line, String> {
    let text = std::str::from_utf8(raw).map_err(|e| e.to_string())?;
    let line: Line = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let canonical = serde_json::to_vec(&line).map_err(|e| e.to_string())?;
    if canonical != raw {
        return Err("not in canonical form".to_owned());
    }
    Ok(line)
}

/// Longest line, newline excluded, that the log reads back, and so the
/// longest it writes. Reading refuses a complete line longer than this as
/// malformed, so that one line cannot make memory grow with the file; writing
/// refuses an entry whose line would be longer with
/// [`AuditError::EntryTooLarge`], before any byte reaches the file, so that
/// warden never writes a log it could not open again.
const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// How long an append waits for another writer to release the file lock.
const LOCK_WAIT: Duration = Duration::from_secs(5);

/// Longest pause between attempts to take the file lock.
const LOCK_BACKOFF_MAX: Duration = Duration::from_millis(50);

/// Bytes read from the end of the file per step when looking for the last line.
const TAIL_WINDOW: u64 = 4096;

/// A chain position: the last line's seq and hash, and the file length up to
/// and including that line's newline.
#[derive(Debug, Clone)]
struct Head {
    seq: u64,
    hash: String,
    len: u64,
}

impl Head {
    fn genesis() -> Self {
        Self {
            seq: 0,
            hash: GENESIS.to_owned(),
            len: 0,
        }
    }
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn unix_now() -> Result<i64, AuditError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuditError::Clock)?
            .as_secs(),
    )
    .map_err(|_| AuditError::Clock)
}

/// An exclusive advisory lock on the log file, shared by every process and
/// every handle that appends to it. Released on drop.
struct FileLock<'a>(&'a File);

impl<'a> FileLock<'a> {
    /// Take the lock, waiting at most [`LOCK_WAIT`] with a growing backoff.
    /// Blocking; call from a blocking thread.
    fn acquire(file: &'a File) -> Result<Self, AuditError> {
        let deadline = Instant::now() + LOCK_WAIT;
        let mut backoff = Duration::from_millis(1);
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self(file)),
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Error(e)) => return Err(e.into()),
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(AuditError::LockTimeout);
            }
            std::thread::sleep(backoff.min(deadline - now));
            backoff = (backoff * 2).min(LOCK_BACKOFF_MAX);
        }
    }
}

impl Drop for FileLock<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.0.unlock() {
            tracing::error!(error = %e, "releasing the audit log lock failed");
        }
    }
}

/// Parse `raw` as a canonical line and check that its own hash matches its
/// content.
fn parse_link(raw: &[u8]) -> Result<Line, AuditError> {
    let line = parse_canonical(raw).map_err(|reason| AuditError::UnreadableLastLine { reason })?;
    let body = Body {
        seq: line.seq,
        ts: line.ts,
        event: &line.event,
    };
    if compute_hash(&line.prev, &body)? != line.hash {
        return Err(AuditError::BrokenChain { seq: line.seq });
    }
    Ok(line)
}

/// `tail` as the line following `head`, if it is exactly that.
fn next_link(tail: &[u8], head: &Head) -> Option<Line> {
    let line = parse_link(tail).ok()?;
    (line.seq == head.seq + 1 && line.prev == head.hash).then_some(line)
}

/// Repair an unterminated `tail` written after `head` by a writer that
/// crashed mid-append. A complete, valid next line is newline-terminated and
/// kept; anything else is truncated and an event describing it is returned
/// for the caller to record.
///
/// Works on raw bytes: a crash can cut a multi-byte UTF-8 character.
fn repair_tail(
    file: &File,
    head: Head,
    tail: &[u8],
) -> Result<(Head, Option<AuditEvent>), AuditError> {
    if tail.is_empty() {
        return Ok((head, None));
    }
    if let Some(line) = next_link(tail, &head) {
        let mut writer = file;
        writer.write_all(b"\n")?;
        file.sync_data()?;
        let len = head.len + len_u64(tail.len()) + 1;
        return Ok((
            Head {
                seq: line.seq,
                hash: line.hash,
                len,
            },
            None,
        ));
    }
    let record = discard_tail(file, &head, len_u64(tail.len()), &Sha256::digest(tail))?;
    Ok((head, Some(record)))
}

/// Cut the file back to `head`, dropping a torn tail of `len` bytes whose
/// SHA-256 is `digest`, and return an event describing it for the caller to
/// record.
fn discard_tail(
    file: &File,
    head: &Head,
    len: u64,
    digest: &[u8],
) -> Result<AuditEvent, AuditError> {
    file.set_len(head.len)?;
    file.sync_data()?;
    Ok(AuditEvent::Error {
        context: "audit".to_owned(),
        message: format!(
            "discarded torn tail of {len} bytes (sha256 {})",
            hex::encode(digest)
        ),
    })
}

/// Find the last newline-terminated line of a `len`-byte file by reading
/// backwards from the end, and return its chain position and the bytes after it.
fn read_last_link(file: &File, len: u64) -> Result<(Head, Vec<u8>), AuditError> {
    let mut window = TAIL_WINDOW;
    loop {
        let start = len.saturating_sub(window);
        let size = usize::try_from(len - start)
            .map_err(|_| std::io::Error::other("audit log tail window exceeds memory"))?;
        let mut buf = vec![0_u8; size];
        file.read_exact_at(&mut buf, start)?;
        let Some(end) = buf.iter().rposition(|b| *b == b'\n') else {
            if start == 0 {
                return Ok((Head::genesis(), buf));
            }
            window = window.saturating_mul(2);
            continue;
        };
        let line_start = match buf[..end].iter().rposition(|b| *b == b'\n') {
            Some(i) => i + 1,
            None if start == 0 => 0,
            None => {
                window = window.saturating_mul(2);
                continue;
            }
        };
        let line = parse_link(&buf[line_start..end])?;
        let head = Head {
            seq: line.seq,
            hash: line.hash,
            len: start + len_u64(end) + 1,
        };
        return Ok((head, buf[end + 1..].to_vec()));
    }
}

/// Serialize `event` as the line after `head`, newline included, and return
/// it with the head after it. Writes nothing.
///
/// # Errors
/// [`AuditError::EntryTooLarge`] if the line would be longer than
/// [`MAX_LINE_BYTES`], which the log could not read back; or if the clock or
/// serialization fails.
fn encode_line(head: &Head, event: &AuditEvent) -> Result<(Vec<u8>, Head), AuditError> {
    let ts = unix_now()?;
    let seq = head.seq + 1;
    let hash = compute_hash(&head.hash, &Body { seq, ts, event })?;
    let line = Line {
        seq,
        ts,
        prev: head.hash.clone(),
        event: event.clone(),
        hash: hash.clone(),
    };
    let mut json = serde_json::to_vec(&line)?;
    if json.len() > MAX_LINE_BYTES {
        let kind = event_kind(&json);
        // The event's content may hold secrets or be huge: only its type and size.
        tracing::error!(
            target: "audit",
            kind,
            bytes = json.len(),
            "audit entry longer than the log can read back; not written"
        );
        return Err(AuditError::EntryTooLarge {
            kind: kind.to_owned(),
            bytes: json.len(),
        });
    }
    json.push(b'\n');
    let next = Head {
        seq,
        hash,
        len: head.len + len_u64(json.len()),
    };
    Ok((json, next))
}

/// The event type named on the serialized line `json`, for reporting a line
/// that is not written.
fn event_kind(json: &[u8]) -> &str {
    #[derive(Deserialize)]
    struct Tagged<'a> {
        #[serde(borrow)]
        event: Tag<'a>,
    }
    #[derive(Deserialize)]
    struct Tag<'a> {
        #[serde(rename = "type")]
        kind: &'a str,
    }
    serde_json::from_slice::<Tagged<'_>>(json).map_or("unknown", |t| t.event.kind)
}

/// Write the encoded line `json` and fsync it.
fn write_line(file: &File, json: &[u8]) -> Result<(), AuditError> {
    let mut writer = file;
    writer.write_all(json)?;
    file.sync_data()?;
    tracing::info!(target: "audit", line = %String::from_utf8_lossy(json).trim_end());
    Ok(())
}

/// Write `event` as the line after `head` and fsync it.
fn write_event(file: &File, head: &Head, event: &AuditEvent) -> Result<Head, AuditError> {
    let (json, next) = encode_line(head, event)?;
    write_line(file, &json)?;
    Ok(next)
}

/// Why a blocking append failed.
enum Failure {
    /// Nothing was written: the lock could not be taken, the file could not
    /// be read to re-sync, or the entry could not be encoded or is too long
    /// to read back. A later append simply tries again.
    NotWritten(AuditError),
    /// A write or fsync failed; the file tail is untrustworthy.
    Write(AuditError),
}

/// Append `event` under the file lock, first re-syncing from the file if
/// another writer (or an earlier append of this handle whose result was
/// lost) changed it since `cached`. Blocking.
fn append_blocking(file: &File, cached: Head, event: &AuditEvent) -> Result<Head, Failure> {
    let _lock = FileLock::acquire(file).map_err(Failure::NotWritten)?;
    let len = file
        .metadata()
        .map_err(|e| Failure::NotWritten(e.into()))?
        .len();
    let mut head = cached;
    if len != head.len {
        let (last, tail) = read_last_link(file, len).map_err(Failure::NotWritten)?;
        let (synced, record) = repair_tail(file, last, &tail).map_err(Failure::Write)?;
        head = synced;
        if let Some(record) = record {
            head = write_event(file, &head, &record).map_err(Failure::Write)?;
        }
    }
    let (json, next) = encode_line(&head, event).map_err(Failure::NotWritten)?;
    write_line(file, &json).map_err(Failure::Write)?;
    Ok(next)
}

struct State {
    file: File,
    head: Head,
    /// Set when a write or fsync failed; the file tail is untrustworthy until
    /// the log is reopened.
    poisoned: bool,
}

/// Handle to the append-only audit log.
///
/// Several handles, in this process or others, may append to the same file:
/// each append holds an exclusive file lock and first re-syncs its chain
/// position from the file if someone else wrote since.
pub struct AuditLog {
    state: Arc<Mutex<State>>,
    #[cfg(feature = "testkit")]
    stall: Arc<stall::Gate>,
}

fn join_error(e: tokio::task::JoinError) -> AuditError {
    AuditError::Io(std::io::Error::other(e))
}

impl AuditLog {
    fn from_parts(file: File, head: Head) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                file,
                head,
                poisoned: false,
            })),
            #[cfg(feature = "testkit")]
            stall: Arc::default(),
        }
    }

    /// Open (creating with mode 0600 if absent) and resume the chain.
    ///
    /// An existing log is fully verified first, streaming: up to its last
    /// complete line without the file lock, so other writers keep appending
    /// meanwhile, then under the lock only what they appended since. A log
    /// with corruption in a complete line or a broken chain is refused, and so
    /// is one whose verified part changed before the lock was taken. A torn
    /// final line (crash mid-append) is repaired under the lock: a valid one is
    /// newline-terminated, a partial one is truncated and the repair is
    /// recorded on the chain.
    ///
    /// # Errors
    /// Returns an [`AuditError`] on I/O failure, lock timeout, if the existing
    /// log is invalid, or [`AuditError::PrefixChanged`].
    pub async fn open(path: &Path) -> Result<Self, AuditError> {
        let path = path.to_owned();
        let (file, head) = tokio::task::spawn_blocking(move || open::open_blocking(&path))
            .await
            .map_err(join_error)??;
        Ok(Self::from_parts(file, head))
    }

    /// Hold every append whose entry `filter` picks, with no time limit, until the
    /// result is dropped.
    #[cfg(feature = "testkit")]
    #[must_use]
    pub fn stall_appends(&self, filter: fn(&AuditEvent) -> bool) -> AppendStall {
        self.stall.hold(filter)
    }

    /// Append `event`, fsyncing before returning.
    ///
    /// Cancel-safe: the write runs on a blocking thread that owns this
    /// handle's state, so dropping the returned future neither interrupts the
    /// write nor loses its effect on the chain position.
    ///
    /// # Errors
    /// Returns an [`AuditError`] if the lock cannot be taken within 5 s
    /// ([`AuditError::LockTimeout`]), the entry is longer than the log can
    /// read back ([`AuditError::EntryTooLarge`], nothing written), or the line
    /// cannot be written durably; after a failed write or fsync the log is
    /// poisoned.
    pub async fn append(&self, event: AuditEvent) -> Result<(), AuditError> {
        #[cfg(feature = "testkit")]
        self.stall.pass(&event).await;
        let mut state = Arc::clone(&self.state).lock_owned().await;
        if state.poisoned {
            return Err(AuditError::Poisoned);
        }
        tokio::task::spawn_blocking(move || {
            let cached = state.head.clone();
            match append_blocking(&state.file, cached, &event) {
                Ok(head) => {
                    state.head = head;
                    Ok(())
                }
                Err(Failure::NotWritten(e)) => Err(e),
                Err(Failure::Write(e)) => {
                    state.poisoned = true;
                    Err(e)
                }
            }
        })
        .await
        .map_err(join_error)?
    }
}

#[cfg(test)]
impl AuditLog {
    /// A log whose every append fails, on a read-only handle to the empty file at
    /// `path`, for tests of what a caller does when a write fails. Test only.
    pub(crate) fn unwritable(path: &Path) -> Self {
        std::fs::write(path, "").unwrap();
        let read_only = File::open(path).unwrap();
        Self::from_parts(read_only, Head::genesis())
    }
}

#[cfg(test)]
mod tests {
    use warden_broker_proto::Id;

    use super::*;

    /// Pins the exact on-disk format and hash of one line: changing either
    /// breaks verification of every existing log.
    #[test]
    fn canonical_line_golden() {
        let event = AuditEvent::Denied {
            id: Id::try_from("00112233445566778899aabbccddeeff".to_owned()).unwrap(),
        };
        let (seq, ts) = (1, 1_800_000_000);
        let hash = compute_hash(
            GENESIS,
            &Body {
                seq,
                ts,
                event: &event,
            },
        )
        .unwrap();
        let line = Line {
            seq,
            ts,
            prev: GENESIS.to_owned(),
            event,
            hash,
        };
        let json = serde_json::to_string(&line).unwrap();
        assert_eq!(
            json,
            r#"{"seq":1,"ts":1800000000,"prev":"0000000000000000000000000000000000000000000000000000000000000000","event":{"type":"denied","id":"00112233445566778899aabbccddeeff"},"hash":"c6eb8215a82f820edf38173bbbf9328156ba10a3caabedf2713f026a5a726c68"}"#
        );
        // Independently: printf '%s\n%s' <64 zeros> '{"seq":1,"ts":1800000000,"event":{…}}' | shasum -a 256
        assert_eq!(
            line.hash,
            "c6eb8215a82f820edf38173bbbf9328156ba10a3caabedf2713f026a5a726c68"
        );
        let mut head = Head::genesis();
        open::verify_lines(&mut format!("{json}\n").as_bytes(), &mut head).unwrap();
        assert_eq!((head.seq, head.hash), (1, line.hash));
    }

    /// A log written by 0.12.0 holds mints with no repository. It must still open,
    /// verify and re-serialise to the same bytes after the upgrade.
    #[test]
    fn a_v0_12_0_github_token_minted_line_still_verifies() {
        let event_json = r#"{"type":"github_token_minted","grant_id":"00112233445566778899aabbccddeeff","agent":"build-agent","installation_id":42,"permissions":["contents:write"],"expires_at":1800003600}"#;
        let event: AuditEvent = serde_json::from_str(event_json).unwrap();
        assert_eq!(serde_json::to_string(&event).unwrap(), event_json);
        let (seq, ts) = (1, 1_800_000_000);
        let hash = compute_hash(
            GENESIS,
            &Body {
                seq,
                ts,
                event: &event,
            },
        )
        .unwrap();
        let line = Line {
            seq,
            ts,
            prev: GENESIS.to_owned(),
            event,
            hash: hash.clone(),
        };
        let text = format!("{}\n", serde_json::to_string(&line).unwrap());
        let mut head = Head::genesis();
        open::verify_lines(&mut text.as_bytes(), &mut head).unwrap();
        assert_eq!((head.seq, head.hash), (1, hash));
    }

    #[test]
    fn unknown_fields_are_rejected_on_parse() {
        let event = r#"{"type":"denied","id":"00112233445566778899aabbccddeeff","note":"x"}"#;
        assert!(serde_json::from_str::<AuditEvent>(event).is_err());
        let line = format!(
            r#"{{"seq":1,"ts":0,"prev":"{GENESIS}","event":{{"type":"denied","id":"00112233445566778899aabbccddeeff"}},"hash":"","note":"x"}}"#
        );
        assert!(serde_json::from_str::<Line>(&line).is_err());
    }

    #[tokio::test]
    async fn append_after_write_error_is_poisoned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "").unwrap();
        // A read-only handle makes every write fail without any test hook in production code.
        let read_only = std::fs::File::open(&path).unwrap();
        let log = AuditLog::from_parts(read_only, Head::genesis());
        let event = || AuditEvent::Denied { id: Id::random() };

        assert!(matches!(log.append(event()).await, Err(AuditError::Io(_))));
        assert!(matches!(
            log.append(event()).await,
            Err(AuditError::Poisoned)
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
    }

    /// An `Error` event whose line after `head` is exactly `bytes` long,
    /// newline excluded, when written with the current clock.
    fn error_event_of_line_len(head: &Head, bytes: usize) -> AuditEvent {
        let event = |message: String| AuditEvent::Error {
            context: "test".to_owned(),
            message,
        };
        let line = Line {
            seq: head.seq + 1,
            ts: unix_now().unwrap(),
            prev: head.hash.clone(),
            event: event(String::new()),
            hash: GENESIS.to_owned(),
        };
        let empty = serde_json::to_vec(&line).unwrap().len();
        event("x".repeat(bytes - empty))
    }

    #[tokio::test]
    async fn an_entry_longer_than_the_log_can_read_back_is_refused_unwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path).await.unwrap();
        log.append(AuditEvent::Denied { id: Id::random() })
            .await
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        let head = log.state.lock().await.head.clone();

        let too_long = error_event_of_line_len(&head, MAX_LINE_BYTES + 1);
        assert!(matches!(
            log.append(too_long).await,
            Err(AuditError::EntryTooLarge { ref kind, bytes })
                if kind == "error" && bytes == MAX_LINE_BYTES + 1
        ));
        // Not a byte was written, and the log is not poisoned.
        assert_eq!(std::fs::read(&path).unwrap(), before);
        log.append(AuditEvent::Denied { id: Id::random() })
            .await
            .unwrap();
        assert_eq!(open::verify(&path).unwrap(), 2);
        drop(log);
        AuditLog::open(&path).await.unwrap();
    }

    #[tokio::test]
    async fn an_entry_exactly_as_long_as_the_bound_is_written_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path).await.unwrap();

        let longest = error_event_of_line_len(&Head::genesis(), MAX_LINE_BYTES);
        log.append(longest).await.unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            len_u64(MAX_LINE_BYTES) + 1
        );
        assert_eq!(open::verify(&path).unwrap(), 1);
        drop(log);
        AuditLog::open(&path).await.unwrap();
    }
}
