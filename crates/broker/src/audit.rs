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
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use warden_broker_proto::{AgentName, Fingerprint, Id, TargetName, UnixUser};

/// `prev` of the first line in a log.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Something worth recording in the audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditEvent {
    /// An agent asked for access.
    RequestCreated {
        /// Request id.
        id: Id,
        /// Requesting agent.
        agent: AgentName,
        /// Request fingerprint.
        fingerprint: Fingerprint,
        /// Free-text summary (never secrets).
        summary: String,
    },
    /// The owner was notified.
    Notified {
        /// Request id.
        id: Id,
        /// Name of the channel that delivered the notification.
        channel: String,
    },
    /// A notification channel failed.
    NotifyFailed {
        /// Request id.
        id: Id,
        /// Channel name.
        channel: String,
        /// Failure reason.
        reason: String,
    },
    /// The owner approved a request.
    Approved {
        /// Request id.
        id: Id,
        /// Grant id.
        grant_id: Id,
        /// Approved window in seconds.
        window_secs: u32,
        /// Passkey that signed the approval.
        passkey_id: String,
    },
    /// The owner denied a request.
    Denied {
        /// Request id.
        id: Id,
    },
    /// An agent withdrew its own pending request.
    RequestCancelled {
        /// Request id.
        id: Id,
        /// The agent that made and cancelled it.
        agent: AgentName,
    },
    /// A request timed out.
    Expired {
        /// Request id.
        id: Id,
    },
    /// A certificate was issued.
    CertIssued {
        /// Grant id.
        grant_id: Id,
        /// Certificate key id.
        key_id: String,
        /// Expiry, unix seconds.
        not_after: i64,
    },
    /// A grant was revoked.
    GrantRevoked {
        /// Grant id.
        grant_id: Id,
        /// Who revoked it.
        by: String,
    },
    /// A proxied HTTP call is about to be sent with an API secret. Written
    /// before anything leaves the broker; the call is not made if this
    /// entry cannot be written.
    ProxyCallStarted {
        /// Grant id.
        grant_id: Id,
        /// Request method.
        method: String,
        /// Origin and path of the URL (no query).
        url: String,
    },
    /// An agent asked the broker to make an HTTP call with an API secret.
    /// Recorded for every call on a usable grant, whether it was refused,
    /// failed or answered. Never holds the secret or the query string.
    ProxyCall {
        /// Grant id.
        grant_id: Id,
        /// Request method, or `invalid`.
        method: String,
        /// Origin and path of the URL (no query), or `invalid`.
        url: String,
        /// Upstream status, if a response arrived.
        status: Option<u16>,
        /// Upstream body length, before redaction.
        response_bytes: u64,
        /// Secret occurrences removed from the response.
        redactions: u32,
        /// `ok`, or the message the agent was given.
        outcome: String,
    },
    /// A relayed SSH session is about to reach its target. Written before
    /// the relay opens any connection to the target; the session does not
    /// start if this entry cannot be written.
    RelaySessionStarted {
        /// Grant id.
        grant_id: Id,
        /// Target name.
        target: TargetName,
        /// Login user on the target.
        user: UnixUser,
        /// The command of an `exec` session (at most 200 characters, cut
        /// with `…`); `None` for a shell.
        command: Option<String>,
    },
    /// A relayed SSH session ended. Follows its `relay_session_started`.
    RelaySessionEnded {
        /// Grant id.
        grant_id: Id,
        /// Why it ended (a fixed phrase, never secrets).
        reason: String,
        /// Bytes the agent sent on to the target.
        bytes_to_target: u64,
        /// Bytes the target sent back (stdout and stderr).
        bytes_from_target: u64,
        /// The command's exit status, if the target reported one.
        exit_status: Option<u32>,
    },
    /// The relay refused to start a session on an authenticated
    /// connection: the grant or the target's policy changed since login.
    RelaySessionRefused {
        /// Grant id.
        grant_id: Id,
        /// Why (a fixed phrase, never secrets).
        reason: String,
    },
    /// A connection to the relay ended without logging in after trying to.
    /// Holds no key material.
    RelayLoginRefused {
        /// The user name asked for (the target), or `<invalid>` if it is
        /// not a valid target name.
        user: String,
        /// The peer's IP address.
        peer: String,
        /// Refused login attempts.
        attempts: u32,
    },
    /// An agent was added.
    AgentAdded {
        /// Agent name.
        agent: AgentName,
    },
    /// An agent was switched to (or created with) request signing by this
    /// public key. The key itself is not recorded, only its fingerprint.
    AgentKeySet {
        /// Agent name.
        agent: AgentName,
        /// The key's `SHA256:…` fingerprint.
        fingerprint: String,
    },
    /// An agent was revoked.
    AgentRevoked {
        /// Agent name.
        agent: AgentName,
    },
    /// A passkey was enrolled.
    PasskeyEnrolled {
        /// Passkey id.
        passkey_id: String,
    },
    /// An approval was refused because the passkey's signature counter did
    /// not increase: a possible cloned authenticator.
    PasskeyCounterRegressed {
        /// Passkey id.
        passkey_id: String,
    },
    /// A passkey was removed.
    PasskeyRemoved {
        /// Passkey id.
        passkey_id: String,
    },
    /// An internal error worth recording.
    Error {
        /// Where it happened.
        context: String,
        /// What happened (never secrets).
        message: String,
    },
}

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

/// Verify newline-terminated lines in `bytes`, returning the line count and the last hash.
///
/// UTF-8 is validated per line so a failure names the offending line.
fn verify_bytes(bytes: &[u8]) -> Result<(u64, String), AuditError> {
    let mut prev = GENESIS.to_owned();
    let mut count = 0_u64;
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if body.is_empty() && bytes.is_empty() {
        return Ok((0, prev));
    }
    for raw in body.split(|b| *b == b'\n') {
        count += 1;
        let line = parse_canonical(raw).map_err(|reason| AuditError::Malformed {
            line: count,
            reason,
        })?;
        if line.seq != count {
            return Err(AuditError::SeqGap {
                expected: count,
                found: line.seq,
            });
        }
        let body = Body {
            seq: line.seq,
            ts: line.ts,
            event: &line.event,
        };
        if line.prev != prev || compute_hash(&prev, &body)? != line.hash {
            return Err(AuditError::BrokenChain { seq: line.seq });
        }
        prev = line.hash;
    }
    Ok((count, prev))
}

/// Split `bytes` into the newline-terminated head and the unterminated tail.
fn split_tail(bytes: &[u8]) -> (&[u8], &[u8]) {
    if bytes.last().is_none_or(|b| *b == b'\n') {
        return (bytes, &[]);
    }
    let head_len = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    bytes.split_at(head_len)
}

/// Verify the chain in the file at `path`, returning the number of lines.
///
/// # Errors
/// Returns an [`AuditError`] naming the line or sequence number at fault. A
/// final line without its newline terminator (a torn write) is reported as
/// [`AuditError::UnterminatedTail`] once the preceding lines verify.
pub fn verify(path: &Path) -> Result<u64, AuditError> {
    let bytes = std::fs::read(path)?;
    let (head, tail) = split_tail(&bytes);
    let (count, _) = verify_bytes(head)?;
    if tail.is_empty() {
        Ok(count)
    } else {
        Err(AuditError::UnterminatedTail { bytes: tail.len() })
    }
}

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
    file.set_len(head.len)?;
    file.sync_data()?;
    let record = AuditEvent::Error {
        context: "audit".to_owned(),
        message: format!(
            "discarded torn tail of {} bytes (sha256 {})",
            tail.len(),
            hex::encode(Sha256::digest(tail))
        ),
    };
    Ok((head, Some(record)))
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

/// Write `event` as the line after `head` and fsync it.
fn write_event(file: &File, head: &Head, event: &AuditEvent) -> Result<Head, AuditError> {
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
    json.push(b'\n');
    let mut writer = file;
    writer.write_all(&json)?;
    file.sync_data()?;
    tracing::info!(target: "audit", line = %String::from_utf8_lossy(&json).trim_end());
    Ok(Head {
        seq,
        hash,
        len: head.len + len_u64(json.len()),
    })
}

/// Open, lock, verify and repair the log at `path`. Blocking.
fn open_blocking(path: &Path) -> Result<(File, Head), AuditError> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .mode(0o600)
        .open(path)?;
    let head = load_locked(&file)?;
    Ok((file, head))
}

/// Read, verify and repair the whole log under the file lock. Blocking.
fn load_locked(file: &File) -> Result<Head, AuditError> {
    let _lock = FileLock::acquire(file)?;
    let mut bytes = Vec::new();
    let mut reader = file;
    reader.read_to_end(&mut bytes)?;
    let (body, tail) = split_tail(&bytes);
    let (seq, hash) = verify_bytes(body)?;
    let head = Head {
        seq,
        hash,
        len: len_u64(body.len()),
    };
    let (mut head, record) = repair_tail(file, head, tail)?;
    if let Some(record) = record {
        head = write_event(file, &head, &record)?;
    }
    Ok(head)
}

/// Why a blocking append failed.
enum Failure {
    /// Nothing was written: the lock could not be taken, or the file could
    /// not be read to re-sync. A later append simply tries again.
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
    write_event(file, &head, event).map_err(Failure::Write)
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
        }
    }

    /// Open (creating with mode 0600 if absent) and resume the chain.
    ///
    /// Under the file lock, an existing log is fully verified first; a log
    /// with corruption in a complete line or a broken chain is refused. A
    /// torn final line (crash mid-append) is repaired: a valid one is
    /// newline-terminated, a partial one is truncated and the repair is
    /// recorded on the chain.
    ///
    /// # Errors
    /// Returns an [`AuditError`] on I/O failure, lock timeout, or if the
    /// existing log is invalid.
    pub async fn open(path: &Path) -> Result<Self, AuditError> {
        let path = path.to_owned();
        let (file, head) = tokio::task::spawn_blocking(move || open_blocking(&path))
            .await
            .map_err(join_error)??;
        Ok(Self::from_parts(file, head))
    }

    /// Append `event`, fsyncing before returning.
    ///
    /// Cancel-safe: the write runs on a blocking thread that owns this
    /// handle's state, so dropping the returned future neither interrupts the
    /// write nor loses its effect on the chain position.
    ///
    /// # Errors
    /// Returns an [`AuditError`] if the lock cannot be taken within 5 s
    /// ([`AuditError::LockTimeout`]) or the line cannot be written durably;
    /// after a failed write or fsync the log is poisoned.
    pub async fn append(&self, event: AuditEvent) -> Result<(), AuditError> {
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
mod tests {
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
        assert_eq!(
            verify_bytes(format!("{json}\n").as_bytes()).unwrap(),
            (1, line.hash)
        );
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
}
