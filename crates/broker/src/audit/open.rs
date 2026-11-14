//! Opening and verifying the log.
//!
//! Opening verifies in two phases so that the file lock, which every writer
//! needs for each append, is held only briefly whatever the log's size:
//!
//! 1. Without the lock, [`verify_prefix`] streams the file from the start up to
//!    its last complete line. Another writer may be appending, or repairing a
//!    torn tail, meanwhile: neither a partial final line nor a line that does
//!    not continue the chain is an error here. Phase one stops at the last line
//!    that verifies, and phase two reads on from there.
//! 2. Under the lock, [`finish_locked`] checks that the verified prefix is still
//!    there, verifies every byte that follows it, and repairs a torn tail as
//!    before. Only an error found here refuses the log.
//!
//! Only `repair_tail` ever shortens the file, and only past its last complete
//! line, so a verified prefix that shrank or whose last line changed was changed
//! by something other than warden: it is refused with
//! [`AuditError::PrefixChanged`].
//!
//! Both phases, and [`verify`], read one line at a time through a
//! [`BufReader`], so memory stays flat whatever the file's size.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek as _, SeekFrom};
use std::path::Path;

use sha2::{Digest as _, Sha256};

use super::{
    AuditError, Body, FileLock, Head, MAX_LINE_BYTES, compute_hash, discard_tail, len_u64,
    parse_canonical, read_last_link, repair_tail, write_event,
};

#[cfg(test)]
mod tests;

/// What follows the last complete line.
pub(super) enum Rest {
    /// Nothing: the file ends with a newline, or is empty.
    Nothing,
    /// A final line without its newline, at most [`MAX_LINE_BYTES`] long.
    Tail(Vec<u8>),
    /// A final line without its newline, longer than any line can be. Only its
    /// length and SHA-256 are kept.
    LongTail {
        /// Its length in bytes.
        len: u64,
        /// Its SHA-256.
        digest: [u8; 32],
    },
}

/// One read from [`read_line`].
enum Step {
    /// A complete line, its newline removed, is in the buffer.
    Line,
    /// A line longer than [`MAX_LINE_BYTES`] ended with a newline; it was
    /// consumed but not kept.
    LongLine,
    /// The end of the file.
    End(Rest),
}

/// Read the next line of `reader` into `buf`, keeping at most
/// [`MAX_LINE_BYTES`] of it in memory.
fn read_line<R: BufRead>(reader: &mut R, buf: &mut Vec<u8>) -> std::io::Result<Step> {
    buf.clear();
    // One byte more than the longest line, for its newline.
    let limit = len_u64(MAX_LINE_BYTES) + 1;
    std::io::Read::take(&mut *reader, limit).read_until(b'\n', buf)?;
    if buf.last() == Some(&b'\n') {
        buf.pop();
        return Ok(Step::Line);
    }
    if buf.is_empty() {
        return Ok(Step::End(Rest::Nothing));
    }
    if buf.len() <= MAX_LINE_BYTES {
        return Ok(Step::End(Rest::Tail(std::mem::take(buf))));
    }
    // Too long to keep: consume the rest of it, hashing in case it is a tail.
    let mut hasher = Sha256::new();
    hasher.update(&*buf);
    let mut len = len_u64(buf.len());
    buf.clear();
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            return Ok(Step::End(Rest::LongTail {
                len,
                digest: hasher.finalize().into(),
            }));
        }
        if let Some(end) = chunk.iter().position(|b| *b == b'\n') {
            reader.consume(end + 1);
            return Ok(Step::LongLine);
        }
        let n = chunk.len();
        hasher.update(chunk);
        len = len.saturating_add(len_u64(n));
        reader.consume(n);
    }
}

/// Check that `raw`, a complete line without its newline, is the entry that
/// follows `head`, and return the position after it.
///
/// UTF-8 is validated per line so a failure names the offending line.
fn next_head(head: &Head, raw: &[u8]) -> Result<Head, AuditError> {
    let seq = head.seq + 1;
    let line =
        parse_canonical(raw).map_err(|reason| AuditError::Malformed { line: seq, reason })?;
    if line.seq != seq {
        return Err(AuditError::SeqGap {
            expected: seq,
            found: line.seq,
        });
    }
    let body = Body {
        seq: line.seq,
        ts: line.ts,
        event: &line.event,
    };
    if line.prev != head.hash || compute_hash(&head.hash, &body)? != line.hash {
        return Err(AuditError::BrokenChain { seq: line.seq });
    }
    Ok(Head {
        seq,
        hash: line.hash,
        len: head.len + len_u64(raw.len()) + 1,
    })
}

/// Verify the complete lines of `reader`, which is positioned at `head.len`,
/// as the continuation of `head`, advancing `head` past each line that
/// verifies. Returns what follows the last complete line.
///
/// # Errors
/// [`AuditError::Malformed`], [`AuditError::SeqGap`] or
/// [`AuditError::BrokenChain`] for the first line that does not continue the
/// chain, or an I/O error. `head` is then the position after the last line
/// that verified.
pub(super) fn verify_lines<R: BufRead>(
    reader: &mut R,
    head: &mut Head,
) -> Result<Rest, AuditError> {
    let mut buf = Vec::new();
    loop {
        match read_line(reader, &mut buf)? {
            Step::Line => *head = next_head(head, &buf)?,
            Step::LongLine => {
                return Err(AuditError::Malformed {
                    line: head.seq + 1,
                    reason: format!("longer than {MAX_LINE_BYTES} bytes"),
                });
            }
            Step::End(rest) => return Ok(rest),
        }
    }
}

/// Verify the chain in the file at `path`, returning the number of lines.
///
/// Reads one line at a time, so memory does not grow with the file, and takes
/// no lock: a writer appending meanwhile can at most leave a partial last line.
///
/// # Errors
/// Returns an [`AuditError`] naming the line or sequence number at fault. A
/// final line without its newline terminator (a torn write) is reported as
/// [`AuditError::UnterminatedTail`] once the preceding lines verify.
pub fn verify(path: &Path) -> Result<u64, AuditError> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut head = Head::genesis();
    let rest = verify_lines(&mut reader, &mut head)?;
    match rest {
        Rest::Nothing => Ok(head.seq),
        Rest::Tail(tail) => Err(AuditError::UnterminatedTail { bytes: tail.len() }),
        Rest::LongTail { len, .. } => Err(AuditError::UnterminatedTail {
            bytes: usize::try_from(len).unwrap_or(usize::MAX),
        }),
    }
}

/// Open, verify and repair the log at `path`, holding the file lock only for
/// what was appended after the unlocked first phase. Blocking.
pub(super) fn open_blocking(path: &Path) -> Result<(File, Head), AuditError> {
    let file = crate::private_files::open_private_log(path)?;
    let verified = verify_prefix(&file)?;
    let head = finish_locked(&file, verified)?;
    Ok((file, head))
}

/// Phase one: verify `file` from its start, without the file lock, and return
/// the position after the last line that continues the chain. Blocking.
///
/// A line that does not continue it is not refused here: another writer
/// repairing a torn tail meanwhile can splice what this read sees. Phase two
/// reads again from the returned position under the lock, where nothing can
/// change, and only its verdict is final.
///
/// # Errors
/// An I/O error, or if an entry cannot be hashed.
pub(super) fn verify_prefix(file: &File) -> Result<Head, AuditError> {
    let mut reader = file;
    reader.seek(SeekFrom::Start(0))?;
    let mut head = Head::genesis();
    match verify_lines(&mut BufReader::new(reader), &mut head) {
        Ok(_)
        | Err(
            AuditError::Malformed { .. }
            | AuditError::SeqGap { .. }
            | AuditError::BrokenChain { .. },
        ) => Ok(head),
        Err(e) => Err(e),
    }
}

/// Phase two: under the file lock, check that the prefix `verified` in phase
/// one is unchanged, verify what follows it and repair a torn tail. Blocking.
///
/// # Errors
/// [`AuditError::PrefixChanged`] if the file is now shorter than `verified`, or
/// the line ending at `verified.len` is no longer the one verified; otherwise
/// as for [`verify_lines`], or if the lock cannot be taken.
pub(super) fn finish_locked(file: &File, verified: Head) -> Result<Head, AuditError> {
    let _lock = FileLock::acquire(file)?;
    let len = file.metadata()?.len();
    if len < verified.len {
        return Err(AuditError::PrefixChanged {
            verified: verified.len,
        });
    }
    check_last_line(file, &verified)?;
    let mut reader = file;
    reader.seek(SeekFrom::Start(verified.len))?;
    let mut head = verified;
    let rest = verify_lines(&mut BufReader::new(reader), &mut head)?;
    let (mut head, record) = match rest {
        Rest::Nothing => (head, None),
        Rest::Tail(tail) => repair_tail(file, head, &tail)?,
        Rest::LongTail { len, digest } => {
            let record = discard_tail(file, &head, len, &digest)?;
            (head, Some(record))
        }
    };
    if let Some(record) = record {
        head = write_event(file, &head, &record)?;
    }
    Ok(head)
}

/// Check that the last line of the prefix verified in phase one is still the
/// one verified. A rewrite to the same length or longer would otherwise go
/// unnoticed when nothing follows the prefix, and the next append would then
/// chain from an entry that is no longer in the file. One read of at most one
/// line, under the lock.
fn check_last_line(file: &File, verified: &Head) -> Result<(), AuditError> {
    if verified.len == 0 {
        return Ok(());
    }
    let changed = || AuditError::PrefixChanged {
        verified: verified.len,
    };
    let (last, _) = read_last_link(file, verified.len).map_err(|e| match e {
        AuditError::Io(e) => AuditError::Io(e),
        _ => changed(),
    })?;
    if last.seq == verified.seq && last.hash == verified.hash && last.len == verified.len {
        Ok(())
    } else {
        Err(changed())
    }
}
