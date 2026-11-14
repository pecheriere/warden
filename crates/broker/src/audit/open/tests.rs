//! Tests of opening and verifying the log: the unlocked first phase, the
//! locked second phase and streaming verification.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use warden_broker_proto::Id;

use super::{MAX_LINE_BYTES, finish_locked, open_blocking, verify, verify_prefix};
use crate::audit::{AuditError, AuditEvent, Body, Head, Line, compute_hash};

/// `n` canonical entries chained after `after`, and the head after them.
fn entries(after: &Head, n: u64) -> (Vec<u8>, Head) {
    let mut head = after.clone();
    let mut bytes = Vec::new();
    for _ in 0..n {
        let seq = head.seq + 1;
        let ts = 1_800_000_000;
        let event = AuditEvent::Denied { id: Id::random() };
        let hash = compute_hash(
            &head.hash,
            &Body {
                seq,
                ts,
                event: &event,
            },
        )
        .unwrap();
        let mut json = serde_json::to_vec(&Line {
            seq,
            ts,
            prev: head.hash.clone(),
            event,
            hash: hash.clone(),
        })
        .unwrap();
        json.push(b'\n');
        head = Head {
            seq,
            hash,
            len: head.len + u64::try_from(json.len()).unwrap(),
        };
        bytes.extend_from_slice(&json);
    }
    (bytes, head)
}

/// A log of `n` entries in a fresh directory, and the head after them.
fn log_of(n: u64) -> (tempfile::TempDir, PathBuf, Head) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let (bytes, head) = entries(&Head::genesis(), n);
    fs::write(&path, bytes).unwrap();
    (dir, path, head)
}

fn append_bytes(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
}

fn open_log(path: &Path) -> File {
    crate::private_files::open_private_log(path).unwrap()
}

#[test]
fn the_lock_is_held_only_for_the_tail() {
    let (_dir, path, written) = log_of(3);
    let holder = File::open(&path).unwrap();
    holder.lock().unwrap();

    // Phase one completes while another handle holds the lock.
    let file = open_log(&path);
    let verified = std::thread::spawn(move || verify_prefix(&file))
        .join()
        .unwrap()
        .unwrap();
    assert_eq!(verified.seq, 3);
    assert_eq!(verified.hash, written.hash);
    assert_eq!(verified.len, written.len);

    // Once the lock is released, the whole open completes. (Whether it waited
    // for the lock is not checked: the opener may start after the release.)
    let opener = {
        let path = path.clone();
        std::thread::spawn(move || open_blocking(&path))
    };
    holder.unlock().unwrap();
    let (_file, head) = opener.join().unwrap().unwrap();
    assert_eq!(head.seq, 3);
    assert_eq!(head.len, written.len);
}

#[test]
fn entries_appended_between_the_phases_are_verified() {
    let (_dir, path, written) = log_of(3);
    let file = open_log(&path);
    let verified = verify_prefix(&file).unwrap();
    assert_eq!(verified.seq, 3);

    let (more, after) = entries(&written, 2);
    append_bytes(&path, &more);

    let head = finish_locked(&file, verified).unwrap();
    assert_eq!(head.seq, 5);
    assert_eq!(head.hash, after.hash);
    assert_eq!(head.len, fs::metadata(&path).unwrap().len());
    assert_eq!(verify(&path).unwrap(), 5);
}

#[test]
fn a_line_half_written_in_phase_one_is_read_whole_in_phase_two() {
    let (_dir, path, written) = log_of(3);
    let (next, after) = entries(&written, 1);
    let (first, rest) = next.split_at(next.len() / 2);
    append_bytes(&path, first);

    let file = open_log(&path);
    let verified = verify_prefix(&file).unwrap();
    assert_eq!(verified.seq, 3);
    assert_eq!(verified.len, written.len);

    append_bytes(&path, rest);
    let head = finish_locked(&file, verified).unwrap();
    assert_eq!(head.seq, 4);
    assert_eq!(head.hash, after.hash);
    // Nothing was discarded or recorded: the line was complete by phase two.
    assert_eq!(verify(&path).unwrap(), 4);
}

#[test]
fn an_error_found_in_phase_one_is_decided_under_the_lock() {
    // Phase one reads a line spliced by a tail repair racing it: a torn tail,
    // then a newline from the line written after the repair.
    let (_dir, path, written) = log_of(3);
    append_bytes(&path, b"{\"seq\":4,\"ts\":1,\"pre\n");
    let file = open_log(&path);
    let verified = verify_prefix(&file).unwrap();
    assert_eq!(verified.seq, 3);
    assert_eq!(verified.len, written.len);

    // Under the lock, the file holds what the repair left: valid lines.
    OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(written.len)
        .unwrap();
    let (more, after) = entries(&written, 2);
    append_bytes(&path, &more);

    let head = finish_locked(&file, verified).unwrap();
    assert_eq!(head.seq, 5);
    assert_eq!(head.hash, after.hash);
    assert_eq!(verify(&path).unwrap(), 5);
}

#[test]
fn an_error_found_in_phase_one_and_still_there_under_the_lock_is_refused() {
    let (_dir, path, written) = log_of(3);
    let (more, _) = entries(&Head::genesis(), 1);
    append_bytes(&path, b"not an entry\n");
    append_bytes(&path, &more);
    let file = open_log(&path);
    let verified = verify_prefix(&file).unwrap();
    assert_eq!(verified.seq, 3);
    assert_eq!(verified.len, written.len);

    let len = fs::metadata(&path).unwrap().len();
    assert!(matches!(
        finish_locked(&file, verified),
        Err(AuditError::Malformed { line: 4, .. })
    ));
    assert_eq!(fs::metadata(&path).unwrap().len(), len);
    assert!(matches!(
        open_blocking(&path),
        Err(AuditError::Malformed { line: 4, .. })
    ));
}

#[test]
fn a_prefix_that_shrank_between_the_phases_is_refused() {
    let (_dir, path, written) = log_of(3);
    let file = open_log(&path);
    let verified = verify_prefix(&file).unwrap();

    OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(written.len - 10)
        .unwrap();

    assert!(matches!(
        finish_locked(&file, verified),
        Err(AuditError::PrefixChanged { verified }) if verified == written.len
    ));
    // Refusing changed nothing.
    assert_eq!(fs::metadata(&path).unwrap().len(), written.len - 10);
}

#[test]
fn a_prefix_rewritten_to_the_same_length_between_the_phases_is_refused() {
    let (_dir, path, written) = log_of(3);
    let file = open_log(&path);
    let verified = verify_prefix(&file).unwrap();

    // Another valid chain of the same length: every line is as long as before.
    let (other, other_head) = entries(&Head::genesis(), 3);
    assert_eq!(other_head.len, written.len);
    fs::write(&path, other).unwrap();

    assert!(matches!(
        finish_locked(&file, verified),
        Err(AuditError::PrefixChanged { .. })
    ));
}

#[test]
fn a_torn_tail_is_still_repaired() {
    let (_dir, path, _written) = log_of(3);
    let intact = fs::read(&path).unwrap();
    append_bytes(&path, b"{\"seq\":4,\"ts\":1,\"pre");

    let (_file, head) = open_blocking(&path).unwrap();
    assert_eq!(head.seq, 4);
    assert_eq!(head.len, fs::metadata(&path).unwrap().len());
    assert_eq!(verify(&path).unwrap(), 4);
    let bytes = fs::read(&path).unwrap();
    assert!(bytes.starts_with(&intact));
    let text = String::from_utf8(bytes).unwrap();
    let repair = text.lines().nth(3).unwrap();
    assert!(
        repair.contains("discarded torn tail of 20 bytes (sha256 "),
        "{repair}"
    );
}

#[test]
fn a_torn_tail_longer_than_any_line_is_discarded_with_its_digest() {
    let (_dir, path, _written) = log_of(2);
    let tail = vec![b'x'; MAX_LINE_BYTES + 5];
    append_bytes(&path, &tail);
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&tail));

    assert!(matches!(
        verify(&path),
        Err(AuditError::UnterminatedTail { bytes }) if bytes == tail.len()
    ));
    let (_file, head) = open_blocking(&path).unwrap();
    assert_eq!(head.seq, 3);
    assert_eq!(verify(&path).unwrap(), 3);
    let text = fs::read_to_string(&path).unwrap();
    let repair = text.lines().nth(2).unwrap();
    assert!(
        repair.contains(&format!(
            "discarded torn tail of {} bytes (sha256 {digest})",
            tail.len()
        )),
        "{repair}"
    );
}

#[test]
fn a_complete_line_longer_than_the_bound_is_refused() {
    let (_dir, path, _written) = log_of(2);
    let mut line = vec![b'x'; MAX_LINE_BYTES + 1];
    line.push(b'\n');
    append_bytes(&path, &line);
    let (more, _) = entries(&Head::genesis(), 1);
    append_bytes(&path, &more);

    assert!(matches!(
        verify(&path),
        Err(AuditError::Malformed { line: 3, .. })
    ));
    assert!(matches!(
        open_blocking(&path),
        Err(AuditError::Malformed { line: 3, .. })
    ));
}

#[test]
fn verify_streams_a_large_log() {
    let (_dir, path, _written) = log_of(100_000);
    assert_eq!(verify(&path).unwrap(), 100_000);
}
