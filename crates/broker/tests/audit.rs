//! Integration tests for the hash-chained audit log.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use warden_broker::audit::{AuditError, AuditEvent, AuditLog, verify};
use warden_broker_proto::{AgentName, Id};

fn denied() -> AuditEvent {
    AuditEvent::Denied { id: Id::random() }
}

fn agent_added(name: &str) -> AuditEvent {
    AuditEvent::AgentAdded {
        agent: name.to_owned().try_into().expect("valid agent name"),
    }
}

async fn three_lines(path: &std::path::Path) {
    let log = AuditLog::open(path).await.unwrap();
    log.append(agent_added("alpha")).await.unwrap();
    log.append(AuditEvent::Error {
        context: "ctx".to_owned(),
        message: "original text".to_owned(),
    })
    .await
    .unwrap();
    log.append(denied()).await.unwrap();
}

#[tokio::test]
async fn chain_verifies_after_appends() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    three_lines(&path).await;
    assert_eq!(verify(&path).unwrap(), 3);
}

#[tokio::test]
async fn resume_continues_chain_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    three_lines(&path).await;
    let log = AuditLog::open(&path).await.unwrap();
    log.append(denied()).await.unwrap();
    assert_eq!(verify(&path).unwrap(), 4);
}

#[tokio::test]
async fn tampered_line_detected_at_its_seq() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    three_lines(&path).await;
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("original text"));
    fs::write(&path, text.replace("original text", "forged text!")).unwrap();
    assert!(matches!(
        verify(&path),
        Err(AuditError::BrokenChain { seq: 2 })
    ));
}

#[tokio::test]
async fn deleted_line_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    three_lines(&path).await;
    let text = fs::read_to_string(&path).unwrap();
    let kept: Vec<&str> = text
        .lines()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, l)| l)
        .collect();
    fs::write(&path, format!("{}\n", kept.join("\n"))).unwrap();
    assert!(matches!(
        verify(&path),
        Err(AuditError::SeqGap {
            expected: 2,
            found: 3
        })
    ));
}

#[tokio::test]
async fn deleted_first_line_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    three_lines(&path).await;
    let text = fs::read_to_string(&path).unwrap();
    let rest: Vec<&str> = text.lines().skip(1).collect();
    fs::write(&path, format!("{}\n", rest.join("\n"))).unwrap();
    assert!(matches!(
        verify(&path),
        Err(AuditError::SeqGap {
            expected: 1,
            found: 2
        })
    ));
}

#[tokio::test]
async fn wrong_genesis_prev_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    three_lines(&path).await;
    let text = fs::read_to_string(&path).unwrap();
    let forged = text.replacen(&"0".repeat(64), &"1".repeat(64), 1);
    fs::write(&path, forged).unwrap();
    assert!(matches!(
        verify(&path),
        Err(AuditError::BrokenChain { seq: 1 })
    ));
}

#[test]
fn malformed_line_is_an_error_not_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    fs::write(&path, "not json\n").unwrap();
    assert!(matches!(
        verify(&path),
        Err(AuditError::Malformed { line: 1, .. })
    ));
}

#[tokio::test]
async fn open_refuses_a_broken_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    fs::write(&path, "garbage\n").unwrap();
    assert!(AuditLog::open(&path).await.is_err());
}

#[tokio::test]
async fn file_mode_is_0600() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let log = AuditLog::open(&path).await.unwrap();
    log.append(AuditEvent::AgentRevoked {
        agent: AgentName::try_from("alpha".to_owned()).unwrap(),
    })
    .await
    .unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[tokio::test]
async fn torn_partial_tail_is_truncated_and_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    three_lines(&path).await;
    let intact = fs::read_to_string(&path).unwrap();
    fs::write(&path, format!("{intact}{{\"seq\":4,\"ts\":1,\"pre")).unwrap();

    let log = AuditLog::open(&path).await.unwrap();
    log.append(denied()).await.unwrap();

    let text = fs::read_to_string(&path).unwrap();
    assert!(text.starts_with(&intact));
    assert!(!text.contains("\"pre\n"));
    // 3 original + repair record + new event.
    assert_eq!(verify(&path).unwrap(), 5);
    let repair = text.lines().nth(3).unwrap();
    assert!(
        repair.contains("discarded torn tail of 20 bytes (sha256 "),
        "{repair}"
    );
}

#[tokio::test]
async fn valid_tail_missing_newline_is_kept_and_terminated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    three_lines(&path).await;
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, text.trim_end_matches('\n')).unwrap();

    let log = AuditLog::open(&path).await.unwrap();
    assert_eq!(verify(&path).unwrap(), 3);
    log.append(denied()).await.unwrap();
    assert_eq!(verify(&path).unwrap(), 4);
    assert!(fs::read_to_string(&path).unwrap().ends_with('\n'));
}

#[tokio::test]
async fn midfile_corruption_still_refuses_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    three_lines(&path).await;
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, text.replace("original text", "forged text!")).unwrap();
    assert!(AuditLog::open(&path).await.is_err());
}

#[tokio::test]
async fn torn_tail_inside_multibyte_char_is_truncated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    three_lines(&path).await;
    let intact = fs::read(&path).unwrap();
    let log = AuditLog::open(&path).await.unwrap();
    log.append(AuditEvent::Error {
        context: "ctx".to_owned(),
        message: "h\u{e9}llo".to_owned(),
    })
    .await
    .unwrap();
    drop(log);
    let mut bytes = fs::read(&path).unwrap();
    let cut = bytes.iter().position(|b| *b == 0xC3).unwrap() + 1;
    bytes.truncate(cut);
    assert!(std::str::from_utf8(&bytes).is_err());
    fs::write(&path, &bytes).unwrap();

    // verify reports the torn tail distinctly instead of an I/O error.
    assert!(matches!(
        verify(&path),
        Err(AuditError::UnterminatedTail { .. })
    ));

    let log = AuditLog::open(&path).await.unwrap();
    log.append(denied()).await.unwrap();
    assert_eq!(verify(&path).unwrap(), 5);
    let text = fs::read_to_string(&path).unwrap();
    let expected = cut - intact.len();
    assert!(
        text.lines()
            .nth(3)
            .unwrap()
            .contains(&format!("discarded torn tail of {expected} bytes (sha256 ")),
        "{text}"
    );
}

#[test]
fn invalid_utf8_in_complete_line_names_the_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    fs::write(&path, b"\xff\xfe\n").unwrap();
    assert!(matches!(
        verify(&path),
        Err(AuditError::Malformed { line: 1, .. })
    ));
}

fn event_types(path: &std::path::Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["event"]["type"].as_str().unwrap().to_owned()
        })
        .collect()
}

#[tokio::test]
async fn two_logs_on_same_file_interleave_and_chain_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let a = std::sync::Arc::new(AuditLog::open(&path).await.unwrap());
    let b = std::sync::Arc::new(AuditLog::open(&path).await.unwrap());

    for _ in 0..3 {
        a.append(denied()).await.unwrap();
        b.append(denied()).await.unwrap();
    }
    assert_eq!(verify(&path).unwrap(), 6);

    let mut tasks = Vec::new();
    for log in [&a, &b] {
        for _ in 0..20 {
            let log = log.clone();
            tasks.push(tokio::spawn(async move { log.append(denied()).await }));
        }
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    // verify checks that seq runs 1..=n without gaps and every link holds.
    assert_eq!(verify(&path).unwrap(), 46);
}

#[tokio::test]
async fn append_resyncs_after_external_append() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let server = AuditLog::open(&path).await.unwrap();
    server.append(denied()).await.unwrap();

    // Another process (here: a second handle, then dropped) appends.
    {
        let admin = AuditLog::open(&path).await.unwrap();
        admin.append(agent_added("beta")).await.unwrap();
        admin.append(agent_added("gamma")).await.unwrap();
    }
    server.append(denied()).await.unwrap();
    assert_eq!(verify(&path).unwrap(), 4);
    assert_eq!(
        event_types(&path),
        ["denied", "agent_added", "agent_added", "denied"]
    );
}

#[tokio::test]
async fn append_repairs_torn_tail_left_by_another_writer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let server = AuditLog::open(&path).await.unwrap();
    server.append(denied()).await.unwrap();

    // Another writer crashed half way through a line.
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    std::io::Write::write_all(&mut file, br#"{"seq":2,"ts":1,"prev":"ab"#).unwrap();
    drop(file);

    server.append(denied()).await.unwrap();
    assert_eq!(verify(&path).unwrap(), 3);
    assert_eq!(event_types(&path), ["denied", "error", "denied"]);
}

#[tokio::test]
async fn append_keeps_valid_unterminated_line_from_another_writer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let server = AuditLog::open(&path).await.unwrap();
    server.append(denied()).await.unwrap();
    {
        let admin = AuditLog::open(&path).await.unwrap();
        admin.append(agent_added("beta")).await.unwrap();
    }
    // Strip the final newline, as if the writer died just before it.
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, text.trim_end_matches('\n')).unwrap();

    server.append(denied()).await.unwrap();
    assert_eq!(verify(&path).unwrap(), 3);
    assert_eq!(event_types(&path), ["denied", "agent_added", "denied"]);
}

#[tokio::test]
async fn append_resyncs_when_last_line_exceeds_read_window() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let server = AuditLog::open(&path).await.unwrap();
    server.append(denied()).await.unwrap();
    {
        let admin = AuditLog::open(&path).await.unwrap();
        admin
            .append(AuditEvent::Error {
                context: "ctx".to_owned(),
                message: "x".repeat(20_000),
            })
            .await
            .unwrap();
    }
    server.append(denied()).await.unwrap();
    assert_eq!(verify(&path).unwrap(), 3);
}

#[tokio::test]
async fn append_times_out_on_held_lock_without_poisoning() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let log = AuditLog::open(&path).await.unwrap();
    let holder = fs::File::open(&path).unwrap();
    holder.lock().unwrap();

    let started = std::time::Instant::now();
    assert!(matches!(
        log.append(denied()).await,
        Err(AuditError::LockTimeout)
    ));
    let waited = started.elapsed();
    assert!(waited >= std::time::Duration::from_secs(5), "{waited:?}");
    assert!(waited < std::time::Duration::from_secs(7), "{waited:?}");

    holder.unlock().unwrap();
    log.append(denied()).await.unwrap();
    assert_eq!(verify(&path).unwrap(), 1);
}

#[tokio::test]
async fn cancelled_append_does_not_poison() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let log = AuditLog::open(&path).await.unwrap();

    // Hold the file lock so the append's blocking write is parked waiting for
    // it; dropping the future then cancels it mid-flight deterministically.
    let holder = fs::File::open(&path).unwrap();
    holder.lock().unwrap();
    let cancelled =
        tokio::time::timeout(std::time::Duration::from_millis(200), log.append(denied())).await;
    assert!(
        cancelled.is_err(),
        "append finished while the lock was held"
    );
    holder.unlock().unwrap();

    log.append(denied()).await.unwrap();
    // The dropped append still completed; both lines are on the chain.
    assert_eq!(verify(&path).unwrap(), 2);
}

/// Rewrite line `n` (1-based) of the log at `path` with `edit`.
fn edit_line(path: &std::path::Path, n: usize, edit: impl Fn(&str) -> String) {
    let text = fs::read_to_string(path).unwrap();
    let lines: Vec<String> = text
        .lines()
        .enumerate()
        .map(|(i, l)| if i + 1 == n { edit(l) } else { l.to_owned() })
        .collect();
    fs::write(path, format!("{}\n", lines.join("\n"))).unwrap();
}

#[tokio::test]
async fn injected_unknown_field_fails_verify() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    three_lines(&path).await;
    edit_line(&path, 2, |l| l.replacen('{', r#"{"note":"forged","#, 1));
    assert!(matches!(
        verify(&path),
        Err(AuditError::Malformed { line: 2, .. })
    ));
    assert!(matches!(
        AuditLog::open(&path).await,
        Err(AuditError::Malformed { line: 2, .. })
    ));
}

#[tokio::test]
async fn injected_unknown_event_field_fails_verify() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    three_lines(&path).await;
    edit_line(&path, 2, |l| {
        l.replacen(
            r#""type":"error","#,
            r#""type":"error","note":"forged","#,
            1,
        )
    });
    assert!(matches!(
        verify(&path),
        Err(AuditError::Malformed { line: 2, .. })
    ));
}

#[tokio::test]
async fn respaced_json_fails_verify() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    three_lines(&path).await;
    edit_line(&path, 2, |l| l.replacen(r#","ts":"#, r#", "ts": "#, 1));
    assert!(matches!(
        verify(&path),
        Err(AuditError::Malformed { line: 2, .. })
    ));
}

#[tokio::test]
async fn reordered_keys_fail_verify() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    three_lines(&path).await;
    // Move "hash" to the front: same JSON object, different bytes.
    edit_line(&path, 2, |l| {
        let (rest, hash) = l.rsplit_once(r#","hash":"#).unwrap();
        format!(
            r#"{{"hash":{},{}}}"#,
            hash.trim_end_matches('}'),
            &rest[1..]
        )
    });
    assert!(matches!(
        verify(&path),
        Err(AuditError::Malformed { line: 2, .. })
    ));
}
