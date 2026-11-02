//! The `warden-demo` binary: what it says at startup, what it refuses and
//! what it leaves behind.

use std::io::{BufRead as _, BufReader};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};

use rustix::process::{Pid, Signal, kill_process};

fn demo() -> Command {
    Command::new(env!("CARGO_BIN_EXE_warden-demo"))
}

/// Kills the child if a test fails before it stopped it.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Everything printed up to the line that ends the banner.
fn read_banner(lines: &mut impl Iterator<Item = std::io::Result<String>>) -> String {
    let mut banner = String::new();
    while !banner.contains("Press Ctrl-C") {
        let line = lines
            .next()
            .expect("the demo stopped before the end of its banner")
            .unwrap();
        banner.push_str(&line);
        banner.push('\n');
    }
    banner
}

/// The word after `marker` in `text`.
fn word_after<'a>(text: &'a str, marker: &str) -> &'a str {
    text.split_once(marker)
        .unwrap_or_else(|| panic!("no {marker:?} in {text}"))
        .1
        .split_whitespace()
        .next()
        .unwrap()
}

fn start(env: &[(&str, &str)]) -> (Running, ChildStdout) {
    let mut child = demo()
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    (Running(child), stdout)
}

#[test]
fn says_it_is_a_demo_and_stays_on_loopback_whatever_the_environment_says() {
    let (running, stdout) = start(&[
        ("WARDEN_API_LISTEN", "0.0.0.0:8080"),
        ("WARDEN_APPROVAL_LISTEN", "0.0.0.0:8081"),
        ("WARDEN_PUBLIC_URL", "https://warden.example.ts.net"),
        ("WARDEN_DB_PATH", "/nonexistent/warden.db"),
    ]);
    let banner = read_banner(&mut BufReader::new(stdout).lines());
    assert!(banner.contains("WARDEN DEMO"), "{banner}");
    assert!(banner.contains("NOT SECURE FOR REAL USE"), "{banner}");
    assert!(banner.contains("Listening on loopback only"), "{banner}");
    assert!(
        word_after(&banner, "exact address:").starts_with("http://localhost:"),
        "{banner}"
    );
    assert!(
        word_after(&banner, "GET ").starts_with("https://localhost:"),
        "{banner}"
    );
    assert!(!banner.contains("0.0.0.0"), "{banner}");
    assert!(!banner.contains("warden.example.ts.net"), "{banner}");
    drop(running);
}

#[test]
fn refuses_any_way_of_choosing_an_address() {
    for args in [
        &["--listen", "0.0.0.0:8080"][..],
        &["--api-listen", "0.0.0.0:8080"][..],
        &["0.0.0.0:8080"][..],
    ] {
        let output = demo().args(args).output().unwrap();
        assert!(!output.status.success(), "{args:?} was accepted");
    }
}

#[test]
fn deletes_its_data_when_stopped_and_verifies_the_audit_log() {
    let (mut running, stdout) = start(&[]);
    let mut lines = BufReader::new(stdout).lines();
    let banner = read_banner(&mut lines);
    let dir = PathBuf::from(word_after(&banner, "Data in "));
    assert!(dir.join("audit.jsonl").is_file(), "{}", dir.display());

    let pid = Pid::from_child(&running.0);
    kill_process(pid, Signal::TERM).unwrap();
    let status = running.0.wait().unwrap();
    assert!(status.success(), "{status}");

    let rest: Vec<String> = lines.map(Result::unwrap).collect();
    let rest = rest.join("\n");
    assert!(rest.contains("hash chain intact"), "{rest}");
    assert!(!dir.exists(), "{} still exists", dir.display());
}
