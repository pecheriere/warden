//! The real `warden` binary's exit code for a command line it does not run: a
//! usage error must not read as a denial (exit 2, tested with a real broker in
//! `e2e_http.rs`), and help and version output is a success.

use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

const EXIT_USAGE: i32 = 64;

/// Runs `warden <args>` with nothing to read: none of these reach a command.
fn warden(args: &[&str]) -> Output {
    let home = TempDir::new().unwrap();
    Command::new(env!("CARGO_BIN_EXE_warden"))
        .args(args)
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_STATE_HOME", home.path().join("state"))
        .env_remove("WARDEN_AGENT_KEY")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn usage_errors_exit_64_and_show_the_usage_on_stderr() {
    for args in [
        &["--no-such-flag"][..],
        &["no-such-command"],
        &["doctor", "--no-such-flag"],
        &["request", "api"],
        &["http"],
        // Without a command, the parser prints the help as an error.
        &[],
    ] {
        let out = warden(args);
        assert_eq!(out.status.code(), Some(EXIT_USAGE), "{args:?}");
        assert_eq!(out.stdout, [] as [u8; 0], "{args:?}");
        assert!(
            stderr(&out).contains("Usage:"),
            "{args:?}: {}",
            stderr(&out)
        );
    }
}

#[test]
fn help_exits_0_on_stdout() {
    for args in [
        &["--help"][..],
        &["-h"],
        &["help"],
        &["doctor", "--help"],
        &["help", "request"],
    ] {
        let out = warden(args);
        assert_eq!(out.status.code(), Some(0), "{args:?}: {}", stderr(&out));
        assert_eq!(out.stderr, [] as [u8; 0], "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("Usage:"),
            "{args:?}"
        );
    }
}

#[test]
fn version_exits_0_on_stdout() {
    for flag in ["--version", "-V"] {
        let out = warden(&[flag]);
        assert_eq!(out.status.code(), Some(0), "{flag}: {}", stderr(&out));
        assert_eq!(out.stderr, [] as [u8; 0], "{flag}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            format!("warden {}", env!("CARGO_PKG_VERSION")),
            "{flag}"
        );
    }
}
