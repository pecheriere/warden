use std::cell::RefCell;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use super::{commands, find_on_path, run_with};
use crate::{EXIT_ERROR, Exit};

fn strings(words: &[&str]) -> Vec<String> {
    words.iter().map(|&w| w.to_owned()).collect()
}

/// An exit status with `code`, as a wait status encodes it.
fn exited(code: i32) -> ExitStatus {
    ExitStatus::from_raw(code << 8)
}

#[test]
fn commands_pin_the_cli_version() {
    let commands = commands("1.2.3");
    assert_eq!(
        commands[0],
        strings(&[
            "claude",
            "plugin",
            "marketplace",
            "add",
            "pecheriere/warden#v1.2.3",
            "--scope",
            "user",
        ])
    );
}

#[test]
fn commands_install_at_user_scope() {
    let commands = commands("1.2.3");
    assert_eq!(
        commands[1],
        strings(&[
            "claude",
            "plugin",
            "install",
            "warden@warden",
            "--scope",
            "user"
        ])
    );
}

#[test]
fn commands_update_an_installed_plugin_to_the_new_tag() {
    let commands = commands("1.2.3");
    assert_eq!(commands.len(), 3);
    assert_eq!(
        commands[2],
        strings(&[
            "claude",
            "plugin",
            "update",
            "warden@warden",
            "--scope",
            "user"
        ])
    );
}

#[test]
fn dry_run_prints_without_running() {
    let mut out = Vec::new();
    let mut run_one =
        |_: &Path, _: &[String]| -> io::Result<ExitStatus> { panic!("a dry run ran a command") };
    run_with(
        true,
        "1.2.3",
        Some(Path::new("/opt/claude")),
        &mut out,
        &mut run_one,
    )
    .unwrap();
    let out = String::from_utf8(out).unwrap();
    assert_eq!(
        out,
        "claude plugin marketplace add pecheriere/warden#v1.2.3 --scope user\n\
         claude plugin install warden@warden --scope user\n\
         claude plugin update warden@warden --scope user\n"
    );
}

#[test]
fn dry_run_prints_the_commands_without_claude_too() {
    let mut out = Vec::new();
    let mut run_one =
        |_: &Path, _: &[String]| -> io::Result<ExitStatus> { panic!("a dry run ran a command") };
    run_with(true, "1.2.3", None, &mut out, &mut run_one).unwrap();
    let out = String::from_utf8(out).unwrap();
    assert!(out.starts_with("claude plugin marketplace add pecheriere/warden#v1.2.3"));
}

#[test]
fn runs_each_command_in_order_with_the_claude_found() {
    let calls = RefCell::new(Vec::new());
    let mut run_one = |program: &Path, args: &[String]| -> io::Result<ExitStatus> {
        calls.borrow_mut().push((program.to_owned(), args.to_vec()));
        Ok(exited(0))
    };
    let mut out = Vec::new();
    run_with(
        false,
        "1.2.3",
        Some(Path::new("/opt/claude")),
        &mut out,
        &mut run_one,
    )
    .unwrap();
    let expected: Vec<(PathBuf, Vec<String>)> = commands("1.2.3")
        .into_iter()
        .map(|command| (PathBuf::from("/opt/claude"), command[1..].to_vec()))
        .collect();
    assert_eq!(calls.into_inner(), expected);
}

#[test]
fn stops_at_the_first_failure_with_its_exit_status() {
    let mut count = 0;
    let mut run_one = |_: &Path, _: &[String]| -> io::Result<ExitStatus> {
        count += 1;
        Ok(exited(if count == 2 { 3 } else { 0 }))
    };
    let mut out = Vec::new();
    let error = run_with(
        false,
        "1.2.3",
        Some(Path::new("/opt/claude")),
        &mut out,
        &mut run_one,
    )
    .unwrap_err();
    assert_eq!(count, 2);
    let exit = error.downcast_ref::<Exit>().expect("an Exit");
    assert_eq!(exit.code, 3);
    assert!(exit.message.contains("claude plugin install warden@warden"));
}

#[test]
fn a_command_killed_by_a_signal_fails_with_the_error_status() {
    let mut run_one =
        |_: &Path, _: &[String]| -> io::Result<ExitStatus> { Ok(ExitStatus::from_raw(9)) };
    let mut out = Vec::new();
    let error = run_with(
        false,
        "1.2.3",
        Some(Path::new("/opt/claude")),
        &mut out,
        &mut run_one,
    )
    .unwrap_err();
    assert_eq!(
        error.downcast_ref::<Exit>().expect("an Exit").code,
        EXIT_ERROR
    );
}

#[test]
fn a_command_that_cannot_start_is_an_error() {
    let mut run_one = |_: &Path, _: &[String]| -> io::Result<ExitStatus> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    };
    let mut out = Vec::new();
    let result = run_with(
        false,
        "1.2.3",
        Some(Path::new("/opt/claude")),
        &mut out,
        &mut run_one,
    );
    assert!(result.is_err());
}

#[test]
fn without_claude_prints_the_plugin_commands_and_succeeds() {
    let mut run_one = |_: &Path, _: &[String]| -> io::Result<ExitStatus> {
        panic!("ran a command without claude")
    };
    let mut out = Vec::new();
    run_with(false, "1.2.3", None, &mut out, &mut run_one).unwrap();
    let out = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines.contains(&"/plugin marketplace add pecheriere/warden#v1.2.3"));
    assert!(lines.contains(&"/plugin install warden@warden"));
}

fn write_file(path: &Path, mode: u32) {
    fs::write(path, "#!/bin/sh\n").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn finds_the_first_executable_on_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let (first, second, third) = (
        dir.path().join("a"),
        dir.path().join("b"),
        dir.path().join("c"),
    );
    for d in [&first, &second, &third] {
        fs::create_dir(d).unwrap();
    }
    // Not executable, then a directory of that name, then the one to find.
    write_file(&first.join("claude"), 0o644);
    fs::create_dir(second.join("claude")).unwrap();
    write_file(&third.join("claude"), 0o755);
    let path_var = std::env::join_paths([
        "relative",
        "",
        first.to_str().unwrap(),
        second.to_str().unwrap(),
        third.to_str().unwrap(),
    ])
    .unwrap();
    assert_eq!(
        find_on_path(&path_var, "claude"),
        Some(third.join("claude"))
    );
}

#[test]
fn skips_relative_path_entries() {
    let path_var = std::env::join_paths(["."]).unwrap();
    assert_eq!(find_on_path(&path_var, "claude"), None);
}
