use std::fs;
use std::path::Path;

use super::{Includes, glob_matches};
use crate::hook::files::{MAX_BYTES, read_small};

fn home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    fs::create_dir_all(home.path().join(".ssh/conf.d")).unwrap();
    home
}

fn text(argument: &str, home: &Path) -> Option<String> {
    Includes::new(home).text(argument, &read_small)
}

#[test]
fn tilde_path_is_under_home() {
    let home = home();
    fs::write(home.path().join("lab.conf"), "Host a\n").unwrap();
    assert_eq!(
        text("~/lab.conf", home.path()).as_deref(),
        Some("Host a\n\n")
    );
}

#[test]
fn relative_path_is_under_dot_ssh() {
    let home = home();
    fs::write(home.path().join(".ssh/extra"), "Host b\n").unwrap();
    assert_eq!(text("extra", home.path()).as_deref(), Some("Host b\n\n"));
}

#[test]
fn absolute_path_is_read_as_given() {
    let home = home();
    let other = tempfile::tempdir().unwrap();
    fs::write(other.path().join("c"), "Host c\n").unwrap();
    let argument = other.path().join("c");
    assert_eq!(
        text(argument.to_str().unwrap(), home.path()).as_deref(),
        Some("Host c\n\n")
    );
}

#[test]
fn glob_in_the_last_component_reads_sorted_matches() {
    let home = home();
    let dir = home.path().join(".ssh/conf.d");
    fs::write(dir.join("b.conf"), "B\n").unwrap();
    fs::write(dir.join("a.conf"), "A\n").unwrap();
    fs::write(dir.join("c.txt"), "C\n").unwrap();
    fs::write(dir.join(".hidden.conf"), "H\n").unwrap();
    assert_eq!(
        text("conf.d/*.conf", home.path()).as_deref(),
        Some("A\n\nB\n\n")
    );
}

#[test]
fn glob_in_a_directory_component_matches_nothing() {
    let home = home();
    fs::write(home.path().join(".ssh/conf.d/a.conf"), "A\n").unwrap();
    assert_eq!(text("conf.*/a.conf", home.path()), None);
}

#[test]
fn missing_files_and_directories_are_ignored() {
    let home = home();
    assert_eq!(text("nothing", home.path()), None);
    assert_eq!(text("nodir/*", home.path()), None);
    assert_eq!(text("conf.d", home.path()), None);
    assert_eq!(text("", home.path()), None);
}

#[test]
fn several_patterns_are_all_read() {
    let home = home();
    fs::write(home.path().join(".ssh/one"), "1\n").unwrap();
    fs::write(home.path().join(".ssh/two"), "2\n").unwrap();
    assert_eq!(text("one two", home.path()).as_deref(), Some("1\n\n2\n\n"));
}

#[test]
fn total_text_stays_under_the_cap() {
    let home = home();
    let big = "a".repeat(usize::try_from(MAX_BYTES).unwrap() / 2);
    for name in ["a", "b", "c"] {
        fs::write(home.path().join(".ssh").join(name), &big).unwrap();
    }
    let got = text("*", home.path()).unwrap();
    assert!(u64::try_from(got.len()).unwrap() <= MAX_BYTES);
    assert!(got.len() > big.len());
}

#[test]
fn glob_rules() {
    let cases = [
        ("*", "a", true),
        ("*.conf", "a.conf", true),
        ("*.conf", "a.conf.bak", false),
        ("a?c", "abc", true),
        ("a?c", "ac", false),
        ("a*b*c", "aXXbYYc", true),
        ("a*b*c", "aXXbYY", false),
        ("*", ".hidden", false),
        (".*", ".hidden", true),
        ("", "", true),
    ];
    for (i, (pattern, name, want)) in cases.iter().enumerate() {
        assert_eq!(glob_matches(pattern, name), *want, "case {i}");
    }
}

#[test]
fn many_include_lines_share_one_budget_and_stop_reading() {
    let home = home();
    let ten_kib = "a".repeat(10 * 1024);
    for i in 0..10 {
        fs::write(home.path().join(".ssh").join(format!("x{i}")), &ten_kib).unwrap();
    }
    let includes = Includes::new(home.path());
    let reads = std::cell::Cell::new(0_u32);
    let read = |path: &Path| {
        reads.set(reads.get() + 1);
        read_small(path)
    };
    let mut total = 0;
    for _ in 0..200 {
        total += includes.text("x*", &read).map_or(0, |text| text.len());
    }
    assert!(u64::try_from(total).unwrap() <= MAX_BYTES);
    assert!(total > 0);
    assert!(reads.get() <= 7, "{} reads", reads.get());
}

#[test]
fn a_glob_lists_regular_files_only() {
    let home = home();
    let ssh = home.path().join(".ssh");
    fs::write(ssh.join("a"), "A\n").unwrap();
    fs::create_dir(ssh.join("b")).unwrap();
    let names = super::list(&ssh);
    assert!(names.contains(&"a".to_owned()));
    assert!(!names.contains(&"b".to_owned()));
    let status = std::process::Command::new("mkfifo")
        .arg(ssh.join("pipe"))
        .status()
        .unwrap();
    assert!(status.success());
    assert!(!super::list(&ssh).contains(&"pipe".to_owned()));
}
