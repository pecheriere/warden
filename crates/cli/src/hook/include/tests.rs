use std::fs;
use std::path::Path;

use super::{glob_matches, include_text};
use crate::hook::files::{MAX_BYTES, read_small};

fn home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    fs::create_dir_all(home.path().join(".ssh/conf.d")).unwrap();
    home
}

fn text(argument: &str, home: &Path) -> Option<String> {
    include_text(argument, home, &read_small)
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
