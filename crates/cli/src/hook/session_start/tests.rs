use std::os::unix::fs::PermissionsExt;

use super::{CUT_NOTE, HEADING, OUTPUT_CAP_CHARS, RULES_FILE, UNREADABLE, render};

const BRIEF: &str = "warden brief\nSSH: build-agent\n";

fn dir_with(rules: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(RULES_FILE), rules).unwrap();
    dir
}

#[test]
fn rules_appended_after_brief() {
    let dir = dir_with("Never use home-api without asking.\n");
    let out = render(BRIEF, Some(dir.path()));
    assert_eq!(
        out,
        format!("{BRIEF}{HEADING}Never use home-api without asking.\n")
    );
}

#[test]
fn missing_rules_prints_brief_only() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(render(BRIEF, Some(dir.path())), BRIEF);
    assert_eq!(render(BRIEF, None), BRIEF);
}

#[test]
fn long_rules_are_cut_with_note() {
    // 3-byte characters: 9 KiB of them, so the cap falls inside a character.
    let dir = dir_with(&"€".repeat(3 * 1024));
    let out = render(BRIEF, Some(dir.path()));
    assert!(out.ends_with(CUT_NOTE));
    let kept = out
        .strip_prefix(BRIEF)
        .unwrap()
        .strip_prefix(HEADING)
        .unwrap()
        .strip_suffix(CUT_NOTE)
        .unwrap();
    assert_eq!(kept.len(), 8190);
    assert!(kept.chars().all(|c| c == '€'));
}

#[test]
fn rules_of_exactly_the_cap_are_not_cut() {
    let dir = dir_with(&"a".repeat(8 * 1024));
    let out = render(BRIEF, Some(dir.path()));
    assert!(!out.contains("(cut"));
}

#[test]
fn output_stays_under_the_session_start_cap_with_a_long_brief() {
    let brief = format!("{}\n", "b".repeat(5_000));
    let dir = dir_with(&"x".repeat(8 * 1024));
    let out = render(&brief, Some(dir.path()));
    assert!(out.chars().count() <= OUTPUT_CAP_CHARS, "{}", out.len());
    assert!(out.ends_with(CUT_NOTE));
    assert!(out.contains('x'));
}

#[test]
fn unreadable_rules_prints_line() {
    let dir = dir_with("secret rules\n");
    let path = dir.path().join(RULES_FILE);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Root reads a mode 000 file: then there is nothing to assert.
    if std::fs::File::open(&path).is_ok() {
        return;
    }
    let out = render(BRIEF, Some(dir.path()));
    assert_eq!(out, format!("{BRIEF}{UNREADABLE}\n"));
    assert!(!out.contains("secret rules"));
}

#[test]
fn a_directory_in_place_of_the_file_is_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(RULES_FILE)).unwrap();
    assert_eq!(
        render(BRIEF, Some(dir.path())),
        format!("{BRIEF}{UNREADABLE}\n")
    );
}
