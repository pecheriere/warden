use std::os::unix::fs::PermissionsExt;

use super::{
    CUT_NOTE, HEADING, LEFT_OUT, OUTPUT_CAP_CHARS, OUTPUT_CUT_NOTE, RULES_FILE, UNREADABLE, render,
};

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
    // The file is exactly 8 KiB: only the output limit cut it.
    assert!(out.ends_with(OUTPUT_CUT_NOTE));
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

#[test]
fn a_file_ending_just_under_the_cap_is_not_cut() {
    // The brief leaves room for the file and its final newline, but not for a
    // cut note: the file is printed whole.
    let rules = format!("{}\n", "r".repeat(2_000));
    let fixed = HEADING.chars().count() + rules.chars().count();
    let brief = format!("{}\n", "b".repeat(OUTPUT_CAP_CHARS - fixed - 1));
    let dir = dir_with(&rules);
    let out = render(&brief, Some(dir.path()));
    assert_eq!(out.chars().count(), OUTPUT_CAP_CHARS);
    assert!(!out.contains("(cut"));
    assert!(out.ends_with(&rules));
}

#[test]
fn a_file_one_char_over_the_room_is_cut_within_the_cap() {
    let rules = "r".repeat(2_001);
    let fixed = HEADING.chars().count() + rules.chars().count();
    let brief = format!("{}\n", "b".repeat(OUTPUT_CAP_CHARS - fixed - 1));
    let dir = dir_with(&rules);
    let out = render(&brief, Some(dir.path()));
    assert!(out.chars().count() <= OUTPUT_CAP_CHARS);
    assert!(out.ends_with(OUTPUT_CUT_NOTE));
    assert!(!out.contains("8 KiB"));
}

#[test]
fn a_brief_leaving_no_room_for_the_rules_says_so_within_the_cap() {
    let dir = dir_with(&format!(
        "Never use home-api without asking.{}\n",
        "!".repeat(200)
    ));
    for brief_len in [
        OUTPUT_CAP_CHARS - 75,
        OUTPUT_CAP_CHARS - 60,
        OUTPUT_CAP_CHARS - 20,
    ] {
        let brief = format!("{}\n", "b".repeat(brief_len - 1));
        let out = render(&brief, Some(dir.path()));
        assert!(out.chars().count() <= OUTPUT_CAP_CHARS, "{brief_len}");
        assert!(!out.contains("home-api"), "{brief_len}");
    }
    let brief = format!("{}\n", "b".repeat(OUTPUT_CAP_CHARS - 76));
    assert!(render(&brief, Some(dir.path())).contains(LEFT_OUT.trim()));
}

#[test]
fn an_unreadable_rules_line_stays_within_the_cap() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(RULES_FILE)).unwrap();
    for brief_len in (OUTPUT_CAP_CHARS - 150)..=OUTPUT_CAP_CHARS {
        let brief = "b".repeat(brief_len);
        let out = render(&brief, Some(dir.path()));
        assert!(out.chars().count() <= OUTPUT_CAP_CHARS, "{brief_len}");
    }
}

#[test]
fn a_brief_over_the_cap_is_cut_to_it_and_the_rules_are_left_out() {
    let dir = dir_with("Never use home-api without asking.\n");
    let brief = "é".repeat(OUTPUT_CAP_CHARS + 500);
    let out = render(&brief, Some(dir.path()));
    assert_eq!(out.chars().count(), OUTPUT_CAP_CHARS);
    assert!(!out.contains("home-api"));
}
