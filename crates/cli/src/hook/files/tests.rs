use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;

use super::{MAX_BYTES, Reader, read_small};

#[test]
fn reads_a_small_text_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config");
    std::fs::write(&file, "Host a\n").unwrap();
    assert_eq!(read_small(&file).as_deref(), Some("Host a\n"));
}

#[test]
fn refuses_a_missing_file_and_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(read_small(&dir.path().join("none")), None);
    assert_eq!(read_small(dir.path()), None);
}

#[test]
fn refuses_a_fifo_without_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("pipe");
    let status = Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(status.success());
    assert_eq!(read_small(&fifo), None);
}

#[test]
fn size_cap_is_inclusive() {
    let dir = tempfile::tempdir().unwrap();
    let max = usize::try_from(MAX_BYTES).unwrap();
    let at = dir.path().join("at");
    std::fs::write(&at, "a".repeat(max)).unwrap();
    assert_eq!(read_small(&at).map(|text| text.len()), Some(max));
    let over = dir.path().join("over");
    std::fs::write(&over, "a".repeat(max + 1)).unwrap();
    assert_eq!(read_small(&over), None);
}

#[test]
fn refuses_text_that_is_not_utf8() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("binary");
    std::fs::write(&file, [0xff, 0xfe, 0x00]).unwrap();
    assert_eq!(read_small(&file), None);
}

#[test]
fn follows_a_link_to_a_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config");
    std::fs::write(&file, "x").unwrap();
    let link = dir.path().join("link");
    symlink(&file, &link).unwrap();
    assert_eq!(read_small(&link).as_deref(), Some("x"));
}

#[test]
fn reader_resolves_relative_paths_against_cwd() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("rel")).unwrap();
    std::fs::write(dir.path().join("rel/config"), "inside").unwrap();
    let reader = Reader::new(dir.path().to_str());
    assert_eq!(
        reader.read(Path::new("rel/config")).as_deref(),
        Some("inside")
    );
    assert_eq!(reader.read(Path::new("rel/missing")), None);
}

#[test]
fn reader_leaves_absolute_paths_alone() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config");
    std::fs::write(&file, "abs").unwrap();
    let other = tempfile::tempdir().unwrap();
    let reader = Reader::new(other.path().to_str());
    assert_eq!(reader.read(&file).as_deref(), Some("abs"));
}

#[test]
fn reader_reads_each_path_once() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config");
    std::fs::write(&file, "first").unwrap();
    let reader = Reader::new(None);
    assert_eq!(reader.read(&file).as_deref(), Some("first"));
    std::fs::write(&file, "second").unwrap();
    assert_eq!(reader.read(&file).as_deref(), Some("first"));
}
