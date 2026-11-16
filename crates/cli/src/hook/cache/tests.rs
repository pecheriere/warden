use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};
use warden_broker_proto::offers::Offers;

use super::{read_from, write_to};

fn offers_body() -> Value {
    json!({
        "ssh_targets": [],
        "api_secrets": [],
        "github": {"configured": false, "max_window": null},
        "commit_signing": {"available": false},
        "releases": {"available": true},
        "unavailable": [],
    })
}

fn expected() -> Offers {
    serde_json::from_value(offers_body()).unwrap()
}

#[test]
fn round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("offers-cache.json");
    write_to(&path, &offers_body()).unwrap();
    assert_eq!(read_from(&path, SystemTime::now()), Some(expected()));
}

#[test]
fn file_is_private_and_no_temp_file_is_left() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("offers-cache.json");
    write_to(&path, &offers_body()).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn rewrite_replaces_the_old_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("offers-cache.json");
    write_to(&path, &json!({"stale": true})).unwrap();
    write_to(&path, &offers_body()).unwrap();
    assert_eq!(read_from(&path, SystemTime::now()), Some(expected()));
}

#[test]
fn stale_after_24_hours() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("offers-cache.json");
    write_to(&path, &offers_body()).unwrap();
    let written = SystemTime::now();
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(written)
        .unwrap();
    let almost = written + Duration::from_hours(24) - Duration::from_secs(1);
    assert_eq!(read_from(&path, almost), Some(expected()));
    let over = written + Duration::from_hours(24) + Duration::from_secs(1);
    assert_eq!(read_from(&path, over), None);
}

#[test]
fn mtime_after_now_is_fresh() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("offers-cache.json");
    write_to(&path, &offers_body()).unwrap();
    let now = SystemTime::now();
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(now + Duration::from_secs(60))
        .unwrap();
    assert_eq!(read_from(&path, now), Some(expected()));
}

#[test]
fn unparsable_missing_oversized_or_not_a_file_gives_none() {
    let dir = tempfile::tempdir().unwrap();
    let now = SystemTime::now();
    let path = dir.path().join("offers-cache.json");
    assert_eq!(read_from(&path, now), None);
    std::fs::write(&path, b"not json").unwrap();
    assert_eq!(read_from(&path, now), None);
    std::fs::write(&path, br#"{"ssh_targets": 3}"#).unwrap();
    assert_eq!(read_from(&path, now), None);
    let mut big = serde_json::to_vec(&offers_body()).unwrap();
    big.extend(std::iter::repeat_n(b' ', 1024 * 1024));
    std::fs::write(&path, big).unwrap();
    assert_eq!(read_from(&path, now), None);
    let as_dir = dir.path().join("directory");
    std::fs::create_dir(&as_dir).unwrap();
    assert_eq!(read_from(&as_dir, now), None);
}

#[test]
fn coverage_carries_whether_github_tokens_are_configured() {
    use warden_agent_hook::context::Coverage;

    assert!(!Coverage::from(&expected()).github);
    let mut body = offers_body();
    body["github"] = json!({"configured": true, "max_window": "30d"});
    let offers: Offers = serde_json::from_value(body).unwrap();
    assert!(Coverage::from(&offers).github);
}
