use warden_agent_hook::settings::{Setting, Signal};

use super::load_from;

const BASE: &str = "server = \"https://warden.example.ts.net/\"\nagent = \"build-agent\"\n";

#[test]
fn missing_config_gives_defaults_and_no_note() {
    let dir = tempfile::tempdir().unwrap();
    let (settings, note) = load_from(&dir.path().join("config.toml"));
    assert_eq!(note, None);
    assert_ne!(settings.get(Signal::SecretStore), Setting::Off);
}

#[test]
fn config_that_does_not_parse_gives_defaults_and_no_note() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "this is [not toml").unwrap();
    let (_, note) = load_from(&path);
    assert_eq!(note, None);
}

#[test]
fn valid_table_is_applied() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, format!("{BASE}\n[hook]\nsecret-store = \"off\"\n")).unwrap();
    let (settings, note) = load_from(&path);
    assert_eq!(note, None);
    assert_eq!(settings.get(Signal::SecretStore), Setting::Off);
}

#[test]
fn invalid_table_gives_defaults_and_a_note() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        format!("{BASE}\n[hook]\nsecret-store = \"sometimes\"\n"),
    )
    .unwrap();
    let (settings, note) = load_from(&path);
    assert!(note.is_some());
    assert_ne!(settings.get(Signal::SecretStore), Setting::Off);
}

#[test]
fn fifo_at_the_config_path_gives_defaults_without_waiting() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let status = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success());
    let (settings, note) = load_from(&path);
    assert_eq!(note, None);
    assert_ne!(settings.get(Signal::SecretStore), Setting::Off);
}

#[test]
fn config_over_the_cap_gives_defaults_and_no_note() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let padding = "# x\n".repeat(20_000);
    std::fs::write(
        &path,
        format!("{BASE}\n[hook]\nsecret-store = \"off\"\n{padding}"),
    )
    .unwrap();
    let (settings, note) = load_from(&path);
    assert_eq!(note, None);
    assert_ne!(settings.get(Signal::SecretStore), Setting::Off);
}
