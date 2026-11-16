use warden_agent_hook::settings::{Setting, Settings, Signal};
use warden_broker_proto::doctor::Status;

use super::settings::doctor_check;
use crate::config::{Config, load_existing_from, save_to};

const WITH_HOOK: &str = r#"
server = "https://warden.example.ts.net/"
agent = "build-agent"

[hook]
covered-ssh = "warn"
"#;

#[test]
fn login_rewrite_keeps_hook_table() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, WITH_HOOK).unwrap();
    let config = load_existing_from(&path).unwrap().unwrap();
    assert!(config.hook.is_some());
    let out = dir.path().join("rewritten.toml");
    save_to(&out, &config).unwrap();
    let reloaded = load_existing_from(&out).unwrap().unwrap();
    assert_eq!(reloaded.hook, config.hook);
    let (settings, note) =
        Settings::from_table(reloaded.hook.as_ref().and_then(toml::Value::as_table));
    assert_eq!(note, None);
    assert_eq!(settings.get(Signal::CoveredSsh), Setting::Warn);
}

fn config_with(hook: &str) -> Config {
    let raw =
        format!("server = \"https://warden.example.ts.net/\"\nagent = \"build-agent\"\n{hook}");
    toml::from_str(&raw).unwrap()
}

#[test]
fn invalid_table_is_reported_by_doctor_check() {
    let bad = config_with("[hook]\ncovered-ssh = \"never\"\n");
    let check = doctor_check(&bad).expect("an invalid table is reported");
    assert_eq!(check.status, Status::Fail);
    assert!(
        check.detail.starts_with("hook settings: "),
        "{}",
        check.detail
    );
    let unknown = config_with("[hook]\ncovered-sssh = \"warn\"\n");
    assert!(doctor_check(&unknown).is_some());
}

#[test]
fn valid_or_absent_table_is_not_reported() {
    assert!(doctor_check(&config_with("")).is_none());
    assert!(doctor_check(&config_with("[hook]\ncovered-ssh = \"warn\"\n")).is_none());
}
