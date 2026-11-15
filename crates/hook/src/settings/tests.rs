use super::{Setting, Settings, Signal};

fn table(src: &str) -> toml::Table {
    src.parse().expect("test table parses")
}

fn defaults() -> [(Signal, Setting); 7] {
    [
        (Signal::CoveredSsh, Setting::Block),
        (Signal::CoveredApi, Setting::Block),
        (Signal::OwnerSshKey, Setting::Ask),
        (Signal::SecretStore, Setting::Ask),
        (Signal::TokenRead, Setting::Ask),
        (Signal::UncoveredHost, Setting::Warn),
        (Signal::OwnerGithub, Setting::Warn),
    ]
}

fn assert_defaults(settings: Settings) {
    for (signal, expected) in defaults() {
        assert_eq!(settings.get(signal), expected, "{}", signal.key());
    }
}

#[test]
fn defaults_match_spec() {
    assert_defaults(Settings::default());
}

#[test]
fn keys_match_spec() {
    let keys: Vec<_> = Signal::ALL.iter().map(|s| s.key()).collect();
    assert_eq!(
        keys,
        [
            "covered-ssh",
            "covered-api",
            "owner-ssh-key",
            "secret-store",
            "token-read",
            "uncovered-host",
            "owner-github"
        ]
    );
}

#[test]
fn missing_table_is_defaults() {
    let (settings, note) = Settings::from_table(None);
    assert_defaults(settings);
    assert!(note.is_none());
}

#[test]
fn partial_table_keeps_other_defaults() {
    let t = table(r#"covered-ssh = "warn""#);
    let (settings, note) = Settings::from_table(Some(&t));
    assert!(note.is_none());
    assert_eq!(settings.get(Signal::CoveredSsh), Setting::Warn);
    for (signal, expected) in defaults() {
        if signal != Signal::CoveredSsh {
            assert_eq!(settings.get(signal), expected);
        }
    }
}

#[test]
fn every_value_parses() {
    let t = table(
        "covered-ssh = \"off\"\ncovered-api = \"warn\"\nowner-ssh-key = \"ask\"\nsecret-store = \"block\"",
    );
    let (settings, note) = Settings::from_table(Some(&t));
    assert!(note.is_none());
    assert_eq!(settings.get(Signal::CoveredSsh), Setting::Off);
    assert_eq!(settings.get(Signal::CoveredApi), Setting::Warn);
    assert_eq!(settings.get(Signal::OwnerSshKey), Setting::Ask);
    assert_eq!(settings.get(Signal::SecretStore), Setting::Block);
}

#[test]
fn unknown_key_falls_back() {
    let t = table("covered-ssh = \"off\"\ncovered-shh = \"off\"");
    let (settings, note) = Settings::from_table(Some(&t));
    assert_defaults(settings);
    let note = note.expect("note");
    assert!(note.contains("covered-shh"), "{note}");
}

#[test]
fn unknown_value_falls_back() {
    let t = table(r#"secret-store = "never""#);
    let (settings, note) = Settings::from_table(Some(&t));
    assert_defaults(settings);
    let note = note.expect("note");
    assert!(note.contains("never"), "{note}");
}

#[test]
fn non_string_value_falls_back() {
    let t = table("covered-ssh = 3\ncovered-api = \"off\"");
    let (settings, note) = Settings::from_table(Some(&t));
    assert_defaults(settings);
    assert!(note.expect("note").contains("covered-ssh"));
}

#[test]
fn note_never_carries_other_config_text() {
    let t = table(
        "\"bad\\u001b[31m key with spaces and a very long tail xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\" = \"off\"",
    );
    let (_, note) = Settings::from_table(Some(&t));
    let note = note.expect("note");
    assert!(!note.contains('\u{1b}'), "{note:?}");
    assert!(!note.contains("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), "{note}");
    assert!(note.ends_with("using the defaults"), "{note}");
}

#[test]
fn token_shaped_value_is_not_echoed() {
    let t = table("secret-store = \"ghp_abcdefghijklmnop1234\"");
    let (settings, note) = Settings::from_table(Some(&t));
    assert_defaults(settings);
    let note = note.expect("note");
    assert!(!note.contains("ghp_"), "{note}");
    assert!(note.contains("secret-store"), "{note}");
    assert!(note.contains("unknown value"), "{note}");
}

#[test]
fn token_shaped_key_is_not_echoed() {
    let t = table("ghp_abcdefghijklmnop1234 = \"off\"");
    let (_, note) = Settings::from_table(Some(&t));
    let note = note.expect("note");
    assert!(!note.contains("ghp_"), "{note}");
    assert!(note.contains("an unknown key"), "{note}");
}

#[test]
fn block_is_strongest() {
    assert!(Setting::Block > Setting::Ask);
    assert!(Setting::Ask > Setting::Warn);
    assert!(Setting::Warn > Setting::Off);
}
