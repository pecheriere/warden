//! Tests of reading the configuration.

use std::fs;
use std::io;
use std::os::unix::fs::{PermissionsExt as _, symlink};

use secrecy::ExposeSecret as _;
use tempfile::TempDir;

use super::{
    BackendSettings, Config, ConfigError, ConnectSettings, MAX_SECRET_FILE_BYTES, UrlTransport,
};
use crate::notify::ChannelSettings;
use crate::requests::RequestLimits;

const TOKEN_FILE: &str = "WARDEN_OP_CONNECT_TOKEN_FILE";
const SECRET: &str = "ops_not-a-real-token";

/// A valid configuration, without the Connect token, plus `extra`.
fn lookup(extra: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
    let base = [
        ("WARDEN_DB_PATH", "/tmp/warden.db"),
        ("WARDEN_AUDIT_PATH", "/tmp/audit"),
        ("WARDEN_PUBLIC_URL", "https://warden.example.ts.net"),
        ("WARDEN_OWNER_LOGIN", "owner@example.com"),
        ("WARDEN_OP_CONNECT_URL", "http://172.31.251.11:8080"),
        ("WARDEN_NOTIFY", "ntfy"),
        ("WARDEN_NOTIFY_NTFY_URL", "https://ntfy.example.com/topic"),
    ];
    let vars: Vec<(String, String)> = extra
        .iter()
        .chain(&base)
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |var| vars.iter().find(|(k, _)| k == var).map(|(_, v)| v.clone())
}

fn request_limits(extra: &[(&str, &str)]) -> Result<RequestLimits, ConfigError> {
    let mut vars = vec![("WARDEN_OP_CONNECT_TOKEN", SECRET)];
    vars.extend_from_slice(extra);
    Config::from_lookup(lookup(&vars)).map(|config| config.requests)
}

#[test]
fn request_limits_default_and_can_be_set() {
    assert_eq!(request_limits(&[]).unwrap(), RequestLimits::default());
    assert_eq!(
        request_limits(&[
            ("WARDEN_REQUEST_MAX_PENDING_PER_AGENT", "2"),
            ("WARDEN_REQUEST_MAX_NEW_PER_AGENT", "2"),
            ("WARDEN_REQUEST_LIMIT_WINDOW_SECS", "60"),
        ])
        .unwrap(),
        RequestLimits {
            max_pending: 2,
            max_new: 2,
            window_secs: 60,
        }
    );
}

#[test]
fn request_limits_out_of_range_are_refused() {
    for (var, value) in [
        ("WARDEN_REQUEST_MAX_PENDING_PER_AGENT", "0"),
        ("WARDEN_REQUEST_MAX_PENDING_PER_AGENT", "257"),
        ("WARDEN_REQUEST_MAX_PENDING_PER_AGENT", "many"),
        ("WARDEN_REQUEST_MAX_NEW_PER_AGENT", "0"),
        ("WARDEN_REQUEST_MAX_NEW_PER_AGENT", "1025"),
        ("WARDEN_REQUEST_LIMIT_WINDOW_SECS", "59"),
        ("WARDEN_REQUEST_LIMIT_WINDOW_SECS", "3601"),
    ] {
        let got = request_limits(&[(var, value)]);
        assert!(
            matches!(got, Err(ConfigError::Invalid { var: named, .. }) if named == var),
            "{var}={value}: {got:?}"
        );
    }
}

#[test]
fn pending_limit_must_fit_under_the_new_request_limit() {
    let got = request_limits(&[
        ("WARDEN_REQUEST_MAX_PENDING_PER_AGENT", "6"),
        ("WARDEN_REQUEST_MAX_NEW_PER_AGENT", "5"),
    ]);
    assert!(
        matches!(
            got,
            Err(ConfigError::Invalid {
                var: "WARDEN_REQUEST_MAX_PENDING_PER_AGENT",
                ..
            })
        ),
        "{got:?}"
    );
}

fn secret_file(dir: &TempDir, name: &str, content: &[u8], mode: u32) -> String {
    let path = dir.path().join(name);
    fs::write(&path, content).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path.to_str().unwrap().to_owned()
}

/// The Connect settings of a configuration that must have them.
fn connect(config: &Config) -> &ConnectSettings {
    match &config.backend {
        BackendSettings::OnePassword(connect) => connect,
        BackendSettings::Local(_) => panic!("expected the 1Password backend"),
    }
}

fn token_from_file(path: &str) -> Result<Config, ConfigError> {
    Config::from_lookup(lookup(&[(TOKEN_FILE, path)]))
}

fn is_invalid_token_file(err: &ConfigError) -> bool {
    matches!(err, ConfigError::Invalid { var, .. } if *var == TOKEN_FILE)
}

#[test]
fn reads_the_connect_token_from_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = secret_file(&dir, "token", SECRET.as_bytes(), 0o400);
    let config = token_from_file(&path).unwrap();
    assert_eq!(connect(&config).token.expose_secret(), SECRET);
}

#[test]
fn strips_the_line_ending_of_a_secret_file() {
    for ending in ["\n", "\r\n", "\n\n"] {
        let dir = tempfile::tempdir().unwrap();
        let content = format!("{SECRET}{ending}");
        let path = secret_file(&dir, "token", content.as_bytes(), 0o400);
        let config = token_from_file(&path).unwrap();
        assert_eq!(connect(&config).token.expose_secret(), SECRET, "{ending:?}");
    }
}

#[test]
fn follows_a_symlink_to_a_secret_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = secret_file(&dir, "token", SECRET.as_bytes(), 0o400);
    let link = dir.path().join("link");
    symlink(&path, &link).unwrap();
    let config = token_from_file(link.to_str().unwrap()).unwrap();
    assert_eq!(connect(&config).token.expose_secret(), SECRET);
}

#[test]
fn accepts_group_access_to_a_secret_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = secret_file(&dir, "token", SECRET.as_bytes(), 0o440);
    assert!(token_from_file(&path).is_ok());
}

#[test]
fn plain_variable_still_works_when_the_file_variable_is_blank() {
    let config = Config::from_lookup(lookup(&[
        ("WARDEN_OP_CONNECT_TOKEN", SECRET),
        (TOKEN_FILE, " "),
    ]))
    .unwrap();
    assert_eq!(connect(&config).token.expose_secret(), SECRET);
}

#[test]
fn empty_plain_variable_does_not_conflict_with_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = secret_file(&dir, "token", SECRET.as_bytes(), 0o400);
    let config = Config::from_lookup(lookup(&[
        ("WARDEN_OP_CONNECT_TOKEN", ""),
        (TOKEN_FILE, &path),
    ]))
    .unwrap();
    assert_eq!(connect(&config).token.expose_secret(), SECRET);
}

#[test]
fn reports_a_missing_token_under_its_plain_name() {
    assert_eq!(
        Config::from_lookup(lookup(&[])).unwrap_err(),
        ConfigError::Missing("WARDEN_OP_CONNECT_TOKEN")
    );
}

#[test]
fn refuses_both_forms_of_a_secret() {
    let dir = tempfile::tempdir().unwrap();
    let path = secret_file(&dir, "token", SECRET.as_bytes(), 0o400);
    let err = Config::from_lookup(lookup(&[
        ("WARDEN_OP_CONNECT_TOKEN", "other"),
        (TOKEN_FILE, &path),
    ]))
    .unwrap_err();
    assert!(is_invalid_token_file(&err), "{err}");
}

/// A secret pasted as the path by mistake must not reach the logs, so the
/// message names the variable and not the path.
#[test]
fn refuses_a_missing_file_without_echoing_the_path() {
    let err = token_from_file(SECRET).unwrap_err();
    assert_eq!(
        err,
        ConfigError::SecretFile {
            var: TOKEN_FILE,
            kind: io::ErrorKind::NotFound
        }
    );
    assert!(
        !format!("{err} {err:?}").contains(SECRET),
        "the error echoes the path"
    );
}

#[test]
fn refuses_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    let err = token_from_file(dir.path().to_str().unwrap()).unwrap_err();
    assert!(is_invalid_token_file(&err), "{err}");
}

#[test]
fn refuses_a_file_other_users_can_access() {
    for mode in [0o404, 0o402, 0o401, 0o644] {
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(&dir, "token", SECRET.as_bytes(), mode);
        let err = token_from_file(&path).unwrap_err();
        assert_eq!(
            err,
            ConfigError::Invalid {
                var: TOKEN_FILE,
                reason: "the file must not be accessible to other users"
            },
            "{mode:o}"
        );
    }
}

/// Whatever is wrong with the content, the error names the variable and
/// shows none of the content.
#[test]
fn refuses_bad_content_without_echoing_it() {
    let oversize = SECRET.repeat(usize::from(MAX_SECRET_FILE_BYTES));
    let invalid_utf8 = [SECRET.as_bytes(), &[0xff, 0xfe]].concat();
    let two_lines = format!("{SECRET}\n{SECRET}");
    let cases: [&[u8]; 6] = [
        b"",
        b"\n",
        b"   \n",
        two_lines.as_bytes(),
        &invalid_utf8,
        oversize.as_bytes(),
    ];
    for content in cases {
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(&dir, "token", content, 0o400);
        let err = token_from_file(&path).unwrap_err();
        assert!(
            is_invalid_token_file(&err),
            "a different error was returned"
        );
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains(SECRET), "the error echoes the content");
    }
}

#[test]
fn accepts_a_secret_file_at_the_size_limit() {
    let dir = tempfile::tempdir().unwrap();
    let content = "x".repeat(usize::from(MAX_SECRET_FILE_BYTES));
    let path = secret_file(&dir, "token", content.as_bytes(), 0o400);
    assert!(token_from_file(&path).is_ok());
}

#[test]
fn reads_notifier_secrets_from_files() {
    let dir = tempfile::tempdir().unwrap();
    let webhook = secret_file(
        &dir,
        "webhook",
        b"https://ha.example.com/api/webhook/id\n",
        0o400,
    );
    let topic = secret_file(
        &dir,
        "topic",
        b"https://ntfy.example.com/private-topic\n",
        0o400,
    );
    let token = secret_file(&dir, "ntfy", b"tk_not-real\n", 0o400);
    let vars = lookup(&[
        ("WARDEN_OP_CONNECT_TOKEN", SECRET),
        ("WARDEN_NOTIFY", "homeassistant,ntfy"),
        ("WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL_FILE", &webhook),
        ("WARDEN_NOTIFY_NTFY_URL_FILE", &topic),
        ("WARDEN_NOTIFY_NTFY_TOKEN_FILE", &token),
    ]);
    let config = Config::from_lookup(|var| {
        (var != "WARDEN_NOTIFY_NTFY_URL")
            .then(|| vars(var))
            .flatten()
    })
    .unwrap();
    let mut channels = config.notify.iter();
    let ChannelSettings::HomeAssistant { webhook_url } = channels.next().unwrap() else {
        panic!("the first channel is Home Assistant");
    };
    assert_eq!(webhook_url.expose_url().path(), "/api/webhook/id");
    let ChannelSettings::Ntfy {
        url,
        token: Some(token),
    } = channels.next().unwrap()
    else {
        panic!("the second channel is ntfy, with a token");
    };
    assert_eq!(url.path(), "/private-topic");
    assert_eq!(token.expose_secret(), "tk_not-real");
}

#[test]
fn refuses_a_secret_file_of_an_unlisted_channel() {
    let dir = tempfile::tempdir().unwrap();
    let path = secret_file(
        &dir,
        "webhook",
        b"https://ha.example.com/api/webhook/id",
        0o400,
    );
    let err = Config::from_lookup(lookup(&[
        ("WARDEN_OP_CONNECT_TOKEN", SECRET),
        ("WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL_FILE", &path),
    ]))
    .unwrap_err();
    assert_eq!(
        err,
        ConfigError::Invalid {
            var: "WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL",
            reason: "set but the channel is not listed in WARDEN_NOTIFY",
        }
    );
}
/// `extra` on top of valid settings, without the Connect URL `lookup`
/// always adds, which a local configuration must not have.
fn without_connect_url(extra: &[(&str, &str)]) -> Result<Config, ConfigError> {
    let vars = lookup(extra);
    Config::from_lookup(|var| {
        let from_base = var == "WARDEN_OP_CONNECT_URL" && !extra.iter().any(|(k, _)| *k == var);
        vars(var).filter(|_| !from_base)
    })
}

const LOCAL: [(&str, &str); 3] = [
    ("WARDEN_SECRET_BACKEND", "local"),
    ("WARDEN_LOCAL_POLICY_FILE", "/etc/warden/policy.toml"),
    ("WARDEN_LOCAL_SECRETS_DIR", "/var/lib/warden/secrets"),
];

#[test]
fn a_missing_setting_keeps_meaning_1password() {
    let config = Config::from_lookup(lookup(&[("WARDEN_OP_CONNECT_TOKEN", SECRET)])).unwrap();
    assert_eq!(config.backend.name(), "1password");
    assert_eq!(connect(&config).vault, "Warden");
    let blank = Config::from_lookup(lookup(&[
        ("WARDEN_OP_CONNECT_TOKEN", SECRET),
        ("WARDEN_SECRET_BACKEND", " "),
    ]))
    .unwrap();
    assert_eq!(blank.backend.name(), "1password");
}

#[test]
fn naming_1password_still_needs_its_token() {
    let err = Config::from_lookup(lookup(&[("WARDEN_SECRET_BACKEND", "1password")])).unwrap_err();
    assert_eq!(err, ConfigError::Missing("WARDEN_OP_CONNECT_TOKEN"));
}

#[test]
fn reads_the_local_settings() {
    let config = without_connect_url(&LOCAL).unwrap();
    let BackendSettings::Local(local) = &config.backend else {
        panic!("expected the local backend");
    };
    assert_eq!(local.policy_file.to_str(), Some(LOCAL[1].1));
    assert_eq!(local.secrets_dir.to_str(), Some(LOCAL[2].1));
}

#[test]
fn refuses_an_unknown_backend_without_echoing_it() {
    for bad in ["Local", "1Password", "vault", SECRET] {
        let err = Config::from_lookup(lookup(&[
            ("WARDEN_OP_CONNECT_TOKEN", SECRET),
            ("WARDEN_SECRET_BACKEND", bad),
        ]))
        .unwrap_err();
        assert_eq!(
            err,
            ConfigError::Invalid {
                var: "WARDEN_SECRET_BACKEND",
                reason: "must be 1password or local"
            }
        );
    }
}

/// The local files never apply unless the weaker backend was asked for by
/// name, and asking for it is refused while 1Password settings remain.
#[test]
fn refuses_settings_of_the_other_backend() {
    for choice in [None, Some("1password")] {
        let mut extra = vec![
            ("WARDEN_OP_CONNECT_TOKEN", SECRET),
            ("WARDEN_LOCAL_POLICY_FILE", "/etc/warden/policy.toml"),
        ];
        extra.extend(choice.map(|c| ("WARDEN_SECRET_BACKEND", c)));
        let err = Config::from_lookup(lookup(&extra)).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    var: "WARDEN_LOCAL_POLICY_FILE",
                    ..
                }
            ),
            "{err}"
        );
    }
    for var in [
        "WARDEN_OP_CONNECT_URL",
        "WARDEN_OP_CONNECT_TOKEN",
        "WARDEN_OP_CONNECT_TOKEN_FILE",
        "WARDEN_OP_VAULT",
    ] {
        let mut extra = LOCAL.to_vec();
        extra.push((var, "something"));
        let err = without_connect_url(&extra).unwrap_err();
        assert!(
            matches!(err, ConfigError::Invalid { var: named, .. } if named == var),
            "{var}: {err}"
        );
    }
}

#[test]
fn the_local_backend_needs_both_paths_and_they_must_be_absolute() {
    for index in [1, 2] {
        let var = LOCAL[index].0;
        let missing: Vec<_> = LOCAL.iter().copied().filter(|(k, _)| *k != var).collect();
        assert_eq!(
            without_connect_url(&missing).unwrap_err(),
            ConfigError::Missing(var)
        );
        for bad in ["relative/path", "/etc/../shadow"] {
            let mut extra = LOCAL.to_vec();
            extra[index].1 = bad;
            let err = without_connect_url(&extra).unwrap_err();
            assert!(
                matches!(err, ConfigError::Invalid { var: named, .. } if named == var),
                "{bad}: {err}"
            );
            assert!(!err.to_string().contains(bad), "the error echoes the path");
        }
    }
}

/// Valid settings with a token, plus `extra`, which wins over them.
fn with_token(extra: &[(&str, &str)]) -> Result<Config, ConfigError> {
    let mut vars = extra.to_vec();
    vars.push(("WARDEN_OP_CONNECT_TOKEN", SECRET));
    Config::from_lookup(lookup(&vars))
}

/// What an existing deployment uses keeps working, with no new setting.
#[test]
fn local_plain_http_keeps_working_and_is_reported() {
    let config = with_token(&[
        ("WARDEN_NOTIFY", "homeassistant"),
        (
            "WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL",
            "http://homeassistant.local:8123/api/webhook/id",
        ),
        ("WARDEN_NOTIFY_NTFY_URL", ""),
    ])
    .unwrap();
    assert_eq!(
        config.plain_http_urls(),
        [
            ("WARDEN_OP_CONNECT_URL", UrlTransport::PlainLocal),
            (
                "WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL",
                UrlTransport::PlainLocal
            ),
        ]
    );
}

#[test]
fn https_is_not_reported_as_plain_http() {
    let config = with_token(&[("WARDEN_OP_CONNECT_URL", "https://connect.example.com")]).unwrap();
    assert_eq!(config.plain_http_urls(), []);
}

#[test]
fn remote_plain_http_is_refused_for_each_url_setting() {
    for (var, extra) in [
        ("WARDEN_OP_CONNECT_URL", ("WARDEN_NOTIFY", "ntfy")),
        ("WARDEN_NOTIFY_NTFY_URL", ("WARDEN_NOTIFY", "ntfy")),
        (
            "WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL",
            ("WARDEN_NOTIFY", "homeassistant,ntfy"),
        ),
    ] {
        let err = with_token(&[extra, (var, "http://service.example.com/secret-id")]).unwrap_err();
        assert!(
            matches!(err, ConfigError::Invalid { var: named, reason }
                if named == var && reason.contains("WARDEN_ALLOW_PLAIN_HTTP")),
            "{var}: {err}"
        );
        assert!(!err.to_string().contains("secret-id"), "{err}");
    }
}

/// A URL read from a file gets the same check as one in the variable.
#[test]
fn remote_plain_http_from_a_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = secret_file(&dir, "topic", b"http://ntfy.example.com/topic\n", 0o400);
    let vars = lookup(&[
        ("WARDEN_OP_CONNECT_TOKEN", SECRET),
        ("WARDEN_NOTIFY_NTFY_URL_FILE", &path),
    ]);
    let err = Config::from_lookup(|var| {
        (var != "WARDEN_NOTIFY_NTFY_URL")
            .then(|| vars(var))
            .flatten()
    })
    .unwrap_err();
    assert!(
        matches!(
            err,
            ConfigError::Invalid {
                var: "WARDEN_NOTIFY_NTFY_URL",
                ..
            }
        ),
        "{err}"
    );
}

#[test]
fn the_opt_in_allows_remote_plain_http_and_it_is_reported() {
    let config = with_token(&[
        ("WARDEN_ALLOW_PLAIN_HTTP", "WARDEN_NOTIFY_NTFY_URL"),
        ("WARDEN_OP_CONNECT_URL", "https://connect.example.com"),
        ("WARDEN_NOTIFY_NTFY_URL", "http://ntfy.example.com/topic"),
    ])
    .unwrap();
    assert_eq!(
        config.plain_http_urls(),
        [("WARDEN_NOTIFY_NTFY_URL", UrlTransport::PlainRemote)]
    );
}

#[test]
fn the_opt_in_refuses_an_entry_that_does_not_apply() {
    for list in [
        "WARDEN_DB_PATH",
        "WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL",
        "WARDEN_NOTIFY_NTFY_URL",
    ] {
        let err = with_token(&[("WARDEN_ALLOW_PLAIN_HTTP", list)]).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    var: "WARDEN_ALLOW_PLAIN_HTTP",
                    ..
                }
            ),
            "{list}: {err}"
        );
    }
}

/// With the local backend there is no Connect URL to allow.
#[test]
fn the_local_backend_refuses_the_opt_in_for_connect() {
    let mut extra = LOCAL.to_vec();
    extra.push(("WARDEN_ALLOW_PLAIN_HTTP", "WARDEN_OP_CONNECT_URL"));
    let err = without_connect_url(&extra).unwrap_err();
    assert!(
        matches!(
            err,
            ConfigError::Invalid {
                var: "WARDEN_ALLOW_PLAIN_HTTP",
                ..
            }
        ),
        "{err}"
    );
}
