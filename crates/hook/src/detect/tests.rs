//! Tests of `check`, driven by one fixture context.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

mod hardening;

use super::{Match, check};
use crate::context::{ApiCover, Context, Coverage, SshAliases, SshCover};
use crate::settings::{Setting, Settings, Signal};

/// What `warden ssh-config switch-01` prints for a relay grant (see
/// `crates/cli/src/ssh_config.rs`, `block`, and `ssh::connection`), with
/// throwaway paths.
const WARDEN_CONFIG: &str = "\
# warden grant 0123456789ab for switch-01, not_after=1800000000 (2027-01-15T08:00:00Z)
Host switch-01
  HostName switch-01.example.internal
  Port 22
  User switch-01
  IdentityAgent \"/tmp/warden-501/abc.sock\"
  IdentityFile none
  IdentitiesOnly no
  UserKnownHostsFile \"/tmp/warden-state/grants/abc/known_hosts\"
  StrictHostKeyChecking yes
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  ForwardAgent no
";

fn coverage() -> Coverage {
    Coverage {
        ssh: vec![
            SshCover {
                name: "switch-01".to_owned(),
                host: Some("switch-01.example.internal".to_owned()),
                users: vec!["build-agent".to_owned()],
            },
            SshCover {
                name: "lab-pi".to_owned(),
                host: None,
                users: Vec::new(),
            },
        ],
        api: vec![ApiCover {
            name: "home-api".to_owned(),
            origin: Some("https://home-api.example.internal".to_owned()),
        }],
    }
}

fn context(covered: bool) -> Context {
    let files: HashMap<PathBuf, String> =
        HashMap::from([(PathBuf::from("/work/warden.conf"), WARDEN_CONFIG.to_owned())]);
    let aliases = SshAliases::parse(
        "Host lab\n  HostName switch-01.example.internal\n",
        &|_: &str| None,
    );
    Context {
        coverage: covered.then(coverage),
        aliases,
        warden_socket_dir: PathBuf::from("/tmp/warden-501"),
        warden_socket_dir_real: None,
        read_small_file: Box::new(move |p: &Path| files.get(p).cloned()),
    }
}

fn signals(command: &str) -> Vec<Signal> {
    check(command, &context(true), &Settings::default())
        .matches
        .iter()
        .map(|m| m.signal)
        .collect()
}

#[test]
fn signals_fire_on_the_commands_that_bypass_warden() {
    let cases: &[(&str, Signal)] = &[
        ("ssh switch-01.example.internal", Signal::CoveredSsh),
        ("ssh build-agent@switch-01", Signal::CoveredSsh),
        ("scp f switch-01:/tmp", Signal::CoveredSsh),
        (
            "rsync -a d switch-01.example.internal:/x",
            Signal::CoveredSsh,
        ),
        (
            "git clone ssh://git@switch-01.example.internal/r",
            Signal::CoveredSsh,
        ),
        ("ssh lab-pi", Signal::CoveredSsh),
        ("ssh lab", Signal::CoveredSsh),
        ("ssh -p 2222 -l root switch-01", Signal::CoveredSsh),
        ("sudo ssh switch-01 uptime", Signal::CoveredSsh),
        ("sftp switch-01:/x", Signal::CoveredSsh),
        (
            "curl https://home-api.example.internal/api/states",
            Signal::CoveredApi,
        ),
        ("wget -q home-api.example.internal/x", Signal::CoveredApi),
        ("http GET home-api.example.internal/x", Signal::CoveredApi),
        (
            "xh --bearer t https://home-api.example.internal",
            Signal::CoveredApi,
        ),
        (
            "curl --url https://home-api.example.internal/x",
            Signal::CoveredApi,
        ),
        ("ssh -i ~/.ssh/id host", Signal::OwnerSshKey),
        ("ssh -o IdentityFile=~/k host", Signal::OwnerSshKey),
        ("SSH_AUTH_SOCK=/x ssh host", Signal::OwnerSshKey),
        ("env SSH_AUTH_SOCK=/x ssh host", Signal::OwnerSshKey),
        ("op read op://v/i/f", Signal::SecretStore),
        ("op run -- env", Signal::SecretStore),
        ("op item get x", Signal::SecretStore),
        ("op --account a inject -i t", Signal::SecretStore),
        (
            "security find-generic-password -s x -w",
            Signal::SecretStore,
        ),
        ("pass show web/x", Signal::SecretStore),
        ("pass web/x", Signal::SecretStore),
        ("gopass show x", Signal::SecretStore),
        ("bw get password x", Signal::SecretStore),
        ("cat ~/.netrc", Signal::TokenRead),
        ("source .env", Signal::TokenRead),
        ("cat ~/.config/gh/hosts.yml", Signal::TokenRead),
        ("grep TOKEN .env.local", Signal::TokenRead),
        ("gh auth token", Signal::TokenRead),
        ("ssh other.example.org", Signal::UncoveredHost),
        (
            "curl -H 'Authorization: Bearer t' https://api.example.org",
            Signal::UncoveredHost,
        ),
        (
            "curl -u me:pw https://api.example.org",
            Signal::UncoveredHost,
        ),
        (
            "curl --oauth2-bearer t https://api.example.org",
            Signal::UncoveredHost,
        ),
        ("curl https://me:pw@api.example.org/", Signal::UncoveredHost),
        (
            "http https://api.example.org Authorization:'Bearer t'",
            Signal::UncoveredHost,
        ),
        ("echo $(ssh switch-01 uptime)", Signal::CoveredSsh),
        ("bash -c 'op read x'", Signal::SecretStore),
    ];
    for (i, (command, signal)) in cases.iter().enumerate() {
        assert!(signals(command).contains(signal), "case {i}");
    }
}

#[test]
fn warden_routes_are_not_bypasses() {
    for (i, command) in [
        "warden ssh switch-01 -- uptime",
        "warden http home-api GET https://home-api.example.internal/api --fail",
        "ssh -o IdentityAgent=/tmp/warden-501/abc.sock switch-01",
        "ssh -oIdentityAgent=/tmp/warden-501/abc.sock switch-01",
        "ssh -o 'IdentityAgent /tmp/warden-501/abc.sock' switch-01",
        "SSH_AUTH_SOCK=/tmp/warden-501/abc.sock ssh switch-01",
        "ssh -F /work/warden.conf switch-01",
        "ssh -F /work/warden.conf -o IdentityAgent=none switch-01",
        "scp -F /work/warden.conf f switch-01:/x",
        "rsync -e 'ssh -F /work/warden.conf' d switch-01:/x",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(signals(command), vec![], "case {i}");
    }
}

#[test]
fn a_config_that_is_not_warden_s_exempts_nothing() {
    assert!(signals("ssh -F /work/missing.conf switch-01").contains(&Signal::CoveredSsh));
    // The config declares switch-01 only.
    assert!(signals("ssh -F /work/warden.conf other.example.org").contains(&Signal::UncoveredHost));
    assert!(
        signals("ssh -o IdentityAgent=/tmp/other.sock switch-01").contains(&Signal::OwnerSshKey)
    );
    assert!(
        signals("ssh -o IdentityAgent=/tmp/warden-501/../x.sock switch-01")
            .contains(&Signal::CoveredSsh)
    );
}

#[test]
fn an_explicit_key_counts_even_on_a_warden_route() {
    let found = signals("ssh -i ~/.ssh/id -F /work/warden.conf switch-01");
    assert_eq!(found, vec![Signal::OwnerSshKey]);
}

#[test]
fn ordinary_work_is_not_reported() {
    for (i, command) in [
        "ssh-keygen -t ed25519",
        "git push origin main",
        "git commit -m 'mail me@example.org: hi'",
        "curl https://example.com",
        "curl -s https://example.com/a.json -o a.json",
        "op --version",
        "op signin",
        "cat README.md",
        "echo ssh switch-01",
        "grep ssh notes.txt",
        "grep .env README.md",
        "rg TOKEN",
        "cat .env.example",
        "pass ls",
        "pass git push",
        "gopass ls",
        "bw status",
        "security find-generic-password -s x",
        "ssh -V",
        "ssh localhost",
        "curl -H 'Authorization: Bearer t' http://localhost:8080/x",
        "command -v ssh",
        "scp a.txt b.txt",
        "rsync -a d1 d2",
        "gh pr list",
        "ls -la",
        "",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(signals(command), vec![], "case {i}");
    }
}

#[test]
fn messages_never_echo_the_command() {
    let cases: &[(&str, &str)] = &[
        (
            "curl -H \"Authorization: Bearer abc123\" https://home-api.example.internal/x",
            "home-api.example.internal",
        ),
        ("op read op://vault-x/item-y/password", "op"),
        (
            "curl https://user:hunter2@api.example.org/",
            "api.example.org",
        ),
        ("ssh -i /secret/path/key host.example.org", "ssh"),
        ("cat /secret/path/.netrc", ".netrc"),
        ("cat /secret/path/.env.hunter2", ".env"),
        (
            "curl -H 'Authorization: Bearer abc123' https://api.example.org/path?token=abc123",
            "api.example.org",
        ),
    ];
    for (case, (command, subject)) in cases.iter().enumerate() {
        let verdict = check(command, &context(true), &Settings::default());
        assert!(!verdict.message.is_empty(), "case #{case}: no message");
        assert!(
            verdict.message.contains(subject),
            "case #{case}: message lacks its subject"
        );
        for (i, secret) in ["abc123", "vault-x", "item-y", "hunter2", "/secret/path"]
            .iter()
            .enumerate()
        {
            assert!(
                !verdict.message.contains(secret),
                "case #{case}: message echoes forbidden fixture #{i}"
            );
        }
        assert!(verdict.message.ends_with("Never look for another way in."));
        for found in &verdict.matches {
            assert!(
                !found.subject.contains('/'),
                "case #{case}: subject with a slash"
            );
        }
    }
}

#[test]
fn messages_name_the_next_step() {
    let ssh = check("ssh switch-01", &context(true), &Settings::default()).message;
    assert!(ssh.contains("warden status"));
    assert!(ssh.contains(
        "warden request ssh switch-01 --user build-agent --for 15m --goal \"<what and why>\""
    ));
    assert!(ssh.contains("warden ssh switch-01 -- <command>"));
    let unknown = check("ssh lab-pi", &context(true), &Settings::default()).message;
    assert!(unknown.contains("--user <user>"));
    let api = check(
        "curl https://home-api.example.internal/x",
        &context(true),
        &Settings::default(),
    )
    .message;
    assert!(api.contains("warden request api home-api"));
    assert!(
        api.contains(
            "warden http home-api <METHOD> https://home-api.example.internal/<path> --fail"
        )
    );
    let owner = check("op read x", &context(true), &Settings::default()).message;
    assert!(owner.contains("warden list"));
    assert!(owner.contains("docs/1password-items.md"));
    assert!(owner.contains("Do not use the owner's credentials meanwhile"));
    let host = check(
        "ssh other.example.org",
        &context(true),
        &Settings::default(),
    )
    .message;
    assert!(host.contains("warden does not list this host here"));
    assert!(!host.contains("is not in warden"));
}

#[test]
fn the_strongest_setting_wins() {
    let verdict = check(
        "op read x && ssh switch-01",
        &context(true),
        &Settings::default(),
    );
    assert_eq!(verdict.setting, Setting::Block);
    assert_eq!(verdict.matches.len(), 2);
    assert_eq!(verdict.settings_note, None);
    assert!(verdict.message.contains("secret-store"));
    assert!(verdict.message.contains("covered-ssh"));
}

#[test]
fn several_signals_can_fire_on_one_command() {
    let found = signals("ssh -i ~/.ssh/id other.example.org");
    assert!(found.contains(&Signal::OwnerSshKey));
    assert!(found.contains(&Signal::UncoveredHost));
}

#[test]
fn matches_are_deduplicated() {
    let verdict = check(
        "ssh switch-01 a; ssh switch-01 b; ssh build-agent@switch-01.example.internal",
        &context(true),
        &Settings::default(),
    );
    assert_eq!(
        verdict.matches,
        vec![Match {
            signal: Signal::CoveredSsh,
            subject: "switch-01".to_owned()
        }]
    );
}

#[test]
fn off_signals_are_dropped() {
    let table: toml::Table = toml::from_str(
        "covered-ssh = \"off\"\ncovered-api = \"off\"\nowner-ssh-key = \"off\"\n\
         secret-store = \"off\"\ntoken-read = \"off\"\nuncovered-host = \"off\"\nowner-github = \"off\"\n",
    )
    .unwrap();
    let (settings, note) = Settings::from_table(Some(&table));
    assert_eq!(note, None);
    let verdict = check(
        "op read x; ssh -i k switch-01; cat .env",
        &context(true),
        &settings,
    );
    assert_eq!(verdict.setting, Setting::Off);
    assert_eq!(verdict.matches, Vec::<Match>::new());
    assert_eq!(verdict.message, "");
}

#[test]
fn a_demoted_signal_sets_the_setting() {
    let table: toml::Table = toml::from_str("covered-ssh = \"warn\"").unwrap();
    let (settings, _) = Settings::from_table(Some(&table));
    let verdict = check("ssh switch-01", &context(true), &settings);
    assert_eq!(verdict.setting, Setting::Warn);
}

#[test]
fn without_offers_only_the_destination_free_signals_fire() {
    let none = |command: &str| -> Vec<Signal> {
        check(command, &context(false), &Settings::default())
            .matches
            .iter()
            .map(|m| m.signal)
            .collect()
    };
    assert_eq!(none("ssh switch-01.example.internal"), vec![]);
    assert_eq!(
        none("curl -H 'Authorization: x' https://api.example.org"),
        vec![]
    );
    assert_eq!(none("curl https://home-api.example.internal/x"), vec![]);
    assert_eq!(none("op read op://v/i/f"), vec![Signal::SecretStore]);
    assert_eq!(none("ssh -i k switch-01"), vec![Signal::OwnerSshKey]);
    assert_eq!(none("cat .netrc"), vec![Signal::TokenRead]);
}

#[test]
fn odd_input_does_not_panic() {
    for command in [
        "ssh",
        "ssh -",
        "ssh --",
        "ssh -i",
        "ssh -o",
        "ssh -F",
        "scp :",
        "scp @:x",
        "curl",
        "curl -H",
        "curl --url",
        "http",
        "http GET",
        "op",
        "pass",
        "security",
        "git ssh://",
        "git ://@:",
        "cat",
        "'",
        "ssh 'a b' c",
        "rsync -e",
        "rsync ::",
        "ssh ü.example",
        "curl http://[::1",
    ] {
        let _ = check(command, &context(true), &Settings::default());
    }
}
