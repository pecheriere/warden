//! Each check's pass, fail and could-not-check paths, with a fake
//! [`Environment`]: no network, no phone, no file system, no clock.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use warden_broker_proto::doctor::{
    Check, EXIT_COULD_NOT_CHECK, EXIT_FAILED, EXIT_NOTHING_FAILED, Report, Status,
};

use super::{Environment, ListenerProbe, PasskeyProbe, PathFacts, examine, invalid_config_report};
use crate::config::{Config, ConfigError};
use crate::notify::{ChannelSettings, Doorbell, NotifyError};
use crate::policy::{CaProbe, LocalProbe, VaultProbe};

const TOKEN: &str = "connect-token-do-not-leak-0123456789";
const WEBHOOK_ID: &str = "webhook-id-do-not-leak-0123456789";
const NTFY_TOKEN: &str = "ntfy-token-do-not-leak-0123456789";
const EUID: u32 = 1000;

/// A configuration through `extra`, on top of valid settings.
fn config(extra: &[(&str, &str)]) -> Config {
    let webhook = format!("https://ha.example/api/webhook/{WEBHOOK_ID}");
    let mut vars: HashMap<String, String> = [
        ("WARDEN_DB_PATH", "/data/warden.db"),
        ("WARDEN_AUDIT_PATH", "/data/audit.jsonl"),
        ("WARDEN_PUBLIC_URL", "https://warden.example.ts.net"),
        ("WARDEN_OWNER_LOGIN", "owner@example.com"),
        ("WARDEN_OP_CONNECT_URL", "http://192.0.2.1:8080"),
        ("WARDEN_OP_CONNECT_TOKEN", TOKEN),
        ("WARDEN_NOTIFY", "homeassistant,ntfy"),
        ("WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL", webhook.as_str()),
        ("WARDEN_NOTIFY_NTFY_URL", "https://ntfy.example/topic"),
        ("WARDEN_NOTIFY_NTFY_TOKEN", NTFY_TOKEN),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    for (k, v) in extra {
        vars.insert((*k).to_owned(), (*v).to_owned());
    }
    Config::from_lookup(|var| vars.get(var).cloned()).unwrap()
}

/// Everything fine, unless a test changes a field.
struct Fake {
    vault: VaultProbe,
    ca: CaProbe,
    local: LocalProbe,
    ring: fn(&str) -> Result<(), NotifyError>,
    passkeys: PasskeyProbe,
    listener: ListenerProbe,
    paths: HashMap<PathBuf, io::ErrorKind>,
    facts: PathFacts,
    rung: Mutex<Vec<(String, Doorbell)>>,
    asked_for_ca: Mutex<bool>,
}

impl Fake {
    fn healthy() -> Self {
        Self {
            vault: VaultProbe::Found,
            ca: CaProbe::Loaded {
                fingerprint: "SHA256:abc".to_owned(),
            },
            local: LocalProbe::Unreadable("not asked for".to_owned()),
            ring: |_| Ok(()),
            passkeys: PasskeyProbe::Enrolled(1),
            listener: ListenerProbe::Accepted,
            paths: HashMap::new(),
            facts: PathFacts {
                is_dir: true,
                is_file: true,
                uid: EUID,
                mode: 0o600,
            },
            rung: Mutex::new(Vec::new()),
            asked_for_ca: Mutex::new(false),
        }
    }
}

#[async_trait]
impl Environment for Fake {
    async fn vault(&self) -> VaultProbe {
        self.vault.clone()
    }

    async fn ca(&self) -> CaProbe {
        *self.asked_for_ca.lock().unwrap() = true;
        self.ca.clone()
    }

    async fn local(&self) -> LocalProbe {
        self.local.clone()
    }

    async fn ring(
        &self,
        channel: &ChannelSettings,
        doorbell: &Doorbell,
    ) -> Result<(), NotifyError> {
        let name = channel.kind().name();
        self.rung
            .lock()
            .unwrap()
            .push((name.to_owned(), doorbell.clone()));
        (self.ring)(name)
    }

    async fn passkeys(&self, _db: &Path) -> PasskeyProbe {
        self.passkeys.clone()
    }

    async fn listener(&self, _addr: SocketAddr) -> ListenerProbe {
        self.listener.clone()
    }

    async fn path_facts(&self, path: &Path) -> io::Result<PathFacts> {
        match self.paths.get(path) {
            Some(kind) => Err(io::Error::from(*kind)),
            None => Ok(self.facts),
        }
    }

    fn euid(&self) -> u32 {
        EUID
    }
}

async fn run(fake: &Fake) -> Report {
    examine(&config(&[]), fake, false).await
}

fn check<'a>(report: &'a Report, name: &str) -> &'a Check {
    report
        .checks
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no check {name} in {report:#?}"))
}

fn status(report: &Report, name: &str) -> Status {
    check(report, name).status
}

fn every_check_not_passing_says_what_to_do(report: &Report) {
    for check in &report.checks {
        assert_eq!(
            check.action.is_some(),
            check.status != Status::Pass,
            "{check:?}"
        );
    }
}

#[tokio::test]
async fn a_healthy_setup_passes_all_but_what_cannot_be_seen() {
    let report = run(&Fake::healthy()).await;
    let not_passed: Vec<&str> = report
        .checks
        .iter()
        .filter(|c| c.status != Status::Pass)
        .map(|c| {
            assert_eq!(c.status, Status::CouldNotCheck, "{c:?}");
            c.name.as_str()
        })
        .collect();
    assert_eq!(
        not_passed,
        [
            "connect.token-read-only",
            "notify",
            "tailscale.funnel-off",
            "tailscale.serve"
        ]
    );
    assert_eq!(report.exit_code(false), EXIT_NOTHING_FAILED);
    assert_eq!(report.exit_code(true), EXIT_COULD_NOT_CHECK);
    every_check_not_passing_says_what_to_do(&report);
}

#[test]
fn an_invalid_configuration_names_the_setting_and_its_documentation() {
    let report = invalid_config_report(&ConfigError::Missing("WARDEN_OWNER_LOGIN"));
    let config = check(&report, "config");
    assert_eq!(config.status, Status::Fail);
    assert!(config.detail.contains("WARDEN_OWNER_LOGIN"), "{config:?}");
    assert!(
        config
            .action
            .as_deref()
            .unwrap()
            .contains("docs/configuration.md#server-environment-variables"),
        "{config:?}"
    );
    assert_eq!(report.exit_code(false), EXIT_FAILED);
    assert_eq!(report.exit_code(true), EXIT_FAILED);
    every_check_not_passing_says_what_to_do(&report);
    // Nothing that needs the configuration looks like it ran.
    for check in &report.checks[1..] {
        assert_eq!(check.status, Status::CouldNotCheck, "{check:?}");
    }
}

#[tokio::test]
async fn connect_answers_map_to_the_right_checks() {
    use Status::{CouldNotCheck, Fail, Pass};
    let cases = [
        (VaultProbe::Found, Pass, Pass, Pass),
        (VaultProbe::Missing, Pass, Pass, Fail),
        (
            VaultProbe::TokenRefused { status: 401 },
            Pass,
            Fail,
            CouldNotCheck,
        ),
        (
            VaultProbe::Unreachable("refused".to_owned()),
            Fail,
            CouldNotCheck,
            CouldNotCheck,
        ),
        (
            VaultProbe::Unhealthy("HTTP 503".to_owned()),
            Fail,
            CouldNotCheck,
            CouldNotCheck,
        ),
        (VaultProbe::UnusableName, CouldNotCheck, CouldNotCheck, Fail),
    ];
    for (probe, reachable, token, vault) in cases {
        let fake = Fake {
            vault: probe.clone(),
            ..Fake::healthy()
        };
        let report = run(&fake).await;
        assert_eq!(status(&report, "connect.reachable"), reachable, "{probe:?}");
        assert_eq!(status(&report, "connect.token"), token, "{probe:?}");
        assert_eq!(status(&report, "connect.vault"), vault, "{probe:?}");
        every_check_not_passing_says_what_to_do(&report);
    }
}

#[tokio::test]
async fn the_token_being_read_only_is_never_inferred() {
    for vault in [
        VaultProbe::Found,
        VaultProbe::TokenRefused { status: 403 },
        VaultProbe::Unreachable("x".to_owned()),
    ] {
        let fake = Fake {
            vault,
            ..Fake::healthy()
        };
        let report = run(&fake).await;
        assert_eq!(
            status(&report, "connect.token-read-only"),
            Status::CouldNotCheck
        );
    }
}

#[tokio::test]
async fn the_ca_is_not_asked_for_unless_the_vault_was_found() {
    let fake = Fake {
        vault: VaultProbe::TokenRefused { status: 401 },
        ..Fake::healthy()
    };
    let report = run(&fake).await;
    assert_eq!(status(&report, "ssh-ca"), Status::CouldNotCheck);
    assert!(!*fake.asked_for_ca.lock().unwrap());
}

#[tokio::test]
async fn ca_answers_map_to_pass_fail_and_could_not_check() {
    let cases = [
        (
            CaProbe::Loaded {
                fingerprint: "SHA256:abc".to_owned(),
            },
            Status::Pass,
        ),
        (CaProbe::NotNeeded, Status::Pass),
        (CaProbe::Missing { cert_targets: 2 }, Status::Fail),
        (CaProbe::Invalid("bad".to_owned()), Status::Fail),
        (CaProbe::Unknown("down".to_owned()), Status::CouldNotCheck),
    ];
    for (probe, expected) in cases {
        let fake = Fake {
            ca: probe.clone(),
            ..Fake::healthy()
        };
        assert_eq!(status(&run(&fake).await, "ssh-ca"), expected, "{probe:?}");
    }
}

#[tokio::test]
async fn without_the_flag_nothing_is_sent_and_the_output_says_so() {
    let fake = Fake::healthy();
    let report = examine(&config(&[]), &fake, false).await;
    assert!(fake.rung.lock().unwrap().is_empty());
    assert_eq!(status(&report, "notify"), Status::CouldNotCheck);
    assert!(
        report.effects.contains("sent no notification"),
        "{report:?}"
    );
    assert!(report.effects.contains("audit log"), "{report:?}");
}

#[tokio::test]
async fn the_flag_rings_every_channel_once_and_says_so() {
    let fake = Fake::healthy();
    let report = examine(&config(&[]), &fake, true).await;
    let rung = fake.rung.lock().unwrap();
    let names: Vec<&str> = rung.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["homeassistant", "ntfy"]);
    assert_eq!(rung[0].1.url.as_str(), "https://warden.example.ts.net/");
    assert!(rung[0].1.title.contains("test"), "{:?}", rung[0].1);
    assert_eq!(status(&report, "notify.homeassistant"), Status::Pass);
    assert_eq!(status(&report, "notify.ntfy"), Status::Pass);
    // Accepted is not delivered.
    assert_eq!(status(&report, "notify.delivery"), Status::CouldNotCheck);
    assert!(
        report.effects.contains("homeassistant, ntfy"),
        "{}",
        report.effects
    );
}

#[tokio::test]
async fn a_broken_fallback_is_not_hidden_by_a_working_primary() {
    let fake = Fake {
        ring: |name| {
            if name == "ntfy" {
                Err(NotifyError::Status {
                    notifier: "ntfy",
                    status: 403,
                })
            } else {
                Ok(())
            }
        },
        ..Fake::healthy()
    };
    let report = examine(&config(&[]), &fake, true).await;
    assert_eq!(status(&report, "notify.homeassistant"), Status::Pass);
    assert_eq!(status(&report, "notify.ntfy"), Status::Fail);
    assert!(check(&report, "notify.ntfy").detail.contains("403"));
    assert_eq!(report.exit_code(false), EXIT_FAILED);
    assert_eq!(report.exit_code(true), EXIT_FAILED);
}

#[tokio::test]
async fn passkey_answers_map_to_pass_fail_and_could_not_check() {
    let cases = [
        (PasskeyProbe::Enrolled(2), Status::Pass),
        (PasskeyProbe::Enrolled(0), Status::Fail),
        (PasskeyProbe::NoDatabase, Status::Fail),
        (
            PasskeyProbe::Unreadable("locked".to_owned()),
            Status::CouldNotCheck,
        ),
    ];
    for (probe, expected) in cases {
        let fake = Fake {
            passkeys: probe.clone(),
            ..Fake::healthy()
        };
        assert_eq!(status(&run(&fake).await, "passkey"), expected, "{probe:?}");
    }
}

#[tokio::test]
async fn listener_answers_map_to_pass_fail_and_could_not_check() {
    let cases = [
        (ListenerProbe::Accepted, Status::Pass),
        (ListenerProbe::Refused, Status::Fail),
        (
            ListenerProbe::Inconclusive("timeout".to_owned()),
            Status::CouldNotCheck,
        ),
    ];
    for (probe, expected) in cases {
        let fake = Fake {
            listener: probe.clone(),
            ..Fake::healthy()
        };
        let report = run(&fake).await;
        assert_eq!(status(&report, "listener.api"), expected, "{probe:?}");
        assert_eq!(status(&report, "listener.approval"), expected, "{probe:?}");
    }
}

#[tokio::test]
async fn a_listener_on_every_interface_fails_even_if_it_answers() {
    let config = config(&[("WARDEN_API_LISTEN", "0.0.0.0:8080")]);
    let report = examine(&config, &Fake::healthy(), false).await;
    let api = check(&report, "listener.api");
    assert_eq!(api.status, Status::Fail);
    assert!(api.detail.contains("WARDEN_API_LISTEN"), "{api:?}");
    assert_eq!(status(&report, "listener.approval"), Status::Pass);
}

#[tokio::test]
async fn the_relay_is_checked_only_when_it_is_on() {
    let report = run(&Fake::healthy()).await;
    assert!(!report.checks.iter().any(|c| c.name.contains("relay")));
    let on = config(&[("WARDEN_RELAY_PUBLIC_ADDR", "relay.example:2222")]);
    let report = examine(&on, &Fake::healthy(), false).await;
    assert_eq!(status(&report, "listener.relay"), Status::Pass);
    assert_eq!(status(&report, "data.relay-host-key"), Status::Pass);
}

#[tokio::test]
async fn data_paths_with_the_wrong_owner_or_mode_fail() {
    let base = Fake::healthy().facts;
    let cases = [
        (
            PathFacts {
                uid: EUID + 1,
                ..base
            },
            "data.database",
        ),
        (
            PathFacts {
                mode: 0o664,
                ..base
            },
            "data.database",
        ),
        (
            PathFacts {
                mode: 0o666,
                ..base
            },
            "data.audit-log",
        ),
        (
            PathFacts {
                mode: 0o620,
                ..base
            },
            "data.audience",
        ),
        (
            PathFacts {
                mode: 0o750,
                ..base
            },
            "data.directory",
        ),
        (
            PathFacts {
                is_file: false,
                ..base
            },
            "data.database",
        ),
        (
            PathFacts {
                is_dir: false,
                ..base
            },
            "data.directory",
        ),
    ];
    for (facts, name) in cases {
        let fake = Fake {
            facts,
            ..Fake::healthy()
        };
        let report = run(&fake).await;
        assert_eq!(status(&report, name), Status::Fail, "{facts:?}");
    }
}

#[tokio::test]
async fn a_database_readable_by_others_is_fine_inside_a_private_directory() {
    let fake = Fake {
        facts: PathFacts {
            mode: 0o644,
            ..Fake::healthy().facts
        },
        ..Fake::healthy()
    };
    assert_eq!(status(&run(&fake).await, "data.database"), Status::Pass);
    // A host key is not, and neither is the directory.
    let on = config(&[("WARDEN_RELAY_PUBLIC_ADDR", "relay.example:2222")]);
    let report = examine(&on, &fake, false).await;
    assert_eq!(status(&report, "data.relay-host-key"), Status::Fail);
    assert_eq!(status(&report, "data.directory"), Status::Fail);
}

#[tokio::test]
async fn a_missing_path_fails_and_an_unreadable_one_could_not_be_checked() {
    let mut fake = Fake::healthy();
    fake.paths
        .insert("/data/audience".into(), io::ErrorKind::NotFound);
    fake.paths
        .insert("/data/audit.jsonl".into(), io::ErrorKind::PermissionDenied);
    let report = run(&fake).await;
    assert_eq!(status(&report, "data.audience"), Status::Fail);
    assert_eq!(status(&report, "data.audit-log"), Status::CouldNotCheck);
}

#[tokio::test]
async fn a_database_path_without_a_directory_still_checks_the_directory() {
    let mut fake = Fake::healthy();
    fake.paths
        .insert(".".into(), io::ErrorKind::PermissionDenied);
    let config = config(&[("WARDEN_DB_PATH", "warden.db")]);
    let report = examine(&config, &fake, false).await;
    assert_eq!(status(&report, "data.directory"), Status::CouldNotCheck);
}

#[tokio::test]
async fn tailscale_is_never_inferred_from_inside_the_container() {
    let report = run(&Fake::healthy()).await;
    for name in ["tailscale.funnel-off", "tailscale.serve"] {
        let check = check(&report, name);
        assert_eq!(check.status, Status::CouldNotCheck);
        assert!(check.action.as_deref().unwrap().contains("tailscale "));
    }
}

#[tokio::test]
async fn no_configured_secret_survives_into_the_report() {
    let echo = format!("echoed {TOKEN} {WEBHOOK_ID} {NTFY_TOKEN} https://ntfy.example/topic");
    let fake = Fake {
        vault: VaultProbe::Found,
        ca: CaProbe::Invalid(echo.clone()),
        passkeys: PasskeyProbe::Unreadable(echo.clone()),
        listener: ListenerProbe::Inconclusive(echo.clone()),
        ..Fake::healthy()
    };
    let text = examine(&config(&[]), &fake, false).await.render(false);
    for secret in [TOKEN, WEBHOOK_ID, NTFY_TOKEN, "https://ntfy.example/topic"] {
        assert!(!text.contains(secret), "{text}");
    }
    assert!(text.contains("[REDACTED]"), "{text}");
}
