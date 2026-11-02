//! `warden-server doctor`: checks a configuration and says what to fix.
//!
//! Each check reports pass, fail or could-not-check
//! ([`warden_broker_proto::doctor`]). Everything outside this process goes
//! through [`Environment`], so the decisions here are tested without a Connect
//! server, a phone or a file system; [`live`] is the real one.
//!
//! Doctor is read-only unless asked to send a test notification. It writes
//! nothing to the audit log, even then: like `agent list`, `passkey list` and
//! `audit verify`, it changes no state, and it must work (and change nothing)
//! on a deployment whose audit log is the thing that is broken.
//!
//! Secrets: no check quotes a response body, and every text of the report
//! then has the configured secrets removed from it, in case an upstream echoed
//! one into an error.

use std::io;
use std::net::SocketAddr;
use std::path::Path;

use async_trait::async_trait;
use secrecy::ExposeSecret;
use warden_broker_proto::doctor::{Check, Report};

use crate::config::{ALLOW_PLAIN_HTTP, BackendSettings, Config, ConfigError, UrlTransport};
use crate::notify::{ChannelSettings, Doorbell, NotifyError};
use crate::policy::{CaProbe, LocalProbe, VaultProbe};
use crate::proxy::{Needles, redact};

pub mod live;
mod local;

/// Where the settings are documented, for the release this binary is from.
const SETTINGS_DOC: &str = concat!(
    "https://github.com/pecheriere/warden/blob/v",
    env!("CARGO_PKG_VERSION"),
    "/docs/configuration.md#server-environment-variables"
);

/// The heading of the report.
const TITLE: &str = "warden-server doctor";

const TEST_TITLE: &str = "warden: doctor test notification";
const TEST_MESSAGE: &str =
    "Sent by warden-server doctor --send-test-notification. No request is waiting.";

/// What the owner does when a check needs the rest to be fixed first.
const FIX_CONFIG_FIRST: &str = "Fix the configuration, then run doctor again.";

/// Whether something accepts connections at an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerProbe {
    /// A process accepted a TCP connection.
    Accepted,
    /// The connection was refused: nothing listens here.
    Refused,
    /// Neither: a timeout or another network error. Holds the reason.
    Inconclusive(String),
}

/// What the database says about passkeys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasskeyProbe {
    /// The database file does not exist.
    NoDatabase,
    /// This many passkeys are enrolled.
    Enrolled(usize),
    /// The database could not be read. Holds the reason.
    Unreadable(String),
}

/// The facts about a path that decide whether its owner and mode are right.
/// Taken without following a symbolic link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathFacts {
    /// A directory.
    pub is_dir: bool,
    /// A regular file.
    pub is_file: bool,
    /// The owner's uid.
    pub uid: u32,
    /// The permission bits.
    pub mode: u32,
}

/// Everything doctor needs from outside this process.
#[async_trait]
pub trait Environment: Send + Sync {
    /// Ask Connect for the configured vault.
    async fn vault(&self) -> VaultProbe;
    /// Load the SSH CA key and drop it.
    async fn ca(&self) -> CaProbe;
    /// Read and validate everything the local backend would read.
    async fn local(&self) -> LocalProbe;
    /// Send `doorbell` through one channel, and only that one.
    async fn ring(&self, channel: &ChannelSettings, doorbell: &Doorbell)
    -> Result<(), NotifyError>;
    /// Count passkeys, without creating or migrating the database.
    async fn passkeys(&self, db: &Path) -> PasskeyProbe;
    /// How many audit entries are waiting in the database for the log, or why
    /// that could not be read.
    async fn waiting_entries(&self, db: &Path) -> Result<i64, String>;
    /// Try a TCP connection to a listener.
    async fn listener(&self, addr: SocketAddr) -> ListenerProbe;
    /// The facts about `path`.
    ///
    /// # Errors
    /// The I/O error of reading them.
    async fn path_facts(&self, path: &Path) -> io::Result<PathFacts>;
    /// The effective uid of this process.
    fn euid(&self) -> u32;
}

/// Removes configured secrets from report text, in the encodings
/// [`Needles`] knows.
struct Scrubber(Vec<Needles>);

impl Scrubber {
    fn new(config: &Config) -> Self {
        let mut secrets = Vec::new();
        // The local backend holds no secret to remove: what doctor reports
        // about it is fixed text, and it keeps no secret file's content.
        if let BackendSettings::OnePassword(connect) = &config.backend {
            secrets.push(connect.token.expose_secret());
            secrets.extend(connect.url.password());
        }
        for channel in config.notify.iter() {
            match channel {
                ChannelSettings::HomeAssistant { webhook_url } => {
                    let url = webhook_url.expose_url();
                    secrets.push(url.as_str());
                    secrets.extend(url.password());
                    secrets.extend(
                        url.path_segments()
                            .and_then(Iterator::last)
                            .filter(|id| !id.is_empty()),
                    );
                }
                ChannelSettings::Ntfy { url, token } => {
                    // The whole URL and not the topic alone, as for the webhook
                    // id: a topic can be an ordinary word of the report.
                    secrets.push(url.as_str());
                    secrets.extend(url.password());
                    secrets.extend(token.as_ref().map(ExposeSecret::expose_secret));
                }
            }
        }
        Self(
            secrets
                .into_iter()
                .map(|secret| Needles::new(secret, ""))
                .collect(),
        )
    }

    fn scrub(&self, text: &str) -> String {
        let bytes = self
            .0
            .iter()
            .fold(text.as_bytes().to_vec(), |data, needles| {
                redact(&data, needles).0
            });
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn report(&self, mut report: Report) -> Report {
        for check in &mut report.checks {
            check.detail = self.scrub(&check.detail);
            check.action = check.action.as_deref().map(|a| self.scrub(a));
        }
        report.effects = self.scrub(&report.effects);
        report
    }
}

/// The report when the configuration itself is unusable: that one failure,
/// everything that depends on it not checked, and the checks that never depend
/// on it.
#[must_use]
pub fn invalid_config_report(error: &ConfigError) -> Report {
    let mut checks = vec![Check::fail(
        "config",
        error.to_string(),
        format!("Fix this setting and run doctor again; there may be more. See {SETTINGS_DOC}"),
    )];
    for name in [
        "plain-http",
        "connect",
        "ssh-ca",
        "notify",
        "passkey",
        "listeners",
        "data",
    ] {
        checks.push(Check::could_not_check(
            name,
            "Not checked: the configuration is invalid.",
            FIX_CONFIG_FIRST,
        ));
    }
    checks.extend(by_hand_checks());
    Report {
        title: TITLE.to_owned(),
        checks,
        effects: "Read the environment and the secret files it names only. Sent nothing and \
                  wrote nothing."
            .to_owned(),
    }
}

/// Run every check against a valid configuration. Sends a notification only
/// when `send_test_notification` is set.
pub async fn examine(
    config: &Config,
    env: &dyn Environment,
    send_test_notification: bool,
) -> Report {
    let mut checks = vec![
        Check::pass("config", "The settings are present and valid."),
        plain_http_check(config),
    ];
    match &config.backend {
        BackendSettings::OnePassword(connect) => {
            let vault_found = connect_checks(env.vault().await, &connect.vault, &mut checks);
            checks.push(ca_check(if vault_found {
                Some(env.ca().await)
            } else {
                None
            }));
        }
        BackendSettings::Local(_) => local::checks(env.local().await, &mut checks),
    }
    let effects = if send_test_notification {
        ring_every_channel(config, env, &mut checks).await
    } else {
        checks.push(Check::could_not_check(
            "notify",
            "Not sent: a test notification reaches the owner's phone, so it takes a flag.",
            "Run doctor with --send-test-notification.",
        ));
        "Read only: sent no notification and changed no data. Wrote nothing to the audit log."
            .to_owned()
    };
    checks.push(passkey_check(env.passkeys(&config.db_path).await));
    checks.push(waiting_entries_check(
        env.waiting_entries(&config.db_path).await,
    ));
    listener_checks(config, env, &mut checks).await;
    data_checks(config, env, &mut checks).await;
    checks.extend(by_hand_checks());
    Scrubber::new(config).report(Report {
        title: TITLE.to_owned(),
        checks,
        effects,
    })
}

/// Which service URLs send their tokens and secrets without TLS. warden can
/// tell what a URL says, not what the network under it is.
fn plain_http_check(config: &Config) -> Check {
    const NAME: &str = "plain-http";
    let urls = config.plain_http_urls();
    let named = |wanted: UrlTransport| {
        urls.iter()
            .filter(|(_, transport)| *transport == wanted)
            .map(|(var, _)| *var)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let (remote, local) = (
        named(UrlTransport::PlainRemote),
        named(UrlTransport::PlainLocal),
    );
    if !remote.is_empty() {
        return Check::could_not_check(
            NAME,
            format!(
                "{remote}: plain http to a host that is not clearly local or private, allowed by \
                 {ALLOW_PLAIN_HTTP}. Tokens and secrets cross that path in clear, and warden \
                 cannot see whether it is safe."
            ),
            "Use https or a tailnet address. If that path really is private, keep the setting.",
        );
    }
    if local.is_empty() {
        return Check::pass(NAME, "Every service URL uses https.");
    }
    Check::pass(
        NAME,
        format!(
            "{local}: plain http to a local or private host, judged from the URL alone. Tokens \
             and secrets cross that network in clear, so share it only with the service."
        ),
    )
}

/// The checks from a Connect answer. Returns whether the vault was found, the
/// only case in which asking it for the CA key can say anything.
fn connect_checks(probe: VaultProbe, vault: &str, checks: &mut Vec<Check>) -> bool {
    const REACHABLE: &str = "connect.reachable";
    const TOKEN: &str = "connect.token";
    const VAULT: &str = "connect.vault";
    let fix_connect = "Fix Connect first, then run doctor again.";
    let not_checked = |name: &str, because: &str| {
        Check::could_not_check(name, format!("Not checked: {because}"), fix_connect)
    };
    let found = probe == VaultProbe::Found;
    match probe {
        VaultProbe::Found => {
            checks.push(Check::pass(REACHABLE, "Connect answered."));
            checks.push(Check::pass(TOKEN, "Connect accepted the token."));
            checks.push(Check::pass(
                VAULT,
                format!("The token can see the vault \"{vault}\"."),
            ));
        }
        VaultProbe::Missing => {
            checks.push(Check::pass(REACHABLE, "Connect answered."));
            checks.push(Check::pass(TOKEN, "Connect accepted the token."));
            checks.push(Check::fail(
                VAULT,
                format!("The token cannot see a vault named \"{vault}\"."),
                "Check WARDEN_OP_VAULT, that the vault exists, and that the Connect server and \
                 this token were given access to it.",
            ));
        }
        VaultProbe::TokenRefused { status } => {
            checks.push(Check::pass(REACHABLE, "Connect answered."));
            checks.push(Check::fail(
                TOKEN,
                format!("Connect refused the token (HTTP {status})."),
                "Issue a new token with `op connect token create`, put it in \
                 WARDEN_OP_CONNECT_TOKEN or the file WARDEN_OP_CONNECT_TOKEN_FILE names, and \
                 restart the server.",
            ));
            checks.push(not_checked(VAULT, "Connect refused the token."));
        }
        VaultProbe::Unreachable(reason) => {
            checks.push(Check::fail(
                REACHABLE,
                format!("No answer from Connect: {reason}"),
                "Check WARDEN_OP_CONNECT_URL, that Connect is running, and the network rules \
                 between warden and Connect.",
            ));
            checks.push(not_checked(TOKEN, "no answer from Connect."));
            checks.push(not_checked(VAULT, "no answer from Connect."));
        }
        VaultProbe::Unhealthy(reason) => {
            checks.push(Check::fail(
                REACHABLE,
                format!("Connect answered with {reason}."),
                "Check WARDEN_OP_CONNECT_URL and Connect's logs; Connect needs its sync \
                 container and its credentials file.",
            ));
            checks.push(not_checked(TOKEN, "Connect did not answer usefully."));
            checks.push(not_checked(VAULT, "Connect did not answer usefully."));
        }
        VaultProbe::UnusableName => {
            checks.push(not_checked(
                REACHABLE,
                "the vault name cannot be asked for.",
            ));
            checks.push(not_checked(TOKEN, "the vault name cannot be asked for."));
            checks.push(Check::fail(
                VAULT,
                "WARDEN_OP_VAULT holds a quote or a backslash, which warden cannot ask for.",
                "Rename the vault and update WARDEN_OP_VAULT.",
            ));
        }
    }
    checks.push(Check::could_not_check(
        "connect.token-read-only",
        "Connect does not report a token's permissions, and warden will not attempt a write to \
         find out.",
        "Confirm the token was created for this vault only and read-only: \
         `op connect token create <name> --server <server> --vault <vault>,r`. If unsure, issue \
         a new one that way.",
    ));
    found
}

/// The CA check; `None` when Connect could not be asked.
fn ca_check(probe: Option<CaProbe>) -> Check {
    const NAME: &str = "ssh-ca";
    match probe {
        None => Check::could_not_check(
            NAME,
            "Not checked: Connect or the vault is not usable.",
            "Fix Connect first, then run doctor again.",
        ),
        Some(CaProbe::Loaded { fingerprint }) => Check::pass(
            NAME,
            format!("The CA key loads; its public key is {fingerprint}."),
        ),
        Some(CaProbe::NotNeeded) => Check::pass(
            NAME,
            "No CA item, and no target in certificate mode needs one.",
        ),
        Some(CaProbe::Missing { cert_targets }) => Check::fail(
            NAME,
            format!(
                "No item is tagged warden:ssh-ca, and {cert_targets} certificate target(s) need one."
            ),
            "Create the CA item: see section 3 of docs/deployment.md.",
        ),
        Some(CaProbe::Invalid(reason)) => Check::fail(
            NAME,
            reason,
            "Exactly one item must be tagged warden:ssh-ca, holding an unencrypted Ed25519 key \
             in the field with id private_key.",
        ),
        Some(CaProbe::Unknown(reason)) => Check::could_not_check(
            NAME,
            reason,
            "Fix what the message names, then run doctor again.",
        ),
    }
}

/// Send one test notification through each channel, because a fallback that
/// is broken would otherwise stay hidden behind a working primary. Returns the
/// sentence saying what was done.
async fn ring_every_channel(
    config: &Config,
    env: &dyn Environment,
    checks: &mut Vec<Check>,
) -> String {
    let doorbell = Doorbell {
        title: TEST_TITLE.to_owned(),
        message: TEST_MESSAGE.to_owned(),
        url: config.public_url.clone(),
    };
    let mut attempted = Vec::new();
    for channel in config.notify.iter() {
        let name = channel.kind().name();
        attempted.push(name);
        let check = format!("notify.{name}");
        checks.push(match env.ring(channel, &doorbell).await {
            Ok(()) => Check::pass(check, "The channel accepted the test notification."),
            Err(e) => Check::fail(
                check,
                e.to_string(),
                format!(
                    "Check the WARDEN_NOTIFY_{}_* settings and that warden may reach the channel \
                     (docs/notifications.md).",
                    name.to_ascii_uppercase()
                ),
            ),
        });
    }
    checks.push(Check::could_not_check(
        "notify.delivery",
        "warden can see that a channel accepted a message, not that it reached the phone.",
        format!("Confirm your phone showed \"{TEST_TITLE}\" once per channel."),
    ));
    format!(
        "Tried to send one test notification through each channel: {}. Changed no data and wrote \
         nothing to the audit log.",
        attempted.join(", ")
    )
}

fn passkey_check(probe: PasskeyProbe) -> Check {
    const NAME: &str = "passkey";
    const ENROLL: &str = "Enroll one: `warden-server enroll` (section 8 of docs/deployment.md).";
    match probe {
        PasskeyProbe::Enrolled(0) => Check::fail(
            NAME,
            "No passkey is enrolled, so nothing can be approved.",
            ENROLL,
        ),
        PasskeyProbe::Enrolled(n) => Check::pass(NAME, format!("{n} passkey(s) enrolled.")),
        PasskeyProbe::NoDatabase => Check::fail(
            NAME,
            "The database does not exist, so no passkey is enrolled.",
            "Start the server, which creates it, then enroll a passkey with `warden-server \
             enroll`.",
        ),
        PasskeyProbe::Unreadable(reason) => Check::could_not_check(
            NAME,
            format!("The database could not be read: {reason}"),
            "Run doctor as the broker's user, then `warden-server passkey list`.",
        ),
    }
}

fn waiting_entries_check(probe: Result<i64, String>) -> Check {
    const NAME: &str = "audit.waiting";
    match probe {
        Ok(0) => Check::pass(NAME, "No audit log entries are waiting."),
        Ok(n) => Check::fail(
            NAME,
            format!("{n} audit log entries are waiting in the database and are not in the log."),
            "Find out why the audit log cannot be written (the server's log, the disk that holds \
             it). A running server writes them once it works.",
        ),
        Err(reason) => Check::could_not_check(
            NAME,
            format!("The database could not be read: {reason}"),
            "Run doctor as the broker's user.",
        ),
    }
}

async fn listener_checks(config: &Config, env: &dyn Environment, checks: &mut Vec<Check>) {
    let mut listeners = vec![
        ("listener.api", "WARDEN_API_LISTEN", config.api_listen),
        (
            "listener.approval",
            "WARDEN_APPROVAL_LISTEN",
            config.approval_listen,
        ),
    ];
    if config.relay.public_addr.is_some() {
        listeners.push(("listener.relay", "WARDEN_RELAY_LISTEN", config.relay.listen));
    }
    for (name, var, addr) in listeners {
        checks.push(listener_check(name, var, addr, env).await);
    }
}

async fn listener_check(name: &str, var: &str, addr: SocketAddr, env: &dyn Environment) -> Check {
    if addr.ip().is_unspecified() {
        return Check::fail(
            name,
            format!("{var} is {addr}, which binds every interface."),
            "Bind it to the address of warden's front network, or to loopback in the sidecar \
             layout (section 6 of docs/deployment.md).",
        );
    }
    match env.listener(addr).await {
        ListenerProbe::Accepted => {
            Check::pass(name, format!("A process accepts connections on {addr}."))
        }
        ListenerProbe::Refused => Check::fail(
            name,
            format!("Nothing listens on {addr} where doctor runs."),
            "Start the server, and run doctor inside its container (`docker compose exec`): \
             another container has its own network.",
        ),
        ListenerProbe::Inconclusive(reason) => Check::could_not_check(
            name,
            format!("Could not tell whether anything listens on {addr}: {reason}"),
            "Run doctor inside the server's container (`docker compose exec`).",
        ),
    }
}

/// Which bits a path must not have, and what it holds.
struct PathRule<'a> {
    name: &'a str,
    path: &'a Path,
    is_dir: bool,
    forbidden_mode: u32,
}

async fn data_checks(config: &Config, env: &dyn Environment, checks: &mut Vec<Check>) {
    // These are what the server enforces or creates: the directory from the
    // deployment guide (0700), the host key refused unless 0600, the rest
    // refused or left unsafe if others may write. The database is 0644 by
    // default and relies on the directory.
    let directory = match config.db_path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let mut rules = vec![PathRule {
        name: "data.directory",
        path: directory,
        is_dir: true,
        forbidden_mode: 0o077,
    }];
    let files = [
        ("data.database", config.db_path.as_path()),
        ("data.audit-log", config.audit_path.as_path()),
        ("data.audience", config.audience_path.as_path()),
    ];
    for (name, path) in files {
        rules.push(PathRule {
            name,
            path,
            is_dir: false,
            forbidden_mode: 0o022,
        });
    }
    if config.relay.public_addr.is_some() {
        rules.push(PathRule {
            name: "data.relay-host-key",
            path: &config.relay.host_key_path,
            is_dir: false,
            forbidden_mode: 0o077,
        });
    }
    for rule in rules {
        let facts = env.path_facts(rule.path).await;
        checks.push(path_check(&rule, facts, env.euid()));
    }
}

fn path_check(rule: &PathRule<'_>, facts: io::Result<PathFacts>, euid: u32) -> Check {
    let shown = rule.path.display();
    let name = rule.name;
    let facts = match facts {
        Ok(facts) => facts,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Check::fail(
                name,
                format!("{shown} does not exist."),
                "Create the data directory (section 5 of docs/deployment.md) and start the \
                 server, which creates the files. Doctor creates nothing.",
            );
        }
        Err(e) => {
            return Check::could_not_check(
                name,
                format!("Cannot read {shown}: {e}"),
                "Run doctor as the broker's user, inside its container.",
            );
        }
    };
    let right_kind = if rule.is_dir {
        facts.is_dir
    } else {
        facts.is_file
    };
    if !right_kind {
        let wanted = if rule.is_dir {
            "a directory"
        } else {
            "a regular file (not a symbolic link)"
        };
        return Check::fail(
            name,
            format!("{shown} is not {wanted}."),
            format!("Replace it with {wanted}."),
        );
    }
    if facts.uid != euid {
        return Check::fail(
            name,
            format!(
                "{shown} belongs to uid {}, and doctor runs as uid {euid}.",
                facts.uid
            ),
            "Run doctor as the broker's user. If that is who ran it, chown the path to that user.",
        );
    }
    let mode = facts.mode & 0o777;
    let extra = mode & rule.forbidden_mode;
    if extra != 0 {
        return Check::fail(
            name,
            format!("{shown} has mode {mode:04o}; the bits {extra:03o} must be off."),
            format!("chmod {:04o} {shown}", mode & !rule.forbidden_mode),
        );
    }
    Check::pass(
        name,
        format!("{shown}: owner and mode {mode:04o} are right."),
    )
}

/// What warden cannot see from inside its container.
fn by_hand_checks() -> [Check; 2] {
    [
        Check::could_not_check(
            "tailscale.funnel-off",
            "warden cannot see Tailscale's configuration from inside its container.",
            "On the host, `tailscale funnel status` must list nothing, and the tailnet policy \
             must give warden's tag no funnel attribute (docs/deployment.md, \"Never use \
             Funnel\").",
        ),
        Check::could_not_check(
            "tailscale.serve",
            "warden cannot see how Tailscale Serve publishes its listeners.",
            "On the host, `tailscale serve status` must show the agent API and the approval UI \
             as in section 2 of docs/deployment.md. Then run `warden doctor` on an agent \
             machine, and open WARDEN_PUBLIC_URL on your phone.",
        ),
    ]
}

#[cfg(test)]
mod tests;
