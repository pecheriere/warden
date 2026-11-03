//! `warden doctor`: checks this machine's setup and says what to fix.
//!
//! Everything outside this process goes through [`Probes`], so the decisions
//! here are tested without a broker or an `ssh-agent`. Nothing local changes:
//! no configuration, grant record or Keychain entry is written. The one call
//! that authenticates, `GET /v1/grants`, is what `warden status` makes.
//!
//! The broker does not publish its version, and this command adds no endpoint
//! for it: whether the two versions are compatible is reported as
//! could-not-check.

use anyhow::Error;
use url::Url;
use warden_broker_proto::doctor::{Check, Report};
use warden_broker_proto::signing::PROTOCOL;
use warden_broker_proto::{GrantAccess, InfoResponse};
use zeroize::Zeroizing;

use crate::client::{CallError, Client, fetch_info};
use crate::config::{self, Config};
use crate::setup_git::current_value;

/// What replaces a bearer key the broker echoed back.
const REDACTED: &str = "[REDACTED]";

/// The name of the check of git's signing setup.
const GIT_SIGNING: &str = "git.signing";

/// What the owner does when a check needs an earlier one to be fixed first.
const FIX_EARLIER: &str = "Fix the failure above, then run doctor again.";

/// Everything doctor needs from outside this process.
pub trait Probes {
    /// The configuration file, or why it is not usable. The reason holds no
    /// text from the file.
    fn config(&self) -> Result<Config, String>;
    /// The broker's `GET /v1/info`.
    async fn info(&self, server: &Url) -> Result<InfoResponse, CallError>;
    /// Whether this agent's credential is available here: the signing key in
    /// the `ssh-agent`, or the bearer key.
    async fn credential(&self, config: &Config) -> Result<(), String>;
    /// One authenticated call to the broker.
    async fn accepted(&self, config: &Config) -> Result<(), CallError>;
    /// How git is set up to sign, as git itself reads it.
    fn git_signing(&self) -> GitSigning;
    /// What the broker says about signing for this agent.
    async fn signing_state(&self, config: &Config) -> Result<SigningState, CallError>;
}

/// Git's settings for signing, each unset if `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitSigning {
    /// `gpg.ssh.program`.
    pub program: Option<String>,
    /// `gpg.format`.
    pub format: Option<String>,
    /// `user.signingkey`.
    pub key: Option<String>,
    /// `commit.gpgsign`.
    pub sign_commits: Option<String>,
}

/// What the broker says about signing for this agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningState {
    /// Whether this agent has an active grant.
    pub grant_active: bool,
    /// The broker's public key. Only an agent with an active grant can ask.
    pub public_key: Option<String>,
}

/// The real probes.
pub struct Live;

impl Probes for Live {
    fn config(&self) -> Result<Config, String> {
        config::load().map_err(|e| describe_config_error(&e))
    }

    async fn info(&self, server: &Url) -> Result<InfoResponse, CallError> {
        fetch_info(server).await
    }

    async fn credential(&self, config: &Config) -> Result<(), String> {
        let describe = |e: Error| format!("{e:#}");
        match config.signer().map_err(describe)? {
            Some(signer) => signer.check_key_loaded().await.map_err(describe),
            None => config::agent_key(config).map(drop).map_err(describe),
        }
    }

    async fn accepted(&self, config: &Config) -> Result<(), CallError> {
        let client =
            Client::for_config(config).map_err(|e| CallError::Refused(format!("{e:#}")))?;
        // The key is only here so that an echo of it can be removed: a
        // key-signed agent has none.
        let key = if config.ssh_key.is_none() {
            config::agent_key(config).ok()
        } else {
            None
        };
        client
            .grants()
            .await
            .map(drop)
            .map_err(|e| without_key(e, key.as_ref()))
    }

    fn git_signing(&self) -> GitSigning {
        let value = |name: &str| current_value(name).ok().flatten();
        GitSigning {
            program: value("gpg.ssh.program"),
            format: value("gpg.format"),
            key: value("user.signingkey"),
            sign_commits: value("commit.gpgsign"),
        }
    }

    async fn signing_state(&self, config: &Config) -> Result<SigningState, CallError> {
        let client =
            Client::for_config(config).map_err(|e| CallError::Refused(format!("{e:#}")))?;
        let grant_active = client
            .grants()
            .await?
            .iter()
            .any(|grant| matches!(grant.access, GrantAccess::CommitSigning(_)));
        let public_key = if grant_active {
            Some(client.commit_signing_key().await?.public_key)
        } else {
            None
        };
        Ok(SigningState {
            grant_active,
            public_key,
        })
    }
}

/// The text of a failure to load the configuration. A parse error's text quotes
/// the file, which is not meant to hold a secret but may by mistake.
fn describe_config_error(e: &Error) -> String {
    if e.chain()
        .any(<dyn std::error::Error>::is::<toml::de::Error>)
    {
        return "the configuration file cannot be parsed".to_owned();
    }
    format!("{e:#}")
}

/// `error` with any echo of the bearer key removed.
fn without_key(error: CallError, key: Option<&Zeroizing<String>>) -> CallError {
    let Some(key) = key else {
        return error;
    };
    let clean = |message: String| message.replace(key.as_str(), REDACTED);
    match error {
        CallError::Unavailable(m) => CallError::Unavailable(clean(m)),
        CallError::Refused(m) => CallError::Refused(clean(m)),
        CallError::Revoked(m) => CallError::Revoked(clean(m)),
        CallError::Expired(m) => CallError::Expired(clean(m)),
        CallError::CallStopped(m) => CallError::CallStopped(clean(m)),
    }
}

/// Run every check.
pub async fn examine(probes: &impl Probes) -> Report {
    Report {
        title: "warden doctor".to_owned(),
        checks: checks(probes).await,
        effects: "Read only: changed nothing on this machine. The broker saw an unauthenticated \
                  GET /v1/info and, if the credential is available, authenticated GET /v1/grants \
                  calls and, if git signs through warden, GET /v1/commit-signing/key."
            .to_owned(),
    }
}

async fn checks(probes: &impl Probes) -> Vec<Check> {
    let config = match probes.config() {
        Ok(config) => config,
        Err(reason) => {
            let mut checks = vec![Check::fail(
                "config",
                reason,
                "Run `warden login` (docs/agent-usage.md, \"One-time setup\").",
            )];
            for name in [
                "server.reachable",
                "audience",
                "credential",
                "broker.accepts-agent",
                GIT_SIGNING,
            ] {
                checks.push(Check::could_not_check(
                    name,
                    "Not checked: there is no usable configuration.",
                    FIX_EARLIER,
                ));
            }
            checks.push(version_check());
            return checks;
        }
    };
    let mut checks = vec![Check::pass(
        "config",
        format!("Agent {} at {}.", config.agent, config.server),
    )];
    let info = probes.info(&config.server).await;
    checks.push(match &info {
        Ok(_) => Check::pass("server.reachable", "The broker answered GET /v1/info."),
        Err(e) => Check::fail(
            "server.reachable",
            e.to_string(),
            "Check the URL, that this machine is on the tailnet, and that the tailnet policy \
             lets it reach the agent API.",
        ),
    });
    let info = info.ok();
    checks.push(audience_check(&config, info.as_ref()));
    if config.ssh_key.is_some()
        && let Some(info) = &info
    {
        checks.push(protocol_check(info));
    }
    let credential = probes.credential(&config).await;
    checks.push(credential_check(&config, credential.as_ref().err()));
    checks.push(if credential.is_ok() {
        accepted_check(&config, probes.accepted(&config).await)
    } else {
        Check::could_not_check(
            "broker.accepts-agent",
            "Not checked: the credential is not available.",
            FIX_EARLIER,
        )
    });
    let git = probes.git_signing();
    let state = if through_warden(&git) && credential.is_ok() {
        Some(probes.signing_state(&config).await)
    } else {
        None
    };
    checks.push(git_signing_check(&git, state));
    checks.push(version_check());
    checks
}

/// Whether git is set to sign through warden.
fn through_warden(git: &GitSigning) -> bool {
    git.program.as_deref().is_some_and(|program| {
        std::path::Path::new(program)
            .file_name()
            .is_some_and(|name| name == "warden")
    })
}

/// The check of git's signing setup: if it goes through warden, that all of it is
/// right, and that commits will work now. `state` is `None` when the broker was not
/// asked.
fn git_signing_check(git: &GitSigning, state: Option<Result<SigningState, CallError>>) -> Check {
    const SETUP: &str = "Run `warden setup git`.";
    if !through_warden(git) {
        return Check::pass(
            GIT_SIGNING,
            "Git does not sign through warden here; `warden setup git` would set that up.",
        );
    }
    if git.format.as_deref() != Some("ssh") {
        return Check::fail(GIT_SIGNING, "gpg.format is not ssh.", SETUP);
    }
    if git.sign_commits.as_deref() != Some("true") {
        return Check::fail(GIT_SIGNING, "commit.gpgsign is not on.", SETUP);
    }
    let state = match state {
        None => {
            return Check::could_not_check(
                GIT_SIGNING,
                "Not checked: the credential is not available.",
                FIX_EARLIER,
            );
        }
        Some(Err(CallError::Unavailable(reason) | CallError::CallStopped(reason))) => {
            return Check::could_not_check(
                GIT_SIGNING,
                reason,
                "Get the broker answering, then run doctor again. Commits fail until it does.",
            );
        }
        Some(Err(e)) => {
            return Check::fail(
                GIT_SIGNING,
                e.to_string(),
                "Ask the owner whether commit signing is configured on the broker.",
            );
        }
        Some(Ok(state)) => state,
    };
    let Some(public_key) = state.public_key.filter(|_| state.grant_active) else {
        return Check::fail(
            GIT_SIGNING,
            "This agent has no active commit signing grant, so `git commit` fails.",
            "Ask the owner: warden request signing --goal \"<why this agent commits>\"",
        );
    };
    if git.key.as_deref() != Some(format!("key::{public_key}").as_str()) {
        return Check::fail(
            GIT_SIGNING,
            "user.signingkey is not the key the broker signs with, so commits fail.",
            SETUP,
        );
    }
    Check::pass(
        GIT_SIGNING,
        "Git signs through warden, and this agent has an active grant.",
    )
}

fn audience_check(config: &Config, info: Option<&InfoResponse>) -> Check {
    const NAME: &str = "audience";
    let Some(ssh_key) = &config.ssh_key else {
        return Check::could_not_check(
            NAME,
            "A bearer-key agent pins no audience, so nothing here tells this broker from another.",
            "Move to a signing key: `warden login --ssh-key` (docs/agent-usage.md). Until then, \
             confirm the server URL with the owner.",
        );
    };
    let Some(info) = info else {
        return Check::could_not_check(
            NAME,
            format!(
                "Not checked: the broker did not answer. Pinned: {}.",
                ssh_key.audience
            ),
            FIX_EARLIER,
        );
    };
    if info.audience == ssh_key.audience {
        Check::pass(
            NAME,
            format!(
                "The broker reports the pinned audience {}.",
                ssh_key.audience
            ),
        )
    } else {
        Check::fail(
            NAME,
            format!(
                "The broker reports audience {}, but {} is pinned: this is another broker, or its \
                 data was reset.",
                info.audience, ssh_key.audience
            ),
            format!(
                "Ask the owner which is right. Only then run `warden login` again with \
                 --audience {}.",
                info.audience
            ),
        )
    }
}

fn protocol_check(info: &InfoResponse) -> Check {
    const NAME: &str = "protocol";
    if info.protocols.iter().any(|p| p == PROTOCOL) {
        Check::pass(NAME, format!("The broker accepts {PROTOCOL}."))
    } else {
        Check::fail(
            NAME,
            format!("The broker does not accept signed requests ({PROTOCOL})."),
            "Ask the owner to upgrade the broker to 0.6 or later.",
        )
    }
}

fn credential_check(config: &Config, problem: Option<&String>) -> Check {
    let (name, available, action) = if config.ssh_key.is_some() {
        (
            "ssh-agent.key",
            "The ssh-agent holds the signing key.",
            "Load the key (`ssh-add -L` lists what the agent holds), and check SSH_AUTH_SOCK or \
             --ssh-agent-socket.",
        )
    } else {
        (
            "bearer-key",
            "The bearer key is available.",
            "Set WARDEN_AGENT_KEY, or on macOS run `warden login` to store it in the Keychain.",
        )
    };
    match problem {
        None => Check::pass(name, available),
        Some(reason) => Check::fail(name, reason.as_str(), action),
    }
}

fn accepted_check(config: &Config, accepted: Result<(), CallError>) -> Check {
    const NAME: &str = "broker.accepts-agent";
    match accepted {
        Ok(()) => Check::pass(
            NAME,
            format!(
                "The broker accepted an authenticated call from {}.",
                config.agent
            ),
        ),
        // Unreachable or failing on its side: the broker gave no verdict.
        Err(CallError::Unavailable(reason) | CallError::CallStopped(reason)) => {
            Check::could_not_check(
                NAME,
                reason,
                "Get the broker answering, then run doctor again.",
            )
        }
        Err(
            CallError::Refused(reason) | CallError::Revoked(reason) | CallError::Expired(reason),
        ) => Check::fail(
            NAME,
            reason,
            format!(
                "Ask the owner to check `warden-server agent list` for {} and its key.",
                config.agent
            ),
        ),
    }
}

fn version_check() -> Check {
    Check::could_not_check(
        "version",
        format!(
            "This CLI is {}. The broker does not publish its version.",
            env!("CARGO_PKG_VERSION")
        ),
        "Ask the owner to run `warden-server --version`; use the same release on both sides.",
    )
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::future::ready;

    use anyhow::{Context as _, anyhow};
    use url::Url;
    use warden_broker_proto::InfoResponse;
    use warden_broker_proto::doctor::{
        Check, EXIT_COULD_NOT_CHECK, EXIT_FAILED, EXIT_NOTHING_FAILED, Report, Status,
    };
    use warden_broker_proto::signing::{Audience, PROTOCOL};
    use zeroize::Zeroizing;

    use super::{
        GIT_SIGNING, GitSigning, Probes, SigningState, describe_config_error, examine,
        git_signing_check, without_key,
    };
    use crate::client::CallError;
    use crate::config::{Config, SshKeyConfig};

    const PINNED: &str = "40ad20029e94984d193159667b296d8a";
    const OTHER: &str = "50ad20029e94984d193159667b296d8b";

    fn audience(id: &str) -> Audience {
        Audience::try_from(id.to_owned()).unwrap()
    }

    fn config(signed: bool) -> Config {
        Config {
            server: Url::parse("https://warden.example.ts.net/").unwrap(),
            agent: "build-agent".to_owned().try_into().unwrap(),
            ssh_key: signed.then(|| SshKeyConfig {
                public_key: "ssh-ed25519 AAAA".to_owned(),
                agent_socket: None,
                audience: audience(PINNED),
            }),
        }
    }

    fn info(id: &str, protocols: &[&str]) -> InfoResponse {
        InfoResponse {
            protocols: protocols.iter().map(|p| (*p).to_owned()).collect(),
            audience: audience(id),
        }
    }

    /// Everything fine for a key-signed agent, unless a test changes a field.
    struct Fake {
        config: Result<Config, String>,
        info: Result<InfoResponse, CallError>,
        credential: Result<(), String>,
        accepted: Result<(), CallError>,
        called_accepted: Cell<bool>,
    }

    impl Fake {
        fn healthy() -> Self {
            Self {
                config: Ok(config(true)),
                info: Ok(info(PINNED, &[PROTOCOL])),
                credential: Ok(()),
                accepted: Ok(()),
                called_accepted: Cell::new(false),
            }
        }
    }

    impl Probes for Fake {
        fn config(&self) -> Result<Config, String> {
            self.config.clone()
        }

        fn info(&self, _server: &Url) -> impl Future<Output = Result<InfoResponse, CallError>> {
            ready(self.info.clone())
        }

        fn credential(&self, _config: &Config) -> impl Future<Output = Result<(), String>> {
            ready(self.credential.clone())
        }

        fn git_signing(&self) -> GitSigning {
            GitSigning::default()
        }

        fn signing_state(
            &self,
            _config: &Config,
        ) -> impl Future<Output = Result<SigningState, CallError>> {
            ready(Err(CallError::Unavailable("not asked here".to_owned())))
        }

        fn accepted(&self, _config: &Config) -> impl Future<Output = Result<(), CallError>> {
            self.called_accepted.set(true);
            ready(self.accepted.clone())
        }
    }

    fn set_up() -> GitSigning {
        GitSigning {
            program: Some("/opt/bin/warden".to_owned()),
            format: Some("ssh".to_owned()),
            key: Some("key::ssh-ed25519 AAAA".to_owned()),
            sign_commits: Some("true".to_owned()),
        }
    }

    fn healthy_state() -> SigningState {
        SigningState {
            grant_active: true,
            public_key: Some("ssh-ed25519 AAAA".to_owned()),
        }
    }

    #[test]
    fn git_that_does_not_sign_through_warden_is_fine() {
        let mut other = GitSigning::default();
        assert_eq!(
            git_signing_check(&other, None).status,
            Status::Pass,
            "not set up"
        );
        other.program = Some("/usr/bin/ssh-keygen".to_owned());
        assert_eq!(git_signing_check(&other, None).status, Status::Pass);
    }

    #[test]
    fn git_set_up_with_a_grant_passes() {
        assert_eq!(
            git_signing_check(&set_up(), Some(Ok(healthy_state()))).status,
            Status::Pass
        );
        assert_eq!(
            git_signing_check(&set_up(), Some(Ok(healthy_state()))).name,
            GIT_SIGNING
        );
    }

    #[test]
    fn every_way_commits_would_fail_is_a_failure() {
        let mut wrong_format = set_up();
        wrong_format.format = None;
        let mut not_on = set_up();
        not_on.sign_commits = Some("false".to_owned());
        let mut wrong_key = set_up();
        wrong_key.key = Some("key::ssh-ed25519 BBBB".to_owned());
        for git in [wrong_format, not_on, wrong_key] {
            assert_eq!(
                git_signing_check(&git, Some(Ok(healthy_state()))).status,
                Status::Fail,
                "{git:?}"
            );
        }
        let no_grant = Some(Ok(SigningState {
            grant_active: false,
            public_key: None,
        }));
        let check = git_signing_check(&set_up(), no_grant);
        assert_eq!(check.status, Status::Fail);
        assert!(check.detail.contains("no active commit signing grant"));
        let refused = Some(Err(CallError::Refused("not configured".to_owned())));
        assert_eq!(git_signing_check(&set_up(), refused).status, Status::Fail);
    }

    #[test]
    fn a_broker_that_gave_no_answer_is_not_a_verdict() {
        let out = Some(Err(CallError::Unavailable("down".to_owned())));
        assert_eq!(
            git_signing_check(&set_up(), out).status,
            Status::CouldNotCheck
        );
        assert_eq!(
            git_signing_check(&set_up(), None).status,
            Status::CouldNotCheck
        );
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

    #[tokio::test]
    async fn a_healthy_key_signed_agent_passes_all_but_the_version() {
        let report = examine(&Fake::healthy()).await;
        for c in &report.checks {
            let expected = if c.name == "version" {
                Status::CouldNotCheck
            } else {
                Status::Pass
            };
            assert_eq!(c.status, expected, "{c:?}");
        }
        assert_eq!(report.exit_code(false), EXIT_NOTHING_FAILED);
        assert_eq!(report.exit_code(true), EXIT_COULD_NOT_CHECK);
        assert!(report.effects.contains("changed nothing"), "{report:?}");
    }

    #[tokio::test]
    async fn no_configuration_fails_and_nothing_else_looks_like_it_ran() {
        let report = examine(&Fake {
            config: Err("no file".to_owned()),
            ..Fake::healthy()
        })
        .await;
        assert_eq!(status(&report, "config"), Status::Fail);
        for c in &report.checks[1..] {
            assert_eq!(c.status, Status::CouldNotCheck, "{c:?}");
        }
        assert_eq!(report.exit_code(false), EXIT_FAILED);
        assert_eq!(report.exit_code(true), EXIT_FAILED);
    }

    #[tokio::test]
    async fn an_unreachable_server_fails_and_the_pin_could_not_be_checked() {
        let fake = Fake {
            info: Err(CallError::Unavailable("no route".to_owned())),
            accepted: Err(CallError::Unavailable("no route".to_owned())),
            ..Fake::healthy()
        };
        let report = examine(&fake).await;
        assert_eq!(status(&report, "server.reachable"), Status::Fail);
        assert_eq!(status(&report, "audience"), Status::CouldNotCheck);
        assert!(!report.checks.iter().any(|c| c.name == "protocol"));
        assert_eq!(
            status(&report, "broker.accepts-agent"),
            Status::CouldNotCheck
        );
    }

    #[tokio::test]
    async fn another_audience_fails_and_names_both() {
        let report = examine(&Fake {
            info: Ok(info(OTHER, &[PROTOCOL])),
            ..Fake::healthy()
        })
        .await;
        let c = check(&report, "audience");
        assert_eq!(c.status, Status::Fail);
        assert!(
            c.detail.contains(PINNED) && c.detail.contains(OTHER),
            "{c:?}"
        );
    }

    #[tokio::test]
    async fn a_bearer_agent_pins_nothing_so_the_audience_could_not_be_checked() {
        let report = examine(&Fake {
            config: Ok(config(false)),
            ..Fake::healthy()
        })
        .await;
        assert_eq!(status(&report, "audience"), Status::CouldNotCheck);
        assert_eq!(status(&report, "bearer-key"), Status::Pass);
        assert!(!report.checks.iter().any(|c| c.name == "protocol"));
        assert!(!report.checks.iter().any(|c| c.name == "ssh-agent.key"));
    }

    #[tokio::test]
    async fn a_broker_without_the_signing_protocol_fails() {
        let report = examine(&Fake {
            info: Ok(info(PINNED, &["something-else"])),
            ..Fake::healthy()
        })
        .await;
        assert_eq!(status(&report, "protocol"), Status::Fail);
    }

    #[tokio::test]
    async fn a_key_missing_from_the_agent_fails_and_no_signed_call_is_tried() {
        let fake = Fake {
            credential: Err("does not hold the key".to_owned()),
            ..Fake::healthy()
        };
        let report = examine(&fake).await;
        assert_eq!(status(&report, "ssh-agent.key"), Status::Fail);
        assert_eq!(
            status(&report, "broker.accepts-agent"),
            Status::CouldNotCheck
        );
        assert!(!fake.called_accepted.get());
    }

    #[tokio::test]
    async fn a_missing_bearer_key_fails() {
        let report = examine(&Fake {
            config: Ok(config(false)),
            credential: Err("no key".to_owned()),
            ..Fake::healthy()
        })
        .await;
        assert_eq!(status(&report, "bearer-key"), Status::Fail);
    }

    #[tokio::test]
    async fn the_broker_refusing_fails_and_it_failing_could_not_be_checked() {
        let refused = examine(&Fake {
            accepted: Err(CallError::Refused("401".to_owned())),
            ..Fake::healthy()
        })
        .await;
        assert_eq!(status(&refused, "broker.accepts-agent"), Status::Fail);
        let failing = examine(&Fake {
            accepted: Err(CallError::Unavailable("503".to_owned())),
            ..Fake::healthy()
        })
        .await;
        assert_eq!(
            status(&failing, "broker.accepts-agent"),
            Status::CouldNotCheck
        );
    }

    #[tokio::test]
    async fn the_version_is_never_inferred() {
        for fake in [
            Fake::healthy(),
            Fake {
                info: Err(CallError::Unavailable("down".to_owned())),
                ..Fake::healthy()
            },
        ] {
            let report = examine(&fake).await;
            let c = check(&report, "version");
            assert_eq!(c.status, Status::CouldNotCheck);
            assert!(c.detail.contains(env!("CARGO_PKG_VERSION")), "{c:?}");
        }
    }

    #[test]
    fn a_bearer_key_the_broker_echoes_is_removed() {
        let key = format!("wdn_{}", "S".repeat(43));
        let echo = CallError::Refused(format!("broker refused: bad key {key}"));
        let clean = without_key(echo, Some(&Zeroizing::new(key.clone())));
        assert!(!clean.to_string().contains(&key), "{clean}");
        assert!(clean.to_string().contains("[REDACTED]"), "{clean}");
    }

    #[test]
    fn a_parse_error_never_quotes_the_configuration_file() {
        let secret = "wdn_pasted_by_mistake";
        let raw = format!("server = {secret}\n");
        let parse = toml::from_str::<Config>(&raw).unwrap_err();
        assert!(parse.to_string().contains(secret), "the premise changed");
        let error = anyhow::Error::new(parse).context("cannot load the file");
        let text = describe_config_error(&error);
        assert!(!text.contains(secret), "{text}");
    }

    #[test]
    fn other_configuration_errors_keep_their_context() {
        let result: anyhow::Result<()> = Err(anyhow!("no such file"));
        let error = result.context("cannot load config.toml").unwrap_err();
        let text = describe_config_error(&error);
        assert!(
            text.contains("config.toml") && text.contains("no such file"),
            "{text}"
        );
    }
}
