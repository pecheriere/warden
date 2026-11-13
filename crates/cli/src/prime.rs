//! `warden prime`: instructions for an agent, from the copy of
//! `docs/agent-instructions.md` built into this CLI, with what the broker
//! offers. It informs and exits 0 whatever the broker does: a session-start
//! hook that failed would hide the rule that matters most when the broker is
//! down.

mod template;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::time::{Instant, timeout_at};
use warden_broker_proto::offers::{OfferPart, Offers, RepositoryOffer};
use warden_broker_proto::release::RepoName;

use crate::client::{CallError, Client};
use crate::{config, list};
use template::{DOC, Section, Template};

/// How long the offers calls get in all, connecting and answer included.
pub const OFFERS_TIMEOUT: Duration = Duration::from_secs(3);

/// All `prime` prints when `warden login` was never run.
const NOT_SET_UP: &str =
    "warden is installed here but not set up: `warden login` has not been run.";
const UNREACHABLE: &str =
    "warden: the broker cannot be reached: run `warden doctor`, and do not go around it.";
const REFUSED: &str =
    "warden: the broker refused this agent's login: run `warden doctor`, and do not go around it.";
const UNUSABLE: &str = "warden: the configuration here cannot be used: run `warden doctor`, and \
                        do not go around it.";

/// What this machine's configuration allows.
enum Setup {
    /// No configuration: `warden login` was never run.
    NotSetUp,
    /// A configuration that cannot be read or used.
    Unusable,
    Ready(Client),
}

/// The setup from the configuration at `path`.
fn setup_from(path: anyhow::Result<PathBuf>) -> Setup {
    match path.and_then(|path| config::load_existing_from(&path)) {
        Ok(None) => Setup::NotSetUp,
        Ok(Some(config)) => Client::for_config(&config).map_or(Setup::Unusable, Setup::Ready),
        Err(_) => Setup::Unusable,
    }
}

/// What the broker said, or the line saying why it said nothing usable.
enum Answer {
    Offered(Offers, Option<RepositoryOffer>),
    Missing(String),
}

/// `warden prime`. Prints the instructions; nothing here fails, so the
/// command always exits 0.
pub async fn run(brief: bool) {
    let dir = std::env::current_dir().ok();
    let setup = setup_from(config::config_path());
    print!(
        "{}",
        output(setup, dir.as_deref(), brief, OFFERS_TIMEOUT).await
    );
}

/// The text for `setup`, run in `dir`: the brief section with `brief`,
/// otherwise the full text with the answer about `dir`'s GitHub repository.
/// The broker gets `limit` in all.
async fn output(setup: Setup, dir: Option<&Path>, brief: bool, limit: Duration) -> String {
    let answer = match setup {
        Setup::NotSetUp => return format!("{NOT_SET_UP}\n"),
        Setup::Unusable => Answer::Missing(UNUSABLE.to_owned()),
        Setup::Ready(client) => {
            let repo = if brief {
                None
            } else {
                dir.and_then(list::checkout_repository)
            };
            ask(&client, repo.as_ref(), limit).await
        }
    };
    let template = match Template::parse(DOC) {
        Ok(template) => template,
        // The tests parse the built-in document, so only a broken build gets here.
        Err(e) => {
            return format!(
                "warden: the instructions built into this CLI cannot be read ({e}). Never use \
                 other credentials, and never look for another way in.\n"
            );
        }
    };
    match answer {
        Answer::Offered(offers, _) if brief => template.brief(&brief_offers(&offers)),
        Answer::Offered(offers, repository) => {
            template.full(&kept(&offers), &list::render(&offers, repository.as_ref()))
        }
        Answer::Missing(reason) if brief => template.brief(&reason),
        Answer::Missing(reason) => template.full(&Section::ALL.into(), &reason),
    }
}

/// Asks the broker what it offers, and what it offers for `repo`, all within
/// `limit`. Past it, the broker counts as unreachable; a repository answer that
/// does not come in time, or fails, is left out.
async fn ask(client: &Client, repo: Option<&RepoName>, limit: Duration) -> Answer {
    let deadline = Instant::now() + limit;
    let offers = match timeout_at(deadline, client.offers()).await {
        Ok(Ok(Some(offers))) => offers,
        Ok(Ok(None)) => return Answer::Missing(format!("warden: {}.", list::too_old_message())),
        Ok(Err(CallError::Unavailable(_))) | Err(_) => {
            return Answer::Missing(UNREACHABLE.to_owned());
        }
        Ok(Err(_)) => return Answer::Missing(REFUSED.to_owned()),
    };
    let repository = match repo {
        Some(repo) => timeout_at(deadline, client.repository_offer(repo))
            .await
            .ok()
            .and_then(Result::ok)
            .flatten(),
        None => None,
    };
    Answer::Offered(offers, repository)
}

/// The sections for what the broker offers, or might: a part it could not
/// read keeps its section.
fn kept(offers: &Offers) -> HashSet<Section> {
    let unknown = |part| offers.unavailable.contains(&part);
    [
        (
            Section::Ssh,
            unknown(OfferPart::SshTargets) || !offers.ssh_targets.is_empty(),
        ),
        (
            Section::Api,
            unknown(OfferPart::ApiSecrets) || !offers.api_secrets.is_empty(),
        ),
        (
            Section::Github,
            unknown(OfferPart::Github) || offers.github.configured,
        ),
        (
            Section::Signing,
            unknown(OfferPart::CommitSigning) || offers.commit_signing.available,
        ),
        (
            Section::Release,
            unknown(OfferPart::Releases) || offers.releases.available,
        ),
    ]
    .into_iter()
    .filter_map(|(section, offered)| offered.then_some(section))
    .collect()
}

/// One line per kind offered, with names only: no destinations, windows or
/// paths. Names are validated, so they are safe to print as they are.
fn brief_offers(offers: &Offers) -> String {
    let unreadable = |part| offers.unavailable.contains(&part);
    let mut lines = Vec::new();
    if unreadable(OfferPart::SshTargets) {
        lines.push("SSH: could not be read".to_owned());
    } else if !offers.ssh_targets.is_empty() {
        let targets: Vec<String> = offers
            .ssh_targets
            .iter()
            .map(|target| {
                let users: Vec<String> = target.users.iter().map(ToString::to_string).collect();
                format!("{} ({})", target.name, users.join(", "))
            })
            .collect();
        lines.push(format!("SSH: {}", targets.join(", ")));
    }
    if unreadable(OfferPart::ApiSecrets) {
        lines.push("API: could not be read".to_owned());
    } else if !offers.api_secrets.is_empty() {
        let names: Vec<String> = offers
            .api_secrets
            .iter()
            .map(|secret| secret.name.to_string())
            .collect();
        lines.push(format!("API: {}", names.join(", ")));
    }
    for (part, on, label) in [
        (OfferPart::Github, offers.github.configured, "GitHub tokens"),
        (
            OfferPart::CommitSigning,
            offers.commit_signing.available,
            "Commit signing",
        ),
        (OfferPart::Releases, offers.releases.available, "Releases"),
    ] {
        if unreadable(part) {
            lines.push(format!("{label}: could not be read"));
        } else if on {
            lines.push(format!("{label}: on"));
        }
    }
    if lines.is_empty() {
        list::NOTHING.to_owned()
    } else {
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests;
