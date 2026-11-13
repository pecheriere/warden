//! `warden list`: what this agent may ask the broker for.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::Result;
use serde_json::json;
use warden_broker_proto::doctor::sanitize;
use warden_broker_proto::offers::{
    ApiSecretOffer, GithubTokenStatus, OfferPart, Offers, ReleaseStatus, RepositoryOffer,
    SshModeName, SshTargetOffer,
};
use warden_broker_proto::release::RepoName;

use crate::client::{CallError, Client};
use crate::github_repo;
use crate::{EXIT_ERROR, EXIT_USAGE, Exit};

/// The repository of the checkout in `dir`, if its origin is on GitHub. Never prints.
#[must_use]
pub fn checkout_repository(dir: &Path) -> Option<RepoName> {
    github_repo::origin_url(dir).and_then(|url| github_repo::from_remote_url(&url))
}

/// `warden list`.
pub async fn run(as_json: bool, repo: Option<String>) -> Result<()> {
    let repo = match repo {
        Some(value) => Some(
            github_repo::from_gh_value(&value)
                .map_err(|e| Exit::new(EXIT_USAGE, format!("--repo: {e}")))?,
        ),
        None => std::env::current_dir()
            .ok()
            .and_then(|dir| checkout_repository(&dir)),
    };
    let (_, client) = crate::client()?;
    let (offers, repository) = fetch(&client, repo.as_ref()).await?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json_output(&offers, repository.as_ref()))?
        );
    } else {
        print!("{}", render(&offers, repository.as_ref()));
    }
    Ok(())
}

/// What `--json` prints.
fn json_output(offers: &Offers, repository: Option<&RepositoryOffer>) -> serde_json::Value {
    json!({ "offers": offers, "repository": repository })
}

/// What the broker offers, and what it offers for `repo`. A broker without the
/// route is an error that says to upgrade it.
async fn fetch(
    client: &Client,
    repo: Option<&RepoName>,
) -> Result<(Offers, Option<RepositoryOffer>)> {
    let offers = client
        .offers()
        .await
        .map_err(|e| failed(&e))?
        .ok_or_else(too_old)?;
    let repository = match repo {
        Some(repo) => client
            .repository_offer(repo)
            .await
            .map_err(|e| failed(&e))?,
        None => None,
    };
    Ok((offers, repository))
}

fn failed(error: &CallError) -> Exit {
    Exit::new(EXIT_ERROR, error.to_string())
}

fn too_old() -> Exit {
    Exit::new(
        EXIT_ERROR,
        format!(
            "this broker is too old to list what it offers; upgrade it to {}",
            env!("CARGO_PKG_VERSION")
        ),
    )
}

/// Text for a person or an agent; sections with nothing in them are left out.
/// Everything the broker supplied is made safe to print.
#[must_use]
pub fn render(offers: &Offers, repo: Option<&RepositoryOffer>) -> String {
    let mut out = String::new();
    let unreadable = |part| offers.unavailable.contains(&part);

    if unreadable(OfferPart::SshTargets) {
        out.push_str("SSH targets: could not be read\n");
    } else if !offers.ssh_targets.is_empty() {
        out.push_str("SSH targets:\n");
        for target in &offers.ssh_targets {
            let _ = writeln!(out, "  {}", ssh_line(target));
        }
    }
    if unreadable(OfferPart::ApiSecrets) {
        out.push_str("API secrets: could not be read\n");
    } else if !offers.api_secrets.is_empty() {
        out.push_str("API secrets:\n");
        for secret in &offers.api_secrets {
            let _ = writeln!(out, "  {}", api_line(secret));
        }
    }
    if unreadable(OfferPart::Github) {
        out.push_str("GitHub tokens: could not be read\n");
    } else if offers.github.configured {
        let _ = match offers.github.max_window {
            Some(window) => writeln!(out, "GitHub tokens: available, up to {}", window.label()),
            None => writeln!(out, "GitHub tokens: available"),
        };
    }
    if unreadable(OfferPart::CommitSigning) {
        out.push_str("Commit signing: could not be read\n");
    } else if offers.commit_signing.available {
        out.push_str("Commit signing: available\n");
    }
    if unreadable(OfferPart::Releases) {
        out.push_str("Releases: could not be read\n");
    } else if offers.releases.available {
        out.push_str("Releases: available\n");
    }
    if let Some(repo) = repo {
        let _ = writeln!(out, "This repository ({}):", repo.repository);
        let _ = writeln!(out, "  GitHub tokens: {}", token_text(repo.github_token));
        let _ = writeln!(
            out,
            "  Commit signing: {}",
            if repo.commit_signing {
                "available"
            } else {
                "not available"
            }
        );
        let _ = writeln!(out, "  Releases: {}", release_text(repo.release));
    }
    if out.is_empty() {
        out.push_str("The broker offers this agent nothing.\n");
    }
    out
}

const fn mode_text(mode: SshModeName) -> &'static str {
    match mode {
        SshModeName::Cert => "cert",
        SshModeName::Relay => "relay",
    }
}

fn ssh_line(target: &SshTargetOffer) -> String {
    let users: Vec<String> = target.users.iter().map(ToString::to_string).collect();
    let mut line = format!(
        "{}: users {}, up to {}, {}",
        target.name,
        users.join(", "),
        target.max_window.label(),
        mode_text(target.mode)
    );
    if let Some(destination) = &target.destination {
        let host = sanitize(&destination.host);
        let _ = if host.contains(':') {
            write!(line, ", [{host}]:{}", destination.port)
        } else {
            write!(line, ", {host}:{}", destination.port)
        };
    }
    line
}

fn api_line(secret: &ApiSecretOffer) -> String {
    let mut line = format!(
        "{}: {} under {}, up to {}",
        secret.name,
        sanitize(&secret.methods.join(", ")),
        sanitize(&secret.path_prefix),
        secret.max_window.label()
    );
    if let Some(origin) = &secret.origin {
        let _ = write!(line, ", {}", sanitize(origin));
    }
    line
}

const fn token_text(status: GithubTokenStatus) -> &'static str {
    match status {
        GithubTokenStatus::Covered => "the GitHub App covers it",
        GithubTokenStatus::NotCovered => "the GitHub App does not cover it",
        GithubTokenStatus::NotConfigured => "no GitHub App is configured",
        GithubTokenStatus::Unavailable => "could not be read",
    }
}

const fn release_text(status: ReleaseStatus) -> &'static str {
    match status {
        ReleaseStatus::Ready => "ready",
        ReleaseStatus::NoKey => "no release signing key names it",
        ReleaseStatus::NoReleaseApp => "no release App is configured",
        ReleaseStatus::Unavailable => "could not be read",
    }
}

#[cfg(test)]
mod tests;
