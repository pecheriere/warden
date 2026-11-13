//! `GET /v1/offers`: what this agent may ask for.
//!
//! It decides no access, asks no one, creates no request and is not an audited
//! request: the audit log records decisions and grants. Every source is read fresh
//! from the backend. A source that cannot be read is named in `unavailable` and the
//! rest of the answer stands; only when no source can be read is the answer the
//! `BACKEND_UNAVAILABLE` error the other agent calls give.
//!
//! The listing view of a target or secret has no field for a host key, a relay
//! credential or a secret value, so none of them can reach the response.

use axum::Json;
use axum::extract::State;
use warden_broker_proto::offers::{
    ApiSecretOffer, Availability, Destination, GithubOffer, OfferPart, Offers, SshModeName,
    SshTargetOffer,
};

use super::Failure;
use crate::AppState;
use crate::identity::AuthedAgent;
use crate::policy::{ApiSecretPolicy, PolicyError, SshMode, SshTarget};
use crate::requests::RequestError;

/// How many parts [`Offers`] reads from the backend.
const PARTS: usize = 5;

pub(super) async fn list(
    State(state): State<AppState>,
    AuthedAgent(agent): AuthedAgent,
) -> Result<Json<Offers>, Failure> {
    let backend = &state.backend;
    let mut read = Reads::default();

    let ssh_targets = read.of(
        OfferPart::SshTargets,
        backend.list_ssh_targets().await.map(|t| ssh_offers(&t)),
    );
    let api_secrets = read.of(
        OfferPart::ApiSecrets,
        backend.list_api_secrets().await.map(|s| api_offers(&s)),
    );
    let github = read.of(OfferPart::Github, backend.has_github_app().await);
    let signing = read.of(
        OfferPart::CommitSigning,
        backend.has_commit_signing_key().await,
    );
    // Releases need both a signing key and a release App; either read failing
    // leaves the answer unknown.
    let releases = read.of(
        OfferPart::Releases,
        match (
            backend.has_release_signing().await,
            backend.has_release_app().await,
        ) {
            (Ok(key), Ok(app)) => Ok(key && app),
            (Err(e), _) | (_, Err(e)) => Err(e),
        },
    );

    if read.unavailable.len() == PARTS {
        return Err(Failure::Request(RequestError::Unavailable(
            read.details.join("; "),
        )));
    }
    for detail in &read.details {
        tracing::warn!(error = %detail, "an offers source could not be read");
    }
    let unavailable = read.unavailable;

    let configured = github.unwrap_or(false);
    tracing::info!(agent = %agent, "offers listed");
    Ok(Json(Offers {
        ssh_targets: ssh_targets.unwrap_or_default(),
        api_secrets: api_secrets.unwrap_or_default(),
        github: GithubOffer {
            configured,
            max_window: configured.then(|| state.requests.github_token_max()),
        },
        commit_signing: Availability {
            available: signing.unwrap_or(false),
        },
        releases: Availability {
            available: releases.unwrap_or(false),
        },
        unavailable,
    }))
}

/// The parts that could not be read, and why.
#[derive(Default)]
struct Reads {
    unavailable: Vec<OfferPart>,
    details: Vec<String>,
}

impl Reads {
    /// The value of a source, or `None` after recording `part` as unreadable.
    fn of<T>(&mut self, part: OfferPart, outcome: Result<T, PolicyError>) -> Option<T> {
        match outcome {
            Ok(value) => Some(value),
            Err(e) => {
                self.unavailable.push(part);
                self.details.push(e.to_string());
                None
            }
        }
    }
}

fn ssh_offers(targets: &[SshTarget]) -> Vec<SshTargetOffer> {
    targets
        .iter()
        .filter(|t| t.listing.is_listed())
        .map(|t| SshTargetOffer {
            name: t.name.clone(),
            users: t.users.clone(),
            max_window: t.max_window,
            mode: match t.mode {
                SshMode::Cert => SshModeName::Cert,
                SshMode::Relay => SshModeName::Relay,
            },
            destination: t.listing.shows_destination().then(|| Destination {
                host: t.host.clone(),
                port: t.port,
            }),
        })
        .collect()
}

fn api_offers(secrets: &[ApiSecretPolicy]) -> Vec<ApiSecretOffer> {
    secrets
        .iter()
        .filter(|s| s.listing.is_listed())
        .map(|s| ApiSecretOffer {
            name: s.name.clone(),
            origin: s
                .listing
                .shows_destination()
                .then(|| s.origin.ascii_serialization()),
            methods: s.methods.iter().map(|m| m.as_str().to_owned()).collect(),
            path_prefix: s.path_prefix.clone(),
            max_window: s.max_window,
        })
        .collect()
}

#[cfg(test)]
mod tests;
