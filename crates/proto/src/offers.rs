//! Wire types of what the broker offers an agent: the targets, secrets and
//! GitHub, signing and release capabilities it may ask for. They carry names
//! and limits only, never a credential, a host key or a secret value.
//!
//! Unknown fields are ignored on purpose, and every enum has an `Unknown`
//! variant for a value it does not know, so an older client still reads the
//! answer of a newer broker. The broker never sends `Unknown`.

use serde::{Deserialize, Serialize};

use crate::release::RepoName;
use crate::{SecretName, TargetName, UnixUser, Window};

/// Everything the broker offers this agent, as `GET /v1/offers` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offers {
    /// SSH targets listed as `full` or `name`.
    pub ssh_targets: Vec<SshTargetOffer>,
    /// API secrets listed as `full` or `name`.
    pub api_secrets: Vec<ApiSecretOffer>,
    /// Whether GitHub tokens can be asked for.
    pub github: GithubOffer,
    /// Whether commit signing can be asked for.
    pub commit_signing: Availability,
    /// Whether releases can be asked for.
    pub releases: Availability,
    /// The parts that could not be read; the rest of the answer is complete.
    pub unavailable: Vec<OfferPart>,
}

impl Offers {
    /// The request path, relative to the broker's base URL.
    #[must_use]
    pub const fn path() -> &'static str {
        "v1/offers"
    }
}

/// One SSH target. `destination` is `None` for a target listed as `name`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshTargetOffer {
    /// The target's name.
    pub name: TargetName,
    /// The users an agent may ask for.
    pub users: Vec<UnixUser>,
    /// The longest window the target allows.
    pub max_window: Window,
    /// How the broker gives access.
    pub mode: SshModeName,
    /// Where the target is, when the listing shows it.
    pub destination: Option<Destination>,
}

/// How the broker gives access to a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshModeName {
    /// A short-lived SSH certificate.
    Cert,
    /// The broker relays the connection.
    Relay,
    /// A value this version does not know, from a newer broker.
    #[serde(other)]
    Unknown,
}

/// The host and port of a target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    /// The host name or address.
    pub host: String,
    /// The port.
    pub port: u16,
}

/// One API secret. `origin` is `None` for a secret listed as `name`. The
/// secret value is never part of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiSecretOffer {
    /// The secret's name.
    pub name: SecretName,
    /// The upstream origin, when the listing shows it.
    pub origin: Option<String>,
    /// The HTTP methods the secret allows.
    pub methods: Vec<String>,
    /// The path prefix the secret allows.
    pub path_prefix: String,
    /// The longest window the secret allows.
    pub max_window: Window,
}

/// Whether GitHub tokens can be asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubOffer {
    /// Whether a GitHub App is configured.
    pub configured: bool,
    /// The longest token window, when configured.
    pub max_window: Option<Window>,
}

/// Whether a capability exists on this broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Availability {
    /// True when the capability can be asked for.
    pub available: bool,
}

/// A part of [`Offers`] that can fail to be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfferPart {
    /// `ssh_targets`.
    SshTargets,
    /// `api_secrets`.
    ApiSecrets,
    /// `github`.
    Github,
    /// `commit_signing`.
    CommitSigning,
    /// `releases`.
    Releases,
    /// A value this version does not know, from a newer broker.
    #[serde(other)]
    Unknown,
}

/// What the broker offers for one repository, as
/// `GET /v1/offers/repository/{owner}/{name}` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryOffer {
    /// The repository asked about.
    pub repository: RepoName,
    /// Whether the agent App covers it.
    pub github_token: GithubTokenStatus,
    /// Whether commit signing is available (machine-wide, repeated here).
    pub commit_signing: bool,
    /// Whether the repository can be released.
    pub release: ReleaseStatus,
}

impl RepositoryOffer {
    /// The request path for `repo`, relative to the broker's base URL. Both
    /// parts are validated by [`RepoName`], so nothing needs encoding.
    #[must_use]
    pub fn path(repo: &RepoName) -> String {
        format!("v1/offers/repository/{repo}")
    }
}

/// Whether the agent App covers a repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubTokenStatus {
    /// The App covers the repository.
    Covered,
    /// The App does not cover it.
    NotCovered,
    /// No GitHub App is configured.
    NotConfigured,
    /// The broker could not tell.
    Unavailable,
    /// A value this version does not know, from a newer broker.
    #[serde(other)]
    Unknown,
}

/// Whether a repository can be released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStatus {
    /// A release signing key names it and a release App exists.
    Ready,
    /// No release signing key names it.
    NoKey,
    /// No release App is configured.
    NoReleaseApp,
    /// The broker could not tell.
    Unavailable,
    /// A value this version does not know, from a newer broker.
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFERS: &str = r#"{
        "ssh_targets": [
            { "name": "web-01", "users": ["deploy"], "max_window": "1h",
              "mode": "cert", "destination": { "host": "web-01.example.internal", "port": 22 } },
            { "name": "switch-01", "users": ["admin"], "max_window": "30m",
              "mode": "relay", "destination": null }
        ],
        "api_secrets": [
            { "name": "home-api", "origin": "https://home-api.example.internal",
              "methods": ["GET"], "path_prefix": "/api/", "max_window": "1h" }
        ],
        "github": { "configured": true, "max_window": "30d" },
        "commit_signing": { "available": true },
        "releases": { "available": true },
        "unavailable": ["api_secrets"]
    }"#;

    const REPOSITORY: &str = r#"{
        "repository": "example-org/example-repo",
        "github_token": "covered",
        "commit_signing": true,
        "release": "ready"
    }"#;

    #[test]
    fn offers_round_trip() {
        let offers: Offers = serde_json::from_str(OFFERS).unwrap();
        assert_eq!(offers.ssh_targets.len(), 2);
        assert_eq!(offers.ssh_targets[0].mode, SshModeName::Cert);
        assert_eq!(offers.ssh_targets[0].max_window, Window::H1);
        assert_eq!(offers.ssh_targets[1].destination, None);
        assert_eq!(offers.github.max_window, Some(Window::D30));
        assert_eq!(offers.unavailable, [OfferPart::ApiSecrets]);
        let expected: serde_json::Value = serde_json::from_str(OFFERS).unwrap();
        assert_eq!(serde_json::to_value(&offers).unwrap(), expected);
    }

    #[test]
    fn repository_offer_round_trip() {
        let offer: RepositoryOffer = serde_json::from_str(REPOSITORY).unwrap();
        assert_eq!(offer.github_token, GithubTokenStatus::Covered);
        assert_eq!(offer.release, ReleaseStatus::Ready);
        let expected: serde_json::Value = serde_json::from_str(REPOSITORY).unwrap();
        assert_eq!(serde_json::to_value(&offer).unwrap(), expected);
    }

    #[test]
    fn enum_spellings() {
        fn spell<T: Serialize>(value: &T) -> String {
            serde_json::to_string(value).unwrap()
        }
        assert_eq!(spell(&GithubTokenStatus::NotCovered), r#""not_covered""#);
        assert_eq!(spell(&ReleaseStatus::NoReleaseApp), r#""no_release_app""#);
        assert_eq!(spell(&OfferPart::ApiSecrets), r#""api_secrets""#);
        assert_eq!(spell(&SshModeName::Relay), r#""relay""#);
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let with_extra = REPOSITORY.replace('{', r#"{ "newer": 1,"#);
        let offer: RepositoryOffer = serde_json::from_str(&with_extra).unwrap();
        assert!(offer.commit_signing);
        let with_extra = OFFERS.replacen('{', r#"{ "newer": {"x": 1},"#, 1).replace(
            r#""configured": true,"#,
            r#""configured": true, "newer": 2,"#,
        );
        serde_json::from_str::<Offers>(&with_extra).unwrap();
    }

    #[test]
    fn unknown_values_are_read() {
        let newer = OFFERS
            .replace(r#""mode": "relay""#, r#""mode": "tunnel""#)
            .replace(
                r#""unavailable": ["api_secrets"]"#,
                r#""unavailable": ["api_secrets", "webhooks"]"#,
            );
        let offers: Offers = serde_json::from_str(&newer).unwrap();
        assert_eq!(offers.ssh_targets[1].mode, SshModeName::Unknown);
        assert_eq!(
            offers.unavailable,
            [OfferPart::ApiSecrets, OfferPart::Unknown]
        );
        let newer = REPOSITORY
            .replace(r#""covered""#, r#""suspended""#)
            .replace(r#""ready""#, r#""frozen""#);
        let offer: RepositoryOffer = serde_json::from_str(&newer).unwrap();
        assert_eq!(offer.github_token, GithubTokenStatus::Unknown);
        assert_eq!(offer.release, ReleaseStatus::Unknown);
    }

    #[test]
    fn paths() {
        assert_eq!(Offers::path(), "v1/offers");
        let repo = RepoName::try_from("example-org/example-repo".to_owned()).unwrap();
        assert_eq!(
            RepositoryOffer::path(&repo),
            "v1/offers/repository/example-org/example-repo"
        );
    }
}
