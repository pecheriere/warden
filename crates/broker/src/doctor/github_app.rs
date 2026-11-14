//! Doctor's check of the GitHub App. Having none is fine: GitHub tokens are optional,
//! and the check says what is missing for whoever wants them.

use warden_broker_proto::doctor::Check;

use crate::policy::GithubAppProbe;

const NAME: &str = "github-app";

/// Which backend's words to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Backend {
    OnePassword,
    Local,
}

impl Backend {
    const fn how_to_add(self) -> &'static str {
        match self {
            Self::OnePassword => {
                "To mint GitHub tokens for agents, tag one item warden:github-app, with the \
                 fields app_id, installation_id and private_key (the App's RSA key as PEM), and \
                 optionally default_permissions and extra_permissions: see \
                 docs/1password-items.md."
            }
            Self::Local => {
                "GitHub tokens need the 1Password backend: the local backend cannot hold the \
                 App's key (docs/local-backend.md)."
            }
        }
    }
}

/// The check; `None` when the backend could not be asked.
pub(super) fn check(probe: Option<GithubAppProbe>, backend: Backend) -> Check {
    match probe {
        None => Check::could_not_check(
            NAME,
            "Not checked: Connect or the vault is not usable.",
            "Fix Connect first, then run doctor again.",
        ),
        Some(GithubAppProbe::Loaded {
            app_id,
            installation_id,
        }) => Check::pass(
            NAME,
            format!(
                "The GitHub App loads: App {app_id}, installation {installation_id}. Warden \
                 cannot tell whether GitHub still accepts it."
            ),
        ),
        Some(GithubAppProbe::NotConfigured) => Check::pass(
            NAME,
            format!(
                "No GitHub App: GitHub tokens are off. {}",
                backend.how_to_add()
            ),
        ),
        Some(GithubAppProbe::Invalid(reason)) => Check::fail(NAME, reason, backend.how_to_add()),
        Some(GithubAppProbe::Unknown(reason)) => Check::could_not_check(
            NAME,
            reason,
            "Fix what the message names, then run doctor again.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use warden_broker_proto::doctor::Status;

    use super::{Backend, check};
    use crate::policy::GithubAppProbe;

    fn status(probe: Option<GithubAppProbe>, backend: Backend) -> Status {
        check(probe, backend).status
    }

    #[test]
    fn doctor_reports_github_app_states() {
        let loaded = GithubAppProbe::Loaded {
            app_id: "123".to_owned(),
            installation_id: 456,
        };
        let report = check(Some(loaded), Backend::OnePassword);
        assert_eq!(report.status, Status::Pass);
        assert!(report.detail.contains("123") && report.detail.contains("456"));

        for backend in [Backend::OnePassword, Backend::Local] {
            assert_eq!(status(None, backend), Status::CouldNotCheck);
            assert_eq!(
                status(Some(GithubAppProbe::NotConfigured), backend),
                Status::Pass
            );
            assert_eq!(
                status(Some(GithubAppProbe::Invalid("bad".to_owned())), backend),
                Status::Fail
            );
            assert_eq!(
                status(Some(GithubAppProbe::Unknown("out".to_owned())), backend),
                Status::CouldNotCheck
            );
        }
    }
}
