//! Doctor's checks of the release signing items and the release GitHub App. Having
//! none is fine: releases through warden are optional, and the checks say what is
//! missing for whoever wants them.

use warden_broker_proto::doctor::Check;

use crate::policy::{ReleaseAppProbe, ReleaseSigningProbe};

const SIGNING: &str = "release-signing";
const APP: &str = "release-app";

/// Which backend's words to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Backend {
    OnePassword,
    Local,
}

impl Backend {
    const fn how_to_add_keys(self) -> &'static str {
        match self {
            Self::OnePassword => {
                "To sign releases through warden, tag one item per repository \
                 warden:release-signing, with the fields private_key, repository, tagger_name \
                 and tagger_email: see docs/1password-items.md."
            }
            Self::Local => {
                "Releases need the 1Password backend: the local backend cannot hold the release \
                 keys (docs/local-backend.md)."
            }
        }
    }

    const fn how_to_add_app(self) -> &'static str {
        match self {
            Self::OnePassword => {
                "To publish releases through warden, tag one item warden:github-release-app, \
                 with the fields app_id and private_key (the App's RSA key as PEM): see \
                 docs/1password-items.md."
            }
            Self::Local => {
                "Releases need the 1Password backend: the local backend cannot hold the release \
                 App's key (docs/local-backend.md)."
            }
        }
    }
}

const NOT_CHECKED: &str = "Not checked: Connect or the vault is not usable.";
const FIX_CONNECT: &str = "Fix Connect first, then run doctor again.";
const FIX_NAMED: &str = "Fix what the message names, then run doctor again.";
const FIX_ITEMS: &str = "Fix what the message names (the item, or the key it shares), then run doctor \
     again. The rules for each field are in docs/1password-items.md.";

/// The release signing check; `None` when the backend could not be asked.
pub(super) fn signing_check(probe: Option<ReleaseSigningProbe>, backend: Backend) -> Check {
    match probe {
        None => Check::could_not_check(SIGNING, NOT_CHECKED, FIX_CONNECT),
        Some(ReleaseSigningProbe::Loaded { repositories }) => Check::pass(
            SIGNING,
            format!(
                "{} release signing key(s) load, for: {}. Warden cannot tell whether GitHub \
                 trusts them.",
                repositories.len(),
                repositories.join(", ")
            ),
        ),
        Some(ReleaseSigningProbe::NotConfigured) => Check::pass(
            SIGNING,
            format!(
                "None configured: no release signing key. {}",
                backend.how_to_add_keys()
            ),
        ),
        Some(ReleaseSigningProbe::Invalid(reason)) => Check::fail(SIGNING, reason, FIX_ITEMS),
        Some(ReleaseSigningProbe::Unknown(reason)) => {
            Check::could_not_check(SIGNING, reason, FIX_NAMED)
        }
    }
}

/// The release App check; `None` when the backend could not be asked.
pub(super) fn app_check(probe: Option<ReleaseAppProbe>, backend: Backend) -> Check {
    match probe {
        None => Check::could_not_check(APP, NOT_CHECKED, FIX_CONNECT),
        Some(ReleaseAppProbe::Loaded { app_id }) => Check::pass(
            APP,
            format!(
                "The release App loads: App {app_id}. Warden cannot tell whether GitHub still \
                 accepts it."
            ),
        ),
        Some(ReleaseAppProbe::NotConfigured) => Check::pass(
            APP,
            format!(
                "No release App: releases through warden are off. {}",
                backend.how_to_add_app()
            ),
        ),
        Some(ReleaseAppProbe::Invalid(reason)) => Check::fail(APP, reason, FIX_ITEMS),
        Some(ReleaseAppProbe::Unknown(reason)) => Check::could_not_check(APP, reason, FIX_NAMED),
    }
}

#[cfg(test)]
mod tests {
    use warden_broker_proto::doctor::Status;

    use super::{Backend, app_check, signing_check};
    use crate::policy::{ReleaseAppProbe, ReleaseSigningProbe};

    #[test]
    fn release_signing_passes_with_no_items() {
        for backend in [Backend::OnePassword, Backend::Local] {
            let check = signing_check(Some(ReleaseSigningProbe::NotConfigured), backend);
            assert_eq!(check.status, Status::Pass);
            assert!(check.detail.contains("None configured"), "{check:?}");
        }
    }

    #[test]
    fn release_signing_lists_repositories() {
        let probe = ReleaseSigningProbe::Loaded {
            repositories: vec![
                "example-owner/one".to_owned(),
                "example-owner/two".to_owned(),
            ],
        };
        let check = signing_check(Some(probe), Backend::OnePassword);
        assert_eq!(check.status, Status::Pass);
        for repository in ["example-owner/one", "example-owner/two"] {
            assert!(check.detail.contains(repository), "{check:?}");
        }
    }

    #[test]
    fn release_signing_text_holds_the_repositories_and_nothing_else() {
        let probe = ReleaseSigningProbe::Loaded {
            repositories: vec!["example-owner/one".to_owned()],
        };
        let check = signing_check(Some(probe), Backend::OnePassword);
        let text = format!("{} {}", check.detail, check.action.unwrap_or_default());
        assert!(text.contains("example-owner/one"), "{text}");
        for value in [
            "Release Bot",
            "release@example.com",
            "SHA256:",
            "ssh-ed25519",
        ] {
            assert!(!text.contains(value), "{text}");
        }
    }

    #[test]
    fn release_signing_fails_on_shared_key() {
        let probe = ReleaseSigningProbe::Invalid("two items share a key".to_owned());
        let check = signing_check(Some(probe), Backend::OnePassword);
        assert_eq!(check.status, Status::Fail);
        assert!(check.detail.contains("share a key"), "{check:?}");
        let action = check.action.unwrap_or_default();
        assert!(action.contains("docs/1password-items.md"), "{action}");
    }

    #[test]
    fn release_signing_maps_the_other_answers() {
        for backend in [Backend::OnePassword, Backend::Local] {
            assert_eq!(signing_check(None, backend).status, Status::CouldNotCheck);
            let unknown = ReleaseSigningProbe::Unknown("down".to_owned());
            assert_eq!(
                signing_check(Some(unknown), backend).status,
                Status::CouldNotCheck
            );
        }
    }

    #[test]
    fn release_app_fails_when_invalid() {
        let probe = ReleaseAppProbe::Invalid("exactly one item".to_owned());
        let check = app_check(Some(probe), Backend::OnePassword);
        assert_eq!(check.status, Status::Fail);
        assert!(check.action.is_some());
    }

    #[test]
    fn release_app_reports_each_state() {
        let loaded = ReleaseAppProbe::Loaded {
            app_id: "123".to_owned(),
        };
        let report = app_check(Some(loaded), Backend::OnePassword);
        assert_eq!(report.status, Status::Pass);
        assert!(report.detail.contains("123"));
        for backend in [Backend::OnePassword, Backend::Local] {
            assert_eq!(app_check(None, backend).status, Status::CouldNotCheck);
            assert_eq!(
                app_check(Some(ReleaseAppProbe::NotConfigured), backend).status,
                Status::Pass
            );
            assert_eq!(
                app_check(Some(ReleaseAppProbe::Unknown("out".to_owned())), backend).status,
                Status::CouldNotCheck
            );
        }
    }
}
