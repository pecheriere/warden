//! Doctor's check of the commit signing key. Having none is fine: commit signing is
//! optional, and the check says what is missing for whoever wants it.

use warden_broker_proto::doctor::Check;

use crate::policy::CommitSigningProbe;

const NAME: &str = "commit-signing";

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
                "To sign commits through warden, tag one item warden:commit-signing, holding an \
                 unencrypted ssh-ed25519 key of its own, not the CA key, in the field with id \
                 private_key: see docs/deployment.md."
            }
            Self::Local => {
                "To sign commits through warden, add a [commit_signing] section naming a file in \
                 WARDEN_LOCAL_SECRETS_DIR that holds an unencrypted ssh-ed25519 key of its own, \
                 not the CA key: see docs/local-backend.md."
            }
        }
    }
}

/// The check; `None` when the backend could not be asked.
pub(super) fn check(probe: Option<CommitSigningProbe>, backend: Backend) -> Check {
    match probe {
        None => Check::could_not_check(
            NAME,
            "Not checked: Connect or the vault is not usable.",
            "Fix Connect first, then run doctor again.",
        ),
        Some(CommitSigningProbe::Loaded { fingerprint }) => Check::pass(
            NAME,
            format!(
                "The commit signing key loads; its public key is {fingerprint}. It must be \
                 registered as a signing key on the account that commits, or signatures show as \
                 unverified."
            ),
        ),
        Some(CommitSigningProbe::NotConfigured) => Check::pass(
            NAME,
            format!(
                "No commit signing key: signing is off. {}",
                backend.how_to_add()
            ),
        ),
        Some(CommitSigningProbe::Invalid(reason)) => {
            Check::fail(NAME, reason, backend.how_to_add())
        }
        Some(CommitSigningProbe::Unknown(reason)) => Check::could_not_check(
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
    use crate::policy::CommitSigningProbe;

    fn status(probe: Option<CommitSigningProbe>) -> Status {
        check(probe, Backend::Local).status
    }

    #[test]
    fn each_answer_has_its_own_status() {
        assert_eq!(status(None), Status::CouldNotCheck);
        let loaded = CommitSigningProbe::Loaded {
            fingerprint: "SHA256:abc".to_owned(),
        };
        assert_eq!(status(Some(loaded)), Status::Pass);
        assert_eq!(
            status(Some(CommitSigningProbe::NotConfigured)),
            Status::Pass
        );
        assert_eq!(
            status(Some(CommitSigningProbe::Invalid("bad".to_owned()))),
            Status::Fail
        );
        assert_eq!(
            status(Some(CommitSigningProbe::Unknown("out".to_owned()))),
            Status::CouldNotCheck
        );
    }
}
