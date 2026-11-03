//! Doctor's checks of the local secret backend.

use warden_broker_proto::doctor::Check;

use crate::policy::{CaProbe, LocalProbe};

const POLICY: &str = "local.policy";
const ENTRIES: &str = "local.entries";
const CA: &str = "ssh-ca";

/// The checks from what the backend found. Each problem is named by its entry
/// and setting; none holds anything read from a secret file.
pub(super) fn checks(probe: LocalProbe, checks: &mut Vec<Check>) {
    match probe {
        LocalProbe::Unreadable(reason) => {
            checks.push(Check::fail(
                POLICY,
                reason,
                "Fix the policy file and its permissions: see docs/local-backend.md.",
            ));
            for name in [ENTRIES, CA, "commit-signing"] {
                checks.push(Check::could_not_check(
                    name,
                    "Not checked: the policy file is not usable.",
                    "Fix the policy file first, then run doctor again.",
                ));
            }
        }
        LocalProbe::Read {
            targets,
            api_secrets,
            problems,
            ca,
            commit_signing,
        } => {
            checks.push(Check::pass(
                POLICY,
                format!(
                    "The policy file holds {targets} target(s) and {api_secrets} API secret(s)."
                ),
            ));
            checks.push(if problems.is_empty() {
                Check::pass(
                    ENTRIES,
                    "Every entry is valid, and its secret files are safe to read.",
                )
            } else {
                Check::fail(
                    ENTRIES,
                    problems.join("; "),
                    "Fix each one: see docs/local-backend.md. The server refuses to start until \
                     all of them are right.",
                )
            });
            checks.push(ca_check(ca));
            checks.push(super::commit_signing::check(
                Some(commit_signing),
                super::commit_signing::Backend::Local,
            ));
        }
    }
    checks.push(Check::could_not_check(
        "local.host-boundary",
        "This backend keeps the secrets on this host, so a compromised host gets them, and no \
         read-only token limits what warden can change. warden cannot tell whether this host is \
         kept as locked down as that needs.",
        "Keep the host dedicated to warden, or move to the recommended 1Password backend \
         (docs/threat-model.md).",
    ));
}

fn ca_check(probe: CaProbe) -> Check {
    match probe {
        CaProbe::Loaded { fingerprint } => Check::pass(
            CA,
            format!("The CA key loads; its public key is {fingerprint}."),
        ),
        CaProbe::NotNeeded => Check::pass(
            CA,
            "No [ca] section, and no target in certificate mode needs one.",
        ),
        CaProbe::Missing { cert_targets } => Check::fail(
            CA,
            format!("No [ca] section, and {cert_targets} certificate target(s) need one."),
            "Create the key and add the section: see docs/local-backend.md.",
        ),
        CaProbe::Invalid(reason) => Check::fail(
            CA,
            reason,
            "[ca] must name a file in WARDEN_LOCAL_SECRETS_DIR holding an unencrypted Ed25519 key.",
        ),
        CaProbe::Unknown(reason) => Check::could_not_check(
            CA,
            reason,
            "Run doctor as the broker's user, then fix what the message names.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use warden_broker_proto::doctor::{Check, Status};

    use super::{CA, ENTRIES, POLICY, checks};
    use crate::policy::{CaProbe, CommitSigningProbe, LocalProbe};

    fn statuses(probe: LocalProbe) -> Vec<(String, Status)> {
        let mut list: Vec<Check> = Vec::new();
        checks(probe, &mut list);
        list.into_iter().map(|c| (c.name, c.status)).collect()
    }

    fn status_of(list: &[(String, Status)], name: &str) -> Status {
        let found = list.iter().find(|(n, _)| n == name);
        found.unwrap_or_else(|| panic!("no check {name}")).1
    }

    fn read(problems: Vec<String>, ca: CaProbe) -> LocalProbe {
        LocalProbe::Read {
            targets: 1,
            api_secrets: 1,
            problems,
            ca,
            commit_signing: CommitSigningProbe::NotConfigured,
        }
    }

    #[test]
    fn a_good_setup_passes_and_still_says_what_is_lost() {
        let list = statuses(read(
            Vec::new(),
            CaProbe::Loaded {
                fingerprint: "SHA256:abc".to_owned(),
            },
        ));
        for name in [POLICY, ENTRIES, CA] {
            assert_eq!(status_of(&list, name), Status::Pass, "{name}");
        }
        assert_eq!(
            status_of(&list, "local.host-boundary"),
            Status::CouldNotCheck
        );
    }

    #[test]
    fn an_unusable_policy_fails_and_nothing_below_counts_as_checked() {
        let list = statuses(LocalProbe::Unreadable("bad".to_owned()));
        assert_eq!(status_of(&list, POLICY), Status::Fail);
        assert_eq!(status_of(&list, ENTRIES), Status::CouldNotCheck);
        assert_eq!(status_of(&list, CA), Status::CouldNotCheck);
    }

    #[test]
    fn a_bad_entry_fails() {
        let list = statuses(read(vec!["bad".to_owned()], CaProbe::NotNeeded));
        assert_eq!(status_of(&list, POLICY), Status::Pass);
        assert_eq!(status_of(&list, ENTRIES), Status::Fail);
    }

    #[test]
    fn ca_answers_map_to_each_status() {
        for (probe, wanted) in [
            (CaProbe::NotNeeded, Status::Pass),
            (CaProbe::Missing { cert_targets: 1 }, Status::Fail),
            (CaProbe::Invalid("bad".to_owned()), Status::Fail),
            (CaProbe::Unknown("down".to_owned()), Status::CouldNotCheck),
        ] {
            let list = statuses(read(Vec::new(), probe));
            assert_eq!(status_of(&list, CA), wanted);
        }
    }
}
