use warden_broker_proto::Id;
use warden_broker_proto::github_permissions::PermissionSet;
use warden_broker_proto::release::RepoName;

use super::{GithubPending, ReplacedGrant, Resolution, ScopedRepository};
use crate::requests::github_permissions::{InstallationCheck, StoredPermissions};

fn pending(permissions: StoredPermissions, replaces: Vec<ReplacedGrant>) -> GithubPending {
    GithubPending {
        resolution: Resolution::Resolved(vec![ScopedRepository {
            id: 1001,
            name: RepoName::try_from("Example-Owner/Example-Repo".to_owned()).unwrap(),
            renamed_from: None,
        }]),
        replaces,
        also_live: Vec::new(),
        permissions,
        not_allowed: Vec::new(),
        installation: InstallationCheck::Holds,
    }
}

/// The approval binds the version, the repositories, then the set: a page digest
/// from before sets were bound (v1) can never match.
#[test]
fn digest_input_is_v2_and_binds_the_set_after_the_repositories() {
    let replaced = Id::random();
    let input = pending(
        StoredPermissions::legacy(),
        vec![ReplacedGrant {
            grant_id: replaced.clone(),
            scope: warden_broker_proto::github_token::GrantScope::Legacy,
            permissions: PermissionSet::legacy(),
            not_after: 0,
        }],
    )
    .digest_input();
    assert_eq!(
        input,
        format!(
            "warden github-token scope v2\0\
             1001\0example-owner/example-repo\0\
             contents:write,issues:write,metadata:read,pull_requests:write\0\
             {}\0",
            replaced.as_str()
        )
    );
}

#[test]
fn digest_input_changes_with_the_set() {
    let wider = StoredPermissions {
        full: PermissionSet::parse("checks:read,contents:write").unwrap(),
        beyond_default: Vec::new(),
    };
    let legacy = pending(StoredPermissions::legacy(), Vec::new());
    let wider = pending(wider, Vec::new());
    assert_ne!(legacy.digest_input(), wider.digest_input());
    assert_ne!(legacy.digest("ab"), wider.digest("ab"));
    assert!(
        wider
            .digest_input()
            .ends_with("checks:read,contents:write,metadata:read\0")
    );
}
