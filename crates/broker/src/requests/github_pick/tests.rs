use warden_broker_proto::Id;
use warden_broker_proto::github_permissions::{GrantedPermissions, PermissionSet};
use warden_broker_proto::github_token::{GithubTokenGrant, GrantRepository, GrantScope};

use super::{Candidate, Pick, pick};

const EVERYDAY: &str = "contents:write,pull_requests:write";
const SENSITIVE: &str = "contents:write,pull_requests:write,workflows:write";

fn set(text: &str) -> PermissionSet {
    PermissionSet::parse(text).unwrap()
}

fn id(n: u8) -> Id {
    format!("{n:032x}").parse().unwrap()
}

/// A candidate `n` holding `permissions` with `extras`, ending at `not_after`.
fn candidate(n: u8, permissions: &str, extras: Option<&str>, not_after: i64) -> Candidate {
    let repository = GrantRepository {
        name: "example-owner/example-repo".to_owned().try_into().unwrap(),
        id: 1001,
    };
    let grant = GithubTokenGrant {
        app_id: "12345".to_owned(),
        installation_id: 67890,
        digest: "00".repeat(32),
        repositories: GrantScope::repositories(vec![repository.clone()]).unwrap(),
        permissions: GrantedPermissions::from(&set(permissions)),
        extra_permissions: extras.map(|e| GrantedPermissions::from(&set(e))),
    };
    Candidate::new(id(n), grant, repository, 86_400, not_after).unwrap()
}

fn picked(found: &Pick<'_>) -> Id {
    match found {
        Pick::One(candidate) => candidate.grant_id.clone(),
        Pick::None => panic!("nothing picked"),
        Pick::Ambiguous(first) => panic!("ambiguous, first {first:?}"),
    }
}

#[test]
fn no_candidate_is_none() {
    assert!(matches!(pick(&[], None), Pick::None));
    assert!(matches!(pick(&[], Some(&set("contents:read"))), Pick::None));
}

#[test]
fn no_wanted_picks_the_least_privileged() {
    let candidates = [
        candidate(
            1,
            "actions:write,contents:write",
            Some("actions:write"),
            100,
        ),
        candidate(2, "contents:write", None, 200),
    ];
    assert_eq!(picked(&pick(&candidates, None)), id(2));
}

#[test]
fn sensitive_grant_only_when_wanted_needs_it() {
    // The sensitive grant ends sooner and comes first: neither changes the pick.
    let candidates = [
        candidate(1, SENSITIVE, Some("workflows:write"), 100),
        candidate(2, EVERYDAY, None, 200),
    ];
    assert_eq!(picked(&pick(&candidates, None)), id(2));
    assert_eq!(
        picked(&pick(&candidates, Some(&set("contents:write")))),
        id(2)
    );
    assert_eq!(
        picked(&pick(
            &candidates,
            Some(&set("contents:write,workflows:write"))
        )),
        id(1)
    );
}

#[test]
fn no_sensitive_comes_before_fewer_permissions() {
    let candidates = [
        candidate(1, "workflows:write", Some("workflows:write"), 100),
        candidate(
            2,
            "actions:write,contents:write,issues:write",
            Some("actions:write"),
            100,
        ),
    ];
    assert_eq!(picked(&pick(&candidates, None)), id(2));
}

#[test]
fn fewest_permissions_then_soonest_end_then_id() {
    // Fewest permissions first, whatever the ends.
    let fewer = [
        candidate(
            1,
            "actions:write,contents:write",
            Some("actions:write"),
            100,
        ),
        candidate(2, "contents:write", None, 900),
    ];
    assert_eq!(picked(&pick(&fewer, Some(&set("contents:write")))), id(2));
    // As many: the one ending soonest.
    let sooner = [
        candidate(
            1,
            "actions:write,contents:write",
            Some("actions:write"),
            900,
        ),
        candidate(2, "contents:write,issues:write", Some("issues:write"), 100),
    ];
    assert_eq!(picked(&pick(&sooner, Some(&set("contents:write")))), id(2));
    // As many, ending together: the smaller id, in either order.
    let tied = [
        candidate(
            2,
            "actions:write,contents:write",
            Some("actions:write"),
            100,
        ),
        candidate(1, "contents:write,issues:write", Some("issues:write"), 100),
    ];
    assert_eq!(picked(&pick(&tied, Some(&set("contents:write")))), id(1));
    let reversed = [tied[1].clone(), tied[0].clone()];
    assert_eq!(
        picked(&pick(&reversed, Some(&set("contents:write")))),
        id(1)
    );
}

#[test]
fn equal_sets_are_ambiguous() {
    // Equal extras, absent counting as none, even with other full sets.
    let candidates = [
        candidate(1, EVERYDAY, None, 100),
        candidate(2, "contents:write", None, 200),
        candidate(3, SENSITIVE, Some("workflows:write"), 300),
    ];
    assert!(matches!(pick(&candidates, None), Pick::Ambiguous(first) if first == id(1)));
    assert!(matches!(
        pick(&candidates, Some(&set("workflows:write"))),
        Pick::Ambiguous(first) if first == id(1)
    ));
    let extras = [
        candidate(1, SENSITIVE, Some("workflows:write"), 100),
        candidate(2, SENSITIVE, Some("workflows:write"), 200),
    ];
    assert!(matches!(pick(&extras, None), Pick::Ambiguous(first) if first == id(1)));
}

#[test]
fn no_holder_falls_back_to_all_candidates() {
    let candidates = [
        candidate(1, SENSITIVE, Some("workflows:write"), 100),
        candidate(2, EVERYDAY, None, 200),
    ];
    // Neither holds `actions:write`: the pick is among both, and the caller then
    // refuses naming what the picked grant lacks.
    assert_eq!(
        picked(&pick(&candidates, Some(&set("actions:write")))),
        id(2)
    );
}
