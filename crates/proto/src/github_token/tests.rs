use serde_json::json;

use super::{
    AutomaticCaller, AutomaticRequest, GithubTokenAccess, GithubTokenGrant, GithubTokenRequest,
    GrantRepository, GrantScope, MAX_REPOSITORIES,
};
use crate::release::RepoName;
use crate::{Access, GrantAccess, InfoResponse};

fn repo(s: &str) -> RepoName {
    RepoName::try_from(s.to_owned()).unwrap()
}

fn granted(name: &str, id: u64) -> GrantRepository {
    GrantRepository {
        name: repo(name),
        id,
    }
}

fn access(repositories: &[&str]) -> Result<GithubTokenAccess, crate::ParseError> {
    GithubTokenAccess::new(repositories.iter().map(|r| repo(r)).collect(), None)
}

#[test]
fn github_token_access_round_trips() {
    let value = json!({"kind": "github_token", "repositories": ["example-owner/example-repo"]});
    let parsed: Access = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        parsed,
        Access::GithubToken(access(&["example-owner/example-repo"]).unwrap())
    );
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

    let value = json!({
        "kind": "github_token",
        "repositories": ["example-owner/example-repo"],
        "automatic": {"by": "git_credential", "dir": "/work/example-repo"},
    });
    let parsed: Access = serde_json::from_value(value.clone()).unwrap();
    let Access::GithubToken(inner) = &parsed else {
        panic!("not a github token: {parsed:?}");
    };
    assert_eq!(
        inner.automatic,
        Some(AutomaticRequest {
            by: AutomaticCaller::GitCredential,
            dir: Some("/work/example-repo".to_owned()),
        })
    );
    assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
}

#[test]
fn legacy_github_token_access_parses() {
    let parsed: Access = serde_json::from_str(r#"{"kind":"github_token"}"#).unwrap();
    let Access::GithubToken(inner) = &parsed else {
        panic!("not a github token: {parsed:?}");
    };
    assert!(inner.is_legacy());
    assert_eq!(
        serde_json::to_string(&parsed).unwrap(),
        r#"{"kind":"github_token"}"#
    );
}

#[test]
fn github_token_access_refuses_unknown_field() {
    let value = json!({
        "kind": "github_token",
        "repositories": ["example-owner/example-repo"],
        "repository": "o/r",
    });
    assert!(serde_json::from_value::<Access>(value).is_err());
}

#[test]
fn automatic_request_refuses_unknown_field() {
    let known = json!({"by": "gh_wrapper", "dir": "/src/home-api"});
    assert!(serde_json::from_value::<AutomaticRequest>(known).is_ok());
    let unknown = json!({"by": "gh_wrapper", "dir": "/src/home-api", "extra": 1});
    assert!(serde_json::from_value::<AutomaticRequest>(unknown).is_err());
    let nested = json!({
        "kind": "github_token",
        "repositories": ["example-owner/example-repo"],
        "automatic": {"by": "git_credential", "extra": true},
    });
    assert!(serde_json::from_value::<Access>(nested).is_err());
}

#[test]
fn github_token_access_refuses_duplicates() {
    assert!(access(&["Example-Owner/Example-Repo", "example-owner/example-repo"]).is_err());
    let value = json!({
        "kind": "github_token",
        "repositories": ["Example-Owner/Example-Repo", "example-owner/example-repo"],
    });
    assert!(serde_json::from_value::<Access>(value).is_err());
}

#[test]
fn github_token_access_refuses_eleven() {
    let names: Vec<String> = (0..=MAX_REPOSITORIES)
        .map(|n| format!("example-owner/repo-{n}"))
        .collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    assert!(access(&refs).is_err());
    assert!(access(&refs[..MAX_REPOSITORIES]).is_ok());
    let value = json!({"kind": "github_token", "repositories": names});
    assert!(serde_json::from_value::<Access>(value).is_err());
}

#[test]
fn automatic_needs_exactly_one_repository() {
    let automatic = || {
        Some(AutomaticRequest {
            by: AutomaticCaller::GhWrapper,
            dir: None,
        })
    };
    let two = vec![repo("example-owner/a"), repo("example-owner/b")];
    assert!(GithubTokenAccess::new(two, automatic()).is_err());
    assert!(GithubTokenAccess::new(Vec::new(), automatic()).is_err());
    assert!(GithubTokenAccess::new(vec![repo("example-owner/a")], automatic()).is_ok());
    let value = json!({
        "kind": "github_token",
        "repositories": ["example-owner/a", "example-owner/b"],
        "automatic": {"by": "gh_wrapper"},
    });
    assert!(serde_json::from_value::<Access>(value).is_err());
}

#[test]
fn automatic_dir_refuses_control_characters() {
    for dir in [
        "/work/a\nb",
        "/work/a\u{202e}b",
        "/work/a\u{2028}b",
        "/work/a\u{3164}b",
        &"d".repeat(513),
    ] {
        let value = json!({
            "kind": "github_token",
            "repositories": ["example-owner/a"],
            "automatic": {"by": "git_credential", "dir": dir},
        });
        assert!(serde_json::from_value::<Access>(value).is_err(), "{dir:?}");
    }
    let long_enough = json!({
        "kind": "github_token",
        "repositories": ["example-owner/a"],
        "automatic": {"by": "git_credential", "dir": "d".repeat(512)},
    });
    assert!(serde_json::from_value::<Access>(long_enough).is_ok());
}

#[test]
fn slot_is_case_and_order_insensitive() {
    assert_eq!(access(&["B/x", "a/Y"]).unwrap().slot(), "a/y,b/x");
    assert_eq!(access(&["a/y", "b/X"]).unwrap().slot(), "a/y,b/x");
}

#[test]
fn grant_scope_legacy_when_absent() {
    let value = json!({"app_id": "1", "installation_id": 2, "digest": "ab"});
    let grant: GithubTokenGrant = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(grant.repositories, GrantScope::Legacy);
    assert_eq!(serde_json::to_value(&grant).unwrap(), value);
    let with_empty =
        json!({"app_id": "1", "installation_id": 2, "digest": "ab", "repositories": []});
    let grant: GithubTokenGrant = serde_json::from_value(with_empty).unwrap();
    assert!(grant.repositories.is_legacy());
    assert_eq!(GrantScope::default(), GrantScope::Legacy);
}

#[test]
fn grant_scope_round_trips_and_refuses_bad_lists() {
    let scope =
        GrantScope::repositories(vec![granted("example-owner/example-repo", 1001)]).unwrap();
    let grant = GrantAccess::GithubToken(GithubTokenGrant {
        app_id: "1".to_owned(),
        installation_id: 2,
        digest: "ab".to_owned(),
        repositories: scope,
    });
    let value = serde_json::to_value(&grant).unwrap();
    assert_eq!(
        value["repositories"],
        json!([{"name": "example-owner/example-repo", "id": 1001}])
    );
    assert_eq!(serde_json::from_value::<GrantAccess>(value).unwrap(), grant);

    assert!(GrantScope::repositories(Vec::new()).is_none());
    assert!(GrantScope::repositories(vec![granted("o/a", 1), granted("o/b", 1)]).is_none());
    assert!(GrantScope::repositories(vec![granted("o/a", 1), granted("O/A", 2)]).is_none());
    let eleven = (0..=10_u64)
        .map(|n| granted(&format!("o/r{n}"), n))
        .collect();
    assert!(GrantScope::repositories(eleven).is_none());
    let dup = json!([{"name": "o/a", "id": 1}, {"name": "o/b", "id": 1}]);
    assert!(serde_json::from_value::<GrantScope>(dup).is_err());
}

#[test]
fn grant_scope_covering_ignores_case() {
    let scope =
        GrantScope::repositories(vec![granted("Example-Owner/Example-Repo", 1001)]).unwrap();
    let found = scope.covering(&repo("example-owner/example-repo")).unwrap();
    assert_eq!(found.id, 1001);
    assert!(scope.covering(&repo("example-owner/other")).is_none());
    assert!(
        GrantScope::Legacy
            .covering(&repo("example-owner/example-repo"))
            .is_none()
    );
}

#[test]
fn grant_scope_overlap_by_id() {
    let a = GrantScope::repositories(vec![granted("o/a", 1), granted("o/b", 2)]).unwrap();
    let renamed = GrantScope::repositories(vec![granted("o/renamed", 2)]).unwrap();
    let disjoint = GrantScope::repositories(vec![granted("o/c", 3)]).unwrap();
    assert!(a.overlaps(&renamed));
    assert!(renamed.overlaps(&a));
    assert!(!a.overlaps(&disjoint));
    assert!(GrantScope::Legacy.overlaps(&a));
    assert!(a.overlaps(&GrantScope::Legacy));
    assert!(GrantScope::Legacy.overlaps(&GrantScope::Legacy));
}

#[test]
fn grant_scope_overlap_by_name_with_other_ids() {
    // A repository deleted and created again under its name has another id.
    let old = GrantScope::repositories(vec![granted("Example-Owner/Example-Repo", 1001)]).unwrap();
    let recreated =
        GrantScope::repositories(vec![granted("example-owner/example-repo", 1003)]).unwrap();
    let other = GrantScope::repositories(vec![granted("example-owner/other", 1003)]).unwrap();
    assert!(old.overlaps(&recreated));
    assert!(recreated.overlaps(&old));
    // Another name with the same id still overlaps; another name and id does not.
    assert!(recreated.overlaps(&other));
    let unrelated = GrantScope::repositories(vec![granted("example-owner/other", 2000)]).unwrap();
    assert!(!old.overlaps(&unrelated));
    // The ended grant's own ids are listed, by id or by name.
    assert_eq!(old.overlapping_ids(&recreated), vec![1001]);
    assert_eq!(recreated.overlapping_ids(&other), vec![1003]);
    assert_eq!(old.overlapping_ids(&unrelated), [] as [u64; 0]);
    assert_eq!(GrantScope::Legacy.overlapping_ids(&old), [] as [u64; 0]);
}

#[test]
fn github_token_request_refuses_empty_object() {
    assert!(serde_json::from_str::<GithubTokenRequest>("{}").is_err());
    assert!(
        serde_json::from_str::<GithubTokenRequest>(r#"{"repository":"example-owner/a"}"#).is_ok()
    );
    assert!(
        serde_json::from_str::<GithubTokenRequest>(r#"{"repository":"example-owner/a","extra":1}"#)
            .is_err()
    );
}

#[test]
fn info_without_flag_is_false() {
    let info: InfoResponse = serde_json::from_value(json!({
        "protocols": [],
        "audience": "0123456789abcdef0123456789abcdef",
    }))
    .unwrap();
    assert!(!info.scoped_github_tokens);
}
