use serde_json::json;

use super::{
    AutomaticCaller, AutomaticRequest, GithubTokenAccess, GithubTokenGrant, GithubTokenRequest,
    GrantRepository, GrantScope, MAX_REPOSITORIES,
};
use crate::github_permissions::{GrantedPermissions, PermissionError, PermissionSet};
use crate::release::RepoName;
use crate::{
    Access, AgentName, CreateRequest, Goal, GrantAccess, InfoResponse, Window, fingerprint,
};

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
    GithubTokenAccess::new(repositories.iter().map(|r| repo(r)).collect(), None, None)
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
    assert!(GithubTokenAccess::new(two, automatic(), None).is_err());
    assert!(GithubTokenAccess::new(Vec::new(), automatic(), None).is_err());
    assert!(GithubTokenAccess::new(vec![repo("example-owner/a")], automatic(), None).is_ok());
    let value = json!({
        "kind": "github_token",
        "repositories": ["example-owner/a", "example-owner/b"],
        "automatic": {"by": "gh_wrapper"},
    });
    assert!(serde_json::from_value::<Access>(value).is_err());
}

#[test]
fn automatic_dir_refuses_control_characters() {
    for dir in ["/work/a\nb", "/work/a\u{202e}b", &"d".repeat(513)] {
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

/// A directory sent now may not hold a separator or a blank filler; one stored
/// before that rule still reads.
#[test]
fn automatic_dir_refuses_separators_only_when_new() {
    for dir in ["/work/a\u{2028}b", "/work/a\u{3164}b"] {
        let automatic = || AutomaticRequest {
            by: AutomaticCaller::GitCredential,
            dir: Some(dir.to_owned()),
        };
        let repositories = vec![RepoName::try_from("example-owner/a".to_owned()).unwrap()];
        assert!(
            GithubTokenAccess::new(repositories, Some(automatic()), None).is_err(),
            "{dir:?}"
        );
        let stored = json!({
            "kind": "github_token",
            "repositories": ["example-owner/a"],
            "automatic": {"by": "git_credential", "dir": dir},
        });
        let Access::GithubToken(access) = serde_json::from_value::<Access>(stored).unwrap() else {
            panic!("not a GitHub token request");
        };
        assert!(access.check_new().is_err(), "{dir:?}");
    }
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
    let mut written = value;
    written["permissions"] = json!("contents:write,issues:write,metadata:read,pull_requests:write");
    assert_eq!(serde_json::to_value(&grant).unwrap(), written);
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
        permissions: GrantedPermissions::legacy(),
        extra_permissions: None,
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

#[test]
fn grant_without_permissions_parses_as_legacy() {
    let grant: GithubTokenGrant = serde_json::from_value(
        json!({"app_id": "12345", "installation_id": 678, "digest": "ab12"}),
    )
    .unwrap();
    assert_eq!(grant.permissions, GrantedPermissions::legacy());
}

#[test]
fn response_without_permissions_parses() {
    let response: super::GithubTokenResponse = serde_json::from_value(json!({
        "token": "t",
        "expires_at": 1,
        "grant_id": crate::Id::random(),
        "repository": "example-owner/example-repo",
        "repository_id": 1001,
    }))
    .unwrap();
    assert_eq!(response.permissions, None);
    let json = serde_json::to_value(&response).unwrap();
    assert!(json.get("permissions").is_none());
}

/// A newer broker may know permission names this CLI does not: they must not
/// break reading its grants or tokens.
#[test]
fn grant_and_response_keep_an_unknown_permission_name() {
    let grant: GithubTokenGrant = serde_json::from_value(json!({
        "app_id": "12345",
        "installation_id": 678,
        "digest": "ab12",
        "permissions": "new_thing:write,contents:read",
    }))
    .unwrap();
    assert_eq!(
        grant.permissions.as_str(),
        "contents:read,metadata:read,new_thing:write"
    );
    assert_eq!(grant.permissions.known(), Err(PermissionError::Unknown));

    let response: super::GithubTokenResponse = serde_json::from_value(json!({
        "token": "t",
        "expires_at": 1,
        "grant_id": crate::Id::random(),
        "repository": "example-owner/example-repo",
        "repository_id": 1001,
        "permissions": "contents:read,metadata:read,new_thing:write",
    }))
    .unwrap();
    assert_eq!(response.permissions, Some(grant.permissions));
}

#[test]
fn grant_and_response_refuse_malformed_permissions() {
    for bad in [
        "contents:wirte",
        "contents:admin",
        "Contents:read",
        "contents",
        "contents:read,contents:write",
        "metadata:write",
        "new-thing:read",
        "",
    ] {
        let grant = json!({
            "app_id": "12345",
            "installation_id": 678,
            "digest": "ab12",
            "permissions": bad,
        });
        assert!(
            serde_json::from_value::<GithubTokenGrant>(grant).is_err(),
            "{bad:?}"
        );
        let response = json!({
            "token": "t",
            "expires_at": 1,
            "grant_id": crate::Id::random(),
            "repository": "example-owner/example-repo",
            "repository_id": 1001,
            "permissions": bad,
        });
        assert!(
            serde_json::from_value::<super::GithubTokenResponse>(response).is_err(),
            "{bad:?}"
        );
    }
}

fn extras(text: &str) -> PermissionSet {
    PermissionSet::parse(text).unwrap()
}

fn with_extras(text: &str) -> GithubTokenAccess {
    GithubTokenAccess::new(
        vec![repo("example-owner/example-repo")],
        None,
        Some(extras(text)),
    )
    .unwrap()
}

#[test]
fn access_with_extras_round_trips() {
    let access = with_extras("checks:read, actions:write");
    let value = serde_json::to_value(Access::GithubToken(access.clone())).unwrap();
    assert_eq!(
        value,
        json!({
            "kind": "github_token",
            "repositories": ["example-owner/example-repo"],
            "extra_permissions": "actions:write,checks:read,metadata:read",
        })
    );
    assert_eq!(
        serde_json::from_value::<Access>(value).unwrap(),
        Access::GithubToken(access)
    );
}

#[test]
fn access_without_extras_writes_no_field() {
    let value = serde_json::to_value(Access::GithubToken(
        access(&["example-owner/example-repo"]).unwrap(),
    ))
    .unwrap();
    assert!(value.get("extra_permissions").is_none());
}

#[test]
fn automatic_with_extras_refused() {
    let tool = Some(AutomaticRequest {
        by: AutomaticCaller::GhWrapper,
        dir: None,
    });
    assert!(
        GithubTokenAccess::new(
            vec![repo("example-owner/example-repo")],
            tool,
            Some(extras("checks:read"))
        )
        .is_err()
    );
    let value = json!({
        "kind": "github_token",
        "repositories": ["example-owner/example-repo"],
        "automatic": {"by": "gh_wrapper"},
        "extra_permissions": "checks:read,metadata:read",
    });
    assert!(serde_json::from_value::<Access>(value).is_err());
}

#[test]
fn extras_refuse_nothing_but_metadata_and_bad_names() {
    assert!(
        GithubTokenAccess::new(
            vec![repo("example-owner/example-repo")],
            None,
            Some(PermissionSet::metadata_only())
        )
        .is_err()
    );
    for bad in [
        "checks:admin",
        "nonsense:read",
        "checks:read,",
        "metadata:write",
        "",
    ] {
        let value = json!({
            "kind": "github_token",
            "repositories": ["example-owner/example-repo"],
            "extra_permissions": bad,
        });
        assert!(serde_json::from_value::<Access>(value).is_err(), "{bad:?}");
    }
    let only_metadata = json!({
        "kind": "github_token",
        "repositories": ["example-owner/example-repo"],
        "extra_permissions": "metadata:read",
    });
    assert!(serde_json::from_value::<Access>(only_metadata).is_err());
}

#[test]
fn sensitive_extras_parse_here_and_are_the_brokers_to_allow() {
    assert!(with_extras("workflows:write").extra_permissions.is_some());
}

#[test]
fn fingerprint_covers_extras() {
    let agent = AgentName::try_from("build-agent".to_owned()).unwrap();
    let request = |access: GithubTokenAccess| CreateRequest {
        goal: Goal::try_from("release".to_owned()).unwrap(),
        access: Access::GithubToken(access),
        window: Window::D1,
        session: None,
        link: None,
    };
    let plain = fingerprint(
        &agent,
        &request(access(&["example-owner/example-repo"]).unwrap()),
    );
    let checks = fingerprint(&agent, &request(with_extras("checks:read")));
    let actions = fingerprint(&agent, &request(with_extras("actions:read")));
    assert_ne!(plain, checks);
    assert_ne!(checks, actions);
    assert_eq!(
        checks,
        fingerprint(&agent, &request(with_extras("checks:read, metadata:read")))
    );
}

#[test]
fn summary_names_extras_without_metadata() {
    assert_eq!(
        with_extras("checks:read,actions:write").summary(),
        "github token for example-owner/example-repo +actions:write,checks:read"
    );
    assert_eq!(
        access(&["example-owner/example-repo"]).unwrap().summary(),
        "github token for example-owner/example-repo"
    );
}

#[test]
fn grant_extras_round_trip_and_are_absent_when_none() {
    let mut grant = GithubTokenGrant {
        app_id: "1".to_owned(),
        installation_id: 2,
        digest: "ab".to_owned(),
        repositories: GrantScope::Legacy,
        permissions: GrantedPermissions::legacy(),
        extra_permissions: None,
    };
    assert!(
        serde_json::to_value(&grant)
            .unwrap()
            .get("extra_permissions")
            .is_none()
    );
    grant.extra_permissions = Some(extras("checks:read").into());
    let value = serde_json::to_value(&grant).unwrap();
    assert_eq!(value["extra_permissions"], "checks:read,metadata:read");
    assert_eq!(
        serde_json::from_value::<GithubTokenGrant>(value).unwrap(),
        grant
    );
}

#[test]
fn sensitive_windows_are_the_short_ones_only() {
    for window in Window::GITHUB_TOKEN_SENSITIVE {
        assert!(window.is_github_token_sensitive());
        assert!(!window.is_github_token());
    }
    for window in Window::GITHUB_TOKEN {
        assert!(!window.is_github_token_sensitive());
    }
    assert!(!Window::H4.is_github_token_sensitive());
}
