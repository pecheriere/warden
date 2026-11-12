//! Tests of the GitHub requests: the arguments, the grant check and the access of
//! the requests git and `gh` make.

use warden_broker_proto::github_token::{AutomaticCaller, GrantRepository, GrantScope};
use warden_broker_proto::release::RepoName;
use warden_broker_proto::{GithubTokenGrant, GrantAccess, GrantView, Id};

use super::{check_github_grant, several_notice, tool_access, tool_window};

fn repo(name: &str) -> RepoName {
    RepoName::try_from(name.to_owned()).unwrap()
}

/// What `warden request github ...` parses to, or the usage error.
fn parse(args: &[&str]) -> Result<Vec<RepoName>, clap::Error> {
    use clap::Parser as _;

    let mut line = vec!["warden", "request", "github"];
    line.extend_from_slice(args);
    match crate::cli::Cli::try_parse_from(line)?.command {
        crate::cli::Cmd::Request {
            kind: crate::cli::RequestKind::Github { repositories, .. },
        } => Ok(repositories),
        other => panic!("not a GitHub request: {other:?}"),
    }
}

#[test]
fn request_github_needs_a_repository() {
    assert!(parse(&["--goal", "push the fix"]).is_err());
    assert!(parse(&["--goal", "push the fix", "--for", "7d"]).is_err());
}

#[test]
fn request_github_takes_owner_and_name_repositories() {
    let got = parse(&[
        "example-owner/example-repo",
        "example-owner/homebrew-tap",
        "--goal",
        "push the fix",
    ])
    .unwrap();
    assert_eq!(
        got,
        [
            repo("example-owner/example-repo"),
            repo("example-owner/homebrew-tap")
        ]
    );
    for bad in ["example-repo", "example-owner/..", "a/b/c"] {
        assert!(parse(&[bad, "--goal", "push the fix"]).is_err(), "{bad}");
    }
}

#[test]
fn request_github_says_n_repositories() {
    assert_eq!(several_notice(1), None);
    assert_eq!(
        several_notice(3).as_deref(),
        Some("this request covers 3 repositories, and the owner sees it as such")
    );
}

fn grant(scope: GrantScope) -> GrantView {
    GrantView {
        grant_id: Id::random(),
        not_before: 0,
        not_after: 1,
        access: GrantAccess::GithubToken(GithubTokenGrant {
            app_id: "1".to_owned(),
            installation_id: 2,
            digest: "ab".repeat(16),
            repositories: scope,
        }),
    }
}

fn scope(names: &[(&str, u64)]) -> GrantScope {
    GrantScope::repositories(
        names
            .iter()
            .map(|(name, id)| GrantRepository {
                name: repo(name),
                id: *id,
            })
            .collect(),
    )
    .unwrap()
}

#[test]
fn check_grant_accepts_a_grant_covering_every_repository_whatever_the_case() {
    let granted = grant(scope(&[
        ("example-owner/example-repo", 1001),
        ("example-owner/homebrew-tap", 1002),
    ]));
    check_github_grant(&granted, &[repo("Example-Owner/Example-Repo")]).unwrap();
    check_github_grant(
        &granted,
        &[
            repo("example-owner/homebrew-tap"),
            repo("example-owner/example-repo"),
        ],
    )
    .unwrap();
}

#[test]
fn check_grant_refuses_legacy_scope() {
    let e = check_github_grant(
        &grant(GrantScope::Legacy),
        &[repo("example-owner/example-repo")],
    )
    .unwrap_err();
    assert_eq!(
        e.to_string(),
        "the broker approved an unscoped GitHub grant: upgrade the broker"
    );
}

#[test]
fn check_grant_refuses_uncovered_repository() {
    let granted = grant(scope(&[("example-owner/example-repo", 1001)]));
    let e = check_github_grant(
        &granted,
        &[
            repo("example-owner/example-repo"),
            repo("example-owner/homebrew-tap"),
        ],
    )
    .unwrap_err();
    assert!(e.to_string().contains("example-owner/homebrew-tap"), "{e}");
}

#[test]
fn check_grant_refuses_another_kind() {
    let mut other = grant(GrantScope::Legacy);
    other.access = GrantAccess::CommitSigning(warden_broker_proto::CommitSigningGrant {
        key_fingerprint: "SHA256:x".to_owned(),
        digest: "ab".repeat(16),
    });
    assert!(check_github_grant(&other, &[repo("example-owner/example-repo")]).is_err());
}

#[test]
fn a_tool_asks_for_exactly_its_repository() {
    let access = tool_access(
        AutomaticCaller::GhWrapper,
        &repo("example-owner/example-repo"),
        Some(std::path::Path::new("/src/home-api")),
    )
    .unwrap();
    assert_eq!(access.repositories, [repo("example-owner/example-repo")]);
    let automatic = access.automatic.unwrap();
    assert_eq!(automatic.by, AutomaticCaller::GhWrapper);
    assert_eq!(automatic.dir.as_deref(), Some("/src/home-api"));
    // A directory that does not fit is left out; the repository stays.
    let long = format!("/{}", "d".repeat(600));
    let access = tool_access(
        AutomaticCaller::GitCredential,
        &repo("example-owner/example-repo"),
        Some(std::path::Path::new(&long)),
    )
    .unwrap();
    assert_eq!(access.repositories.len(), 1);
    assert_eq!(access.automatic.unwrap().dir, None);
}

#[test]
fn a_request_for_git_or_gh_asks_for_no_more_than_the_broker_allows() {
    use warden_broker_proto::Window;

    assert_eq!(tool_window(None), Window::D30);
    assert_eq!(tool_window(Some(Window::D30)), Window::D30);
    assert_eq!(tool_window(Some(Window::D7)), Window::D7);
    assert_eq!(tool_window(Some(Window::D1)), Window::D1);
    // A broker that allowed longer still gets at most 30 days.
    assert_eq!(tool_window(Some(Window::D90)), Window::D30);
}
