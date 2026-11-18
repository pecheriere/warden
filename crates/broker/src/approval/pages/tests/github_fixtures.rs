//! Fixtures for the GitHub token pages, and the pages they make for the checks
//! that render every page and for the screenshots.

use maud::Markup;
use warden_broker_proto::github_permissions::PermissionSet;
use warden_broker_proto::github_token::{
    AutomaticCaller, AutomaticRequest, GithubTokenAccess, GrantRepository, GrantScope,
};
use warden_broker_proto::release::RepoName;
use warden_broker_proto::{Access, CreateRequest, GrantAccess, Window};

use super::{NOW, active, agent, approve, fingerprint, goal, grants, history, id, idle, pending};
use crate::policy::GithubTokenPolicy;
use crate::requests::{
    Destination, GithubPending, HistoryEntry, InstallationCheck, LinkHosts, PendingEntry,
    ReplacedGrant, Resolution, ScopedRepository, StoredPermissions,
};

pub(super) const REPO: &str = "example-owner/example-repo";
pub(super) const TAP: &str = "example-owner/homebrew-tap";
pub(super) const LONG: &str =
    "example-owner/a-repository-with-a-rather-long-name-for-narrow-screens";

pub(super) fn name(text: &str) -> RepoName {
    RepoName::try_from(text.to_owned()).unwrap()
}

pub(super) fn access(names: &[&str], automatic: Option<AutomaticRequest>) -> GithubTokenAccess {
    GithubTokenAccess::new(names.iter().map(|n| name(n)).collect(), automatic, None).unwrap()
}

pub(super) fn github_token_request_for(access: GithubTokenAccess) -> CreateRequest {
    CreateRequest {
        goal: goal("Push the fix and open a pull request"),
        access: Access::GithubToken(access),
        window: Window::D30,
        session: None,
        link: None,
    }
}

fn github_token_request() -> CreateRequest {
    github_token_request_for(access(&[REPO], None))
}

pub(super) fn github_token_policy() -> GithubTokenPolicy {
    GithubTokenPolicy {
        app_id: "123456".to_owned(),
        installation_id: 7_654_321,
        max_window: Window::D30,
    }
}

pub(super) fn scoped(id: u64, text: &str, renamed_from: Option<&str>) -> ScopedRepository {
    ScopedRepository {
        id,
        name: name(text),
        renamed_from: renamed_from.map(name),
    }
}

pub(super) fn resolved(list: Vec<ScopedRepository>) -> GithubPending {
    GithubPending {
        resolution: Resolution::Resolved(list),
        replaces: Vec::new(),
        also_live: Vec::new(),
        permissions: StoredPermissions::legacy(),
        not_allowed: Vec::new(),
        installation: InstallationCheck::Holds,
    }
}

/// The legacy set and `checks:read`: wider than what a grant of 0.14 holds.
pub(super) fn with_checks() -> PermissionSet {
    PermissionSet::parse("checks:read,contents:write,issues:write,pull_requests:write").unwrap()
}

/// The single-repository page of a request holding `permissions`, which the
/// installation `installation`.
pub(super) fn permissions_view(
    permissions: PermissionSet,
    installation: InstallationCheck,
) -> crate::requests::PendingView {
    let mut github = resolved(vec![scoped(1001, REPO, None)]);
    github.permissions = StoredPermissions {
        full: permissions,
        beyond_default: Vec::new(),
    };
    github.installation = installation;
    github_view(access(&[REPO], None), Some(github))
}

pub(super) fn replaced(grant: u8, list: &[(u64, &str)]) -> ReplacedGrant {
    ReplacedGrant {
        permissions: PermissionSet::legacy(),
        not_after: NOW + 3_600,
        grant_id: id(grant),
        scope: GrantScope::repositories(
            list.iter()
                .map(|(id, text)| GrantRepository {
                    name: name(text),
                    id: *id,
                })
                .collect(),
        )
        .unwrap(),
    }
}

/// The approval page of a GitHub token request, as `view.github` says.
pub(super) fn github_view(
    access: GithubTokenAccess,
    github: Option<GithubPending>,
) -> crate::requests::PendingView {
    let mut view = pending(
        agent("build-agent"),
        github_token_request_for(access),
        Destination::GithubToken(github_token_policy()),
    );
    view.github = github;
    view
}

pub(super) fn page(view: &crate::requests::PendingView) -> String {
    approve(view, &LinkHosts::default(), NOW).into_string()
}

/// Three repositories, one with a long name.
pub(super) fn multi_view() -> crate::requests::PendingView {
    github_view(
        access(&[REPO, TAP, LONG], None),
        Some(resolved(vec![
            scoped(1001, REPO, None),
            scoped(1002, TAP, None),
            scoped(1004, LONG, None),
        ])),
    )
}

/// The App cannot reach the repository.
pub(super) fn unreachable_view() -> crate::requests::PendingView {
    github_view(
        access(&[REPO, TAP], None),
        Some(GithubPending {
            resolution: Resolution::NotAccessible,
            replaces: Vec::new(),
            also_live: Vec::new(),
            permissions: StoredPermissions::legacy(),
            not_allowed: Vec::new(),
            installation: InstallationCheck::Holds,
        }),
    )
}

/// Approving ends a grant for the same repository under another id (it was deleted
/// and recreated under the name, so only the name overlaps), one for a different
/// repository that shares the tap, and a legacy one.
pub(super) fn replaces_view() -> crate::requests::PendingView {
    replaces_view_with(3)
}

/// The same, with only the first `n` of the replaced grants.
pub(super) fn replaces_view_with(n: usize) -> crate::requests::PendingView {
    github_view(
        access(&[REPO, TAP], None),
        Some(GithubPending {
            resolution: Resolution::Resolved(vec![
                scoped(1003, REPO, None),
                scoped(1002, TAP, None),
            ]),
            also_live: Vec::new(),
            replaces: vec![
                replaced(11, &[(1001, REPO)]),
                ReplacedGrant {
                    permissions: PermissionSet::parse("contents:read").unwrap(),
                    ..replaced(12, &[(1002, TAP), (1005, LONG)])
                },
                ReplacedGrant {
                    grant_id: id(13),
                    scope: GrantScope::Legacy,
                    permissions: PermissionSet::legacy(),
                    not_after: NOW + 3_600,
                },
            ]
            .into_iter()
            .take(n)
            .collect(),
            permissions: StoredPermissions::legacy(),
            not_allowed: Vec::new(),
            installation: InstallationCheck::Holds,
        }),
    )
}

/// A request that replaces nothing, while the agent holds an everyday grant on
/// `REPO` and another on `TAP` and `LONG`, which stay.
pub(super) fn also_live_view() -> crate::requests::PendingView {
    let mut github = resolved(vec![scoped(1001, REPO, None)]);
    github.also_live = vec![
        ReplacedGrant {
            permissions: PermissionSet::parse("contents:write,pull_requests:write").unwrap(),
            not_after: NOW + 26 * 86_400,
            ..replaced(21, &[(1001, REPO), (1002, TAP)])
        },
        ReplacedGrant {
            permissions: PermissionSet::parse("actions:write").unwrap(),
            ..replaced(22, &[(1001, REPO), (1005, LONG)])
        },
    ];
    github_view(access(&[REPO], None), Some(github))
}

/// The approval page of a request for `REPO` with the extras `extras` (written form,
/// with `metadata:read`) on top of the legacy default. A request for 30 days, as an
/// agent's usual one; for 30 minutes when an extra is sensitive, which the broker
/// accepts for no longer than an hour.
pub(super) fn extras_view(extras: &str) -> crate::requests::PendingView {
    let extras = PermissionSet::parse(extras).unwrap();
    let default = PermissionSet::legacy();
    let full = default.union(&extras);
    let beyond_default = full.extras_beyond(&default).iter().collect();
    let mut github = resolved(vec![scoped(1001, REPO, None)]);
    github.permissions = StoredPermissions {
        full,
        beyond_default,
    };
    let access = GithubTokenAccess::new(vec![name(REPO)], None, Some(extras)).unwrap();
    let sensitive = access.has_sensitive_extra();
    let mut view = github_view(access, Some(github));
    if sensitive {
        view.request.window = Window::M30;
    }
    view
}

/// A request for an extra the owner's allowlist no longer holds.
fn not_allowed_view() -> crate::requests::PendingView {
    let mut view = extras_view("checks:read,metadata:read");
    view.github.as_mut().unwrap().not_allowed = vec!["checks:read".parse().unwrap()];
    view
}

/// A tool asked, from a directory.
pub(super) fn automatic_view(dir: Option<&str>) -> crate::requests::PendingView {
    github_view(
        access(
            &[REPO],
            Some(AutomaticRequest {
                by: AutomaticCaller::GitCredential,
                dir: dir.map(str::to_owned),
            }),
        ),
        Some(resolved(vec![scoped(1001, REPO, None)])),
    )
}

/// An active GitHub token grant of `scope`.
pub(super) fn github_grant(n: u8, scope: GrantScope) -> crate::requests::ActiveGrant {
    grant_with_extras(n, scope, None)
}

/// An active GitHub token grant of `scope` that was asked for `extras` (written form).
pub(super) fn grant_with_extras(
    n: u8,
    scope: GrantScope,
    extras: Option<&str>,
) -> crate::requests::ActiveGrant {
    let extras = extras.map(|e| PermissionSet::parse(e).unwrap());
    let sensitive = extras
        .as_ref()
        .is_some_and(|e| e.iter().any(|p| p.is_sensitive()));
    let full = extras
        .as_ref()
        .map_or_else(PermissionSet::legacy, |e| PermissionSet::legacy().union(e));
    let mut grant = active(
        n,
        github_token_request(),
        GrantAccess::GithubToken(github_token_policy().grant(scope, full, extras)),
    );
    // A grant with a sensitive permission lasts at most an hour, and this one has
    // 40 minutes left.
    grant.not_after = NOW + if sensitive { 40 * 60 } else { 26 * 86_400 };
    grant
}

/// A grant of the given repositories (id, name).
pub(super) fn scope_of(list: &[(u64, &str)]) -> GrantScope {
    GrantScope::repositories(
        list.iter()
            .map(|(id, text)| GrantRepository {
                name: name(text),
                id: *id,
            })
            .collect(),
    )
    .unwrap()
}

/// The pending list with one GitHub token request for `names`, whose policy was
/// readable when `readable` and not otherwise.
pub(super) fn pending_page(names: &[&str], readable: bool) -> String {
    let entry = PendingEntry {
        id: id(10),
        agent: agent("build-agent"),
        fingerprint: fingerprint(10),
        request: github_token_request_for(access(names, None)),
        destination: readable.then(|| Destination::GithubToken(github_token_policy())),
        expires_at: NOW + 240,
    };
    super::super::pending(&[entry], &LinkHosts::default(), NOW).into_string()
}

/// The history page with one GitHub token request for `names`.
pub(super) fn history_page(names: &[&str]) -> String {
    history(&[history_entry(names)], &LinkHosts::default()).into_string()
}

fn history_entry(names: &[&str]) -> HistoryEntry {
    HistoryEntry {
        id: id(10),
        agent: agent("build-agent"),
        fingerprint: fingerprint(10),
        request: github_token_request_for(access(names, None)),
        status: "approved".to_owned(),
        created_at: NOW - 600,
        granted_secs: Some(2_592_000),
    }
}

/// The pages of a GitHub token grant.
pub(super) fn github_token_pages() -> Vec<(&'static str, Markup)> {
    let legacy = vec![github_grant(10, GrantScope::Legacy)];
    let multi = vec![github_grant(
        11,
        scope_of(&[(1001, REPO), (1002, TAP), (1004, LONG)]),
    )];
    let pending_list = vec![PendingEntry {
        id: id(10),
        agent: agent("build-agent"),
        fingerprint: fingerprint(10),
        request: github_token_request(),
        destination: Some(Destination::GithubToken(github_token_policy())),
        expires_at: NOW + 240,
    }];
    let single = github_view(
        access(&[REPO], None),
        Some(resolved(vec![scoped(1001, REPO, None)])),
    );
    let lnk = LinkHosts::default();
    vec![
        ("approve-github-token", approve(&single, &lnk, NOW)),
        (
            "approve-github-token-multi",
            approve(&multi_view(), &lnk, NOW),
        ),
        (
            "approve-github-token-unreachable",
            approve(&unreachable_view(), &lnk, NOW),
        ),
        (
            "approve-github-token-replaces",
            approve(&replaces_view(), &lnk, NOW),
        ),
        (
            "approve-github-token-also-live",
            approve(&also_live_view(), &lnk, NOW),
        ),
        (
            "approve-github-token-permissions",
            approve(
                &permissions_view(with_checks(), InstallationCheck::Holds),
                &lnk,
                NOW,
            ),
        ),
        (
            "approve-github-token-app-lacks",
            approve(
                &permissions_view(
                    with_checks(),
                    InstallationCheck::Missing(vec!["checks:read".parse().unwrap()]),
                ),
                &lnk,
                NOW,
            ),
        ),
        (
            "approve-github-token-unreadable",
            approve(
                &permissions_view(with_checks(), InstallationCheck::Unreadable),
                &lnk,
                NOW,
            ),
        ),
        (
            "approve-github-token-automatic",
            approve(&automatic_view(Some("/work/example-repo")), &lnk, NOW),
        ),
        (
            "pending-github-token",
            super::super::pending(&pending_list, &lnk, NOW),
        ),
        (
            "grants-github-token-multi",
            grants(&multi, &idle(&multi), &lnk, NOW, 0),
        ),
        (
            "grants-github-token-legacy",
            grants(&legacy, &idle(&legacy), &lnk, NOW, 0),
        ),
        (
            "history-github-token",
            history(&[history_entry(&[REPO, TAP])], &lnk),
        ),
    ]
}

/// The pages of a GitHub token request or grant with extra permissions.
pub(super) fn github_extras_pages() -> Vec<(&'static str, Markup)> {
    let with_extras = vec![grant_with_extras(
        12,
        scope_of(&[(1001, REPO)]),
        Some("checks:read,deployments:write,metadata:read,workflows:write"),
    )];
    let lnk = LinkHosts::default();
    vec![
        (
            "approve-github-token-extras",
            approve(
                &extras_view("actions:read,checks:read,deployments:write,metadata:read"),
                &lnk,
                NOW,
            ),
        ),
        (
            "approve-github-token-sensitive",
            approve(
                &extras_view("checks:read,metadata:read,secrets:read,workflows:write"),
                &lnk,
                NOW,
            ),
        ),
        (
            "approve-github-token-extra-not-allowed",
            approve(&not_allowed_view(), &lnk, NOW),
        ),
        (
            "grants-github-token-extras",
            grants(&with_extras, &idle(&with_extras), &lnk, NOW, 0),
        ),
    ]
}
