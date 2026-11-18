//! What the approval page says about the repositories of a GitHub token request.

use super::github_fixtures::{
    LONG, REPO, TAP, access, also_live_view, automatic_view, github_grant, github_view,
    history_page, multi_view, page, pending_page, permissions_view, replaces_view,
    replaces_view_with, resolved, scope_of, scoped, unreachable_view, with_checks,
};
use crate::approval::pages::grants;
use crate::requests::{ActiveGrant, LinkHosts};
use crate::requests::{GithubPending, InstallationCheck, StoredPermissions};
use warden_broker_proto::github_permissions::Permission;
use warden_broker_proto::github_token::GrantScope;

fn grants_page(list: &[ActiveGrant]) -> String {
    grants(
        list,
        &super::idle(list),
        &LinkHosts::default(),
        super::NOW,
        0,
    )
    .into_string()
}

/// How many times `needle` appears in `haystack`.
fn count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

#[test]
fn single_repository_is_the_headline() {
    let html = page(&github_view(
        access(&[REPO], None),
        Some(resolved(vec![scoped(1001, REPO, None)])),
    ));
    assert!(
        html.contains(&format!(
            r#"<span class="repos headline"><code><bdi>{REPO}</bdi></code>"#
        )),
        "{html}"
    );
    assert!(
        html.contains(&format!("Can push and merge on <bdi>{REPO}</bdi>")),
        "{html}"
    );
    assert!(
        html.contains("GitHub App <code><bdi>123456</bdi></code>"),
        "{html}"
    );
    assert!(!html.contains("This request covers"), "{html}");
    assert!(html.contains(r#"id="approve""#), "{html}");
}

#[test]
fn multi_repository_notice_and_list() {
    let html = page(&multi_view());
    assert!(
        html.contains("This request covers 3 repositories"),
        "{html}"
    );
    assert!(
        html.contains("Can push and merge on these 3 repositories"),
        "{html}"
    );
    for name in [REPO, TAP, LONG] {
        assert_eq!(
            count(&html, &format!("<bdi>{name}</bdi>")),
            1,
            "{name}: {html}"
        );
    }
    assert!(
        html.find("This request covers").unwrap() < html.find(REPO).unwrap(),
        "the notice comes first: {html}"
    );
}

#[test]
fn unreachable_has_no_approve_button() {
    let html = page(&unreachable_view());
    assert!(
        html.contains(&format!(
            "This request cannot be approved: the App is not installed on <code><bdi>{REPO}</bdi></code>, \
             <code><bdi>{TAP}</bdi></code>, or one of them does not exist."
        )),
        "{html}"
    );
    assert!(!html.contains(r#"id="approve""#), "{html}");
    assert!(html.contains(r#"id="deny""#), "{html}");
    assert!(!html.contains(r#"name="window""#), "{html}");
    assert!(!html.contains("Grant for"), "{html}");
    assert!(
        html.contains(r#"<p class="cannot" id="cannot-approve" role="alert">"#),
        "{html}"
    );
    assert!(
        html.contains(&format!(
            "<code><bdi>{REPO}</bdi></code>, <code><bdi>{TAP}</bdi></code>"
        )),
        "{html}"
    );
    assert!(!html.contains("Can push and merge"), "{html}");
}

#[test]
fn replaced_grants_are_listed() {
    let html = page(&replaces_view());
    // Replaced by name only: the stored grant has another id.
    assert!(
        html.contains(&format!(
            "Approving ends <bdi>build-agent</bdi>\u{2019}s grant for <code><bdi>{REPO}</bdi></code>"
        )),
        "{html}"
    );
    assert!(
        html.contains(&format!(
            "grant for <code><bdi>{TAP}</bdi></code>, <code><bdi>{LONG}</bdi></code>"
        )),
        "{html}"
    );
    assert_eq!(count(&html, "Approving ends"), 3, "{html}");
    assert!(
        html.contains(r#"<div class="replaces"><strong>"#)
            && html.contains("Approving also ends 3 existing grants of <bdi>build-agent</bdi>"),
        "{html}"
    );
    // The warning comes right after the reach badge, before the fine print.
    let block = html.find(r#"class="replaces""#).unwrap();
    assert!(
        html.find("Can push and merge on").unwrap() < block
            && block < html.find("Mints tokens for").unwrap()
            && block < html.find("Permissions: ").unwrap(),
        "{html}"
    );
}

#[test]
fn one_replaced_grant_is_singular() {
    let html = page(&replaces_view_with(1));
    assert!(
        html.contains("Approving also ends 1 existing grant of <bdi>build-agent</bdi>"),
        "{html}"
    );
}

#[test]
fn no_replaced_grants_no_block() {
    let html = page(&multi_view());
    assert!(!html.contains(r#"class="replaces""#), "{html}");
}

#[test]
fn legacy_replaced_grant_says_all_repositories() {
    let html = page(&replaces_view());
    assert!(
        html.contains("grant for all repositories of the installation"),
        "{html}"
    );
}

#[test]
fn automatic_label_and_dir_escaped() {
    let html = page(&automatic_view(Some("/work/example-repo")));
    assert!(
        html.contains(
            "Filed automatically by the git credential helper. Working directory: \
             <code><bdi>/work/example-repo</bdi></code>"
        ),
        "{html}"
    );
    assert!(html.contains(r#"<span class="automatic">"#), "{html}");
    let html = page(&automatic_view(Some("/work/<b>x</b>")));
    assert!(
        html.contains("<bdi>/work/&lt;b&gt;x&lt;/b&gt;</bdi>"),
        "{html}"
    );
    assert!(!html.contains("<b>x</b>"), "{html}");
    let html = page(&automatic_view(None));
    assert!(
        html.contains("Filed automatically by the git credential helper"),
        "{html}"
    );
    assert!(!html.contains("Working directory"), "{html}");
}

#[test]
fn rename_shows_both_names() {
    let html = page(&github_view(
        access(&[REPO], None),
        Some(resolved(vec![scoped(
            1001,
            "example-owner/renamed-repo",
            Some(REPO),
        )])),
    ));
    assert!(
        html.contains(&format!(
            "<code><bdi>example-owner/renamed-repo</bdi></code> (approved as \
             <code><bdi>{REPO}</bdi></code>)"
        )),
        "{html}"
    );
}

#[test]
fn page_never_says_every_repository_for_scoped() {
    for view in [
        multi_view(),
        unreachable_view(),
        replaces_view(),
        automatic_view(None),
    ] {
        let html = page(&view);
        assert!(!html.contains("every repository"), "{html}");
    }
}

#[test]
fn grants_page_lists_repositories() {
    let grants = vec![github_grant(11, scope_of(&[(1001, REPO), (1002, TAP)]))];
    let html = grants_page(&grants);
    for name in [REPO, TAP] {
        assert_eq!(
            count(&html, &format!("<li><code><bdi>{name}</bdi></code>")),
            1,
            "{html}"
        );
    }
    assert!(
        html.contains("Can push and merge on these 2 repositories"),
        "{html}"
    );
    assert!(!html.contains("every repository"), "{html}");
    assert!(!html.contains("ended at upgrade"), "{html}");
    let one = grants_page(&[github_grant(12, scope_of(&[(1001, REPO)]))]);
    assert!(
        one.contains(&format!("Can push and merge on <bdi>{REPO}</bdi>")),
        "{one}"
    );
}

#[test]
fn grants_page_shows_legacy() {
    let html = grants_page(&[github_grant(13, GrantScope::Legacy)]);
    assert!(
        html.contains("All repositories of the installation (ended at upgrade)"),
        "{html}"
    );
    assert!(!html.contains("Can push and merge"), "{html}");
    assert!(!html.contains(r#"class="renew""#), "no Renew: {html}");
    assert!(!html.contains("Mints tokens"), "{html}");
    let current = grants_page(&[github_grant(14, scope_of(&[(1001, REPO)]))]);
    assert!(current.contains(r#"class="renew""#), "{current}");
}

#[test]
fn history_names_repositories() {
    let html = history_page(&[REPO, TAP]);
    assert!(
        html.contains(&format!("github token for {REPO}, {TAP}")),
        "{html}"
    );
    assert!(
        history_page(&[]).contains("github token (all repositories)"),
        "a request from before scoping"
    );
}

#[test]
fn pending_list_names_repositories() {
    let html = pending_page(&[REPO, TAP], false);
    assert!(
        html.contains(&format!("github token for {REPO}, {TAP}")),
        "{html}"
    );
    let readable = pending_page(&[REPO, TAP], true);
    for name in [REPO, TAP] {
        assert_eq!(
            count(&readable, &format!("<bdi>{name}</bdi>")),
            1,
            "{name} once: {readable}"
        );
    }
    assert!(!readable.contains("github token for"), "{readable}");
}

#[test]
fn several_repositories_notice_is_not_a_warning() {
    let html = page(&multi_view());
    assert!(
        html.contains(r#"<p class="notice-count">This request covers 3 repositories</p>"#),
        "{html}"
    );
    assert_eq!(
        count(&html, r#"class="badge modify""#),
        1,
        "one warning: {html}"
    );
}

#[test]
fn page_lists_the_full_set() {
    let html = page(&permissions_view(with_checks(), InstallationCheck::Holds));
    for says in [
        "checks: read",
        "contents: write",
        "issues: write",
        "metadata: read",
        "pull_requests: write",
    ] {
        assert!(html.contains(says), "{says}: {html}");
    }
    assert!(!html.contains("beyond the default"), "{html}");
    assert!(html.contains(r#"id="approve""#), "{html}");
}

#[test]
fn page_says_how_many_are_beyond_the_default() {
    let mut view = permissions_view(with_checks(), InstallationCheck::Holds);
    view.github.as_mut().unwrap().permissions.beyond_default =
        vec!["checks:read".parse::<Permission>().unwrap()];
    assert!(page(&view).contains("1 beyond the default"));
}

#[test]
fn page_says_which_permissions_the_app_lacks() {
    let missing = vec![
        "checks:read".parse::<Permission>().unwrap(),
        "contents:write".parse::<Permission>().unwrap(),
    ];
    let html = page(&permissions_view(
        with_checks(),
        InstallationCheck::Missing(missing),
    ));
    assert!(
        html.contains(
            "This request cannot be approved: the App does not hold \
             <code>checks:read</code>, <code>contents:write</code> on GitHub"
        ),
        "{html}"
    );
    assert!(!html.contains(r#"id="approve""#), "{html}");
    assert!(html.contains(r#"id="deny""#), "{html}");
    assert!(html.contains("checks: read"), "{html}");
}

#[test]
fn page_says_which_extras_the_allowlist_no_longer_holds() {
    let mut view = permissions_view(with_checks(), InstallationCheck::Holds);
    view.github.as_mut().unwrap().not_allowed = vec![
        "actions:read".parse::<Permission>().unwrap(),
        "checks:read".parse::<Permission>().unwrap(),
    ];
    let html = page(&view);
    assert!(
        html.contains(
            "This request cannot be approved: this broker does not allow these extra GitHub \
             permissions: <code>actions:read</code>, <code>checks:read</code>."
        ),
        "{html}"
    );
    // One permission is "that permission", and its level is named.
    view.github.as_mut().unwrap().not_allowed = vec!["checks:write".parse().unwrap()];
    let html = page(&view);
    assert!(
        html.contains(
            "This request cannot be approved: this broker does not allow that extra GitHub \
             permission: <code>checks:write</code>."
        ),
        "{html}"
    );
    assert!(!html.contains(r#"id="approve""#), "{html}");
    assert!(html.contains(r#"id="deny""#), "{html}");
}

#[test]
fn page_says_when_installation_unreadable() {
    let html = page(&permissions_view(
        with_checks(),
        InstallationCheck::Unreadable,
    ));
    assert!(
        html.contains(
            "This request cannot be approved: the broker could not read the App\u{2019}s \
             permissions on GitHub"
        ),
        "{html}"
    );
    assert!(!html.contains(r#"id="approve""#), "{html}");
}

/// A request from before grants were scoped is `Unreadable` without a read of
/// GitHub: its page gives the legacy reason, never the one about GitHub.
#[test]
fn legacy_request_never_says_unreadable() {
    let view = github_view(
        access(&[], None),
        Some(GithubPending {
            resolution: crate::requests::Resolution::Resolved(Vec::new()),
            replaces: Vec::new(),
            also_live: Vec::new(),
            permissions: StoredPermissions::legacy(),
            not_allowed: Vec::new(),
            installation: InstallationCheck::Unreadable,
        }),
    );
    let html = page(&view);
    assert!(html.contains("it names no repository"), "{html}");
    assert!(!html.contains("could not read"), "{html}");
    assert!(!html.contains(r#"id="approve""#), "{html}");
}

#[test]
fn unreachable_repository_comes_before_the_installation() {
    let mut view = unreachable_view();
    view.github.as_mut().unwrap().installation = InstallationCheck::Unreadable;
    let html = page(&view);
    assert!(html.contains("the App is not installed on"), "{html}");
    assert!(!html.contains("could not read"), "{html}");
}

#[test]
fn replaced_grant_shows_its_permissions() {
    let html = page(&replaces_view());
    // The first holds the legacy set, the second only `contents:read`.
    assert!(
        html.contains(&format!(
            "grant for <code><bdi>{TAP}</bdi></code>, <code><bdi>{LONG}</bdi></code>. \
             Its permissions: <code class=\"perm\">contents: read</code>"
        )),
        "{html}"
    );
    assert_eq!(count(&html, "Its permissions: "), 3, "{html}");
}

#[test]
fn pending_github_lists_other_live_grants() {
    let html = page(&also_live_view());
    assert!(!html.contains(r#"class="replaces""#), "{html}");
    let block = html.find(r#"class="also-live""#).expect(&html);
    assert!(
        html.contains("<strong>Also live</strong>")
            && html.contains("Approving leaves <bdi>build-agent</bdi>\u{2019}s other grants"),
        "{html}"
    );
    // Permissions, repositories and the end, one line per grant.
    assert!(
        html[block..].contains("contents: write</code>, <code class=\"perm\">metadata: read"),
        "{html}"
    );
    // A grant's extras and sensitive permissions are marked as everywhere else.
    assert!(
        html[block..].contains(r#"<code class="perm extra-write">actions: write</code>"#),
        "{html}"
    );
    assert!(
        html[block..].contains(r#"<code class="perm sensitive">workflows: write</code>"#),
        "{html}"
    );
    assert_eq!(count(&html[block..], r#"class="perm extra-"#), 1, "{html}");
    assert_eq!(count(&html, "<li>"), 3, "{html}");
    assert!(
        html.contains(&format!(
            "<code><bdi>{REPO}</bdi></code>, <code><bdi>{TAP}</bdi></code>"
        )),
        "{html}"
    );
    // A date and a time, as the grants page shows an end: these grants can last 30 days.
    assert_eq!(count(&html[block..], ", until 20"), 3, "{html}");
    assert_eq!(count(&html[block..], " UTC</li>"), 3, "{html}");
    // Right after where the replaced block goes, before the fine print.
    assert!(
        html.find("Can push and merge on").unwrap() < block
            && block < html.find("Mints tokens for").unwrap(),
        "{html}"
    );
    // Nothing links to or acts on those grants.
    assert!(!html[block..].contains("Revoke"), "{html}");
}

#[test]
fn also_live_absent_without_other_grants() {
    for view in [multi_view(), replaces_view()] {
        let html = page(&view);
        assert!(!html.contains("also-live"), "{html}");
        assert!(!html.contains("Also live"), "{html}");
    }
}
