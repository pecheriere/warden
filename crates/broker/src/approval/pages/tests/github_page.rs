//! What the approval page says about the repositories of a GitHub token request.

use super::github_fixtures::{
    LONG, REPO, TAP, access, automatic_view, github_view, multi_view, page, replaces_view,
    resolved, scoped, unreachable_view,
};

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
            r#"<span class="repos"><code><bdi>{REPO}</bdi></code>"#
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
            "This request cannot be approved: the App is not installed on {REPO}, {TAP}, or \
             one of them does not exist."
        )),
        "{html}"
    );
    assert!(!html.contains(r#"id="approve""#), "{html}");
    assert!(html.contains(r#"id="deny""#), "{html}");
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
