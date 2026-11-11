//! What the approval, pending, grants and history pages say about a release.

use super::super::{approve, grants};
use super::release_fixtures::{
    CHANGELOG, COMMIT, HALFWAY, KEY, release_facts, release_grants, release_pages, release_view,
};
use super::{NOW, idle};
use crate::requests::{LinkHosts, ReleaseProgress};

fn page(facts: crate::requests::ReleaseFacts) -> String {
    approve(&release_view(facts), &LinkHosts::default(), NOW).into_string()
}

#[test]
fn approve_page_shows_release_facts() {
    let html = page(release_facts(Some(CHANGELOG)));
    for says in [
        "example-owner/example-repo",
        "v1.2.3",
        COMMIT,
        KEY,
        "Add the release workflow",
        "2026-11-07T10:30:00Z",
        "on the default branch",
        "- The release workflow.",
        "sign and create tag v1.2.3",
        "sign example-1.2.3-SHA256SUMS",
        "publish the draft",
        "For at most 1 day, and it ends when the last step is done.",
        r#"href="https://github.com/example-owner/example-repo/compare/v1.2.2...0123456789abcdef0123456789abcdef01234567""#,
        r#"rel="noopener noreferrer""#,
    ] {
        assert!(html.contains(says), "{says}: {html}");
    }
    // One window, already chosen: there is nothing to pick.
    assert_eq!(html.matches(r#"name="window""#).count(), 1, "{html}");
    assert!(html.contains(r#"value="1d" checked>"#), "{html}");
    assert!(!html.contains("tag is already in place"), "{html}");
    assert!(!html.contains("Cut at 16 KiB"), "{html}");

    let mut first = release_facts(Some(CHANGELOG));
    first.previous_tag = None;
    let html = page(first);
    assert!(
        html.contains(&format!(
            r#"href="https://github.com/example-owner/example-repo/commit/{COMMIT}""#
        )),
        "{html}"
    );
    assert!(!html.contains("/compare/"), "{html}");

    let html = page(release_facts(None));
    assert!(
        html.contains("No changelog section for this version."),
        "{html}"
    );
    assert!(!html.contains("<pre"), "{html}");
}

#[test]
fn approve_page_escapes_changelog() {
    let hostile =
        "<script>alert(1)</script>\n\u{1b}[31mred & \"quoted\"\u{7}\tkept\r\u{202e}\u{200b}";
    let mut facts = release_facts(Some(hostile));
    facts.commit_title = "<img src=x onerror=1> \u{1b}[2J".to_owned();
    let html = page(facts);
    assert!(
        html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "{html}"
    );
    assert!(
        html.contains(r"\u{1b}[31mred &amp; &quot;quoted&quot;"),
        "{html}"
    );
    assert!(html.contains("\\u{7}\tkept"), "{html}");
    assert!(html.contains(r"\u{d}"), "{html}");
    assert!(html.contains(r"\u{202e}\u{200b}"), "{html}");
    assert!(
        html.contains("&lt;img src=x onerror=1&gt; \\u{1b}[2J"),
        "{html}"
    );
    assert!(!html.contains("<script>"), "{html}");
    assert!(!html.contains("<img"), "{html}");
    for raw in ['\u{1b}', '\u{7}', '\r', '\u{202e}', '\u{200b}'] {
        assert!(!html.contains(raw), "{raw:?} reached the page");
    }
}

#[test]
fn approve_page_cut_changelog_note() {
    let cut = format!("- {}\n\u{2026}(cut)", "x".repeat(100));
    let html = page(release_facts(Some(&cut)));
    assert!(html.contains("Cut at 16 KiB"), "{html}");
    assert!(html.contains("\u{2026}(cut)"), "{html}");
}

#[test]
fn approve_page_tag_in_place() {
    let mut facts = release_facts(Some(CHANGELOG));
    facts.tag_in_place = true;
    let html = page(facts);
    assert!(
        html.contains("The tag is already in place on this commit."),
        "{html}"
    );
    assert!(!html.contains("sign and create tag"), "{html}");
    assert!(html.contains("sign example-1.2.3-SHA256SUMS"), "{html}");
    assert!(html.contains("publish the draft"), "{html}");
}

#[test]
fn grants_page_lists_steps() {
    let list = release_grants(HALFWAY);
    let html = grants(&list, &idle(&list), &LinkHosts::default(), NOW, 0).into_string();
    assert!(
        html.contains(
            "sign and create tag v1.2.3: <strong class=\"step-state complete\">done</strong>"
        ),
        "{html}"
    );
    assert!(
        html.contains("sign example-1.2.3-SHA256SUMS: <span class=\"step-state\">not yet</span>"),
        "{html}"
    );
    assert!(
        html.contains("publish the draft: <span class=\"step-state\">not yet</span>"),
        "{html}"
    );
    assert!(html.contains("example-owner/example-repo"), "{html}");
    assert!(html.contains(r#"data-kind="release""#), "{html}");

    let all = ReleaseProgress {
        tag: true,
        manifest: true,
        publish: true,
    };
    let list = release_grants(all);
    let html = grants(&list, &idle(&list), &LinkHosts::default(), NOW, 0).into_string();
    assert_eq!(html.matches(">done</strong>").count(), 3, "{html}");
    assert!(!html.contains("not yet"), "{html}");
}

#[test]
fn release_grant_has_no_renew() {
    let list = release_grants(HALFWAY);
    let html = grants(&list, &idle(&list), &LinkHosts::default(), NOW, 0).into_string();
    assert!(html.contains(">Revoke</button>"), "{html}");
    assert!(!html.contains("Renew"), "{html}");
    assert!(!html.contains(r#"class="renew""#), "{html}");
}

#[test]
fn pending_and_history_name_the_release() {
    for (name, html) in release_pages() {
        if name == "pending-release" || name == "history-release" {
            assert!(html.into_string().contains("v1.2.3"), "{name}");
        }
    }
}
