//! What the approval and grants pages say about the extra permissions of a GitHub
//! token request: how they are marked, and the windows offered with them.

use warden_broker_proto::github_permissions::{Permission, SENSITIVE, sensitive_meaning};
use warden_broker_proto::github_token::GithubTokenAccess;
use warden_broker_proto::github_token::GrantScope;

use super::github_fixtures::{
    REPO, extras_view, github_view, grant_with_extras, name, page, resolved, scope_of, scoped,
};
use crate::approval::pages::grants;
use crate::requests::LinkHosts;

const READ_AND_WRITE: &str = "actions:read,checks:read,deployments:write,metadata:read";
const SENSITIVE_REQUEST: &str = "checks:read,metadata:read,secrets:read,workflows:write";

fn offered(html: &str) -> Vec<&str> {
    ["15m", "30m", "1h", "4h", "1d", "7d", "30d"]
        .into_iter()
        .filter(|w| html.contains(&format!(r#"value="{w}""#)))
        .collect()
}

#[test]
fn page_marks_read_and_write_extras_apart() {
    let html = page(&extras_view(READ_AND_WRITE));
    for says in [
        r#"<code class="perm extra-read">actions: read</code>"#,
        r#"<code class="perm extra-read">checks: read</code>"#,
        r#"<code class="perm extra-write">deployments: write</code>"#,
        // The owner's default is not an extra.
        r#"<code class="perm">contents: write</code>"#,
        r#"<code class="perm">metadata: read</code>"#,
    ] {
        assert!(html.contains(says), "{says}: {html}");
    }
    assert!(!html.contains("sensitive"), "{html}");
}

#[test]
fn page_counts_extras_beyond_default() {
    let html = page(&extras_view(READ_AND_WRITE));
    assert!(html.contains("3 beyond the default"), "{html}");
    let none = page(&github_view(
        GithubTokenAccess::new(vec![name(REPO)], None, None).unwrap(),
        Some(resolved(vec![scoped(1001, REPO, None)])),
    ));
    assert!(!none.contains("beyond the default"), "{none}");
}

#[test]
fn page_marks_sensitive_permissions_with_their_meaning() {
    let html = page(&extras_view(SENSITIVE_REQUEST));
    // Red wins over the read and write styles.
    for says in [
        r#"<code class="perm sensitive">secrets: read</code>"#,
        r#"<code class="perm sensitive">workflows: write</code>"#,
        r#"<code class="perm extra-read">checks: read</code>"#,
    ] {
        assert!(html.contains(says), "{says}: {html}");
    }
    assert!(!html.contains("extra-write"), "{html}");
    assert!(html.contains("Sensitive permissions"), "{html}");
    // The text is the one for the level shown: names only for `secrets: read`.
    for text in ["secrets:read", "workflows:write"] {
        let meaning = sensitive_meaning(&text.parse::<Permission>().unwrap());
        assert!(html.contains(&format!(" can {meaning}.")), "{text}: {html}");
    }
    assert!(
        html.contains("can list the names of the repository&#39;s secrets")
            || html.contains("can list the names of the repository's secrets"),
        "{html}"
    );
    assert!(
        html.contains(
            "can change GitHub Actions workflows, which run with the repository's secrets."
        ),
        "{html}"
    );
    // The permission that is not sensitive has no meaning line.
    assert_eq!(html.matches(" can ").count(), 2, "{html}");
}

#[test]
fn every_sensitive_permission_is_marked() {
    for name in SENSITIVE {
        let html = page(&extras_view(&format!("{name}:read,metadata:read")));
        assert!(
            html.contains(&format!(
                r#"<code class="perm sensitive">{name}: read</code>"#
            )),
            "{name}: {html}"
        );
    }
}

#[test]
fn sensitive_request_page_offers_short_windows_only() {
    let html = page(&extras_view(SENSITIVE_REQUEST));
    assert_eq!(offered(&html), ["15m", "30m", "1h"], "{html}");
    // The request asks for 30 minutes, which the page starts on, with nothing to
    // explain.
    assert!(
        html.contains(r#"<input id="window-30m" type="radio" name="window" value="30m" checked>"#),
        "{html}"
    );
    assert!(!html.contains("Asked for"), "{html}");
}

#[test]
fn request_without_a_sensitive_extra_offers_long_windows() {
    let html = page(&extras_view(READ_AND_WRITE));
    assert_eq!(offered(&html), ["1d", "7d", "30d"], "{html}");
    assert!(html.contains(r#"value="30d" checked"#), "{html}");
}

#[test]
fn not_approvable_extra_is_in_the_notice_and_names_are_code() {
    let mut view = extras_view("checks:read,metadata:read");
    view.github.as_mut().unwrap().not_allowed = vec!["checks:read".parse().unwrap()];
    let html = page(&view);
    assert!(
        html.contains(r#"<p class="cannot" id="cannot-approve" role="alert">"#),
        "{html}"
    );
    assert!(html.contains("<code>checks:read</code>."), "{html}");
    assert!(!html.contains(r#"id="approve""#), "{html}");
}

#[test]
fn grants_page_shows_extras() {
    let list = vec![grant_with_extras(
        12,
        scope_of(&[(1001, REPO)]),
        Some("checks:read,deployments:write,metadata:read,workflows:write"),
    )];
    let html = grants(
        &list,
        &super::idle(&list),
        &LinkHosts::default(),
        super::NOW,
        0,
    )
    .into_string();
    for says in [
        r#"<code class="perm extra-read">checks: read</code>"#,
        r#"<code class="perm extra-write">deployments: write</code>"#,
        r#"<code class="perm sensitive">workflows: write</code>"#,
        "3 extra",
        "Sensitive permissions",
    ] {
        assert!(html.contains(says), "{says}: {html}");
    }
    // A grant without extras shows none.
    let plain = vec![grant_with_extras(13, GrantScope::Legacy, None)];
    let html = grants(
        &plain,
        &super::idle(&plain),
        &LinkHosts::default(),
        super::NOW,
        0,
    )
    .into_string();
    assert!(!html.contains("extra"), "{html}");
}
