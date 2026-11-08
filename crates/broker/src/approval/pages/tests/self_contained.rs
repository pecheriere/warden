//! Every page loads nothing but the broker's own stylesheet and script.

use std::path::PathBuf;

use super::super::super::STYLESHEET;
use super::pages;

/// The text of every tag (`<...>`) in `html`. Maud escapes `<` and `>` in
/// text and attribute values, so tags split cleanly; text content (such
/// as an API origin shown to the owner) is not a resource reference and
/// is left out.
fn tags(html: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find('<') {
        let after = &rest[start..];
        let end = after.find('>').expect("unterminated tag");
        found.push(&after[..=end]);
        rest = &after[end + 1..];
    }
    found
}

fn assert_self_contained(name: &str, html: &str) {
    assert!(!html.contains("style="), "{name}: inline style attribute");
    assert!(!html.contains("<style"), "{name}: style element");
    assert!(!html.contains("<img"), "{name}: image element");
    for tag in tags(html) {
        // The one thing a page may point away with, and only for someone to
        // open: not a resource the page loads.
        if tag.starts_with(r#"<a class="stated-link" href="https://"#)
            && tag.ends_with(r#" target="_blank" rel="noopener noreferrer">"#)
        {
            continue;
        }
        let without_svg = tag.replace("http://www.w3.org/2000/svg", "");
        assert!(
            !without_svg.contains("http://") && !without_svg.contains("https://"),
            "{name}: external origin in {tag}"
        );
        if tag.starts_with("<link") {
            assert_eq!(
                tag, r#"<link rel="stylesheet" href="/static/warden.css">"#,
                "{name}: unexpected link"
            );
        }
        if tag.starts_with("<script") {
            assert_eq!(
                tag, r#"<script src="/static/warden.js" defer>"#,
                "{name}: unexpected script"
            );
        }
    }
}

#[test]
fn every_page_renders_self_contained() {
    let out = std::env::var_os("WARDEN_RENDER_PAGES_DIR").map(PathBuf::from);
    if let Some(dir) = &out {
        std::fs::create_dir_all(dir.join("static")).unwrap();
        std::fs::write(dir.join("static/warden.css"), STYLESHEET).unwrap();
    }
    for (name, page) in pages() {
        let html = page.into_string();
        assert_self_contained(name, &html);
        if let Some(dir) = &out {
            std::fs::write(dir.join(format!("{name}.html")), &html).unwrap();
        }
    }
}

#[test]
fn the_self_contained_check_catches_violations() {
    for bad in [
        r#"<p style="color:red">x</p>"#,
        "<style>p{}</style>",
        r#"<img src="/x.png">"#,
        r#"<link rel="stylesheet" href="https://cdn.example.com/a.css">"#,
        r#"<script src="https://cdn.example.com/a.js"></script>"#,
        r#"<a href="http://example.com">x</a>"#,
        r#"<link rel="stylesheet" href="/static/other.css">"#,
    ] {
        assert!(
            std::panic::catch_unwind(|| assert_self_contained("bad", bad)).is_err(),
            "not caught: {bad}"
        );
    }
    assert_self_contained(
        "svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg"></svg><p>https://api.example.com</p>"#,
    );
}
