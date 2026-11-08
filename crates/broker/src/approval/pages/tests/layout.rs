//! The layout every page shares: navigation, inline icons and end states.

use super::super::{
    approve, cancelled, grants, history, internal_error, not_found, not_pending, unavailable,
};
use super::{NOW, agent, api_destination, api_request, goal, pending};
use crate::requests::LinkHosts;

#[test]
fn marks_the_current_page_in_the_navigation() {
    let html = grants(&[], &[], &LinkHosts::default(), NOW, 0).into_string();
    // Both the inline links and the menu's copy mark it.
    assert_eq!(
        html.matches(r#"<a href="/grants" aria-current="page">"#)
            .count(),
        2,
        "{html}"
    );
    assert!(
        !html.contains(r#"<a href="/history" aria-current"#),
        "{html}"
    );
    let html = not_found().into_string();
    assert!(!html.contains("aria-current"), "{html}");
    assert!(html.contains("viewport-fit=cover"), "{html}");
    assert!(
        html.contains("<summary class=\"menu\" aria-label=\"Menu\">"),
        "{html}"
    );
}

#[test]
fn inline_svg_shapes_are_closed() {
    // In inline SVG an unclosed `<rect>` would swallow the shapes after it.
    let html = approve(
        &pending(
            agent("build-agent"),
            api_request(goal("Read device status"), &["GET"]),
            api_destination(),
        ),
        &LinkHosts::default(),
        NOW,
    )
    .into_string();
    for shape in ["rect", "circle", "path", "ellipse"] {
        assert_eq!(
            html.matches(&format!("<{shape} ")).count(),
            html.matches(&format!("</{shape}>")).count(),
            "{shape}: {html}"
        );
    }
    assert!(html.contains(r#"<svg class="mascot" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" aria-hidden="true">"#));
}

#[test]
fn end_states_show_the_mascot_in_a_halo_with_a_chip() {
    for (name, page) in [
        ("not_pending", not_pending()),
        ("cancelled", cancelled()),
        ("not_found", not_found()),
        ("unavailable", unavailable("x")),
        ("internal_error", internal_error()),
        (
            "grants_empty",
            grants(&[], &[], &LinkHosts::default(), NOW, 0),
        ),
        ("history_empty", history(&[], &LinkHosts::default())),
    ] {
        let html = page.into_string();
        assert!(
            html.contains(r#"<main class="done"><div class="halo"><svg class="mascot" "#),
            "{name}: {html}"
        );
        assert!(
            html.contains(r#"<span class="chip center"><svg "#),
            "{name}: {html}"
        );
        // Header mascot, menu icon, halo mascot, chip icon: all decoration.
        assert_eq!(html.matches(r#"aria-hidden="true""#).count(), 4, "{name}");
        assert!(!html.contains("<script"), "{name}: {html}");
    }
    assert!(
        not_pending()
            .into_string()
            .contains(r#"<a class="btn ghost block" href="/pending">View pending requests</a>"#)
    );
}

#[test]
fn unavailable_escapes_and_isolates_the_message() {
    let html = unavailable("<b>\u{202e}x").into_string();
    assert!(
        html.contains("<strong><bdi>&lt;b&gt;\u{202e}x</bdi></strong>"),
        "{html}"
    );
}
