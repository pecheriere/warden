//! Accessibility that the markup and the stylesheet can prove: landmarks, the
//! pending cards' headings, and contrast computed from the real tokens.

use super::super::super::STYLESHEET;
use super::{NOW, pages, pending_entries};

/// The value of `--name` in `block`, as red, green and blue.
fn token(block: &str, name: &str) -> [f64; 3] {
    let key = format!("--{name}:#");
    let start = block.find(&key).expect(name) + key.len();
    let hex = &block[start..start + 6];
    [0, 2, 4].map(|at| f64::from(u8::from_str_radix(&hex[at..at + 2], 16).unwrap()))
}

/// The light and the dark token blocks of the stylesheet.
fn modes() -> [&'static str; 2] {
    let (light, rest) = STYLESHEET.split_once('}').unwrap();
    let dark = rest.split_once("}}").unwrap().0;
    [light, dark]
}

/// `over` at `opacity` on `under` (WCAG compositing, per channel).
fn blend(over: [f64; 3], opacity: f64, under: [f64; 3]) -> [f64; 3] {
    [0, 1, 2].map(|at| over[at] * opacity + under[at] * (1.0 - opacity))
}

/// The WCAG contrast ratio of two colours.
fn contrast(a: [f64; 3], b: [f64; 3]) -> f64 {
    let luminance = |colour: [f64; 3]| {
        let [r, g, b] = colour.map(|channel| {
            let c = channel / 255.0;
            if c <= 0.03928 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        });
        0.2126 * r + 0.7152 * g + 0.0722 * b
    };
    let (x, y) = (luminance(a), luminance(b));
    (x.max(y) + 0.05) / (x.min(y) + 0.05)
}

#[test]
fn contrast_matches_known_pairs() {
    let white = [255.0; 3];
    assert!((contrast(white, [0.0; 3]) - 21.0).abs() < 1e-9);
    assert!((contrast(white, white) - 1.0).abs() < 1e-9);
    assert_eq!(blend(white, 0.5, [0.0; 3]), [127.5; 3]);
}

#[test]
fn every_page_labels_its_two_navigation_landmarks_differently() {
    for (name, page) in pages() {
        let html = page.into_string();
        assert_eq!(html.matches("<nav ").count(), 2, "{name}: {html}");
        assert_eq!(
            html.matches(r#"<nav aria-label="Main">"#).count(),
            1,
            "{name}: {html}"
        );
        assert_eq!(
            html.matches(r#"<nav aria-label="Main menu">"#).count(),
            1,
            "{name}: {html}"
        );
    }
}

#[test]
fn every_pending_card_has_a_heading_under_the_page_title() {
    let entries = pending_entries();
    let html = super::super::pending(&entries, NOW).into_string();
    assert_eq!(html.matches("<h1").count(), 1, "{html}");
    assert_eq!(
        html.matches(r#"<h2 class="who""#).count(),
        entries.len(),
        "{html}"
    );
}

#[test]
fn selected_segment_border_keeps_three_to_one_in_both_modes() {
    assert!(
        STYLESHEET.contains(".seg input:checked+label{background:var(--raised);color:var(--ink);border-color:var(--primary);"),
        "the selected segment's border is what this test measures"
    );
    for block in modes() {
        let border = token(block, "primary");
        assert!(contrast(border, token(block, "soft")) >= 3.0, "{block}");
        assert!(contrast(border, token(block, "raised")) >= 3.0, "{block}");
    }
}

#[test]
fn ended_pending_card_text_keeps_four_and_a_half_to_one_in_both_modes() {
    let rule = ".pending.ended .field,.pending.ended .meta{opacity:";
    let start = STYLESHEET.find(rule).expect(rule) + rule.len();
    let rest = &STYLESHEET[start..];
    let opacity: f64 = rest[..rest.find('}').unwrap()].parse().unwrap();
    for block in modes() {
        let surface = token(block, "surface");
        for (ink, ground) in [
            ("muted", surface),
            ("ink", surface),
            ("soft-ink", token(block, "soft")),
            ("warn-ink", token(block, "warn-bg")),
        ] {
            let shown = blend(token(block, ink), opacity, blend(ground, opacity, surface));
            let under = blend(ground, opacity, surface);
            assert!(contrast(shown, under) >= 4.5, "{ink}: {block}");
        }
    }
}
