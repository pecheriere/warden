//! The history and enrollment pages.

use super::super::{enroll, history};
use super::history_entries;
use crate::requests::LinkHosts;

#[test]
fn history_labels_every_cell_for_the_phone_cards() {
    let html = history(&history_entries(), &LinkHosts::default()).into_string();
    assert!(html.contains(r#"<table class="history">"#), "{html}");
    for label in [
        "Time",
        "Agent",
        "Goal",
        "Access",
        "Fingerprint",
        "Status",
        "Window",
    ] {
        assert_eq!(
            html.matches(&format!(r#"data-label="{label}""#)).count(),
            3,
            "{label}: {html}"
        );
        assert!(html.contains(&format!(r#"<th class="label">{label}</th>"#)));
    }
    assert!(
        html.contains(
            r#"<span><span class="nowrap">2027-01-15</span> <span class="nowrap">07:00:00 UTC</span></span>"#
        ),
        "{html}"
    );
}

#[test]
fn enroll_page_keeps_the_script_hooks() {
    let html = enroll().into_string();
    for hook in [
        r#"<label class="label" for="code">Enrollment code</label>"#,
        r#"<input class="input" id="code" type="text" autocomplete="one-time-code""#,
        r#"<label class="label" for="label">Name for this passkey</label>"#,
        r#"<input class="input" id="label" type="text" autocomplete="off" maxlength="64""#,
        r#"<button class="btn approve" id="enroll" type="button">"#,
        r#"<p class="result" id="result" role="status"></p>"#,
    ] {
        assert!(html.contains(hook), "{hook}: {html}");
    }
}
