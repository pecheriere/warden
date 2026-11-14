//! Free text read from storage with the rules of earlier versions, and checked
//! with the stricter ones when an agent sends it.

use serde_json::json;

use crate::{CreateRequest, Goal, SessionLabel, is_hidden_char};

/// Accepted before line and paragraph separators and blank fillers were refused.
const STORED_ONLY: [char; 6] = [
    '\u{2028}', '\u{2029}', '\u{3164}', '\u{2800}', '\u{034F}', '\u{FE00}',
];

fn request(goal: &str, session: Option<&str>) -> serde_json::Value {
    let mut value = json!({
        "goal": goal,
        "access": {"kind": "commit_signing"},
        "window": "15m",
    });
    if let Some(session) = session {
        value["session"] = json!(session);
    }
    value
}

#[test]
fn a_stored_goal_with_a_separator_or_filler_still_reads() {
    for c in STORED_ONLY {
        let text = format!("tidy{c}tests");
        let goal: Goal = serde_json::from_value(json!(text)).unwrap();
        assert_eq!(goal.as_str(), text);
        assert!(
            Goal::try_from(text.clone()).is_err(),
            "U+{:04X}",
            u32::from(c)
        );
        let stored: CreateRequest = serde_json::from_value(request(&text, None)).unwrap();
        assert!(stored.check_new().is_err(), "U+{:04X}", u32::from(c));
    }
}

#[test]
fn reading_still_refuses_what_earlier_versions_refused() {
    for text in ["a\nb", "a\u{202e}b", "a\u{200b}b", "", &"g".repeat(501)] {
        assert!(
            serde_json::from_value::<Goal>(json!(text)).is_err(),
            "{text:?}"
        );
    }
    // A label already had to be one line.
    for text in ["a\u{2028}b", "a\u{2029}b", "a\u{202e}b"] {
        assert!(
            serde_json::from_value::<SessionLabel>(json!(text)).is_err(),
            "{text:?}"
        );
    }
}

#[test]
fn a_stored_label_with_a_filler_still_reads() {
    let text = "release\u{3164}work";
    let label: SessionLabel = serde_json::from_value(json!(text)).unwrap();
    assert_eq!(label.as_str(), text);
    assert!(SessionLabel::try_from(text.to_owned()).is_err());
    let stored: CreateRequest = serde_json::from_value(request("tidy", Some(text))).unwrap();
    assert!(stored.check_new().is_err());
}

#[test]
fn a_new_request_with_ordinary_text_passes() {
    let sent: CreateRequest =
        serde_json::from_value(request("fix the ⚠️ deploy 🛠️", Some("ops ❤️"))).unwrap();
    assert!(sent.check_new().is_ok());
}

/// The presentation selectors only choose how an emoji is drawn: emoji text holds
/// them, so they are allowed, and the other variation selectors are not.
#[test]
fn emoji_presentation_selectors_are_allowed() {
    for c in ['\u{FE0E}', '\u{FE0F}'] {
        assert!(!is_hidden_char(c), "U+{:04X}", u32::from(c));
        assert!(Goal::try_from(format!("fix \u{26A0}{c} deploy")).is_ok());
        assert!(SessionLabel::try_from(format!("ops \u{2764}{c}")).is_ok());
    }
    for c in ['\u{FE00}', '\u{FE0D}', '\u{E0100}'] {
        assert!(is_hidden_char(c), "U+{:04X}", u32::from(c));
        assert!(Goal::try_from(format!("fix \u{26A0}{c} deploy")).is_err());
    }
}
