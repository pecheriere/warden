use serde_json::{Value, json};
use warden_agent_hook::detect::Verdict;
use warden_agent_hook::settings::Setting;

use super::{answer, parse_event};

fn verdict(setting: Setting) -> Verdict {
    let message = match setting {
        Setting::Off => String::new(),
        _ => "warden: use the broker.".to_owned(),
    };
    Verdict {
        setting,
        matches: Vec::new(),
        message,
        settings_note: None,
    }
}

fn decision(value: &Value) -> Option<&str> {
    value["hookSpecificOutput"]["permissionDecision"].as_str()
}

#[test]
fn block_denies() {
    let out = answer(&verdict(Setting::Block), None, None).unwrap();
    assert_eq!(
        out,
        json!({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "warden: use the broker.",
        }})
    );
}

#[test]
fn ask_asks_without_or_with_unknown_mode() {
    let v = verdict(Setting::Ask);
    for mode in [
        None,
        Some("default"),
        Some("acceptEdits"),
        Some("plan"),
        Some("auto"),
        Some("novel"),
    ] {
        let out = answer(&v, None, mode).unwrap();
        assert_eq!(decision(&out), Some("ask"));
    }
}

#[test]
fn ask_becomes_deny_where_it_could_be_skipped() {
    let v = verdict(Setting::Ask);
    for mode in ["bypassPermissions", "dontAsk"] {
        let out = answer(&v, None, Some(mode)).unwrap();
        assert_eq!(decision(&out), Some("deny"));
    }
}

#[test]
fn warn_adds_context_only() {
    let out = answer(&verdict(Setting::Warn), None, None).unwrap();
    assert_eq!(
        out,
        json!({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": "warden: use the broker.",
        }})
    );
    assert!(out.get("systemMessage").is_none());
}

#[test]
fn off_gives_no_answer_even_with_a_note() {
    assert_eq!(answer(&verdict(Setting::Off), None, None), None);
    assert_eq!(answer(&verdict(Setting::Off), Some("note"), None), None);
}

#[test]
fn note_is_its_own_last_line() {
    for setting in [Setting::Block, Setting::Ask, Setting::Warn] {
        let out = answer(&verdict(setting), Some("a setting is invalid"), None).unwrap();
        let hook = &out["hookSpecificOutput"];
        let reason = hook
            .get("permissionDecisionReason")
            .or_else(|| hook.get("additionalContext"))
            .and_then(Value::as_str)
            .unwrap();
        assert_eq!(reason, "warden: use the broker.\na setting is invalid");
    }
}

fn event(tool: &str, input: &Value, extra: &Value) -> Vec<u8> {
    let mut body = json!({"tool_name": tool, "tool_input": input});
    if let (Some(map), Some(more)) = (body.as_object_mut(), extra.as_object()) {
        map.extend(more.clone());
    }
    serde_json::to_vec(&body).unwrap()
}

#[test]
fn parses_a_bash_event() {
    let stdin = event(
        "Bash",
        &json!({"command": "ls -l"}),
        &json!({"permission_mode": "plan", "cwd": "/work"}),
    );
    let parsed = parse_event(&stdin).unwrap();
    assert_eq!(parsed.command, "ls -l");
    assert_eq!(parsed.permission_mode.as_deref(), Some("plan"));
    assert_eq!(parsed.cwd.as_deref(), Some("/work"));
}

#[test]
fn bash_event_without_mode_has_none() {
    let stdin = event("Bash", &json!({"command": "ls"}), &json!({}));
    assert_eq!(parse_event(&stdin).unwrap().permission_mode, None);
}

#[test]
fn ignores_other_tools_and_bad_input() {
    let read = event("Read", &json!({"command": "ls"}), &json!({}));
    assert!(parse_event(&read).is_none());
    assert!(parse_event(b"not json").is_none());
    assert!(parse_event(b"").is_none());
    let numeric = event("Bash", &json!({"command": 7}), &json!({}));
    assert!(parse_event(&numeric).is_none());
    let missing = event("Bash", &json!({}), &json!({}));
    assert!(parse_event(&missing).is_none());
}

/// A Bash event of exactly `size` bytes, padded in the command.
fn sized(size: usize) -> Vec<u8> {
    let bare = event("Bash", &json!({"command": ""}), &json!({})).len();
    let command = "a".repeat(size - bare);
    let stdin = event("Bash", &json!({"command": command}), &json!({}));
    assert_eq!(stdin.len(), size);
    stdin
}

#[test]
fn input_limit_is_64_kib_inclusive() {
    assert!(parse_event(&sized(65_536)).is_some());
    assert!(parse_event(&sized(65_537)).is_none());
}
