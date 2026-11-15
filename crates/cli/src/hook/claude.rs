//! Claude Code's side of the hook: reading what it sends and answering it.
//!
//! What this relies on, verified against Claude Code 2.1.325 on 2026-11-15
//! from <https://code.claude.com/docs/en/hooks.md> and
//! <https://code.claude.com/docs/en/permission-modes.md>:
//!
//! - A `PreToolUse` hook gets one JSON object on stdin with `tool_name`,
//!   `tool_input` (for Bash `{command, description, timeout,
//!   run_in_background}`) and `permission_mode`, one of `default`, `plan`,
//!   `acceptEdits`, `auto`, `dontAsk` and `bypassPermissions`.
//! - On exit 0 its stdout is one JSON object whose
//!   `hookSpecificOutput.permissionDecision` is `deny` (the reason goes to the
//!   model) or `ask` (the reason goes to the user's prompt).
//!   `hookSpecificOutput.additionalContext` adds a string to the model's
//!   context. The docs show no example of it without a decision, so that is
//!   documented but not verified empirically. `systemMessage` reaches the
//!   user, not the model, so it is never used.
//! - An `ask` with nobody to answer (a `-p` run) becomes a deny, and
//!   `dontAsk` denies whatever would prompt. Whether an `ask` prompts in
//!   `bypassPermissions` is not documented, so in both modes an `ask` is sent
//!   as `deny`: a mode that could turn an ask into an allow gets a refusal.
//! - A timeout discards the output and does not block the tool call.

use serde_json::{Value, json};
use warden_agent_hook::detect::Verdict;
use warden_agent_hook::settings::Setting;

/// The most stdin an event may have: 64 KiB. A larger one is not parsed.
const MAX_EVENT_BYTES: usize = 65_536;

/// Modes in which an `ask` might not reach a person.
const NO_PROMPT_MODES: [&str; 2] = ["bypassPermissions", "dontAsk"];

/// The part of a `PreToolUse` event for a Bash call that the hook reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The command line Claude is about to run.
    pub command: String,
    /// Claude's `permission_mode`, when it sent one.
    pub permission_mode: Option<String>,
    /// The directory the agent works in, which relative paths in the command
    /// are relative to.
    pub cwd: Option<String>,
}

/// The Bash call in `stdin`; `None` for any other tool, input that is not
/// JSON of the expected shape, or more than 64 KiB.
#[must_use]
pub fn parse_event(stdin: &[u8]) -> Option<Event> {
    if stdin.len() > MAX_EVENT_BYTES {
        return None;
    }
    let event: Value = serde_json::from_slice(stdin).ok()?;
    if event.get("tool_name")?.as_str()? != "Bash" {
        return None;
    }
    let command = event.get("tool_input")?.get("command")?.as_str()?;
    Some(Event {
        command: command.to_owned(),
        permission_mode: event
            .get("permission_mode")
            .and_then(Value::as_str)
            .map(str::to_owned),
        cwd: event.get("cwd").and_then(Value::as_str).map(str::to_owned),
    })
}

/// What the hook prints for `verdict`, or `None` to print nothing.
///
/// The reason is the verdict's message followed by `settings_note` as its own
/// line. `ask` becomes `deny` in modes where it might not prompt.
#[must_use]
pub fn answer(
    verdict: &Verdict,
    settings_note: Option<&str>,
    permission_mode: Option<&str>,
) -> Option<Value> {
    let decision = match verdict.setting {
        Setting::Off => return None,
        Setting::Warn => None,
        Setting::Block => Some("deny"),
        Setting::Ask if permission_mode.is_some_and(|m| NO_PROMPT_MODES.contains(&m)) => {
            Some("deny")
        }
        Setting::Ask => Some("ask"),
    };
    let reason = match settings_note {
        Some(note) => format!("{}\n{note}", verdict.message),
        None => verdict.message.clone(),
    };
    let output = match decision {
        Some(decision) => json!({
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }),
        None => json!({
            "hookEventName": "PreToolUse",
            "additionalContext": reason,
        }),
    };
    Some(json!({ "hookSpecificOutput": output }))
}

#[cfg(test)]
mod tests;
