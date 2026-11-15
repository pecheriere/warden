//! End to end: `warden hook check` from the real `warden` binary, fed a Claude
//! Code `PreToolUse` event on standard input. The environment is a throwaway
//! one: `HOME`, the XDG directories and `TMPDIR` all point into a temporary
//! directory, so nothing here reads the configuration of whoever runs it.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};
use tempfile::TempDir;

const SWITCH_CACHE: &str = r#"{
    "ssh_targets": [
        { "name": "switch-01", "users": ["admin"], "max_window": "30m",
          "mode": "direct",
          "destination": { "host": "switch-01.example.internal", "port": 22 } }
    ],
    "api_secrets": [],
    "github": { "configured": false, "max_window": null },
    "commit_signing": { "available": false },
    "releases": { "available": false },
    "unavailable": []
}"#;

const CONFIG: &str = "server = \"https://warden.example.ts.net/\"\nagent = \"build-agent\"\n";

struct Env {
    root: TempDir,
}

impl Env {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        for sub in ["home", "config/warden", "state/warden", "tmp"] {
            fs::create_dir_all(root.path().join(sub)).unwrap();
        }
        Self { root }
    }

    fn path(&self, sub: &str) -> PathBuf {
        self.root.path().join(sub)
    }

    fn write_config(&self, text: &str) {
        fs::write(self.path("config/warden/config.toml"), text).unwrap();
    }

    fn write_cache(&self, text: &str) {
        fs::write(self.path("state/warden/offers-cache.json"), text).unwrap();
    }

    fn check(&self, stdin: &[u8]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_warden"))
            .args(["hook", "check"])
            .env_clear()
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("XDG_STATE_HOME", self.path("state"))
            .env("TMPDIR", self.path("tmp"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // The command may exit before it reads everything: ignore a broken pipe.
        let _ = child.stdin.take().unwrap().write_all(stdin);
        child.wait_with_output().unwrap()
    }
}

fn bash_event(command: &str, mode: Option<&str>) -> Vec<u8> {
    let mut event = json!({
        "session_id": "s",
        "cwd": "/work",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    });
    if let Some(mode) = mode {
        event["permission_mode"] = json!(mode);
    }
    serde_json::to_vec(&event).unwrap()
}

fn answer(out: &Output) -> Value {
    assert!(out.status.success(), "exit {:?}", out.status);
    assert!(out.stderr.is_empty(), "stderr is not empty");
    let text = std::str::from_utf8(&out.stdout).unwrap();
    assert_eq!(text.matches('\n').count(), 1, "one line");
    serde_json::from_str(text).unwrap()
}

fn decision(value: &Value) -> &str {
    value["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap()
}

fn reason(value: &Value) -> &str {
    value["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
}

fn assert_silent(out: &Output) {
    assert!(out.status.success(), "exit {:?}", out.status);
    assert!(out.stdout.is_empty(), "stdout is not empty");
}

#[test]
fn secret_store_without_config_asks() {
    let env = Env::new();
    let out = env.check(&bash_event("op read x", None));
    assert_eq!(decision(&answer(&out)), "ask");
}

#[test]
fn bypass_permissions_denies_instead_of_asking() {
    let env = Env::new();
    let out = env.check(&bash_event("op read x", Some("bypassPermissions")));
    assert_eq!(decision(&answer(&out)), "deny");
}

#[test]
fn covered_host_without_cache_is_silent() {
    let env = Env::new();
    let out = env.check(&bash_event("ssh switch-01.example.internal", None));
    assert_silent(&out);
}

#[test]
fn covered_host_with_cache_is_denied_naming_the_request() {
    let env = Env::new();
    env.write_cache(SWITCH_CACHE);
    let out = env.check(&bash_event("ssh switch-01.example.internal", None));
    let value = answer(&out);
    assert_eq!(decision(&value), "deny");
    assert!(reason(&value).contains("warden request ssh switch-01"));
}

#[test]
fn ssh_alias_reaches_a_covered_host() {
    let env = Env::new();
    env.write_cache(SWITCH_CACHE);
    fs::create_dir_all(env.path("home/.ssh")).unwrap();
    fs::write(env.path("home/.ssh/config"), "Include conf.d/*.conf\n").unwrap();
    fs::create_dir_all(env.path("home/.ssh/conf.d")).unwrap();
    fs::write(
        env.path("home/.ssh/conf.d/lab.conf"),
        "Host lab\n  HostName switch-01.example.internal\n",
    )
    .unwrap();
    let out = env.check(&bash_event("ssh lab", None));
    assert_eq!(decision(&answer(&out)), "deny");
}

#[test]
fn garbage_stdin_is_silent() {
    let env = Env::new();
    assert_silent(&env.check(b"not json at all"));
    assert_silent(&env.check(b""));
}

#[test]
fn event_over_the_cap_is_silent() {
    let env = Env::new();
    let command = format!("op read {}", "x".repeat(70_000));
    assert_silent(&env.check(&bash_event(&command, None)));
}

#[test]
fn read_tool_event_is_silent() {
    let env = Env::new();
    let event = json!({
        "tool_name": "Read",
        "tool_input": { "file_path": "/work/op" },
    });
    assert_silent(&env.check(&serde_json::to_vec(&event).unwrap()));
}

#[test]
fn invalid_hook_table_adds_its_note_to_the_reason() {
    let env = Env::new();
    env.write_config(&format!("{CONFIG}\n[hook]\nsecret-store = \"sometimes\"\n"));
    let out = env.check(&bash_event("op read x", None));
    let value = answer(&out);
    assert_eq!(decision(&value), "ask");
    let lines: Vec<&str> = reason(&value).lines().collect();
    assert!(lines.len() >= 2, "the note is its own line");
    assert!(
        lines.last().unwrap().contains("hook"),
        "note names the table"
    );
}

#[test]
fn hook_table_can_turn_a_signal_off() {
    let env = Env::new();
    env.write_config(&format!("{CONFIG}\n[hook]\nsecret-store = \"off\"\n"));
    assert_silent(&env.check(&bash_event("op read x", None)));
}
