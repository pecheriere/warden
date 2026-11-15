# Agent plugin (#199) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Claude Code plugin, shipped from this repository, that starts every session with `warden prime --brief` and the owner's rules, and checks each shell command for a way around warden.

**Architecture:** Detection is a pure library crate, `crates/hook` (`warden-agent-hook`): a shell tokenizer, the signals, the settings and the matching, with no I/O, so it is unit-tested and fuzzed. The CLI adds `warden hook check` and `warden hook session-start`, which gather the inputs (offers cache, `~/.ssh/config`, `[hook]` settings, the checkout's git config), call the library and speak Claude Code's hook JSON. The plugin under `plugins/warden/` is wiring only; `warden setup claude` installs it.

**Tech Stack:** Rust (workspace toolchain, clippy pedantic denied), serde/serde_json/toml (already workspace dependencies), cargo-fuzz, Claude Code plugin manifests (JSON).

**Spec:** `docs/superpowers/specs/2026-11-15-agent-plugin-design.md` (approved 2026-11-15). Read it first; this plan cites its sections and does not repeat them.

## Global Constraints

- No `#[allow]`/`#[expect]` without a comment saying why; `unsafe_code` forbidden; clippy `all` + `pedantic` deny.
- Every line of output is free of secrets: a message names only the signal, the host, origin or tool, never any other token of the command (spec, Anti-goals).
- Every message points to `warden status` / `warden request … --goal "…"` or to the owner, never a way around a denial (`crates/cli/src/guidance.rs` wording style).
- `warden hook check` makes no network call and must answer within the hook timeout of 2 s; `warden hook session-start` keeps `prime`'s 3 s broker limit and always exits 0.
- Input to `check` is capped at 64 KiB; the owner's rules file is printed up to 8 KiB, with a line saying it was cut.
- The offers cache is stale after 24 hours.
- Setting values: `block`, `ask`, `warn`, `off`. Defaults: `covered-ssh = block`, `covered-api = block`, `owner-ssh-key = ask`, `secret-store = ask`, `token-read = ask`, `uncovered-host = warn`, `owner-github = warn`.
- An invalid `[hook]` table falls back to all defaults and says so; it never turns protection off.
- Public repository: tests and docs use generic names only (`build-agent`, `home-api`, `switch-01`, `warden.example.ts.net`, `192.0.2.0/24`).
- No new third-party dependency: the tokenizer is hand-written. **[call]**
- Files stay under about 800 lines of code; tests go in `<module>/tests.rs` as the CLI already does. `crates/cli/src/doctor.rs` is at 727 lines of code: the `[hook]` check lives in `hook/settings.rs` and doctor calls it in one line.
- Commits use `git commit -s`. One pull request per group below, each naming #199.

## Pull requests

1. **PR 1, detection library** (Tasks 1–5): no user-visible change.
2. **PR 2, the hook commands** (Tasks 6–8): `warden hook check`, `warden hook session-start`, `[hook]` settings, docs for them.
3. **PR 3, the plugin and its install** (Tasks 9–10): plugin files, version guard, `warden setup claude`, the user-facing docs and threat model.
4. **PR 4, GitHub signal** (Task 11). (owner's decision: later than the SSH and API signals)

## Review Focus

1. **A legitimate warden route flagged.** `warden ssh pi -- uptime`, `ssh -F <file written by warden ssh-config> pi`, `-o IdentityAgent=$TMPDIR/warden-<uid>/x.sock` must not fire `covered-ssh` or `owner-ssh-key`. Tests in Task 4.
2. **A secret in the command echoed.** `curl -H "Authorization: Bearer abc123" https://home-api.example.internal/x`, `op read op://vault/item/password`, `https://user:hunter2@host/` produce messages without `abc123`, `vault/item`, `hunter2`. Test in Task 4 and the fuzz property in Task 5.
3. **Ordinary work flagged.** `ssh-keygen -t ed25519`, `git push` over HTTPS, `curl https://example.com`, `op --version`, `cat README.md`, `echo ssh pi` produce no match. Test in Task 4.
4. **Nested and quoted commands.** `bash -c 'ssh pi'`, `x=$(op read op://v/i/f)`, `` `ssh pi` ``, `cd dir && ssh pi | tee log` are matched; `echo 'ssh pi'` and a heredoc body are not. Tests in Task 1.
5. **A broken environment blocks work.** No config, no cache, stale cache, unreadable `~/.ssh/config`, malformed hook input: `check` gives no opinion or a destination-free answer, never an error exit that blocks the tool. Tests in Task 7.

---

### Task 1: Crate and shell tokenizer

**Files:**
- Create: `crates/hook/Cargo.toml`, `crates/hook/src/lib.rs`, `crates/hook/src/shell.rs`, `crates/hook/src/shell/tests.rs`
- Modify: `Cargo.toml` (members, `[workspace.dependencies] warden-agent-hook = { path = "crates/hook", version = "0.15.0" }`)

**Interfaces:**
- Produces:
  - `pub struct SimpleCommand { pub env: Vec<(String, String)>, pub argv: Vec<String> }`
  - `pub fn simple_commands(input: &str) -> Vec<SimpleCommand>` — never panics, returns what it could split.

- [ ] **Step 1: Write the failing tests** in `shell/tests.rs`, one per row, each asserting the `argv` lists (and `env` where shown):

| Input | Expected `argv`s |
|---|---|
| `ssh pi uptime` | `[ssh, pi, uptime]` |
| `cd d && ssh pi \| tee log; ls` | `[cd, d]`, `[ssh, pi]`, `[tee, log]`, `[ls]` |
| `SSH_AUTH_SOCK=/x ssh h` | env `[(SSH_AUTH_SOCK, /x)]`, argv `[ssh, h]` |
| `bash -c 'ssh pi'` | `[bash, -c, ssh pi]`, `[ssh, pi]` |
| `x=$(op read op://v/i/f)` | `[op, read, op://v/i/f]` (and the assignment-only command with empty argv dropped) |
| `` echo `ssh pi` `` | `[echo, ssh pi]`, `[ssh, pi]` |
| `echo 'ssh pi'` | `[echo, ssh pi]` only |
| `"ss"h pi` | `[ssh, pi]` |
| `cat <<EOF\nssh pi\nEOF` | `[cat]` only |
| `ssh pi 'a; b'` | `[ssh, pi, a; b]` |
| unterminated `ssh 'pi` | `[ssh, pi]` (best effort, no panic) |

- [ ] **Step 2: Run** `cargo nextest run -p warden-agent-hook` — expect compile failure.
- [ ] **Step 3: Implement** `simple_commands` in `shell.rs`: a single-pass scanner over chars handling `'…'`, `"…"` (with `\` escapes and `$(…)` inside), `\`, operators `; & && || | |& ( ) \n`, `$(…)` and backticks (recursed, depth limit 4), heredoc bodies skipped (`<<WORD`, `<<-WORD`, quoted words), comments after unquoted `#` at word start, redirections (`>f`, `2>&1`, `<f`) dropped from argv. Leading `NAME=value` words are `env`. `bash|sh|zsh|dash -c <string>` (also after `env`, `sudo`, `nohup`, `exec`, `command`, `time`) recurses into the string once. **[call]**: `sudo`/`env`/`nohup`/`exec`/`command`/`time` prefixes are stripped from `argv` by a helper `fn effective_argv(&SimpleCommand) -> &[String]` used by detection, not by the tokenizer.
- [ ] **Step 4: Run** the tests — PASS. Also `cargo clippy -p warden-agent-hook --all-targets -- -D warnings`.
- [ ] **Step 5: Commit** `Add the warden-agent-hook crate with a shell tokenizer (#199)`.

### Task 2: Signals and settings

**Files:**
- Create: `crates/hook/src/settings.rs`, `crates/hook/src/settings/tests.rs`

**Interfaces:**
- Produces:
  - `pub enum Signal { CoveredSsh, CoveredApi, OwnerSshKey, SecretStore, TokenRead, UncoveredHost, OwnerGithub }` with `pub const ALL: [Signal; 7]` and `pub fn key(self) -> &'static str` (`covered-ssh` …, the spec's names).
  - `pub enum Setting { Off, Warn, Ask, Block }` — `Ord` in that order, so the strongest wins with `max`.
  - `pub struct Settings` with `pub fn get(&self, Signal) -> Setting` and `impl Default` (Global Constraints values).
  - `pub fn Settings::from_table(table: Option<&toml::Table>) -> (Settings, Option<String>)`: the `String` is the "invalid setting" note naming the bad key or value, and when present the settings are all defaults.
- Modify: `crates/hook/Cargo.toml` (add `toml.workspace = true`).

- [ ] **Step 1: Failing tests:** `defaults_match_spec` (each of the seven), `missing_table_is_defaults`, `partial_table_keeps_other_defaults` (`covered-ssh = "warn"` changes only that), `unknown_key_falls_back` (`covered-shh = "off"` → defaults, note contains `covered-shh`), `unknown_value_falls_back` (`secret-store = "never"` → defaults, note contains `never`), `non_string_value_falls_back`, `block_is_strongest` (`Setting::Block > Ask > Warn > Off`).
- [ ] **Step 2: Run** — fail. **Step 3: Implement.** **Step 4: Run** — pass, clippy clean.
- [ ] **Step 5: Commit** `Hook signals and per-signal settings (#199)`.

### Task 3: What warden covers, SSH aliases and warden's own routes

**Files:**
- Create: `crates/hook/src/context.rs`, `crates/hook/src/context/tests.rs`
- Modify: `crates/hook/Cargo.toml` (add `warden-broker-proto.workspace = true`)

**Interfaces:**
- Consumes: `warden_broker_proto::offers::{Offers, SshTargetOffer, ApiSecretOffer}`.
- Produces:
  - `pub struct Coverage { pub ssh: Vec<SshCover>, pub api: Vec<ApiCover>, pub github: bool }`, `pub struct SshCover { pub name: String, pub host: Option<String> }`, `pub struct ApiCover { pub name: String, pub origin: Option<String> }`; `impl From<&Offers> for Coverage`. `Coverage::default()` means "unknown": no cache.
  - `pub struct SshAliases` with `pub fn parse(text: &str, include: &dyn Fn(&str) -> Option<String>) -> SshAliases` and `pub fn host_for(&self, alias: &str) -> Option<&str>`: `Host` patterns without wildcards mapped to their `HostName`; one level of `Include` through the callback; `Match` blocks ignored; case-insensitive keywords; `Key=Value` and `Key Value` forms.
  - `pub struct Context { pub coverage: Option<Coverage>, pub aliases: SshAliases, pub warden_socket_dir: PathBuf, pub read_small_file: Box<dyn Fn(&Path) -> Option<String>>, pub github_helper: Option<bool> }` — `coverage: None` when the cache is missing or stale; `read_small_file` caps at 64 KiB; `github_helper` is whether the checkout's git config names `warden git-credential` (`None` outside a checkout). Task 11 is the only reader of `github_helper`.
  - `pub fn Context::is_warden_socket(&self, path: &str) -> bool` (the literal path starts with `warden_socket_dir/`; no `~` or variable expansion, so an unexpanded path is not exempt) and `pub fn Context::is_warden_ssh_config(&self, file: &str) -> bool` (the file reads, and every `IdentityAgent` in it is a warden socket, and it has at least one).
  - `pub fn Coverage::ssh_target_for(&self, host_or_alias: &str, aliases: &SshAliases) -> Option<&SshCover>`: matches the listed host, the target name used as an alias, or an `~/.ssh/config` alias whose `HostName` is the listed host; hosts compared case-insensitively. `pub fn Coverage::api_for(&self, url: &str) -> Option<&ApiCover>`: origin compare (scheme, host, port with defaults) via `url::Url` (`url` is already a workspace dependency; add it).
- [ ] **Step 1: Failing tests:** `name_listed_target_matches_by_name_only`, `full_target_matches_host_and_name`, `alias_with_hostname_matches` (the #199 shape: `Host lab\n HostName switch-01.example.internal\n IdentityAgent ~/pw-manager/agent.sock` + a target with host `switch-01.example.internal` → `ssh lab` matches), `include_one_level`, `wildcard_hosts_ignored`, `api_origin_default_port`, `api_other_origin_no_match`, `warden_socket_prefix`, `warden_ssh_config_needs_all_agents_under_prefix`, `unreadable_file_is_not_warden`.
- [ ] **Step 2–4:** fail, implement, pass + clippy.
- [ ] **Step 5: Commit** `Hook context: covered destinations, ssh aliases, warden routes (#199)`.

### Task 4: Detection and messages for SSH, API and secrets

**Files:**
- Create: `crates/hook/src/detect.rs`, `crates/hook/src/detect/ssh.rs`, `crates/hook/src/detect/http.rs`, `crates/hook/src/detect/secrets.rs`, `crates/hook/src/detect/tests.rs`, `crates/hook/src/message.rs`

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces:
  - `pub struct Match { pub signal: Signal, pub subject: String }` — `subject` is the host, origin or tool name only.
  - `pub struct Verdict { pub setting: Setting, pub matches: Vec<Match>, pub message: String, pub settings_note: Option<String> }`; `setting` is the max over matches' settings, `Off` with no matches (and then `message` is empty).
  - `pub fn check(command: &str, ctx: &Context, settings: &Settings) -> Verdict`.
  - `message::render(&[Match], &Coverage-or-None) -> String`.

Signals, per the spec's table and rules (spec, "Signals and their default settings"):

- `covered-ssh`: `ssh`, `scp`, `sftp`, `rsync` with `-e ssh…` or `host:path`, `git` with `ssh://` or `user@host:` remotes in argv; destination from the first non-option argument (`user@host`, `host:path`, `ssh://user@host:port/`), with the option arguments of `-p -l -i -o -F -J -E -c -b -L -R -D -W -S -O -Q` skipped. Fires when `coverage.ssh_target_for` matches and the command is not a warden route.
- `covered-api`: `curl`, `wget`, `http`, `https`, `xh` with a URL whose origin `api_for` matches.
- `owner-ssh-key`: `ssh`/`scp`/`sftp` with `-i`, `-o IdentityFile=…` (not `none`), `-o IdentityAgent=…`, or env `SSH_AUTH_SOCK`, unless the agent is a warden socket or `-F` is a warden ssh-config.
- `secret-store`: `op read|run|item get|inject`, `security find-generic-password|find-internet-password` with `-w` or `-g`, `pass show|<name>` (not `pass ls|init|git`), `gopass show|<name>`, `bw get`.
- `token-read`: `cat|less|more|head|tail|bat|grep|rg|sed|awk|jq|source|.` with an argument whose last path components are `.netrc`, `.config/gh/hosts.yml`, `.env` or `.env.<x>`; and `gh auth token`.
- `uncovered-host`: only when `coverage` is `Some`; `ssh` (any destination not covered) or an HTTP client with `-H`/`--header` `Authorization:`, `-u user:…`, `--oauth2-bearer`, or credentials in the URL, to an origin not covered. Message says "warden does not list this host here", never "is not in warden".
- With `coverage: None`, the two `covered-*` signals and `uncovered-host` never fire.

Messages: one paragraph per match, with the exact next step: `covered-ssh` → `warden status`, then `warden request ssh <target> --user <user> --for 15m --goal "<what and why>"` (users from the cover when known, else `<user>`) and `warden ssh <target> -- <command>`; `covered-api` → `warden request api <secret> …` and `warden http <secret> <METHOD> <url> --fail`; `owner-ssh-key`, `secret-store`, `token-read` → "this uses the owner's own credentials; if warden covers it, use warden (`warden list`); if not, ask the owner to add it to warden (docs/1password-items.md); do not use the owner's credentials meanwhile"; `uncovered-host` → the "ask the owner to add a target or API secret item" text. End every message with "Never look for another way in." The settings note, when present, is appended as its own line.

- [ ] **Step 1: Failing tests** in `detect/tests.rs`, table-driven with a fixture context (target `switch-01` host `switch-01.example.internal`, users `[build-agent]`; target `lab-pi` listed by name; secret `home-api` origin `https://home-api.example.internal`; socket dir `/tmp/warden-501`):
  - positive: `ssh switch-01.example.internal`, `ssh build-agent@switch-01`, `scp f switch-01:/tmp`, `rsync -a d switch-01.example.internal:/x`, `git clone ssh://git@switch-01.example.internal/r`, `ssh lab-pi`, `ssh lab` (alias fixture), `curl https://home-api.example.internal/api/states` → covered; `ssh -i ~/.ssh/id host`, `SSH_AUTH_SOCK=/x ssh host`, `op read op://v/i/f`, `op run -- env`, `security find-generic-password -s x -w`, `cat ~/.netrc`, `source .env`, `gh auth token` → their signal; `ssh other.example.org` and `curl -H 'Authorization: Bearer t' https://api.example.org` → `uncovered-host`.
  - Review Focus 1 (warden routes): `warden ssh switch-01 -- uptime`, `warden http home-api GET https://home-api.example.internal/api --fail`, `ssh -o IdentityAgent=/tmp/warden-501/abc.sock switch-01`, `ssh -F <fixture warden config> switch-01` → no match.
  - Review Focus 3 (ordinary work): `ssh-keygen -t ed25519`, `git push origin main`, `curl https://example.com`, `op --version`, `cat README.md`, `echo ssh switch-01`, `grep ssh notes.txt` → no match.
  - Review Focus 2 (no secret echoed): for each of `curl -H "Authorization: Bearer abc123" https://home-api.example.internal/x`, `op read op://vault-x/item-y/password`, `curl https://user:hunter2@api.example.org/`, `ssh -i /secret/path/key host`, assert the message contains none of `abc123`, `vault-x`, `item-y`, `hunter2`, `/secret/path` and does contain the subject.
  - strongest wins: a command with `secret-store` (ask) and `covered-ssh` (block) → `Block`; all `off` → no matches reported.
  - `coverage: None` → `ssh switch-01.example.internal` gives no `covered-ssh` and no `uncovered-host`, while `op read …` still gives `secret-store`.
- [ ] **Step 2–4:** fail, implement, pass + clippy.
- [ ] **Step 5: Commit** `Hook detection: SSH, API, secret stores and token files (#199)`.

### Task 5: Fuzz target

**Files:**
- Create: `fuzz/fuzz_targets/hook_check.rs`, `fuzz/seeds/hook_check/` (a few commands from Task 4's tables, generic names only)
- Modify: `fuzz/Cargo.toml` (`warden-agent-hook = { path = "../crates/hook", version = "0.15.0" }`, `[[bin]] hook_check`), `fuzz/Cargo.lock` (`cargo update --workspace` in `fuzz/`)

- [ ] **Step 1:** Write the target: input bytes → UTF-8 lossy command; fixed fixture context as in Task 4 with `read_small_file` returning `None`; call `check`. Property: for every whitespace-separated token of the input that is at least 8 chars, contains a char outside `[A-Za-z0-9.-]`, and is not a `subject` of any match, `!verdict.message.contains(token)`. **[call]**: the property is limited to such tokens because subjects and fixed message words legitimately appear.
- [ ] **Step 2: Run** `scripts/fuzz.sh 60 hook_check` — no crash, no property failure. `cargo clippy` and `cargo fmt --check` from `fuzz/`.
- [ ] **Step 3: Run the PR 1 gate** (AGENTS.md "Before you push", all lines; `cargo deny --manifest-path fuzz/Cargo.toml check` and the `cargo metadata --locked` fuzz line included).
- [ ] **Step 4: Commit** `Fuzz the hook check (#199)`; open PR 1.

### Task 6: `[hook]` settings in the CLI config, and doctor

**Files:**
- Modify: `crates/cli/src/config.rs` (field on `Config`), `crates/cli/Cargo.toml` (`warden-agent-hook.workspace = true`), `crates/cli/src/doctor.rs` (one call)
- Create: `crates/cli/src/hook.rs`, `crates/cli/src/hook/settings.rs`, `crates/cli/src/hook/tests.rs`

**Interfaces:**
- Produces:
  - `Config.hook: Option<toml::Table>` with `#[serde(default, skip_serializing_if = "Option::is_none")]`: kept raw so `warden login`, which rewrites the file, preserves it. **[call]**
  - `hook::settings::load() -> (warden_agent_hook::Settings, Option<String>)`: reads `config_path()`; a missing or unreadable config gives defaults and no note (doctor reports config problems already).
  - `hook::settings::doctor_line() -> Option<String>`: `Some("hook settings: <note>")` when the table is invalid.
- [ ] **Step 1: Failing tests:** `login_rewrite_keeps_hook_table` (load a config with `[hook] covered-ssh = "warn"`, `save_to`, reload, table equal), `invalid_table_is_reported_by_doctor_line`, `missing_config_gives_defaults`.
- [ ] **Step 2–4:** fail, implement, pass. Add the doctor line where doctor lists its local checks (as a failed check with the note).
- [ ] **Step 5: Commit** `Read [hook] settings from the CLI config (#199)`.

### Task 7: `warden hook check`

**Files:**
- Create: `crates/cli/src/hook/check.rs`, `crates/cli/src/hook/cache.rs`, `crates/cli/src/hook/claude.rs`, `crates/cli/tests/e2e_hook.rs`
- Modify: `crates/cli/src/cli.rs` (`Cmd::Hook { what: HookCmd }`, `HookCmd::{Check, SessionStart}`, listed in the help as "Run by an agent's hooks"), `crates/cli/src/main.rs` (dispatch; both exit 0 on their own errors)

**Interfaces:**
- Consumes: Tasks 2–4, Task 6.
- Produces:
  - `hook::cache::write(offers_json: &serde_json::Value) -> Result<()>` — `state_dir()/offers-cache.json`, 0600, write to a temp file and rename; `hook::cache::read(now) -> Option<Offers>` — `None` if missing, unreadable, unparsable or older than 24 h (file mtime).
  - `hook::claude::parse_event(stdin: &[u8]) -> Option<String>` — the command, only for `tool_name == "Bash"`; `None` for anything else or over 64 KiB.
  - `hook::claude::answer(&Verdict) -> Option<serde_json::Value>`.
  - `hook::check::run()` — reads stdin (capped), builds `Context` (cache, `~/.ssh/config` via `dirs::home_dir`, socket dir = the value `agent::socket_dir()` gives, made `pub(crate)`), loads settings, prints `answer` or nothing; always exit 0.

- [ ] **Step 0: Verify the hook contract** against the current Claude Code hooks documentation (ask the `claude-code-guide` agent type, or read the docs): the `PreToolUse` input fields, the output JSON for deny / ask / a non-blocking note to the model, the exit-code semantics, and what `ask` does in non-interactive (`-p`) and background-agent modes. Record the findings at the top of `hook/claude.rs` as a doc comment with the doc URL. The expected shape is `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"|"ask","permissionDecisionReason":"…"}}`, and for `warn` an `additionalContext` (or equivalent) that does not change the decision. **If any mode turns `ask` into an allow, `answer` sends `deny` instead in that mode** (spec, "`ask` with no one at the terminal"), detected from the input's permission-mode field if one exists; otherwise always `ask` and document it.
- [ ] **Step 1: Failing tests:** `answer` maps `Block → deny`, `Ask → ask`, `Warn → note only`, `Off → None`; `parse_event` ignores `Read` events, invalid JSON, 65 KiB input; cache round trip, stale after 24 h (set the mtime with std's `File::set_modified`), unparsable → `None`. Review Focus 5 in `e2e_hook.rs`: run the built `warden hook check` with `XDG_CONFIG_HOME`/`XDG_STATE_HOME`/`HOME` pointed at temp dirs: no config + `op read x` event → `ask` JSON; no cache + `ssh switch-01.example.internal` → no output, exit 0; garbage stdin → no output, exit 0; with a cache fixture + `ssh switch-01.example.internal` → `deny` JSON whose reason names `warden request ssh switch-01`.
- [ ] **Step 2–4:** fail, implement, pass.
- [ ] **Step 5: Commit** `warden hook check (#199)`.

### Task 8: `warden hook session-start`, the rules file, docs for PR 2

**Files:**
- Create: `crates/cli/src/hook/session_start.rs`
- Modify: `crates/cli/src/prime.rs` (expose the brief text and the raw offers body from one broker call), `docs/configuration.md` (the `[hook]` table, values, defaults, the rules file path and cap), `docs/agent-usage.md` (the two hook commands), `CHANGELOG.md` (Unreleased: `warden hook check`, `warden hook session-start`, `[hook]` settings)

**Interfaces:**
- Consumes: `prime` internals, Task 7's `cache::write`.
- Produces:
  - `prime::brief_and_offers(limit: Duration) -> (String, Option<serde_json::Value>)`: the same text `prime --brief` prints, plus the offers body when the broker answered; `prime::run` uses it, so the two cannot differ.
  - `hook::session_start::run()`: prints the brief; then, if `config_dir/agent-rules.md` exists, `\n## The owner's rules for this machine\n\n` and the file up to 8 KiB (cut at a char boundary, then `\n(cut: the file is longer than 8 KiB)\n`); an unreadable file prints `warden: the owner's rules file cannot be read.`; then writes the cache if offers came back. Exit 0 always.
- [ ] **Step 1: Failing tests:** `rules_appended_after_brief`, `missing_rules_prints_brief_only`, `long_rules_are_cut_with_note` (9 KiB of multibyte text, no panic, note present), `unreadable_rules_prints_line` (chmod 000; skip assertion when running as root, documented), `prime_brief_unchanged` (existing prime tests still pass).
- [ ] **Step 2–4:** fail, implement, pass.
- [ ] **Step 5: Run the PR 2 gate** (all AGENTS.md lines), **commit** `warden hook session-start and the owner's rules file (#199)`, open PR 2.

### Task 9: Plugin files and the version guard

**Files:**
- Create: `.claude-plugin/marketplace.json`, `plugins/warden/.claude-plugin/plugin.json`, `plugins/warden/hooks/hooks.json`, `plugins/warden/README.md`, `scripts/check-plugin-version.sh`
- Modify: `.github/workflows/ci.yml` (run the script in `lint`, next to `check-demo-not-shipped.sh`), `AGENTS.md` ("Before you push" list; Releases step 1 bumps `plugins/warden/.claude-plugin/plugin.json`; Layout table rows for `plugins/` and `.claude-plugin/`)

- [ ] **Step 0: Verify** with the current Claude Code plugin docs (or `claude plugin validate --help`): marketplace and plugin manifest fields, `hooks.json` shape, `SessionStart` matchers covering startup/resume/clear/compact, the per-hook `timeout` unit, and whether a marketplace can be added pinned to a git tag (`owner/repo` plus ref). Record in `plugins/warden/README.md`.
- [ ] **Step 1:** Write the manifests: marketplace `name: "warden"`, one plugin `warden`, `source: "./plugins/warden"`; `plugin.json` `version: "0.15.0"`; hooks: `SessionStart` → `warden hook session-start` (timeout 5 s), `PreToolUse` matcher `Bash` → `warden hook check` (timeout 2 s). README: what it does, that it is not a security boundary, `warden setup claude`, needs `warden` ≥ the plugin's version on the PATH.
- [ ] **Step 2:** `scripts/check-plugin-version.sh` (documented usage at top, like the other guards): fails unless `plugin.json` `version` equals the workspace `version` in `Cargo.toml`. Test it by hand with a wrong version (fails) and the right one (passes); add `claude plugin validate plugins/warden` to the PR description's verification if run locally.
- [ ] **Step 3:** `uvx zizmor@1.31.1 .` — no findings.
- [ ] **Step 4: Commit** `The warden Claude Code plugin and its version guard (#199)`.

### Task 10: `warden setup claude`, docs for PR 3

**Files:**
- Create: `crates/cli/src/setup_claude.rs`, `crates/cli/src/setup_claude/tests.rs`
- Modify: `crates/cli/src/cli.rs` (`SetupWhat::Claude { dry_run: bool }`), `crates/cli/src/main.rs`, `README.md`, `docs/agent-usage.md` (the plugin as the way to set up a Claude Code session; the one-line rule stays for other agents), `docs/threat-model.md` and `docs/assurance-case.md` (the hook catches mistakes, is not a boundary: same user, editable config, obfuscation), `docs/security-assessment.md` (risk entry and date), `docs/upgrading.md` (sessions get the plugin after `warden setup claude`), `CHANGELOG.md`, `site/index.html` only if it lists agent setup steps (it names no commands: check, likely no change)

**Interfaces:**
- Produces: `setup_claude::commands(version: &str) -> Vec<Vec<String>>` (pure, tested) and `setup_claude::run(dry_run: bool) -> Result<()>`.
- [ ] **Step 1: Failing tests:** `commands_pin_the_cli_version` (the marketplace-add command carries `v<version>` in the form Task 9 Step 0 found), `commands_install_at_user_scope`, `dry_run_prints_without_running`.
- [ ] **Step 2–4:** fail, implement: run each command with `std::process::Command` (no shell), stop at the first failure with its exit status; if `claude` is not on the PATH, print the equivalent `/plugin marketplace add …` and `/plugin install warden@warden` lines and exit 0. It touches no file itself.
- [ ] **Step 5: Run the PR 3 gate**, commit `warden setup claude (#199)`, open PR 3. Verification in the PR: install the plugin locally from the branch checkout (`claude plugin marketplace add <path>`), start a session, confirm the brief appears and `op read op://x/y/z` is answered with `ask`.

### Task 11: `owner-github` signal (PR 4)

**Files:**
- Create: `crates/hook/src/detect/github.rs`
- Modify: `crates/hook/src/detect.rs`, `crates/hook/src/detect/tests.rs`, `crates/cli/src/hook/check.rs` (fill `github_helper` by reading `.git/config` of the checkout found from the event's `cwd`, following a `gitdir:` file for worktrees, and `~/.gitconfig`; no subprocess), `docs/configuration.md`, `CHANGELOG.md`

- [ ] **Step 1: Failing tests:** with `coverage.github = true`: `gh pr list` → `owner-github`; `GH_TOKEN=$(warden github token --repo o/n) gh pr list` → none; `git push origin x` with `github_helper = Some(false)` and a github.com remote in argv or the fixture config → `owner-github`; `Some(true)` → none; `None` → none; `coverage.github = false` → none. Message: `GH_TOKEN=$(warden github token --repo <owner/name>) gh …` and, for `git push`, the three `git config --local credential…` lines from `docs/agent-usage.md`; never a token.
- [ ] **Step 2–4:** fail, implement, pass.
- [ ] **Step 5: Run the gate**, commit `Hook signal for the owner's GitHub login (#199)`, open PR 4, which closes #199.
