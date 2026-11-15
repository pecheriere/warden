# The warden agent plugin: know when to use warden, notice going around it (#199)

Status: draft for the owner's review, 2026-11-15. Builder check done; its
open questions are answered below.

Statements are tagged: (owner's decision) the owner decided it; (owner's idea)
the owner proposed it, in #199 or in the design conversation; **[call]** the
designer's call, open to the owner's veto; **[guess]** an assumption about how
things work that the builder must check.

## Why

A session that has not been told about warden does what it would do without
it. #199 records one using the owner's own SSH key, from their password
manager, for a host warden had a target for: a biometric prompt per
connection, no approval, no audit entry. The same happens with secrets read
through `op read` or from a dotfile, where `warden http` would have made the
call without the agent ever seeing the secret. (owner's idea, #199)

`warden prime` (#246) now tells a session what the broker offers and how to
ask, but something has to run it, and nothing notices the moment a session
reaches for the owner's credentials instead. Owners also need a place for
their own rules about one machine, which `prime` leaves out on purpose.
(owner's decision, recorded on #199)

This is a product feature, for any warden owner who runs coding agents, not a
setup for one machine. (owner's decision)

## What success looks like

- An owner runs one command per machine, and from then on every agent session
  there starts knowing what warden covers, plus the owner's own rules.
- A session about to use the owner's key or a secret for something warden
  covers is stopped or warned, with the warden command to use instead, before
  the command runs.
- A session reaching for a host or API warden does not cover tells the owner
  to add it to warden, instead of quietly using their credentials.
- Owners keep the hook on, because it is quiet when nothing is wrong.

## Goals

1. **A Claude Code plugin** in this repository, which also serves as its
   marketplace, installed once per machine at user scope. (owner's decision:
   approach A)
2. **`warden hook session-start`**: prints `warden prime --brief`, then the
   owner's rules file, and refreshes the cache the check reads.
3. **`warden hook check`**: reads one Claude Code `PreToolUse` event for the
   Bash tool on stdin, decides, and prints the hook's answer. All detection
   lives here, in Rust, tested with the CLI. (owner's decision: approach A)
4. **Per-signal settings**, chosen by the owner: `block`, `ask`, `warn` or
   `off` for each kind of signal. (owner's decision: configurable by the user)
5. **`warden setup claude`**: installs the plugin.
6. Docs: `docs/agent-usage.md` (the plugin as the way to set up a session),
   `docs/configuration.md` (the settings and rules file), the README,
   `docs/threat-model.md` and `docs/security-assessment.md` (what the hook is
   and is not), `CHANGELOG.md`.

## Non-goals

- **A security boundary.** The agent runs as the same user as the hook and its
  config. A determined agent can edit the config, obfuscate a command, or call
  a credential through a tool the hook does not see. The hook catches honest
  mistakes, the #199 kind. warden's boundary stays where it is: the agent never
  holds the secret or the key. The docs and threat model say so. **[call]**
- **Agents other than Claude Code**, in this issue. `warden hook check` takes a
  documented input so another agent's adapter can call it later; for agents
  without hooks, `docs/agent-usage.md` keeps the one-line rule from #246.
  Follow-up issue. **[call]**
- **Hooks on tools other than Bash** (file reads of `~/.netrc`, web fetches).
  The Bash tool is where #199 happened. Follow-up if it proves needed. **[call]**
- **Writing to the owner's Claude settings files.** That was approach B,
  dropped: it edits a file the owner manages, the same mistake as a global
  `warden setup git` on a shared user. (owner's decision)

## Anti-goals

Any of these makes the feature a failure even if it works:

- The hook or plugin text teaches a way around a denial, or nudges an agent to
  ask for more than the task needs (#78). Every message points to `warden
  request` with an honest goal, or to the owner.
- A message, log line or error contains a secret, or any part of the command
  beyond the host, origin or tool the signal names. Commands carry tokens.
- False positives that make owners turn it off. A pattern that cannot be told
  apart from ordinary work is `warn` or not shipped.
- The plugin keeps its own copy of instructions or patterns, and drifts from
  the CLI. It holds wiring only.
- The check slows every shell command: it makes no network call.

## Approaches

The owner picked **A**. (owner's decision)

- **A. A thin plugin, with the logic in the `warden` CLI.** The plugin is
  `hooks.json` calling `warden hook session-start` and `warden hook check`.
  Detection is Rust, tested and linted with the CLI, released with it, fed by
  the broker's offers, and reusable by other agents. Cost: the plugin and the
  CLI must agree on a version.
- **B. `warden setup claude` writes hooks into `~/.claude/settings.json`.** No
  plugin. Dropped: it edits a file the owner manages (often a dotfiles link),
  and upgrades and uninstalls are fragile.
- **C. A self-contained plugin with a script.** Ships without a CLI release,
  but untested, needs an interpreter, and duplicates the patterns, which drift.

## Design

### The plugin

`.claude-plugin/marketplace.json` at the repository root lists one plugin,
`warden`, at `plugins/warden/`. **[call]** The plugin holds:

- `.claude-plugin/plugin.json`: name, description, and `version` equal to the
  workspace version, bumped by the release pull request with the rest.
- `hooks/hooks.json`:
  - `SessionStart` (every source: startup, resume, clear, compact): `warden
    hook session-start`, with a timeout of about 5 seconds.
  - `PreToolUse` with matcher `Bash`: `warden hook check`, with a timeout of
    about 2 seconds.
- Nothing else: no skills, no instructions, no patterns. `warden prime` is the
  long form, and sessions run it before their first request, as it already
  says. **[call]**

If `warden` is missing or too old to know `hook`, the hook command fails; Claude
Code shows a hook error and the session goes on. The plugin's README says to
upgrade. **[guess]** that a failed `SessionStart` or `PreToolUse` command does
not block the session or the tool call: the builder checks the current Claude
Code hook semantics and picks the exit code that warns without blocking.

### `warden hook session-start`

Prints, in order:

1. the output of `warden prime --brief` (the same function, not a subprocess);
2. the owner's rules file, if it exists, under a heading such as "The owner's
   rules for this machine";

then refreshes the offers cache (below), within `prime`'s existing 3-second
limit. It always exits 0 and always prints something useful, like `prime`.
**[call]**

**The owner's rules file** is `agent-rules.md` next to the CLI's config
(`$XDG_CONFIG_HOME/warden/` or `~/.config/warden/`). It is printed as is, up to
a size cap (8 KiB **[call]**), with a line saying it was cut if longer. A
missing file prints nothing; an unreadable one prints a line saying so.
**[call]**

### `warden hook check`

Input: the `PreToolUse` JSON on stdin. It reads `tool_name` and
`tool_input.command`; any other tool, or input it cannot parse, gets "no
opinion" (exit 0, no output). The input is untrusted and size-limited (64 KiB
**[call]**). **[guess]** the exact field names and the output schema
(`hookSpecificOutput.permissionDecision` of `deny` or `ask` with a reason, and a
way to add a non-blocking warning to the model's context): the builder checks
the current Claude Code hooks reference.

It splits the command into simple commands (pipes, `;`, `&&`, `||`, subshells,
`$(...)`, `bash -c`/`sh -c` one level deep) with a shell-word tokenizer, and
matches each against the signals below. It decides from the strongest setting
among the matches, and says which signals matched and what to run instead. No
network: it reads the offers cache only.

It must never panic, and gets a `cargo-fuzz` target (its input is untrusted
and parsed), checking the property that the output never contains a token
from the input other than the named host, origin or tool. **[call]**

### Signals and their default settings

| Signal | Matches | Default |
|---|---|---|
| `covered-ssh` | `ssh`, `scp`, `sftp`, `rsync -e ssh`, `git` over SSH, to a host the offers list as an SSH target, not through `warden ssh` | `block` |
| `covered-api` | `curl`, `wget`, `http`/`xh` to an origin the offers list for an API secret, not through `warden http` | `block` |
| `owner-ssh-key` | `ssh -i`, `-o IdentityAgent=`, `IdentityFile=`, or `SSH_AUTH_SOCK=` set on the command, for any host | `ask` |
| `secret-store` | `op read`, `op run`, `op item get`, `op inject`; `security find-generic-password -w`; `pass`, `gopass`, `bw get` | `ask` |
| `token-read` | reading a known credential file (`~/.netrc`, `~/.config/gh/hosts.yml`, `.env*`), or `gh auth token` | `ask` |
| `owner-github` | plain `gh` with no `GH_TOKEN` on the command, or `git push` to github.com in a checkout whose `.git/config` has no warden credential helper, when the offers say GitHub tokens are configured | `warn` |
| `uncovered-host` | `ssh` or an HTTP client with an `Authorization` header or token flag, to a host or origin warden does not cover | `warn`, with the "ask the owner to add it" text |

**warden's own routes are exempt.** A command run through `warden ssh` or
`warden http`, an `ssh -F <file>` whose file is one `warden ssh-config` wrote,
and an `IdentityAgent` socket under the CLI's grant socket directory
(`agent.rs`) are warden, not a bypass: neither `covered-ssh` nor
`owner-ssh-key` fires. The check knows these from their paths, without reading
grant records. **[call]**

**Matching a host.** An SSH destination matches a target when the command's
host is the target's listed host, the target's name used as an alias (`ssh
<target>`), or an alias in `~/.ssh/config` whose `HostName` is the target's
host. The check reads `~/.ssh/config` and one level of `Include` itself, with
no subprocess. This is what catches the #199 shape: an alias for a covered
host whose `IdentityAgent` is the owner's password manager. A test builds that
case. **[call]**

**Items listed by name only, or hidden.** The offers give a host or origin only
for items listed `full`. For a `name` item the check matches the target name as
an alias and nothing else; a `hidden` item is invisible to it. So
`uncovered-host` never says a host *is not* in warden: it says "warden does not
list this host here", and that the owner can add it if it is missing.
There is no broker change to expose destinations to the hook: an owner who
hid an item chose that, and the docs tell owners to list items `full` for the
hook to protect them. (owner's decision)

**`ask` with no one at the terminal.** In modes where Claude Code cannot show
the prompt (headless, some background agents), `ask` does what Claude Code does
with an unanswered permission prompt. **[guess]** that this denies rather than
allows: the builder checks, and if any mode turns an `ask` into an allow, `ask`
is sent as `deny` there, with the same message. **[call]**

Defaults are **[call]**: block where warden covers that exact destination
(the #199 case), ask where the signal is real but the destination is not known
to be covered. The builder may drop or demote a pattern that tests show is
noisy, and records it in the pull request.

**Messages.** Each names the signal, the host, origin or tool, and the warden
way: for `covered-ssh`, `warden status`, then `warden request ssh <target>
--user <user> --for 15m --goal "..."` and `warden ssh <target> -- <cmd>`; for
`uncovered-host`, that the owner can add a target or secret item
(`docs/1password-items.md`) so the next session goes through warden, and that
the session must not use the owner's credentials meanwhile. Wording follows
`guidance.rs`: the next step is never a way around the owner.

### Settings

A `[hook]` table in the CLI's existing `config.toml`, one key per signal:

```toml
[hook]
covered-ssh = "block"
covered-api = "block"
owner-ssh-key = "ask"
owner-github = "warn"
secret-store = "ask"
token-read = "ask"
uncovered-host = "warn"
```

Missing keys take the defaults. An unknown key or value makes the check fall
back to the defaults and say once, in its output, that the setting is invalid
and which: a typo must not switch protection off. **[call]** `warden doctor`
reports an invalid `[hook]` table. **[call]** Settings live with warden, not in
Claude Code's plugin options, so other agents' adapters share them. **[call]**

### The offers cache

`session-start` writes the broker's offers (as `warden list --json` returns
them) to a file in the CLI's state directory, 0600, atomically. `check` reads
it. With no cache, or one older than 24 hours **[call]**, `covered-*` signals
cannot match, so `check` falls back to the destination-free signals and
`uncovered-host` is not raised (it cannot tell covered from uncovered). It
never fails the tool call for a missing cache. **[call]**

### `warden setup claude`

Runs `claude plugin marketplace add` for this repository, pinned to the
release tag matching the CLI's own version, then `claude plugin install
warden@warden` at user scope. **[guess]** that the marketplace source accepts a
tag: the builder checks, and if not, finds the supported way to keep the
plugin from getting ahead of the installed CLI. It touches nothing else, needs
no grant, and `--dry-run` prints the commands. If `claude` is not on the PATH,
it prints the `/plugin` commands to run instead. **[call]**

## Testing

- Table tests for the tokenizer and every signal, positive and negative,
  including the false-positive cases (`ssh-keygen`, `git` over HTTPS, `curl` to
  an uncovered origin with no credentials, `op --version`).
- A test that no output contains secret-looking input (a token after `-H`, a
  password in a URL).
- Settings: defaults, each value, invalid table falls back to defaults.
- `session-start`: rules file present, missing, unreadable, too long; broker
  unreachable.
- An end-to-end test that feeds a recorded `PreToolUse` event to the built
  binary and checks the JSON answer against the schema.
- `claude plugin validate plugins/warden` in CI, if available without network
  access. **[guess]**

## Left to the builder

- Exact hook output schema and exit codes, from the current Claude Code docs.
- The tokenizer: a small hand-written one or a vetted crate (with
  `cargo deny` and the 7-day age rule).
- Where detection lives so the fuzz workspace can reach it: the CLI crate has
  no library target today, so a lib target or a small new crate.
- Splitting the work into pull requests; a likely order is `warden hook check`
  with signals and settings, `owner-github` in a later one than the SSH and API
  signals (owner's decision), then `session-start` and the rules file, then the
  plugin files and `warden setup claude`, then docs.
