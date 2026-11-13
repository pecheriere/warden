# warden list and warden prime: the CLI tells an agent what it can ask for and how (#246)

Status: approved by the owner, 2026-11-12.

Statements are tagged: (owner's decision) the owner decided it; (owner's idea)
the owner proposed it; **[call]** the designer's call, open to the owner's
veto; **[guess]** an assumption about how things work that the builder must
check.

## Why

An agent learns what warden offers from a block pasted by hand into its
`AGENTS.md` or `CLAUDE.md`: `docs/agent-instructions.md`, with the owner
filling in "Available here: <the targets and users, and the secrets, this
agent may ask for>". That copy drifts from the CLI the agent runs and from
the broker's policy, and the doc tells the agent it "cannot list them, and it
should not guess". A session that never read the block does what it would do
without warden: #199 records a session using the owner's own SSH key for a
host warden had a target for. (owner's idea, #246)

The warden plugin (#199) and the owner's onboarding skill (#247) both need
the same two things this issue builds: a way to ask the broker what is on
offer, and instructions that come from the installed CLI rather than a copy.

## What success looks like

- A new session on a machine set up with warden knows, from its first turn,
  which hosts, APIs, repositories and services warden covers here, and that it
  must not go around them, without anyone pasting anything. (owner's decision)
- When the owner adds a target or secret item, the next session sees it, with
  no edit to any instructions file.
- The instructions an agent reads always match the `warden` it runs.

## Goals

- `GET /v1/offers` on the broker: what an agent may request, read from the
  policy, authenticated like the other agent calls. (owner's idea)
- `warden list` (with `--json`): prints it. Asks the person nothing, changes
  nothing, safe at any time, like `warden doctor`. (owner's idea)
- `warden prime` and `warden prime --brief`: instructions for an agent,
  printed by the CLI, with the list folded in. (owner's idea; the two sizes are
  the owner's decision)
- A per-item `list` field on SSH target and API secret items, in both secret
  backends, so the owner chooses how much each item shows. (owner's idea: a
  1Password setting per item)
- `docs/agent-instructions.md` stays the one source of the instruction text.
  (owner's decision: approach 1 below)

## Non-goals

- **Per-agent policy** (an agent sees, and may request, only some items).
  Every agent can request every item today; scoping that is its own feature
  and would change request checks, not only listing. **[call]**
- **Machine-specific or owner-specific rules.** `prime` prints only warden's
  generic instructions and what the broker offers. The plugin (#199) is where
  an owner adds their own rules on top, without touching the base
  instructions. (owner's decision; recorded on #199)
- **Installing the SessionStart hook.** That is #199's job. This issue
  documents the hook command and a one-line rule for agents without hooks.
  **[call]**
- **Checking GitHub's side of a repository's setup** (App installed, signers
  file, tag ruleset). That is #248. (owner's decision)
- **Agent-driven onboarding.** That is #247, widened on 2026-11-12. (owner's
  decision)
- **A destination lookup endpoint** ("does this host belong to a target?").
  Dropped once destinations are listed by default: the #199 hook matches
  locally against `warden list --json`. **[call]**, agreed by the owner.

## Anti-goals (a failure even if it works)

- The listing or `prime` ever carries a secret, a 1Password item id, a vault
  name, a relay credential or a key.
- A broker that is down, too old or misconfigured makes session start fail or
  hang. `prime --brief` is a hook; it must always print something useful and
  exit 0.
- `prime` teaches anything that works around a denial or asks for more than a
  task needs (the rule in #78).
- An item whose `list` value cannot be read is shown more fully than the owner
  meant.

## Design

### The `list` field on items

SSH target items (tag `warden:ssh-target`) and API secret items (tag
`warden:api-secret`) gain an optional field `list`. In the local backend it is
an optional key `list` in `[targets.<name>]` and `[api_secrets.<name>]`.
(owner's idea; values and defaults below are **[call]**s the owner agreed to)

| Value | `warden list` shows |
|---|---|
| `full` | name; what may be requested (SSH: users, longest window, mode; API: methods, path prefix, longest window); and where it points (SSH: host and port; API: origin) |
| `name` | name and what may be requested, not where it points |
| `hidden` | nothing. The item can still be requested by an agent that knows its name |

- **Missing field:** `full`. An agent on the owner's host can already see the
  network and its own SSH config, so hiding addresses by default protects
  little and costs #199 its best signal. (owner's decision)
- **Any other value** (misspelled, empty, other case): treated as `hidden` for
  listing, fail closed. The item stays usable for requests: `list` decides
  listing only, never access. **[call]**
- **Local backend:** a bad `list` value is a bad setting like any other:
  `seal-policy` refuses it and the broker refuses to start, as for every other
  `local.entries` problem. "Fail closed to hidden" applies to the 1Password
  backend, where one bad item must not take the broker down. **[call]**, from
  the builder check: `LocalBackend::open` already refuses any probe problem.
- **1Password backend:** doctor has no per-item check of SSH target and API
  secret items today (only the local backend has `local.entries`). A new
  doctor check that validates every target and secret item, `list` included,
  is its own issue (#249), not part of this one. Until it lands, an item with a bad
  `list` value, or an invalid item, silently drops out of the listing. **[call]**
- `hidden` hides the listing, not the item's existence: the broker already
  answers `unknown target <name>` for a name that does not exist, so an agent
  can test a guess one call at a time. The threat model says so. **[call]**

### Broker: `GET /v1/offers`

Authenticated with `AuthedAgent`, like `GET /v1/grants`, under the same body
limit and Funnel refusal. It asks no one, notifies no one, creates no request,
and is not an audited request. **[call]**: it decides no access; the audit log
records decisions and grants. The `tracing` log records that an agent listed
offers, like other reads.

Response (in `crates/proto`, so CLI and broker share it) **[call]** on shape:

```jsonc
{
  "ssh_targets": [
    { "name": "web-01", "users": ["deploy"], "max_window": "1h",
      "mode": "cert", "destination": { "host": "web-01.example.internal", "port": 22 } },
    { "name": "switch-01", "users": ["admin"], "max_window": "30m",
      "mode": "relay", "destination": null }   // listed as `name`
  ],
  "api_secrets": [
    { "name": "home-api", "origin": "https://home-api.example.internal",
      "methods": ["GET"], "path_prefix": "/api/", "max_window": "1h" }
  ],
  "github": { "configured": true, "max_window": "30d" },
  "commit_signing": { "available": true },
  "releases": { "available": true },
  "unavailable": ["api_secrets"]
}
```

- `destination` / `origin` is `null` for an item listed as `name`. `hidden`
  items are absent.
- **What it reads.** Targets and secrets: the tagged item summaries, then each
  item, through new `SecretBackend` methods that return the listing view of
  every valid item. The view type has no field for a host key body, a
  credential or a secret value, so nothing secret can reach the response by
  accident. **[call]**
- **Invalid items** (fail validation today) are left out of the listing:
  their `list` field cannot be trusted. **[call]**
- **Relay targets** show their host and port under `full` too, although the
  agent never connects there: it is still the address a command that goes
  around warden would use, which is what #199's hook matches. **[call]**
- **Fresh reads, like the rest of the backend** ("Always reads fresh data").
  A session start reads every target and secret item once. That is a few
  Connect calls per session on a home setup, and each read already appears in
  1Password's usage reports like a request's. **[call]** **[guess]**: the
  builder confirms that reading an API secret item for its listing view goes
  through the same path as `api_secret` (which validates without returning the
  value) and adds no new handling of secret bytes.
- **GitHub.** `configured` is whether a `warden:github-app` item loads. No
  repository names: the broker never lists the repositories it covers. An
  agent asks about the one it is working in (next section). (owner's
  decision)
- **Commit signing:** `available` is `has_commit_signing_key`, which reads no
  key. **[call]**
- **Releases:** `available` only, no repository names: true when at least one
  `warden:release-signing` item and a `warden:github-release-app` item exist,
  from item summaries alone. The repository is a field inside the key item, so
  naming it would read every release private key at every session start.
  **[call]**, from the builder check. Whether one repository can be released
  is the per-repository question below.
- **Partial failure.** If one source cannot be read (Connect down, GitHub
  unreachable), the response carries what could be read and names the rest in
  `unavailable`, with a 200. If the policy backend cannot be read at all, the
  same `BACKEND_UNAVAILABLE` error the other agent calls give. **[call]**:
  a session is better off knowing GitHub works while the vault is down.

### Broker: `GET /v1/offers/repository/{owner}/{name}`

The agent asks about one repository, the one it is working in, and the
broker answers for that repository only. Nothing lists every repository.
(owner's decision)

Same authentication, Funnel refusal and audit stance as `GET /v1/offers`.
The name is validated as a `RepoName` before anything else.

```jsonc
{
  "repository": "example-org/example-repo",
  "github_token": "covered",   // or "not_covered", "not_configured", "unavailable"
  "commit_signing": true,      // machine-wide; repeated so one answer is enough
  "release": "ready"           // or "no_key", "no_release_app", "unavailable"
}
```

- **`github_token`.** The broker asks GitHub whether the agent App's
  installation covers this repository, the way it already resolves a
  repository when minting a scoped token (`github_app.rs`), with the token
  dropped unused. No call to GitHub's list of the installation's
  repositories. **[guess]**: the builder confirms how the existing minting
  path tells "not covered" (an error answer from GitHub for a repository
  outside the installation) apart from GitHub being unreachable, and maps
  only a clear answer to `not_covered`.
- **`release`.** `ready` when a release signing item names this repository
  and a release App item exists. This reads the release signing items, keys
  included, as `release_signing` does today: acceptable here because it runs
  only when an agent asks about a repository, not at every session start.
  Whether GitHub trusts the key, the signers file and the tag ruleset are
  #248's checks, not this answer's. **[call]**
- **Cache.** Answers are cached in memory per repository for 5 minutes, so
  repeated `prime` runs in one checkout do not each mint a token. `unavailable`
  answers are not cached. **[call]**
- **Exposure.** This answers one guess at a time, the same as the broker
  already does for target and secret names. The threat model says so.
  **[call]**

### CLI: `warden list`

- Calls `GET /v1/offers` and prints it for a person or agent to read: one
  section per kind, one line per item, sections with nothing in them left out.
  `--json` prints the broker's response as is, for the plugin (#199).
  (owner's idea for `--json`)
- **This repository.** In a git checkout whose remote is on GitHub, `warden
  list` also asks about that repository and prints a "this repository"
  section. The CLI already works out the repository from the checkout for
  GitHub tokens (`github_repo.rs`). `warden list --repo owner/name` asks about
  another one. Outside a checkout, or with a remote that is not GitHub, the
  section is left out. **[call]**
- Exit codes follow `docs/agent-usage.md#exit-codes`: 0 on success (also with
  `unavailable` parts, which it prints as such), 1 when the broker cannot be
  reached or refuses the login, 64 on wrong arguments. **[call]**
- A broker without the endpoint (404): exit 1, "this broker is too old to list
  what it offers; upgrade it to <version>". **[call]**

### CLI: `warden prime`

The text comes from `docs/agent-instructions.md`, embedded at build time with
`include_str!`. (owner's decision: approach 1)

- **Markers.** The fenced block an owner pastes today becomes the template.
  Sections are wrapped in HTML comments that render to nothing on GitHub:
  `<!-- warden:section github -->` … `<!-- warden:end -->`, and the "Available
  here" line becomes `<!-- warden:offers -->`. Section names: `ssh`, `api`,
  `signing`, `github`, `release`. Text outside sections always prints.
  **[call]** on syntax.
- **Which sections print.** A section prints when the broker offers that kind
  (at least one listed SSH target, API secret, a configured GitHub App,
  commit signing, releases available). The text inside stays conditional
  ("if this machine signs through warden"), because the broker cannot see
  this machine's git setup. **[call]**
- **`warden prime`** prints the whole filtered block with the offers in place
  of the marker, and, in a GitHub checkout, the "this repository" answer
  (GitHub tokens, signing, release) as `warden list` does. `--brief` does not
  ask about the repository, so session start stays one cheap call. **[call]** For the owner reading the doc on GitHub, the doc still says,
  outside the block, that `warden prime` prints this and that pasting it is
  the fallback for agents with no shell access at session start.
- **`warden prime --brief`** prints about 10 lines: that warden covers access
  here, the names it covers (one line per kind: SSH targets and users, API
  secrets, whether GitHub, signing and releases are on; no destinations, to keep
  it short), "never use other credentials or another way in", and "run
  `warden prime` before your first request". Its text is its own marked
  section of the doc (`<!-- warden:section brief -->`), so it too has one
  source. (owner's decision on the two sizes; content **[call]**)
- **Time limit.** `prime` and `prime --brief` give the offers call 3 seconds
  in all (connect and answer); past that, they fall back as below. `warden
  list` keeps the client's normal timeouts. The CLI client's overall timeout
  today is about 11 minutes, sized for `warden request`, so `prime` needs its
  own. **[call]**, from the builder check.
- **Signing at session start.** Every call is signed through the agent's
  ssh-agent. The docs say the session-start hook suits a key that signs
  without a prompt (a dedicated agent socket, as `warden login` sets up); with
  a key that prompts per signature, use the one-line rule instead of the hook.
  The 3-second limit bounds the wait either way. **[call]**
- **When the broker cannot be reached, refuses the login or is too old,**
  both print the rules without the offers, plus one line saying why ("the
  broker cannot be reached: run `warden doctor`, and do not go around it"),
  and exit 0. With no configuration at all (`warden login` never run), they
  print one line saying warden is installed but not set up, and exit 0.
  **[call]**: these commands inform; a failed hook would hide the very rule
  that matters most when the broker is down.
- **Wiring for agents.** `docs/agent-instructions.md` and
  `docs/agent-usage.md` give the SessionStart hook command
  (`warden prime --brief`) and, for agents with no hooks, the one rule to
  paste instead: "Run `warden prime` before a task that needs an SSH host, an
  API secret, GitHub, commit signing or a release." **[call]**

### Tests

- Broker: the offers endpoint per backend (1Password via the existing Connect
  fixtures, local backend files), each `list` value, a misspelled value,
  an invalid item left out, a partial failure, and that no fixture secret,
  host key body, item id or vault name appears in any response (search the
  serialized body for each).
- CLI: marker parsing (a missing or unbalanced marker fails a test that runs
  against the real `docs/agent-instructions.md`, so a doc edit cannot silently
  drop a section), section filtering, `--brief`, broker down / too old / not
  set up all exit 0 with the right line, `warden list --json` round trip.
- End to end (`crates/cli/tests`): a broker with one item of each kind and
  each `list` value; `warden list` and `warden prime` print what the owner
  configured.

### Docs

- `docs/agent-instructions.md`: markers, the "Available here" placeholder
  replaced, and the paragraph saying the agent "cannot list them, and it
  should not guess" replaced by `warden list` / `warden prime`.
- `docs/1password-items.md` and `docs/local-backend.md`: the `list` field.
- `docs/agent-usage.md`, `docs/agent-protocol.md` (`GET /v1/offers`),
  `docs/interfaces.md`, `docs/configuration.md` (the CLI commands table; the
  doctor check), README where it shows pasting instructions.
- `docs/threat-model.md` and `docs/security-assessment.md` (with its date):
  the listing hands any agent key the names, and by default the destinations,
  of what warden covers; why that is acceptable (an agent on the host already
  sees the network; listing grants no access); `hidden` and `name` as the
  owner's controls; `hidden` does not hide existence from a guess.
- `CHANGELOG.md` under Unreleased.

## Approaches considered (for where the instruction text lives)

1. **The doc is the source, and the CLI embeds it.** Section markers in
   `docs/agent-instructions.md`, `include_str!`, a small parser and a test
   against the real doc. People and the CLI read the same words with no copy
   step. Chosen. (owner's decision)
2. **The CLI is the source, and the doc is generated** by
   `warden prime --template`, with CI refusing a stale doc. Full control of
   structure, but every doc edit goes through a generator and the doc reads
   like build output. Not chosen.
3. **The broker serves the text.** Dropped: the text must match the CLI the
   agent runs, not the broker's version, and an unreachable broker would leave
   a session with no rules at all.

## Constraints

- Public repository: examples and tests use generic names only
  (`web-01`, `home-api`, `example-org/example-repo`, documentation
  addresses).
- No new dependency is expected **[guess]**; if one is needed, the
  workspace's rules apply (7-day age, `cargo deny`).
- Files stay under about 800 lines: `crates/broker/src/api.rs` is large
  already, so the offers handler goes in its own module (`api/offers.rs`),
  like `api/github_token.rs`. The CLI's `prime` and marker parsing get their
  own module. **[call]**
- Clippy `all` and `pedantic` deny, `unsafe_code` forbidden, tests that do
  not depend on timing (the 5-minute GitHub cache takes an injectable clock).

## Left to the builder

- The text lines `warden list` prints, and the exact wording of `--brief`,
  within the content above.
- How the `SecretBackend` listing methods are split between the two backends.
- Whether the GitHub repository cache lives in `github_app.rs` or next to the
  offers handler.
