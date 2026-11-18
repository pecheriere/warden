# One GitHub grant per permission set: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Approving or revoking a GitHub token grant leaves the agent's grants with other permission sets untouched, and a token carries an extra permission only when the request names it (bead warden-dqs).

**Architecture:** The broker's replacement rule (`requests/github_overlap.rs`) narrows from "shares a repository" to "shares a repository and has the same permission set". The mint lookup (`requests/github_token.rs`, `api/github_token.rs`) picks the least privileged grant for the request's named permissions, or mints the owner's default set when none are named. The CLI names permissions from `git-credential` through `WARDEN_GITHUB_PERMISSIONS`, and its token cache stops dropping other grants' tokens.

**Tech stack:** Rust workspace (`crates/proto`, `crates/broker`, `crates/cli`), sqlx/SQLite, axum, maud pages, nextest.

**Spec:** `docs/superpowers/specs/2026-11-17-separate-sensitive-github-grants-design.md`. Read it first: every **[call]** there is decided.

## Global constraints

- `AGENTS.md` applies in full: no `#[allow]`/`#[expect]` without a reason comment, no dead code, no TODOs, secrets never in logs or errors, fail closed on unreadable state.
- Files stay under about 800 lines. `crates/broker/src/requests/github_token.rs` and `crates/broker/src/approval/pages/github_token.rs` are already long: put new logic in a new module (named in each task) rather than growing them past that.
- No migration: stored grants and requests keep their shape.
- Tests never sleep and never mutate the process environment. Run only the affected crate while iterating: `cargo nextest run -p <crate> -E 'test(<name>)'`. Keep output short (`| tail -50`).
- Never set `CARGO_TARGET_DIR` or any other `CARGO_*` variable.
- Commits use `git commit -s` (the maintainer asked for this work) and carry no AI attribution trailer.
- Every user-visible change gets a `## [Unreleased]` line in `CHANGELOG.md`, in the task that makes it.

## Review focus

1. A grant revoked or replaced between the pick and the post-mint recheck: the token is withheld (`github_token_refused`), whichever grant was picked.
2. An approval while another approval for the same agent and repository commits: `end_overlapping` still refuses (`ReplacedChanged`) when what it finds differs from what the digest bound.
3. A grant whose stored permissions this version cannot read: the mint refuses (storage `Corrupt`), not skips it and picks another grant. Picking another would hide corruption.
4. `WARDEN_GITHUB_PERMISSIONS` set but empty, or with only whitespace: invalid, so the helper prints nothing and fails, never falls back to the default set.
5. A v3 cache file on disk after the upgrade: ignored, never served.

Each has its test in the owning task.

---

### Task 1: Replacement only within one permission set, and pending requests per set

**Files:**
- Modify: `crates/broker/src/requests/github_overlap.rs` (`overlapping_grants`, `github_replaced_events`, `end_overlapping`)
- Modify: `crates/broker/src/requests/github_scope.rs` (`replaced_grants`, around line 300)
- Modify: `crates/broker/src/requests/create.rs:209` (dedupe key), `crates/broker/src/requests/github_permissions.rs:298-328` (`pending_in_request_slot`), `crates/broker/src/requests/renewal.rs` (its call of `pending_in_request_slot`), and every use of `RequestError::OtherPermissionsPending` (`requests.rs`, `api.rs`, `approval/renew.rs`, `tests/github_token/extras.rs`)
- Test: `crates/broker/tests/github_token/overlap.rs`, `crates/broker/tests/github_token/extras.rs`

**Interfaces:**
- Produces: `Requests::overlapping_grants(&self, agent: &AgentName, new: &GrantScope, permissions: &PermissionSet) -> Result<Vec<ReplacedGrant>, RequestError>`, which returns only grants that overlap `new` **and** whose `PermissionSet` equals `permissions`. A legacy (unscoped) grant is returned whatever its set.
- Produces: `Requests::other_live_grants(&self, agent: &AgentName, new: &GrantScope, permissions: &PermissionSet) -> Result<Vec<ReplacedGrant>, RequestError>`, the overlapping grants with **another** set (Task 3 shows them).
- `end_overlapping` gains a `permissions: &PermissionSet` parameter and applies the same filter inside the transaction. `same_ids` against `expected` stays.
- Dedupe key: `format!("{agent}|github_token|{}|{}", github.slot(), <the request's full permission set as its canonical string>)`. Use the full set the request resolves to (default plus extras), the one `github_replaced_events` compares, not the raw extras.

- [ ] **Step 1: Write the failing tests** in `tests/github_token/overlap.rs`:
  - `grant_with_other_permissions_stays`: approve `[A]` with no extras, then `[A]` with extras `workflows:write` (window 30m). Assert neither is revoked, `active_covering(1001) == 2`, and there is no `grant_revoked` entry.
  - `revoking_one_set_leaves_the_other` (the bead's acceptance test): same two grants, revoke the `workflows:write` one through the API. Assert the everyday one is not revoked, is listed by `GET /v1/grants` as active, and a mint for `A` with no permissions named succeeds with its grant id.
  - Keep `overlapping_grant_is_replaced` passing as is (same default set, so it still replaces), and add `same_set_on_overlapping_repositories_is_replaced` with extras `actions:write` on both.
  - `legacy_grant_is_replaced_by_any` stays green unchanged.
- [ ] **Step 2: Write the failing pending test** in `tests/github_token/extras.rs`: replace the test that expects `OtherPermissionsPending` with `requests_for_other_permissions_wait_side_by_side`. Create a request for `[A]` with no extras, then one for `[A]` with `workflows:write`. Assert two distinct pending ids, and that repeating the second returns the second's id (duplicate).
- [ ] **Step 3: Run** `cargo nextest run -p warden-broker -E 'test(/overlap|extras/)' | tail -30`. Expected: the new tests FAIL.
- [ ] **Step 4: Implement** the interfaces above. Pass the new grant's full `PermissionSet` (from `github_permissions_of`) from `approval_events` and `end_replaced` in `requests/decide.rs`. Delete `OtherPermissionsPending` and its message everywhere: it can no longer happen. Update the module docs of `github_overlap.rs` and `github_token.rs` ("An agent holds at most one grant per repository") to "at most one grant per repository and permission set".
- [ ] **Step 5: Run** `cargo nextest run -p warden-broker | tail -30`. Expected: all pass.
- [ ] **Step 6: Docs in the same commit:** `docs/github-app.md` (what approving does to existing grants), `docs/threat-model.md` (around line 1197: "approving one ends the agent's overlapping ones" becomes "… overlapping ones with the same permission set"), plus a one-line note at the top of `docs/superpowers/specs/2026-11-14-github-token-permissions-design.md` that the 2026-11-17 design reverses its option A. CHANGELOG line under Changed.
- [ ] **Step 7: Commit** `git commit -s -m "GitHub grants: approving ends only grants with the same permission set (warden-dqs)"`

### Task 2: Mint from the least privileged grant, with the default set unless permissions are named

**Files:**
- Create: `crates/broker/src/requests/github_pick.rs` (the pick and the default-set computation, with unit tests in `github_pick/tests.rs`)
- Modify: `crates/broker/src/requests/github_token.rs` (`active_github_token_for`, `GithubLookup`)
- Modify: `crates/broker/src/api/github_token.rs` (`attempt`: lookup, `narrowed`, recheck)
- Modify: `crates/proto/src/github_permissions.rs` (add `PermissionSet::intersection`)
- Modify: `crates/proto/src/github_token.rs` (doc of `GithubTokenRequest::permissions`: "Absent means the owner's default set, limited to what the grant holds")
- Test: `crates/broker/tests/github_token/mint.rs`, and a new `crates/broker/tests/github_token/pick.rs` registered in that test binary's `main.rs`/`mod` list

**Interfaces:**
- Consumes: Task 1's replacement rule, so several grants can cover one repository.
- Produces: `PermissionSet::intersection(&self, other: &Self) -> Self`. Per name in both, the lower level (`write` covers `read`). `metadata:read` stays.
- Produces: `active_github_token_for(&self, agent: &AgentName, repository: &RepoName, wanted: Option<&PermissionSet>) -> Result<GithubLookup, RequestError>`. `ActiveGithubToken` gains `mint: PermissionSet`, the set to mint with (before `narrowed`).
- Produces in `github_pick.rs`: `pub(super) fn pick<'a>(candidates: &'a [Candidate], wanted: Option<&PermissionSet>) -> Pick<'a>`, where `Candidate { grant_id: Id, permissions: PermissionSet, not_after: i64, .. }` and `Pick` is `None | One(&'a Candidate) | Ambiguous(Id)`.

**The pick (spec "Minting"):**
- Candidates: active grants covering the repository (as today, by id or name).
- Two candidates with equal extras (absent counts as empty) give `Ambiguous`, as today's two-grants case does. `Candidate` carries `extras: PermissionSet` for this.
- With `wanted`: the holders are candidates whose set `covers_all(wanted)`. If there are none, every candidate is a holder, and `narrowed` then refuses naming what the picked grant lacks, as today.
- Order among holders: no sensitive permission first, then the fewest permissions (`iter().count()`), then the smallest `not_after`, then `grant_id` for a total order.
- `mint`: with `wanted`, the grant's full set (`narrowed` cuts it to `wanted`). Without, `owner_default.intersection(&grant_set)`. `owner_default` is the current `default_permissions` of the `warden:github-app` item, read the way `api/offers.rs` reads it. An unreadable default refuses, like every storage failure.
- A candidate whose stored permissions do not parse fails the whole lookup (`Corrupt`), never skipped.

- [ ] **Step 1: Unit tests in `github_pick/tests.rs`:** `no_wanted_picks_the_least_privileged`, `sensitive_grant_only_when_wanted_needs_it` (an everyday and a `workflows:write` candidate: `wanted = contents:write` picks the everyday one, `wanted = contents:write,workflows:write` picks the other), `fewest_permissions_then_soonest_end_then_id`, `equal_sets_are_ambiguous`, `no_holder_falls_back_to_all_candidates`. Plus `intersection_takes_the_lower_level` in `github_permissions.rs` tests: `contents:write ∩ contents:read == contents:read`, a name in one set only is dropped, and `metadata:read` stays.
- [ ] **Step 2: Integration tests in `tests/github_token/pick.rs`:**
  - `plain_request_gets_the_default_set`: one grant with extras `actions:write`, owner default `contents:write,pull_requests:write`. A mint naming nothing asks GitHub for exactly the default set (assert on the fake upstream's recorded body) and returns those `permissions`.
  - `named_extra_is_minted`: the same grant, naming `actions:write`. The token has `actions:write`.
  - `named_sensitive_uses_the_sensitive_grant`: everyday plus `workflows:write` grants. Naming `contents:write,workflows:write` mints with the sensitive grant's id, and a plain mint uses the everyday grant's id.
  - `sensitive_grant_revoked_during_mint_gives_nothing` (review focus 1): hold the mint at GitHub with the fake (see `revoked_during_mint_not_returned` in `mint.rs`), revoke the sensitive grant, release. Expected: refused, plus a `github_token_refused` entry.
  - `unreadable_grant_permissions_refuse` (review focus 3): corrupt one candidate's stored permissions with SQL. The mint refuses even though another grant would serve.
- [ ] **Step 3: Run** `cargo nextest run -p warden-broker -p warden-broker-proto -E 'test(/pick|intersection|mint/)' | tail -30`. Expected: FAIL.
- [ ] **Step 4: Implement.** `attempt` passes `request.permissions.as_ref()` to the lookup and `narrowed(request.permissions, active.mint)`. The recheck calls the lookup with the same `wanted` and requires the same `grant_id` and repository id, as today. The `window_secs` / sensitive-too-long check stays on the picked grant.
- [ ] **Step 5: Run** `cargo nextest run -p warden-broker -p warden-broker-proto | tail -30`. Expected: all pass.
- [ ] **Step 6: Docs in the same commit:** `docs/agent-protocol.md` (`POST /v1/github-token`: absent `permissions` means the default set, and how a grant is picked), `docs/threat-model.md` (add "an extra permission reaches a token only when the request names it" next to the GitHub token controls), `docs/security-assessment.md` (the change in exposure, with today's date), `docs/upgrading.md` (breaking: name extras), CHANGELOG under Changed, marked breaking.
- [ ] **Step 7: Commit** `git commit -s -m "GitHub tokens: least privileged grant, extras only when named (warden-dqs)"`

### Task 3: "Also live" on the approval page

**Files:**
- Modify: `crates/broker/src/requests/github_scope.rs` (the pending view: add `also_live`), the pending view struct holding `replaces`
- Create: `crates/broker/src/approval/pages/github_also_live.rs` (the markup)
- Modify: `crates/broker/src/approval/pages/github_token.rs:332` (render it after `replaced(...)`)
- Test: the page tests next to `approval/pages/tests/github_fixtures.rs`

**Interfaces:**
- Consumes: Task 1's `other_live_grants`.
- Produces: `PendingView.also_live: Vec<ReplacedGrant>` (same type as `replaces`), and `fn also_live(agent: &AgentName, grants: &[ReplacedGrant]) -> Markup`.

- [ ] **Step 1: Failing page test** `pending_github_lists_other_live_grants`: an agent with an everyday grant on `A` and a pending `workflows:write` request for `A`. The page shows an "Also live" block naming the everyday grant's permissions and end, and no "replaces" block. A second test, `also_live_absent_without_other_grants`.
- [ ] **Step 2: Run, expect FAIL; implement:** same structure and classes as the `replaced` block, heading "Also live", one line per grant: the repositories, the permissions as `was()` formats them, and "until <local time>". Follow `docs/design-language.md`. Nothing on the page links to or acts on those grants: revoking stays on the grants page.
- [ ] **Step 3: Run** `cargo nextest run -p warden-broker -E 'test(/also_live|pending_github/)' | tail -30`. Expected: PASS.
- [ ] **Step 4: Screenshots:** `scripts/screenshot-pages.sh <scratch dir>` at the PR template's sizes, light and dark. Headless shell only (`p.chromium.launch()` with no `channel`), never installed Chrome. If the headless shell is missing, stop and report it. Keep the files for the PR.
- [ ] **Step 5: Commit** `git commit -s -m "Approval page: list the agent's other live grants on the repositories (warden-dqs)"`

### Task 4: CLI: name permissions from git, keep other grants' tokens

**Files:**
- Modify: `crates/cli/src/github_token/cache.rs` (`AskedSet::Full` → `AskedSet::Default`, `VERSION` 3 → 4, `put`)
- Modify: `crates/cli/src/git_credential.rs` (`run` reads the variable, a pure helper parses it)
- Modify: `crates/cli/src/main.rs:109` only if the variable is read there to keep `run` testable
- Modify: the `warden prime` text (find it with `rg -n "git push" crates/cli/src`), `docs/agent-usage.md`, `docs/configuration.md` (the variable, and the cache file version in the state table near line 462)
- Test: `crates/cli/src/github_token/tests/cache.rs`, `crates/cli/src/git_credential.rs` tests

**Interfaces:**
- Produces: `fn asked_from_env(value: Option<&OsStr>) -> Result<AskedSet, String>`. `None` gives `AskedSet::Default`. `Some(v)` gives `AskedSet::Exactly(PermissionSet::parse(v))`, and an error for non-UTF-8, empty, whitespace-only or invalid values. `run` reads `std::env::var_os("WARDEN_GITHUB_PERMISSIONS")` once and passes it in.

- [ ] **Step 1: Failing tests:**
  - cache: `put_keeps_entries_of_other_grants` (entries for repository R under grant G1 with `Default` and under G2 with `Exactly(contents:write,workflows:write)`; `put` of a new G1 `Default` entry keeps G2's entry and replaces the old G1 one), and `version_3_file_is_ignored` (review focus 5: write a v3 file, `Cache::load` gives none).
  - git_credential: `asked_from_env_cases`: unset → `Default`; `contents:write,workflows:write` → that set; `""`, `"  "`, `bogus:read` and `checks:admin` → error (review focus 4).
  - `run` with an invalid variable: drive `answer()` the way the existing tests do and assert stdout stays empty and the exit code is `EXIT_USAGE`.
- [ ] **Step 2: Run** `cargo nextest run -p warden-broker-cli -E 'test(/cache|asked_from_env|git_credential/)' | tail -30`. Expected: FAIL.
- [ ] **Step 3: Implement.** `put` drops only entries with the same repository **and** the same `asked`. Delete the `superseded` logic and update its doc comment. On an invalid variable, `run` prints `warden: WARDEN_GITHUB_PERMISSIONS: <error>` to stderr, prints nothing to stdout and returns `EXIT_USAGE`.
- [ ] **Step 4: Run** `cargo nextest run -p warden-broker-cli | tail -30`. Expected: all pass.
- [ ] **Step 5: Docs:** `warden prime` and `docs/agent-usage.md` give the exact lines `WARDEN_GITHUB_PERMISSIONS=contents:write,workflows:write git push` and `GH_TOKEN=$(warden github token --repo owner/name --permissions actions:write) gh run rerun …`. They say a plain `git push` or `gh` call gets the default set, and to revoke a superseded or sensitive grant after use. CHANGELOG under Added.
- [ ] **Step 6: Commit** `git commit -s -m "CLI: WARDEN_GITHUB_PERMISSIONS for git, cache keeps other grants' tokens (warden-dqs)"`

### Task 5: Full gate and PR

- [ ] Run the full "Before you push" list from `AGENTS.md`, except the CI-only lines (fuzz metadata, crate age), and fix anything it finds. Keep each output to `| tail -30`.
- [ ] Push the branch and open the PR from the template. It names warden-dqs and lists what was and wasn't verified locally. Attach the Task 3 screenshots per the `pr-screenshots` memory.
- [ ] After merge, outside this repository: update `~/.claude/rules/warden.md` (dotfiles) with the `WARDEN_GITHUB_PERMISSIONS` line, and remind the owner to commit dotfiles.

## Amendment after Task 1 (2026-11-17)

Replacement and the pending slot compare the grant's **extras** (`extra_permissions`, absent = empty), not its full set: a renewal carries the old grant's extras, and a full-set comparison left the renewed grant live after a change of default. Task 1's fix round makes this change and restores the renewal tests' original expectations (renewal replaces, the page shows "was …").
