# Scoped GitHub tokens Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every GitHub token the broker mints for an agent reaches exactly one repository that the owner approved on the phone, and an agent can hold several such grants at once.

**Architecture:** A `github_token` request names its repositories; the broker resolves them to numeric ids with a throwaway metadata-only token when the owner opens the approval page, and the grant stores names and ids. Each mint names one repository, picks the one active grant covering it, mints with `repository_ids: [id]` and refuses any answer that is not exactly that repository. Approving a grant ends the agent's grants whose repositories overlap it; unscoped grants and requests from before the upgrade parse as a legacy shape that is never minted from and are ended at startup. The CLI works out the repository from `--repo`, git's `path`, `gh -R`, `GH_REPO` or `origin`, and refuses when it cannot.

**Tech Stack:** Rust (workspace pinned toolchain), axum, sqlx/SQLite, reqwest (no decompression), serde, clap, maud pages as the approval module builds them.

**Spec:** `docs/superpowers/specs/2026-11-11-scoped-github-tokens-design.md` (read it before any task). Background: `docs/threat-model.md` ("GitHub tokens"), `docs/github-app.md`.

## Global Constraints

- Everything in `AGENTS.md`: no `#[allow]`/`#[expect]` without a reason comment, clippy `all`+`pedantic` denied, `unsafe_code` forbidden, no dead code, no `TODO`, secrets never logged or formatted into errors, fail closed: unreadable or ambiguous state refuses and audits.
- Files stay under about 800 lines of code (`tokei`). Code lines today: `crates/cli/src/doctor.rs` 722, `crates/cli/src/client.rs` 683, `crates/broker/src/approval/pages/tests.rs` 692, `crates/broker/src/audit.rs` 672, `crates/broker/src/api.rs` 638, `crates/cli/src/request.rs` 572, `crates/broker/src/approval/mod.rs` 571. Add only dispatch lines to these; new code goes in the new modules each task names. `crates/cli/src/agent.rs` (792) is not touched: it is the ssh-agent code, not GitHub.
- New migration file only: `crates/broker/migrations/0011_scoped_github_tokens.sql`. Never edit 0001–0010.
- No new crate.
- reqwest never gains a decompression feature; every GitHub call goes through `github_http` as today.
- No text from GitHub ever goes into an error, a log line or an audit entry, except values the broker parsed and validated (ids, `RepoName`s).
- Repository: `RepoName` from `warden_broker_proto::release` (`owner/name`), compared ASCII-case-insensitively with `RepoName::matches`. At most `MAX_REPOSITORIES = 10` per request or grant. Duplicates (case-insensitive) are refused, not merged.
- Token permissions stay `PERMISSIONS` (contents, pull requests, issues write; metadata read). Resolution tokens: `{"metadata":"read"}` only. Windows unchanged (1d, 7d, 30d).
- One repository per minted token: `repository_ids: [<id>]`, even for a grant covering several.
- Tests never depend on timing (wait on conditions; the broker's manual clock moves time). GitHub is faked with `HttpsUpstream::script_github_token` (`crates/broker/src/testkit/upstream.rs`). Public repo: example names only: `example-owner/example-repo` (id `1001`), `example-owner/homebrew-tap` (id `1002`), `build-agent`.
- Each PR: a `CHANGELOG.md` line under `## [Unreleased]`, docs updated in the same PR, `.github/pull_request_template.md` filled in, commits `git commit -s` under the maintainer's configured identity, no AI attribution.
- Before each push, the full list in `AGENTS.md` "Before you push" passes. Build output kept short: `--quiet`, `| tail -40`.
- Implementers read narrowly (`rg`, line ranges). Budget per task: about 100 tool calls; past that, stop and report status and what is left.

## Review Focus

1. **A helper `path` that is almost a repository.** `owner/repo.git/`, `owner/repo.git.git`, `owner/repo.git/info/lfs` (git-lfs), `owner`, `owner/repo/extra`, a percent-encoded slash: only the first gives `owner/repo`; the rest get no answer and git fails asking for credentials. Test in Task 1.
2. **The same repository spelled in another case.** The agent asks for `Example-Owner/Example-Repo` while the grant stores `example-owner/example-repo`: the mint finds the grant, the CLI accepts the answer and serves the cached entry, and a second request in the other case lands in the same pending slot. Tests in Tasks 6, 8 and 10.
3. **A legacy row the startup step did not end** (a database restored from a backup after the broker started). The grants page still renders it, a mint never uses it (`NO_ACTIVE_GRANT`), and approving any GitHub grant for that agent ends it as overlapping. Tests in Tasks 5 and 7.
4. **The repository changed on GitHub between approval and mint** (deleted and recreated under the name, or renamed and replaced). GitHub answers another id or 422: the broker discards the token, refuses with a fixed message and audits; it never retries. Tests in Tasks 4 and 8.
5. **Two overlapping approvals for one agent at the same time.** Exactly one grant covers each repository id afterwards; if storage ever holds two, minting for that id refuses and audits. Tests in Tasks 7 and 8.

---

## Issue and PR split

The controller opens one issue per PR before starting, each linking #230, and works them in order.

| PR | Tasks | Delivers | Main after merge |
|---|---|---|---|
| 1 | 1–2 | the CLI knows which repository git and `gh` work on: `--repo`, helper `path`, `gh -R`, `GH_REPO`, `origin`; refusal when it cannot tell; `setup github` sets `useHttpPath` and the wrapper passes gh's arguments; doctor checks it | releasable: no wire change, tokens unchanged; automatic requests name the repository in their goal |
| 2 | 3–11 | scoped grants end to end: wire types, resolution, scoped mint, per-agent counter, overlap replacement, legacy end at startup, capability flag, the approval page, the CLI's wire switch and cache, docs | releasable: broker and CLI change the wire together |
| 3 | 12 | display: grants page, history and pending list, `warden status`, ending-soon notice name the repositories | releasable |

**Why the wire change and both of its ends are one PR.** The proto change breaks the CLI's build (`Access::GithubToken {}` is constructed in `crates/cli/src/request.rs:296`), and a broker that mints scoped tokens next to a CLI that caches one token for every repository would serve a token for a repository its grant does not name (an anti-goal). The approval page must show the repositories the moment the broker accepts them, or the owner approves a request whose reach the page hides. So proto, broker, approval page and CLI wire land together in PR 2; everything that does not depend on the wire is pulled forward into PR 1, and display that is safe to lag (grants page, history, status) goes to PR 3. PR 2 is large; its tasks are reviewed one by one before the two PR-level reviewers.

## Task 0: Spike the guesses against real GitHub (controller, not a subagent)

Run before Task 4; its results fix two choices there. Needs the agent App's private key, which only the owner holds: ask the owner to run the steps, or to approve the controller reading the key with `op read` into a shell variable, never to disk. Only `pecheriere/warden-app-test` and `pecheriere/warden` (both the owner's, App installed on both) are touched. Record the answers in the PR 2 description.

- [ ] **Step 1:** Confirm the agent App's installation is set to *All repositories* (owner, on GitHub's installation settings page). Build an App JWT (RS256, `iat` now−60, `exp` now+540, `iss` the App id).
- [ ] **Step 2 (guess: `repositories` takes bare names; selection value):** `POST /app/installations/<id>/access_tokens` with `{"repositories":["warden-app-test"],"permissions":{"metadata":"read"}}`. Record: status, `repository_selection`, and `repositories[].{id,full_name}`. Then the same with `{"repository_ids":[<that id>],"permissions":{"contents":"write","pull_requests":"write","issues":"write","metadata":"read"}}`; record `repository_selection`, `repositories`, `permissions`. Expected: `"selected"` and exactly that one repository.
- [ ] **Step 3 (guess: scoped token cannot touch another repository the App is installed on):** with the second token, `POST /repos/pecheriere/warden/issues` (title `scoped-token test, please ignore`) and `POST /repos/pecheriere/warden/issues/<an existing issue>/comments`. Record both statuses. Expected 403/404. If either succeeds: close the issue at once (`PATCH … {"state":"closed"}`), delete the comment (`DELETE /repos/pecheriere/warden/issues/comments/<id>`), ask the owner to delete the issue in the UI, and stop: the design's core assumption fails; take it to the owner before Task 4.
- [ ] **Step 4 (guess: 422 for an inaccessible name):** mint with `{"repositories":["warden-no-such-repo-0"],"permissions":{"metadata":"read"}}`. Record the status. Expected 422. Also mint with `{"repositories":["warden-app-test","warden-no-such-repo-0"],…}`: expected 422 too (all or nothing).
- [ ] **Step 5:** Write down the outcomes: `SELECTION_IS_SELECTED` (Step 2 says `"selected"` with the installation on *All*: yes/no), `CROSS_REPO_BLOCKED` (Step 3: yes/no), `INACCESSIBLE_STATUS` (Step 4's status). Task 4 uses them; Task 11 writes in the threat model only what Step 3 showed.

---

## PR 1: Which repository

### Task 1: Repository detection, helper `path`, `gh -R`, and refusing

**Files:**
- Create: `crates/cli/src/github_repo.rs` (pure parsing plus one `git` call), `crates/cli/src/github_repo/tests.rs`
- Modify: `crates/cli/src/git_credential.rs` (read `path`; answer only with a repository), `crates/cli/src/github_token.rs` (`obtain` and `goal_for` take the repository), `crates/cli/src/cli.rs` (`GithubCmd::Token` arguments), `crates/cli/src/main.rs` (dispatch, `mod github_repo;`)
- Test: `crates/cli/src/github_repo/tests.rs`, `crates/cli/src/github_token/tests.rs`, the tests module of `git_credential.rs`

**Interfaces:**
- Produces (`github_repo`):
  - `pub fn from_helper_path(path: &str) -> Option<RepoName>`: strip one trailing `/`, then exactly one `.git` suffix, then parse as `RepoName`; anything else `None`.
  - `pub fn from_remote_url(url: &str) -> Option<RepoName>`: `https://github.com/<o>/<r>[.git][/]` or `git@github.com:<o>/<r>[.git]`; any other host, scheme, port or user `None`.
  - `pub enum RepoArgError { OtherHost, Invalid }` (`thiserror`, fixed messages that do not quote the value).
  - `pub fn from_gh_value(value: &str) -> Result<RepoName, RepoArgError>`: `OWNER/REPO`, `github.com/OWNER/REPO`, `https://github.com/OWNER/REPO`; another host is `OtherHost`. Used for `-R` and for `GH_REPO`.
  - `pub fn repo_flag(args: &[OsString]) -> Result<Option<RepoName>, RepoArgError>`: finds `-R X`, `-RX`, `--repo X`, `--repo=X` before a `--`; no other parsing (spec: wrapper is interim). A repeated flag with different values is `Invalid`.
  - `pub fn choose(explicit: Option<RepoName>, gh_repo: Option<&str>, origin: impl FnOnce() -> Option<String>) -> Result<RepoName, Undetermined>`: explicit, else `GH_REPO` via `from_gh_value` (an unusable `GH_REPO` is `Undetermined`, never skipped), else `origin` via `from_remote_url`. `pub struct Undetermined;`
  - `pub fn origin_url(dir: &Path) -> Option<String>`: `git -C <dir> config --get remote.origin.url`, `None` on any failure.
  - `pub const UNDETERMINED_TOKEN: &str = "cannot tell which repository this token is for; pass --repo owner/name";` and `pub const UNDETERMINED_GH: &str = "cannot tell which repository; pass -R owner/name";`
- Produces (CLI): `warden github token [--repo <owner/name>] [--gh-args -- <gh's arguments>...]`: `GithubCmd::Token { repo: Option<RepoName>, gh_args: bool, args: Vec<OsString> }` (`args` is `#[arg(last = true)]`, accepted only with `--gh-args`). With `--gh-args`, `-R` from `args` is the explicit repository and refusal says `UNDETERMINED_GH`; otherwise `--repo` is explicit and refusal says `UNDETERMINED_TOKEN`. Refusal exits `EXIT_ERROR` with nothing on stdout.
- Produces: `github_token::obtain(caller: Caller, repository: &RepoName) -> Result<Zeroizing<String>>`; `print_token(repository: &RepoName) -> Result<()>`; `goal_for(caller, repository: &RepoName, dir: Option<&Path>) -> Result<Goal>` giving `GitHub token for <repo>, requested automatically by the git credential helper[, in <dir>]` (or `… by the gh wrapper …`). The token itself is unchanged in this PR.
- git credential helper: `Asked` gains `path: Option<String>` (a repeated `path` is unreadable input, like `host`). `get` for github.com: `path` absent prints nothing and writes to stderr `warden: git sent no repository path; run \`warden setup github\`, which sets credential.https://github.com.useHttpPath`; `path` that `from_helper_path` refuses prints nothing (no stderr line: git-lfs sends such paths routinely).

- [ ] **Step 1: Write failing tests.** `github_repo`: `helper_path_accepts_plain_and_dot_git` (`example-owner/example-repo`, `example-owner/example-repo.git`, `example-owner/example-repo.git/` all give `example-owner/example-repo`), `helper_path_refuses` (cases: `example-owner`, `example-owner/example-repo/extra`, `example-owner/example-repo.git/info/lfs`, `example-owner%2Fexample-repo`, empty, `/`; and `example-owner/example-repo.git.git` gives `example-owner/example-repo.git`, never `example-owner/example-repo`: only one suffix is stripped), `remote_url_forms` (https with and without `.git` and trailing `/`, scp-like; refuses `https://gitlab.com/o/r`, `ssh://git@github.com:2222/o/r`, `https://user@github.com/o/r`, `http://github.com/o/r`), `gh_value_forms` (three accepted forms; `ghe.example.com/o/r` is `OtherHost`; `o` is `Invalid`), `repo_flag_forms` (`["pr","view","-R","o/r"]`, `["-Ro/r"]`, `["--repo=o/r"]`, `["--repo","o/r"]`, after `--` ignored, two different values `Invalid`, none `Ok(None)`), `choose_order` (explicit beats `GH_REPO` beats origin; the origin closure is not called when an earlier source answers; bad `GH_REPO` is `Undetermined` even with a good origin; nothing is `Undetermined`). `git_credential`: `get_with_path_answers_for_that_repository` (the obtain function is injected as the existing tests inject it; assert it received `example-owner/example-repo`), `get_without_path_answers_nothing`, `get_with_lfs_path_answers_nothing`, `repeated_path_is_unreadable`. `github_token`: `goal_names_the_repository` (`goal_for(Caller::GhWrapper, &repo, Some(dir))` contains `GitHub token for example-owner/example-repo` and the dir). CLI parse: `token_command_takes_repo_and_gh_args` (clap `try_parse_from` of `warden github token --gh-args -- pr view -R o/r` gives `gh_args: true` and the four args; `--repo bad` fails to parse).
- [ ] **Step 2: Run, see them fail.** `cargo test -p warden-broker-cli --quiet github 2>&1 | tail -40` and `cargo test -p warden-broker-cli --quiet git_credential 2>&1 | tail -40`.
- [ ] **Step 3: Implement** the functions above. `print_token` runs `choose(explicit, env GH_REPO, || origin_url(cwd))`; the helper uses only `path`.
- [ ] **Step 4: Run the tests; they pass.** Same commands, then `cargo clippy -p warden-broker-cli --all-targets --all-features --locked -- -D warnings 2>&1 | tail -20`.
- [ ] **Step 5: Commit** `git commit -s -m "Work out which repository a GitHub token is for, and refuse when unclear"`.

### Task 2: `setup github` sets `useHttpPath`, the wrapper passes gh's arguments, doctor checks it

**Files:**
- Modify: `crates/cli/src/setup_github.rs` (`USE_HTTP_PATH_KEY`, `set_use_http_path`, new wrapper text), `crates/cli/src/doctor/github.rs` (`GithubSetup.use_http_path`, the check), `crates/cli/src/doctor.rs` (dispatch only, at most a few lines)
- Modify: `docs/agent-usage.md` (GitHub section: which repository, `-R`, git-lfs unsupported over the helper, `gh` outside a checkout needs `-R`), `docs/configuration.md` (`warden github token` options, doctor `github` row), `docs/upgrading.md` (run `warden setup github` again), `CHANGELOG.md`
- Test: `crates/cli/src/doctor/github/tests.rs`, the tests module of `setup_github.rs`

**Interfaces:**
- `const USE_HTTP_PATH_KEY: &str = "credential.https://github.com.useHttpPath";` set to `true` in git's global config by `run()`, printing `credential.https://github.com.useHttpPath = true`.
- `fn wrapper_script(exe: &str, real_gh: &str) -> String` now writes `GH_TOKEN="$(<exe> github token --gh-args -- "$@")" || exit $?`, keeping the marker, `export GH_TOKEN` and `exec <real_gh> "$@"`. An existing wrapper of ours is rewritten as today.
- `GithubSetup` gains `pub use_http_path: bool`, read with `git config --type=bool --get credential.https://github.com.useHttpPath` through the same `configure` closure the helper probe uses. `check`: helper through warden but `use_http_path` false is `Check::fail(NAME, "git does not send the repository to warden (credential.https://github.com.useHttpPath is not true)", SETUP)`.

- [ ] **Step 1: Write failing tests** `the_wrapper_passes_gh_arguments_to_warden` (script contains `github token --gh-args -- "$@")" || exit $?`; still ends with `exec '/usr/bin/gh' "$@"\n`; `is_ours` still true), `setup_sets_use_http_path` (isolated global config as the existing setup tests isolate it: the key reads back `true`), `doctor_fails_without_use_http_path`, `doctor_passes_with_use_http_path` (existing pass cases gain `use_http_path: true`).
- [ ] **Step 2: Run, see them fail** (`cargo test -p warden-broker-cli --quiet setup_github 2>&1 | tail -40`, `cargo test -p warden-broker-cli --quiet doctor 2>&1 | tail -40`).
- [ ] **Step 3: Implement and write the docs.** CHANGELOG under Changed: "`warden setup github` sets `credential.https://github.com.useHttpPath`, and the `gh` wrapper refuses to run when it cannot tell the repository; run `warden setup github` again after upgrading."
- [ ] **Step 4: Run tests and the full "Before you push" list; all pass.**
- [ ] **Step 5: Commit** `git commit -s -m "Have git send the repository to the helper, and gh's arguments to warden"`, push, open PR 1 ("Part of #230").

---

## PR 2: Scoped grants

### Task 3: Wire types

**Files:**
- Modify: `crates/proto/src/github_token.rs` (new types and consts), `crates/proto/src/lib.rs` (`Access::GithubToken(GithubTokenAccess)`, `InfoResponse.scoped_github_tokens`, re-exports)
- Modify, to compile only (match arms `Access::GithubToken {}` become `Access::GithubToken(_)`; constructions use the new types): `crates/broker/src/approval/{mod.rs,pages.rs}`, `approval/pages/{history.rs,pending.rs}`, `requests/{create.rs,pending.rs,renewal.rs}`, `policy/github_app.rs` (`grant()` takes the scope, see Task 6), `testkit/broker/requests.rs`, `crates/cli/src/{recover.rs,request.rs}`; find them all with `rg -n 'GithubToken \{\}|GithubTokenGrant \{' crates fuzz`
- Modify: `fuzz/fuzz_targets/validated_names.rs` (property for `github_token` bodies)
- Test: `crates/proto/src/tests.rs` (or a new `crates/proto/src/github_token/tests.rs` if `tests.rs` would pass 650 code lines)

**Interfaces (all in `warden_broker_proto::github_token`):**
- `pub const MAX_REPOSITORIES: usize = 10;`
- `pub const OLD_CLIENT: &str = "this warden CLI predates repository-scoped GitHub grants; upgrade it";`
- `pub const REPOSITORY_UNREACHABLE: &str = "GitHub would not issue a token for this repository: the App may no longer reach it, or it was deleted or replaced";`
- `pub const AMBIGUOUS_GRANT: &str = "more than one GitHub grant covers this repository; ask the owner to revoke one";`
- `NO_ACTIVE_GRANT` becomes `"no active GitHub token grant for this agent and repository"`.
- `pub struct GithubTokenAccess { pub repositories: Vec<RepoName>, pub automatic: Option<AutomaticRequest> }`: `#[serde(try_from = "RawGithubTokenAccess")]`, the raw struct `#[serde(deny_unknown_fields)]` with `#[serde(default)]` on both fields. Refuses more than `MAX_REPOSITORIES`, case-insensitive duplicates, and `automatic` with other than exactly one repository. Empty is accepted and is the legacy shape (stored rows from before the upgrade). `pub fn new(repositories: Vec<RepoName>, automatic: Option<AutomaticRequest>) -> Result<Self, ParseError>`, `pub fn is_legacy(&self) -> bool`, `pub fn slot(&self) -> String` (names lowercased, sorted, joined with `,`).
- `pub struct AutomaticRequest { pub by: AutomaticCaller, pub dir: Option<String> }`; `dir` at most 512 bytes, refused with control or format characters (`crate::check_free_text`). `pub enum AutomaticCaller { GitCredential, GhWrapper }`, serde `snake_case`.
- `pub struct GrantRepository { pub name: RepoName, pub id: u64 }`.
- `pub enum GrantScope { Legacy, Repositories(Vec<GrantRepository>) }`, serde `from`/`into` `Option<Vec<GrantRepository>>` (absent or empty is `Legacy`); `Default` is `Legacy`. `pub fn repositories(list: Vec<GrantRepository>) -> Option<Self>` (`None` for empty, more than 10, or a repeated id or name); `pub fn is_legacy(&self) -> bool`; `pub fn covering(&self, name: &RepoName) -> Option<&GrantRepository>` (case-insensitive; `None` for legacy); `pub fn overlaps(&self, other: &Self) -> bool` (by id; legacy overlaps everything).
- `GithubTokenGrant` gains `#[serde(default, skip_serializing_if = "GrantScope::is_legacy")] pub repositories: GrantScope`. `digest` keeps its meaning (App and installation).
- `pub struct GithubTokenRequest { pub repository: RepoName }`, `#[serde(deny_unknown_fields)]`: the body of `POST /v1/github-token`.
- `GithubTokenResponse` gains `pub repository: RepoName` and `pub repository_id: u64`.
- `Access::GithubToken(GithubTokenAccess)`, serde kind `github_token`: `{"kind":"github_token","repositories":["example-owner/example-repo"]}`.
- `InfoResponse` gains `#[serde(default)] pub scoped_github_tokens: bool`.
- Testkit (changed here so the workspace builds; used from Task 5 on): `TestBroker::github_token_request(goal: &str, window: Window, repositories: &[&str]) -> CreateRequest`. Existing callers pass `&["example-owner/example-repo"]`.

- [ ] **Step 1: Write failing tests** `github_token_access_round_trips` (the exact JSON above, and with `"automatic":{"by":"git_credential","dir":"/work/example-repo"}`), `legacy_github_token_access_parses` (`{"kind":"github_token"}` parses, `is_legacy()`), `github_token_access_refuses_unknown_field` (`"repository":"o/r"` alongside: error), `github_token_access_refuses_duplicates` (`Example-Owner/Example-Repo` and `example-owner/example-repo`), `github_token_access_refuses_eleven`, `automatic_needs_exactly_one_repository`, `automatic_dir_refuses_control_characters`, `slot_is_case_and_order_insensitive` (`["B/x","a/Y"]` and `["a/y","b/X"]` give `a/y,b/x`), `grant_scope_legacy_when_absent` (old grant JSON without `repositories` gives `Legacy` and re-serializes without the key), `grant_scope_covering_ignores_case`, `grant_scope_overlap_by_id` (same id different names overlap; disjoint ids do not; `Legacy` overlaps a scoped one both ways), `github_token_request_refuses_empty_object` (`{}` is an error), `info_without_flag_is_false`. If serde keeps the `kind` key in the newtype's content so that `deny_unknown_fields` refuses every body, the round-trip test says so: then put the fields on a struct variant and refuse unknown keys in the raw type's `TryFrom` instead; the tests stay as written.
- [ ] **Step 2: Run, see them fail.** `cargo test -p warden-broker-proto --quiet github 2>&1 | tail -40`.
- [ ] **Step 3: Implement**, then fix every construction site so the workspace builds (`cargo check --workspace --all-targets --all-features --locked 2>&1 | tail -40`). Interim behaviour until later tasks: the broker refuses a legacy `GithubTokenAccess` at creation with `OLD_CLIENT` (Task 6 adds the rest); the CLI builds its request with the repositories it already knows (Task 10 finishes it). The fuzz target asserts that any accepted `github_token` body has at most 10 repositories, no case-insensitive duplicate, and `automatic` only with one.
- [ ] **Step 4: Run the tests; they pass.** Same command, plus `cargo test -p warden-broker-cli --quiet recover 2>&1 | tail -20`.
- [ ] **Step 5: Commit** `git commit -s -m "Name repositories in GitHub token requests and grants"`.

### Task 4: Minting for one repository id, resolving names, and checking GitHub's answer

Uses Task 0's results: `SELECTION_IS_SELECTED` decides whether the selection check is in; `INACCESSIBLE_STATUS` is the status mapped to `NotAccessible` (expected 422).

**Files:**
- Modify: `crates/broker/src/github_app.rs` (`mint` takes an id; `resolve`, `current_names`; answer checks), `crates/broker/src/testkit/github_app.rs` (scripted answers)
- Test: `crates/broker/src/github_app/tests.rs`

**Interfaces:**
- `pub struct ResolvedRepository { pub id: u64, pub name: RepoName }`.
- `pub async fn mint(api: &GithubApi, key: &GithubAppKey, repository_id: u64, now: i64) -> Result<InstallationToken, MintError>`: body `{"permissions":<PERMISSIONS>,"repository_ids":[<id>]}`. Refuses (`MintError::WrongScope`) unless the answer's `repositories` is exactly one entry with that id, its `permissions` are a subset of `PERMISSIONS` at no higher level, and (only if `SELECTION_IS_SELECTED`) `repository_selection == "selected"`.
- `pub async fn resolve(api: &GithubApi, key: &GithubAppKey, names: &[RepoName], now: i64) -> Result<Vec<ResolvedRepository>, MintError>`: body `{"permissions":{"metadata":"read"},"repositories":[<name part of each>]}`. The owner part is not sent (GitHub takes bare names within the installation's account); it is checked instead: the answer must hold exactly one entry per requested name whose `full_name` matches it case-insensitively (another owner is `WrongScope`), and permissions exactly `metadata: read`. Returns GitHub's `id` and `full_name` (case as GitHub returns it). The token is dropped unused.
- `pub async fn current_names(api: &GithubApi, key: &GithubAppKey, ids: &[u64], now: i64) -> Result<Vec<ResolvedRepository>, MintError>`: body with `repository_ids` and `metadata: read`; the answer must hold exactly those ids. For renewal (Task 7).
- `MintError` gains `NotAccessible` ("GitHub says the App cannot reach that repository") for `INACCESSIBLE_STATUS`, and `WrongScope` ("GitHub's token was not limited as asked"). Nothing GitHub said is kept.
- Testkit: `pub fn token_answer(token: &str, expires_at: i64, repositories: &[(u64, &str)], permissions: &[(&str, &str)], selection: &str) -> Scripted` in `testkit/github_app.rs`, a `201` with that JSON.

- [ ] **Step 1: Write failing tests** `mint_names_one_repository_id` (the recorded body is exactly `{"permissions":{...4...},"repository_ids":[1001]}`), `mint_refuses_other_repository` (answer id `1002`), `mint_refuses_two_repositories`, `mint_refuses_missing_repositories`, `mint_refuses_wider_permissions` (`administration: write` added, or `contents: admin`), `mint_refuses_selection_all` (only if `SELECTION_IS_SELECTED`), `resolve_sends_bare_names_and_metadata_only` (body `{"permissions":{"metadata":"read"},"repositories":["example-repo","homebrew-tap"]}`), `resolve_returns_ids_and_github_case`, `resolve_refuses_other_owner` (asked `other-owner/example-repo`, GitHub answers `example-owner/example-repo`), `resolve_refuses_missing_or_extra_entry`, `resolve_maps_inaccessible_status`, `current_names_returns_new_name_for_id`, `errors_carry_no_github_text` (a refused answer with a marker string in its body: no error text contains it). Existing `mint_*` tests move to the new signature.
- [ ] **Step 2: Run, see them fail.** `cargo test -p warden-broker --all-features --lib github_app --quiet 2>&1 | tail -40`.
- [ ] **Step 3: Implement.** One private function sends a body and parses the shared answer shape (`token`, `expires_at`, `repositories[].{id,full_name}`, `permissions`, `repository_selection`); the three public functions differ only in body and check.
- [ ] **Step 4: Run the tests; they pass.** The callers of `mint` in `api/github_token.rs` still compile only after Task 8; until then pass the grant's first repository id there (`GrantScope::Repositories(list)` → `list[0].id`; `Legacy` refuses with `NO_ACTIVE_GRANT`), so no unscoped mint path ever exists.
- [ ] **Step 5: Commit** `git commit -s -m "Mint GitHub tokens for one repository id and check GitHub's answer"`.

### Task 5: Migration, per-agent hourly counter, ending unscoped grants at startup, capability flag

**Files:**
- Create: `crates/broker/migrations/0011_scoped_github_tokens.sql`, `crates/broker/src/requests/github_scope.rs` (the legacy end here; Task 6 adds to it)
- Modify: `crates/broker/src/requests/github_token.rs` (`take_mint` per agent), `crates/broker/src/requests.rs` (`mod github_scope;`), `crates/broker/src/audit.rs` (variants), `crates/broker/src/main.rs` (call at startup), `crates/broker/src/testkit/broker.rs` (call at start; `insert_legacy_github_grant`, `insert_legacy_github_request`), `crates/broker/src/api.rs` (`scoped_github_tokens: true` in `info`), `crates/broker/src/requests/renewal.rs` (`ENDING_SOON` skips legacy rows)
- Test: `crates/broker/tests/github_token/legacy.rs` (new, `mod legacy;` in `main.rs` of that test), `crates/broker/tests/github_token/mint.rs`

**Interfaces:**
- Migration `0011_scoped_github_tokens.sql`:
  - `github_token_mints(agent TEXT PRIMARY KEY, mint_hour INTEGER NOT NULL, mint_count INTEGER NOT NULL)`: the per-agent hourly count. The `grants.mint_hour`/`mint_count` columns of 0009 stop being read or written (a comment says so; a later migration may drop them).
  - `github_repositories(request_id TEXT PRIMARY KEY REFERENCES requests(id), resolution TEXT NOT NULL)`: what a GitHub request's names resolved to (Task 6).
- `pub(crate) async fn take_mint(&self, agent: &AgentName) -> Result<bool, RequestError>`: one upsert statement, `INSERT … ON CONFLICT(agent) DO UPDATE SET mint_count = CASE WHEN mint_hour = excluded.mint_hour THEN mint_count + 1 ELSE 1 END, mint_hour = excluded.mint_hour WHERE mint_hour IS NOT excluded.mint_hour OR mint_count < ?limit`; true when a row was written.
- Audit (`audit.rs`): `GithubUnscopedEnded { request_id: Id, grant_id: Option<Id> }` (doc: ended at upgrade because GitHub grants are now scoped to repositories; `grant_id` `None` for a pending request). `GithubTokenMinted` gains `repository: RepoName` and `repository_id: u64` (filled in Task 8; until then from the grant's repository the interim mint used).
- `pub async fn end_unscoped_github(&self) -> Result<usize, RequestError>` (`github_scope.rs`): in one `begin()` transaction, revokes every active `github_token` grant whose `json_array_length(view, '$.access.repositories')` is null or 0 (its request becomes `revoked`), and expires every pending `github_token` request whose body has no repositories; one `GithubUnscopedEnded` per row, through `commit_with_entries`; returns how many. Idempotent.
- `main.rs`: called once after `Requests` is built, before the listeners start; a failure stops startup with context. `tracing::info!` with the count when non-zero.
- `renewal.rs` `ENDING_SOON` gains `AND (json_extract(view, '$.access.kind') != 'github_token' OR json_array_length(view, '$.access.repositories') > 0)`, so legacy grants are never noticed or offered for renewal; `renew_grant` refuses a legacy grant with `NotFound`.

- [ ] **Step 1: Write failing tests** `startup_ends_unscoped_grants` (insert a legacy grant and a legacy pending request with the testkit helpers, run `end_unscoped_github`: grant revoked, request expired, two `github_unscoped_ended` entries), `ending_unscoped_is_idempotent` (second run returns 0, writes nothing), `legacy_grant_still_renders` (grants page 200 and contains `bot`), `legacy_grant_is_never_minted` (with the startup step skipped: mint for `example-owner/example-repo` is 403 `NO_ACTIVE_GRANT`, no call reached GitHub: `upstream.received()` empty), `legacy_grant_not_offered_for_renewal`, `hourly_limit_is_per_agent_across_grants` (limit 2, two grants for different repositories: third mint across them is 429 `HOURLY_LIMIT`), `hourly_limit_survives_restart`, `info_says_scoped_github_tokens`.
- [ ] **Step 2: Run, see them fail.** `cargo test -p warden-broker --all-features --test github_token --quiet 2>&1 | tail -40`.
- [ ] **Step 3: Implement.** The legacy test helpers write rows as 0.12.0 wrote them (grant view without `repositories`, request body `{"kind":"github_token"}`), straight into SQLite.
- [ ] **Step 4: Run the tests; they pass.** Also `cargo test -p warden-broker --all-features --lib --quiet renewal 2>&1 | tail -20`.
- [ ] **Step 5: Commit** `git commit -s -m "Count GitHub tokens per agent and end unscoped grants at upgrade"`.

### Task 6: Requests, resolution on the approval page, and approving

**Files:**
- Modify: `crates/broker/src/requests/github_scope.rs` (checks, slot, resolution, pending view part, digest part), `crates/broker/src/requests/create.rs` (the `github_token` arm calls into it), `crates/broker/src/requests/decide.rs` (`pending_for_token` fills `github`), `crates/broker/src/requests.rs` (`PendingView.github`, `PendingView::destination_digest`), `crates/broker/src/policy/github_app.rs` (`GithubTokenPolicy::grant(scope)`)
- Create: `crates/broker/src/approval/github_token.rs` (approve-time check and grant building, so `approval/mod.rs` gets dispatch lines only)
- Modify: `crates/broker/src/approval/mod.rs` (`check_policy`, `approve_begin`/`approve_finish` use `view.destination_digest()`), `approval/grant.rs` (dispatch), `approval/pages/approve.rs` (`data-target` from `view.destination_digest()`), `crates/broker/src/audit.rs` (`GithubRepositoriesResolved`)
- Test: `crates/broker/tests/github_token/scope.rs` (new, `mod scope;` in that target's `main.rs`)

**Interfaces:**
- Consumes: Task 3's `GithubTokenAccess`, `GrantScope`, testkit `github_token_request`; Task 4's `github_app::resolve` and `MintError::NotAccessible`; Task 5's `github_repositories` table.
- `pub(super) fn check_request(access: &GithubTokenAccess) -> Result<(), RequestError>`: legacy is `Rejected(OLD_CLIENT)`; names with more than one owner are `Rejected("the repositories of one request must belong to one account")` (one installation is one account; GitHub confirms the account at resolution). No key is read: `create.rs` keeps calling only `has_github_app`.
- Dedupe key `format!("{agent}|github_token|{}", access.slot())`; subject `github token for <names joined by ", ">`.
- Stored resolution: `#[derive(Serialize, Deserialize)] pub enum Resolution { Resolved(Vec<ScopedRepository>), NotAccessible }`; `pub struct ScopedRepository { pub id: u64, pub name: RepoName, pub renamed_from: Option<RepoName> }`.
- `pub struct GithubPending { pub resolution: Resolution, pub replaces: Vec<ReplacedGrant> }`; `pub struct ReplacedGrant { pub grant_id: Id, pub scope: GrantScope }`; `GithubPending::digest_input(&self) -> String` (ids and lowercased names in order, then replaced grant ids, each `\0`-separated, prefixed `warden github-token scope v1\0`).
- `PendingView` gains `pub github: Option<GithubPending>`; `pub fn destination_digest(&self) -> String`: `self.destination.digest()` for every kind but GitHub, and for GitHub hex SHA-256 over the policy digest and `digest_input()`.
- `pub(super) async fn github_pending(&self, id: &Id, agent: &AgentName, access: &GithubTokenAccess) -> Result<GithubPending, RequestError>`: reads `github_repositories`; when absent, reads the App, calls `github_app::resolve`, appends `GithubRepositoriesResolved { request_id, repository_ids, accessible }` to the audit log, then `INSERT OR IGNORE` and reads the row back (the first render's result wins). `MintError::NotAccessible` stores `NotAccessible`; any other `MintError` is `RequestError::Unavailable` with the fixed text and stores nothing. `replaces`: the agent's active `github_token` grants whose scope overlaps the resolved ids (legacy rows always). Called only by `pending_for_token`.
- `approval/github_token.rs`: `pub(super) fn check(view: &PendingView) -> Result<(), String>`: refuses a legacy request, a missing `github`, `NotAccessible`, or an empty set (`"this request cannot be approved: the App cannot reach every repository it names"`). `pub(super) fn grant(view: &PendingView, policy: &GithubTokenPolicy, window: Window, now: i64) -> Result<GrantView, GrantFailure>`: `GrantScope::repositories` of the resolved names and ids.
- `GithubTokenPolicy::grant(&self, repositories: GrantScope) -> GithubTokenGrant`.

- [ ] **Step 1: Write failing tests** `creates_request_for_one_repository`, `creation_reads_no_key` (a backend whose `github_app()` fails but `has_github_app()` is true: creation succeeds), `refuses_legacy_body_with_upgrade_message` (`OLD_CLIENT`), `refuses_two_owners`, `same_set_any_case_is_one_slot` (`Example-Owner/Example-Repo` then `example-owner/example-repo`: second answer is `created: false` with the first id), `different_repositories_are_two_slots`, `page_resolves_once` (render twice: one call to GitHub, one `github_repositories_resolved` entry), `page_shows_not_installed_and_no_approve` (scripted 422: page has `cannot be approved` and no `#approve` button), `page_unavailable_when_github_down_and_stores_nothing` (scripted 500: 503 page; a later render with a good answer resolves), `approve_builds_scoped_grant` (grant view's repositories are `[{name: example-owner/example-repo, id: 1001}]`), `approve_refuses_not_accessible`, `approve_refuses_when_resolution_changed` (begin with the page's digest, then overwrite the row in SQLite with another id: finish is 409 `DESTINATION_CHANGED`).
- [ ] **Step 2: Run, see them fail.** `cargo test -p warden-broker --all-features --test github_token scope --quiet 2>&1 | tail -40`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and the whole `github_token` test target; they pass.**
- [ ] **Step 5: Commit** `git commit -s -m "Resolve a GitHub request's repositories when the owner opens it"`.

### Task 7: Overlap replacement, renewal, and the post-approval rules

**Files:**
- Create: `crates/broker/src/requests/github_overlap.rs`
- Modify: `crates/broker/src/requests/renewal.rs` (GitHub stays renewable but no longer replaces by kind; renewal copies names and ids and re-reads current names), `crates/broker/src/requests/decide.rs` (`mark_approved_now` and `approval_events` call the overlap functions), `crates/broker/src/audit.rs` (`GithubTokenGrantReplaced`)
- Test: `crates/broker/tests/github_token/renewal.rs`, `crates/broker/tests/github_token/overlap.rs` (new)

**Interfaces:**
- `renewal::replaced_kind` returns `Some` only for commit signing; `renewable` still true for both kinds.
- `const REPLACED: &str = "replaced";` (the `by` of `GrantRevoked`).
- `Requests::github_replaced_events(&self, agent: &AgentName, access: &GrantAccess) -> Result<(Vec<AuditEvent>, Vec<Id>), RequestError>`: for a GitHub grant, the overlapping active grants of `agent` (by id; legacy always), one `GrantRevoked { by: REPLACED }` and one `GithubTokenGrantReplaced { grant_id, by_grant, repository_ids }` (the overlapping ids; empty for legacy) each, and their ids. Empty for other kinds. Computed under `recorded_change`, as today.
- `pub(super) async fn end_overlapping(tx: &mut Transaction<'static, Sqlite>, agent: &AgentName, kept: &Id, new: &GrantScope, expected: &[Id], now: i64) -> Result<Vec<Id>, RequestError>`: selects inside the `BEGIN IMMEDIATE` transaction that inserts `kept`, ends what overlaps, marks requests revoked, returns them; if the set differs from `expected`, `RequestError::Internal("the GitHub grants to replace changed")` so the transaction rolls back.
- Renewal of a GitHub grant: the request is `GithubTokenAccess { repositories: <the grant's names>, automatic: None }`, goal `Renew GitHub token for <names>`; its `github_repositories` row is written at creation from `github_app::current_names(<the grant's ids>)`, each `ScopedRepository` carrying `renamed_from: Some(<grant's name>)` when GitHub's name differs (case-insensitively); `NotAccessible` on that error. Dedupe slot as in Task 6. The audit entry `GithubRepositoriesResolved` is written for it too.

- [ ] **Step 1: Write failing tests** `grants_for_other_repositories_stay` (approve A then B: both active), `overlapping_grant_is_replaced` (approve {A,B} then {B}: first ends with `by: "replaced"` and a `github_token_grant_replaced` entry naming `1002`), `legacy_grant_is_replaced_by_any` (insert legacy, approve A: legacy ended), `concurrent_overlapping_approvals_leave_one` (two pending requests for A, both pages rendered, both finished under `tokio::join!`: exactly one active grant covers `1001`, the other approval is refused or replaced, never both active), `renewal_copies_names_and_ids` (renew from the grants page: the new request names the same repository and its stored resolution has id `1001` without a second resolve call), `renewal_shows_rename` (`current_names` answers `example-owner/renamed-repo` for `1001`: the stored resolution has `renamed_from: example-owner/example-repo`), `renewal_of_unreachable_repository_cannot_be_approved` (422 at renewal: page says cannot be approved).
- [ ] **Step 2: Run, see them fail.** `cargo test -p warden-broker --all-features --test github_token --quiet overlap 2>&1 | tail -40` and `… renewal …`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and the whole `github_token` target; they pass.**
- [ ] **Step 5: Commit** `git commit -s -m "Replace only the GitHub grants a new one overlaps"`.

### Task 8: The mint handler names its repository

**Files:**
- Modify: `crates/broker/src/api/github_token.rs`, `crates/broker/src/requests/github_token.rs` (lookup by repository)
- Test: `crates/broker/tests/github_token/mint.rs`, `crates/broker/tests/github_token_logs.rs`

**Interfaces:**
- `pub struct ActiveGithubToken { pub grant_id: Id, pub grant: GithubTokenGrant, pub repository: GrantRepository }`.
- `pub enum GithubLookup { None, One(ActiveGithubToken), Ambiguous }`.
- `pub async fn active_github_token_for(&self, agent: &AgentName, repository: &RepoName) -> Result<GithubLookup, RequestError>`: the active, non-legacy grants of `agent` covering `repository` (`GrantScope::covering`); then counts the active grants of `agent` containing that grant's repository id: more than one is `Ambiguous`. Remove `active_github_token(agent)` if nothing else uses it.
- Handler: body `ApiJson<GithubTokenRequest>`; a body that does not parse as one is 400 `OLD_CLIENT` when it is `{}`, else 400 `"the request body is not valid"`, both audited as now. Then: lookup (`None` → 403 `NO_ACTIVE_GRANT`; `Ambiguous` → 409 `AMBIGUOUS_GRANT`, audited), App digest check (409 `APP_CHANGED`), `take_mint(agent)` (429 `HOURLY_LIMIT`), `github_app::mint(…, repository.id, …)` (`NotAccessible` or `WrongScope` → 409 `REPOSITORY_UNREACHABLE`, audited, token discarded, no retry; other errors 503 as now), `GithubTokenMinted` with `repository` and `repository_id`, then the post-mint recheck: `active_github_token_for` again must be `One` with the same `grant_id` and the same repository id, else the existing ended/revoked 409. Response carries `repository` (the grant's stored name) and `repository_id`.

- [ ] **Step 1: Write failing tests** `mints_for_the_named_repository` (recorded body has `repository_ids: [1001]`; response `repository_id` 1001; audit entry has both), `mint_finds_grant_in_any_case` (asks `Example-Owner/Example-Repo`), `mint_refuses_repository_without_grant` (grant for A, ask B: 403, nothing sent to GitHub), `mint_uses_the_right_grant_of_two` (grants A and B: asking B mints `1002` under B's grant id), `mint_refuses_two_grants_covering_one_id` (insert a second active grant row covering `1001` straight into SQLite: 409 `AMBIGUOUS_GRANT`, audited, nothing sent), `mint_refuses_github_answer_for_other_id` (scripted answer for `1002`: 409 `REPOSITORY_UNREACHABLE`, body has no `ghs_`, audited), `mint_reports_unreachable_repository` (scripted 422: same, exactly one call to GitHub), `old_cli_body_says_upgrade` (`{}`: 400 `OLD_CLIENT`), `grant_replaced_during_mint_gets_nothing` (gate the scripted answer, approve an overlapping grant meanwhile, open the gate: 409, as the existing revoked-during test does). Existing mint tests move to the new body.
- [ ] **Step 2: Run, see them fail.** `cargo test -p warden-broker --all-features --test github_token mint --quiet 2>&1 | tail -40`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests, `--test github_token_logs`, and the whole broker crate (`cargo test -p warden-broker --all-features --locked --quiet 2>&1 | tail -40`); they pass.**
- [ ] **Step 5: Commit** `git commit -s -m "Mint a GitHub token for the repository the agent names"`.

### Task 9: The approval page shows the repositories

**Files:**
- Modify: `crates/broker/src/approval/pages/github_token.rs` (headline, multi notice, list, not-accessible state, grants it will end, automatic label, rename), `crates/broker/src/approval/pages/approve.rs` and `pages.rs` (`destination_access` passes `view.github` and the request; no approve button for `NotAccessible`)
- Create: `crates/broker/src/approval/pages/tests/github_fixtures.rs` (move the GitHub fixtures out of `pages/tests.rs`, lines ~471–545, and add the new ones; `pages/tests.rs` keeps one `chain` line), `crates/broker/src/approval/pages/tests/github_page.rs`
- Test: `crates/broker/src/approval/pages/tests/github_page.rs`

**Interfaces (follow `docs/design-language.md`):**
- `pub(super) fn access(policy: &GithubTokenPolicy, request: &GithubTokenAccess, pending: &GithubPending) -> Markup`.
- One repository: the access line's headline is the repository name in the identifier type (`code` inside `bdi`); the badge reads `Can push and merge on <owner/name>`; App and installation move into a detail line.
- Several: a highlighted notice (the existing warning badge style) `This request covers N repositories` above the details, then each repository on its own line; the badge reads `Can push and merge on these N repositories`.
- `renamed_from`: `example-owner/renamed-repo (approved as example-owner/example-repo)`.
- `NotAccessible`: `This request cannot be approved: the App is not installed on <names>, or one of them does not exist.` and no approve button (deny stays).
- `replaces` non-empty: `Approving ends <agent>'s grant for <names>` per grant (`for all repositories of the installation` for legacy).
- `automatic`: `Filed automatically by the git credential helper` / `by the gh wrapper`, and `Working directory: <dir>` when given (escaped, in `bdi`).
- Fixtures emit `approve-github-token` (one repository), `approve-github-token-multi` (three), `approve-github-token-unreachable`, `approve-github-token-replaces`, `approve-github-token-automatic`.

- [ ] **Step 1: Write failing tests** `single_repository_is_the_headline`, `multi_repository_notice_and_list` (contains `This request covers 3 repositories` and each name once), `unreachable_has_no_approve_button`, `replaced_grants_are_listed`, `legacy_replaced_grant_says_all_repositories`, `automatic_label_and_dir_escaped` (dir `/work/<b>x</b>` appears as `&lt;b&gt;`), `rename_shows_both_names`, `page_never_says_every_repository_for_scoped` (no `every repository` in the scoped fixtures). The existing layout, accessibility and self-contained tests run over the new fixtures through the moved `github_token_pages()`.
- [ ] **Step 2: Run, see them fail.** `cargo test -p warden-broker --all-features --lib --quiet approval::pages 2>&1 | tail -40`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests; render and screenshot** with `scripts/screenshot-pages.sh <out-dir>` at the PR template's sizes, light and dark; run `scripts/check-grants-live.py <out-dir>`. Keep the screenshots for the PR.
- [ ] **Step 5: Commit** `git commit -s -m "Show the repositories a GitHub request covers on the approval page"`.

### Task 10: The CLI switches to scoped grants

**Files:**
- Create: `crates/cli/src/client/github.rs` (move `Client::github_token` out of `client.rs`), `crates/cli/src/github_token/cache.rs` (the cache, moved out of `github_token.rs` and changed), `crates/cli/src/request/github.rs` (GitHub request functions moved out of `request.rs`)
- Modify: `crates/cli/src/cli.rs` (`RequestKind::Github { repositories: Vec<RepoName>, … }`, positional, at least one), `crates/cli/src/github_token.rs`, `crates/cli/src/doctor/github.rs` and `doctor.rs` (capability line; dispatch only in `doctor.rs`), `crates/cli/tests/e2e_github_token.rs`
- Test: `crates/cli/src/github_token/tests.rs`, `crates/cli/src/request/tests.rs`, `crates/cli/src/doctor/github/tests.rs`, `crates/cli/tests/e2e_github_token.rs`

**Interfaces:**
- `Client::github_token(&self, repository: &RepoName) -> Result<GithubTokenResponse, CallError>`: body `GithubTokenRequest`.
- `pub(crate) async fn require_scoped(server: &Url) -> Result<()>`: `fetch_info`; `scoped_github_tokens` false or the call failing is `Exit(EXIT_ERROR, "the broker does not support repository-scoped GitHub grants: upgrade the broker before asking for GitHub access")`. Called before any GitHub request is created and before any mint that is not served from the cache.
- `warden request github <owner/name>... --goal … [--for 30d]`: more than one prints to stderr `this request covers N repositories, and the owner sees it as such`. Automatic requests (`request_github_for_tool`) name exactly the repository asked for, with `automatic: Some(AutomaticRequest { by, dir })`; `Pending::AnyOfKind` stays correct because the slot is now the repository set.
- `check_github_grant(grant: &GrantView, repositories: &[RepoName]) -> Result<()>`: refuses another kind, a legacy scope (`"the broker approved an unscoped GitHub grant: upgrade the broker"`), or a scope not covering every asked name.
- Mint answer check: a response whose `repository` does not match the asked name (case-insensitive) is refused and not cached: `"the broker sent a token for another repository"`.
- Cache `github-token.json` (`cache.rs`): `{"version":2,"agent":…,"server":…,"entries":[{"repository":"o/r","repository_id":1001,"grant_id":…,"token":…,"expires_at":…}]}`, `deny_unknown_fields`; any other shape (version 1 included) is treated as absent and replaced on the next write. Same 0600 / owner / regular-file checks; `MAX_CACHE_BYTES` stays 16 KiB with at most 32 entries (the one ending soonest is dropped first). `fn lookup(&self, repository: &RepoName, now: i64) -> Option<&Entry>` (case-insensitive, at least `MIN_REMAINING_SECS` left); `fn put(&mut self, entry: Entry)` replaces an entry with the same id or name; `pub fn discard(grant: &Id) -> Result<bool>` drops that grant's entries.
- `explain` maps `REPOSITORY_UNREACHABLE` (`EXIT_ERROR`, "… do not retry; ask the owner whether the App still reaches it"), `AMBIGUOUS_GRANT` and `OLD_CLIENT`; `APP_CHANGED`'s hint becomes `warden request github <owner/name> --goal …`.
- Doctor: the `github` check adds `broker supports repository-scoped grants` / fails with the upgrade-the-broker fix when `info.scoped_github_tokens` is false.

- [ ] **Step 1: Write failing tests** `request_github_needs_a_repository` (clap: no positional is an error), `request_github_says_n_repositories`, `refuses_old_broker_before_creating` (fake info without the flag: no create call made), `check_grant_refuses_legacy_scope`, `check_grant_refuses_uncovered_repository`, `cache_serves_only_its_repository` (entry for A; lookup B is `None`), `cache_lookup_ignores_case`, `cache_discards_version_one_file`, `cache_keeps_entries_of_other_repositories_on_put`, `discard_drops_only_that_grants_entries`, `cache_refuses_wrong_mode` (existing 0600 tests carried over), `mint_answer_for_other_repository_is_refused`, doctor `github_fails_on_broker_without_scoped_grants`. e2e (`e2e_github_token.rs`, real broker and fake GitHub as today): `git_push_gets_token_for_its_repository` (helper input with `path=example-owner/example-repo.git`), `second_repository_files_its_own_request` (A granted; helper for B files a request naming B; approve; token for `1002`), `gh_wrapper_without_repository_refuses` (`warden github token --gh-args -- auth status` outside a checkout with no `GH_REPO`: exit non-zero, stderr `cannot tell which repository; pass -R owner/name`, stdout empty).
- [ ] **Step 2: Run, see them fail.** `cargo test -p warden-broker-cli --quiet github 2>&1 | tail -40` and `cargo test -p warden-broker-cli --test e2e_github_token --quiet 2>&1 | tail -40`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests; they pass.** Then `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings 2>&1 | tail -20`.
- [ ] **Step 5: Commit** `git commit -s -m "Ask for, mint and cache GitHub tokens per repository"`.

### Task 11: Docs for scoped grants, and PR 2

**Files:**
- Modify: `docs/github-app.md` (tokens reach one repository; keep "never All repositories" as defence in depth), `docs/agent-usage.md`, `docs/agent-instructions.md`, `docs/agent-protocol.md` (`github_token` access body, `POST /v1/github-token` body and response, `scoped_github_tokens` in `/v1/info`, the new error strings), `docs/configuration.md` (`warden request github <owner/name>...`), `docs/interfaces.md`, `docs/threat-model.md` (GitHub tokens: a token for A cannot reach B the App is installed on, stated only as far as Task 0 Step 3 showed; remaining risk: the owner approving the wrong repository; the CLI's choice of repository is not a boundary; revocation residual up to an hour per repository; git-lfs unsupported over the helper), `docs/assurance-case.md`, `docs/security-assessment.md` (risk moved; its date), `docs/upgrading.md` (existing GitHub grants and pending requests end at upgrade, agents ask again per repository; upgrade broker before CLI; run `warden setup github`), `README.md`, `site/index.html` (only if it says what a GitHub grant reaches), `CHANGELOG.md` (Changed: grants scoped to repositories, several per agent, existing grants end at upgrade, migration 0011)
- Find every other mention: `rg -n 'request github|GitHub token grant|every repository' docs README.md site crates/cli/src/guidance.rs`

- [ ] **Step 1: Write the docs**; `crates/cli/src/guidance.rs` texts that show `warden request github --goal` gain the repository argument (its tests follow).
- [ ] **Step 2: Run the full "Before you push" list; all pass.**
- [ ] **Step 3: Commit** `git commit -s -m "Document repository-scoped GitHub grants"`, push, open PR 2 with Task 0's results and the Task 9 screenshots ("Part of #230").

---

## PR 3: Display

### Task 12: Grants page, history, pending list, `warden status`, ending-soon notice

**Files:**
- Modify: `crates/broker/src/approval/pages/github_token.rs` (`grant_access(app_id, installation_id, scope: &GrantScope)`), `approval/pages/grants.rs`, `approval/pages/history.rs`, `approval/pages/pending.rs`, `approval/pages.rs` (summary), `crates/broker/src/requests/renewal.rs` (the notice text names the repositories), `crates/cli/src/recover.rs` (`broker_grant_line`, `access_summary`)
- Modify: `crates/broker/src/approval/pages/tests/github_fixtures.rs` (`grants-github-token-multi`, `grants-github-token-legacy`, `history-github-token`), `docs/agent-usage.md` (status output), `docs/notifications.md` (the notice), `CHANGELOG.md`
- Test: `crates/broker/src/approval/pages/tests/github_page.rs`, `crates/cli/src/recover.rs` tests, `crates/broker/tests/github_token/renewal.rs`

**Interfaces:**
- Grants page: each GitHub grant lists its repositories (one per line); legacy: `All repositories of the installation (ended at upgrade)`. Summaries (history, pending list): `github token for <names joined by ", ">`, legacy `github token (all repositories)`.
- `warden status`: `github token for example-owner/example-repo  grant <id>  until <time>`.
- Notice: `GitHub token for <names> ends in <time>`.

- [ ] **Step 1: Write failing tests** `grants_page_lists_repositories`, `grants_page_shows_legacy`, `history_names_repositories`, `pending_list_names_repositories`, `status_line_names_repositories`, `access_summary_names_repositories`, `ending_soon_notice_names_repositories`.
- [ ] **Step 2: Run, see them fail.** `cargo test -p warden-broker --all-features --lib --quiet approval::pages 2>&1 | tail -40`, `cargo test -p warden-broker-cli --quiet recover 2>&1 | tail -40`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests; screenshots** of the grants and history pages at the template's sizes, light and dark; `scripts/check-grants-live.py <out-dir>`; the full "Before you push" list passes.
- [ ] **Step 5: Commit** `git commit -s -m "Name the repositories of GitHub grants on every page and in status"`, push, open PR 3 with the screenshots ("Closes #230").

After PR 3: the controller deploys to the Pi with the owner, confirms `warden doctor` on the broker and an agent, and runs one real push through a scoped grant on `warden-app-test`.
