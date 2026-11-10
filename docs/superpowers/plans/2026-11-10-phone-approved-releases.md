# Phone-approved releases Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One phone approval lets the broker sign and create a repository's release tag, sign its manifest, and publish its draft, for any repository with a release item, and moves warden's own releases onto it.

**Architecture:** A new grant kind, `release`, bound to repository + tag + commit, lasting at most one day, whose three steps are each claimed once in a new table. Per-repository release keys and a second GitHub App (the release App) are loaded from 1Password like the existing commit-signing key and agent App. The broker talks to GitHub's REST API itself with a repository-scoped release App token that never leaves it.

**Tech Stack:** Rust (workspace pinned toolchain), axum, sqlx/SQLite, reqwest (no decompression), `ssh-key`, `sha1`/`sha2`, clap, HTML pages built the way the approval module already builds them.

**Spec:** `docs/superpowers/specs/2026-11-10-phone-approved-releases-design.md` (read it before any task). Background: `docs/superpowers/specs/2026-11-08-agent-access-model-design.md` ("Release"), `docs/threat-model.md`.

## Global Constraints

- Everything in `AGENTS.md`: no `#[allow]`/`#[expect]` without a reason comment, clippy `all`+`pedantic` denied, `unsafe_code` forbidden, no dead code, no `TODO`, secrets never logged or formatted into errors, fail closed.
- Every file stays under about 800 lines of code (`tokei`). These are already large, so add to them only dispatch lines and put the new code in new modules: `approval/mod.rs` (709), `api.rs` (625), `main.rs` (651), `audit.rs` (639), `cli/src/client.rs` (682), `cli/src/agent.rs`, `cli/src/doctor.rs`. If a task would still push one over, it splits it in the same PR.
- New migration file only: `crates/broker/migrations/0010_release.sql`. Never edit 0001–0009.
- No new crate unless unavoidable; if one is added, `[workspace.dependencies]`, default features off, `cargo deny check`, 7-day crate age.
- reqwest never gains a decompression feature; every GitHub call sends `accept-encoding: identity` and refuses encoded bodies, as `github_app.rs` does.
- No text from GitHub ever goes into an error, a log line or an audit entry, except values the broker parsed and validated (ids, digests, names that passed their pattern).
- Tag pattern: `^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`, at most 64 characters. Commit: exactly 40 lowercase hex. Repository: `owner/name`, owner `^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`, name `^[A-Za-z0-9._-]{1,100}$` and not `.` or `..`; compared ASCII-case-insensitively.
- Item tags: `warden:release-signing` (one per repository), `warden:github-release-app` (at most one).
- Release grant window: exactly 1 day (`Window::D1`), not renewable, ends early when its last step is done.
- Release App token permissions: `contents: write`, `metadata: read`, `repositories: [<name>]`.
- Manifest: at most 64 KiB; lines `<64 lowercase hex>  <name>`; name is a file name `^[A-Za-z0-9._+-]+$` (not `.`/`..`) or `<registry>/<path>:<version>` with lowercase `[a-z0-9._-]` segments and the tag exactly the approved version; at least one line; no duplicate names; every line ends with `\n`.
- Tests never depend on timing (wait on conditions). Public repo: example names only (`build-agent`, `example-owner/example-repo`, `warden.example.ts.net`).
- Each PR: a `CHANGELOG.md` line under `## [Unreleased]`, docs updated in the same PR, `.github/pull_request_template.md` filled in, commits `git commit -s`, no AI attribution.
- Before each push, the full list in `AGENTS.md` "Before you push" passes.

## Review Focus

1. **A tag that already exists.** On the approved commit and signed by this repository's key: the grant covers only the remaining steps. On another commit, unsigned, or signed by another key: refused at request time with a fixed message. Test in Task 6.
2. **Two calls of the same step at once, or a retry after a failure.** Exactly one claims the step; the other gets 409 `STEP_DONE`, and a failed step stays used (the agent asks for a new grant). Test in Task 8.
3. **GitHub hands back a different tag object id.** No ref is created, the step stays used, the refusal is audited, and the agent sees a fixed message. Test in Task 9.
4. **The draft is missing, already published, or lost its manifest when the step runs.** A read-only precondition fails before the step is claimed, so it is not used up. Test in Tasks 10 and 11.
5. **A changelog or commit title with HTML, control characters or megabytes of text.** It is escaped on the page, control characters are shown as escapes, and it is cut at 16 KiB with a note. Test in Task 7.

---

## Issue and PR split

The controller opens one issue per PR before starting, each linking #187, and works them in order. Each PR is reviewable and shippable alone: nothing user-visible appears until PR 3.

| PR | Tasks | Delivers |
|---|---|---|
| 1 | 1–2 | release items load and doctor reports them |
| 2 | 3–4 | the broker's GitHub client for releases, against a fake GitHub |
| 3 | 5–8 | the release grant: request, approval page, grants page, CLI request |
| 4 | 9–12 | the three steps and their CLI commands |
| 5 | 13–14 | warden's own release process on it, docs, ops |
| tap | 15 | the Homebrew tap checks warden's attestations (in `pecheriere/homebrew-tap`) |

A follow-up issue is opened at the end, not built: retire the old key from `docs/release-signers` and the tap after the first warden-signed release, and move landfall (in landfall's repository).

## Task 0: Gate on the spike

The owner ran `spike.sh` on `pecheriere/warden-app-test` (controller's scratchpad). Both results must say "byte-identical" and "bypass works". If either does not, stop and take the result to the owner before any task: the tag step or the ruleset design changes.

---

## PR 1: Release items

### Task 1: Policy types for release items

**Files:**
- Create: `crates/proto/src/release.rs` (validated names and wire types, used from Task 1 on)
- Modify: `crates/proto/src/lib.rs` (`pub mod release;`)
- Create: `crates/broker/src/policy/release_signing.rs`, `crates/broker/src/policy/release_app.rs`
- Modify: `crates/broker/src/policy/mod.rs` (trait methods, `PolicyError` variants), `policy/github_app.rs` (factor the RSA PEM check into `pub(crate) fn parse_rsa_key(pem: &str) -> Result<Arc<KeyPair>, &'static str>` shared by both Apps), `policy/onepassword.rs` (tag consts, trait impls), `policy/local.rs`, `testkit/backend.rs`, `crates/demo/src/parts.rs`
- Test: `crates/broker/src/policy/release_signing/tests.rs`, `crates/broker/tests/policy/release.rs`, `crates/proto/src/release/tests.rs`

**Interfaces:**
- Produces (proto `release`): `RepoName`, `ReleaseTag` (with `fn version(&self) -> &str`), `CommitId`, each via `string_newtype!` with the patterns in Global Constraints; `RepoName::matches(&self, other: &RepoName) -> bool` (ASCII case-insensitive); `RepoName::owner()`, `RepoName::name()`.
- Produces (broker `policy::release_signing`):
  - `pub struct ManifestSpec { pattern: String, namespace: String }` with `fn file_name(&self, version: &str) -> String`
  - `pub struct ReleaseSigningKey { repository: RepoName, key: PrivateKey, tagger_name: String, tagger_email: String, manifest: Option<ManifestSpec>, publish: bool }` with accessors, `fn fingerprint(&self) -> String` (SHA256 form), and `fn destination_digest(&self) -> String` (hex SHA-256 over repository lowercased, fingerprint, tagger, manifest pattern+namespace, publish)
  - `pub fn parse_item(title: &str, fields: &[SecretField]) -> Result<ReleaseSigningKey, String>` — fields `private_key`, `repository`, `tagger_name`, `tagger_email`, optional `manifest`, `manifest_namespace` (required with `manifest`), `publish` (`true`/`false`). Errors never quote a value.
  - `pub fn check_distinct(keys: &[ReleaseSigningKey], commit_signing: Option<&CommitSigningKey>, ca: &PublicKey) -> Result<(), String>` — no two items for one repository, no key shared between two items, with the commit-signing key or with the SSH CA.
- Produces (broker `policy::release_app`): `pub struct ReleaseAppKey { app_id: String, key: Arc<KeyPair> }` with `fn sign_rs256(&self, msg: &[u8])` matching `GithubAppKey`'s, `fn digest(&self) -> String`; `pub fn parse_item(title, fields) -> Result<ReleaseAppKey, String>` — fields `app_id`, `private_key`.
- Produces (trait `SecretBackend`): `fn release_signing(&self, repository: &RepoName) -> Result<ReleaseSigningKey, PolicyError>` (reads every `warden:release-signing` item, runs `check_distinct` over all, then picks the match; any unusable item fails every repository), `fn release_app(&self) -> Result<ReleaseAppKey, PolicyError>`. New `PolicyError` variants: `NoReleaseKey`, `ReleaseKey(String)`, `NoReleaseApp`, `ReleaseApp(String)`. Local and demo backends return `NoReleaseKey`/`NoReleaseApp`; `FakeBackend` gains `with_release_key(ReleaseSigningKey)` and `with_release_app(ReleaseAppKey)`.

- [ ] **Step 1: Write failing tests.** Proto: `repo_name_accepts_owner_slash_name`, `repo_name_refuses` (cases: `owner`, `owner/`, `/name`, `a/b/c`, `owner/..`, `-owner/x`, a 40-char owner, a 101-char name), `release_tag_patterns` (accepts `v1.2.3`, `v0.1.0-rc.2`; refuses `1.2.3`, `v1.2`, `v1.2.3+meta`, `v1.2.3-`, a 65-char tag; `version()` of `v0.1.0-rc.2` is `0.1.0-rc.2`), `commit_id_is_40_lower_hex` (refuses 64 hex, uppercase, 39 chars). Broker: `parses_a_full_item`, `parses_a_tag_only_item` (no `manifest`, `publish` false), `refuses_manifest_without_version_placeholder`, `refuses_manifest_with_slash`, `refuses_manifest_without_namespace`, `refuses_namespace_outside_pattern` (`Warden`, empty, 65 chars), `refuses_non_ed25519_key`, `refuses_bad_publish_value` (`yes`), `refuses_repeated_field`, `errors_never_quote_values` (the error text of each refusal contains none of the field values), `check_distinct_refuses_two_items_for_one_repository` (`Example/Repo` and `example/repo`), `check_distinct_refuses_shared_key`, `check_distinct_refuses_commit_signing_key`, `check_distinct_refuses_ca_key`, `manifest_file_name` (`warden-{version}-SHA256SUMS` + `0.12.0` → `warden-0.12.0-SHA256SUMS`). Integration (`tests/policy/release.rs`, fake Connect): `one_bad_item_fails_every_repository`, `unknown_repository_is_not_configured`, `release_app_loads`, `two_release_apps_fail`.
- [ ] **Step 2: Run them; they fail to compile.** `cargo test -p warden-broker-proto release --quiet 2>&1 | tail -20` and `cargo test -p warden-broker --all-features policy::release --quiet 2>&1 | tail -20`.
- [ ] **Step 3: Implement** the types and functions above; mirror `commit_signing_key()`/`github_app()` in `onepassword.rs` (`tagged()` for many items, `tagged_item` for the App).
- [ ] **Step 4: Run the tests; they pass.** Same commands, then `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings 2>&1 | tail -20`.
- [ ] **Step 5: Commit** `git commit -s -m "Load release signing keys and the release App from 1Password"`.

### Task 2: Doctor checks and item docs

**Files:**
- Create: `crates/broker/src/doctor/release.rs`
- Modify: `crates/broker/src/doctor/mod.rs` (two checks), `doctor/live.rs`, `doctor/local.rs` (names list), `policy/onepassword/probe.rs` (`probe_release_signing`, `probe_release_app`)
- Modify: `docs/1password-items.md`, `docs/configuration.md` (doctor table rows `release-signing`, `release-app`), `CHANGELOG.md`
- Test: `crates/broker/src/doctor/tests.rs`, `crates/broker/tests/doctor.rs`

**Interfaces:**
- Consumes: Task 1's trait methods and `check_distinct`.
- Produces: check names `release-signing` (passes with "none configured" when there are no items; otherwise names each repository it loaded, never a key) and `release-app` (same shape as `github-app`).

- [ ] **Step 1: Write failing tests** `release_signing_passes_with_no_items`, `release_signing_lists_repositories`, `release_signing_fails_on_shared_key`, `release_app_fails_on_two_items`, `local_backend_reports_release_checks_not_configured`.
- [ ] **Step 2: Run, see them fail** (`cargo test -p warden-broker --all-features doctor --quiet 2>&1 | tail -20`).
- [ ] **Step 3: Implement**, mirroring `doctor/github_app.rs`; write the two item sections in `docs/1password-items.md` with every field, its rule and an example using `example-owner/example-repo`.
- [ ] **Step 4: Run tests and the full "Before you push" list; all pass.**
- [ ] **Step 5: Commit**, push, open PR 1 ("Closes #<issue>", "Part of #187").

---

## PR 2: The GitHub client for releases

### Task 3: Release App tokens and the uploads host

**Files:**
- Create: `crates/broker/src/github_release.rs` (module doc: what it calls and why no GitHub text escapes)
- Modify: `crates/broker/src/github_app.rs` (`GithubApi` gains `uploads: Url`; `public()` sets `https://uploads.github.com`; `pinned(base, uploads, ca_pem)`; extract the shared request/response helpers — headers, `refuse_encoded`, bounded body read — into `pub(crate)` functions in `crates/broker/src/github_http.rs`, used by both modules)
- Modify: call sites of `GithubApi::pinned` in tests and `crates/demo/src/lib.rs`
- Modify: `crates/broker/src/testkit/upstream.rs` (dispatch only) and create `crates/broker/src/testkit/github_release.rs` (fake routes and scripting)
- Test: `crates/broker/src/github_release/tests.rs`

**Interfaces:**
- Produces:
  - `pub async fn installation_for(api: &GithubApi, app: &ReleaseAppKey, repo: &RepoName, now: i64) -> Result<u64, GithubError>` — `GET /repos/{owner}/{name}/installation` with the App JWT.
  - `pub async fn release_token(api: &GithubApi, app: &ReleaseAppKey, installation: u64, repo: &RepoName, now: i64) -> Result<InstallationToken, GithubError>` — body `{"repositories":["<name>"],"permissions":{"contents":"write","metadata":"read"}}`; refuses an answer whose `permissions` differ or whose expiry is past `MAX_TOKEN_LIFETIME_SECS`.
  - `pub struct ReleaseClient<'a> { api: &'a GithubApi, token: InstallationToken, repo: RepoName }` constructed by `ReleaseClient::connect(api, app, repo, now) -> Result<Self, GithubError>` (both calls above).
  - `#[derive(thiserror::Error)] pub enum GithubError { Unreachable, Refused(StatusCode), NotFound, Unreadable }` with fixed messages.
- Fake: `GithubReleaseFake` in testkit, a small in-memory repository (default branch, commits with title/date and ancestry, tags, refs, releases with assets, file contents at a commit) that the routes of Tasks 3–4 read and write, plus `record()` of calls for assertions, and a switch to answer any route with a given status.

- [ ] **Step 1: Write failing tests** `installation_lookup_uses_app_jwt`, `release_token_is_limited_to_the_repository` (asserts the exact request body), `release_token_refuses_wider_permissions`, `refuses_encoded_answers`, `refuses_oversized_answers`, `errors_carry_no_github_text` (a 500 whose body contains a marker string: the error's text does not).
- [ ] **Step 2: Run, see them fail** (`cargo test -p warden-broker --all-features github_release --quiet 2>&1 | tail -20`).
- [ ] **Step 3: Implement**; the JWT is built as `github_app::jwt` builds it, with the release App's id.
- [ ] **Step 4: Run tests; they pass. Run the existing `github_app` tests too; they still pass.**
- [ ] **Step 5: Commit** `"Mint repository-scoped release App tokens"`.

### Task 4: The REST calls a release needs

**Files:**
- Create: `crates/broker/src/github_release/rest.rs`, `crates/broker/src/github_release/tag_object.rs`
- Modify: `crates/broker/src/testkit/github_release.rs`
- Test: `crates/broker/src/github_release/tests/rest.rs`

**Interfaces (all methods of `ReleaseClient`, all `-> Result<_, GithubError>`):**
- `commit(&self, id: &CommitId) -> CommitInfo { title: String, date: String }` — first line of the message, at most 200 chars.
- `on_default_branch(&self, id: &CommitId) -> bool` — `GET /repos/{r}` for `default_branch`, then `GET /compare/{id}...{branch}`; true when `status` is `identical` or `ahead`.
- `tag_target(&self, tag: &ReleaseTag) -> Option<ExistingTag>` — `GET /git/ref/tags/{tag}`; for an annotated tag also `GET /git/tags/{sha}`. `ExistingTag { object_sha: String, commit: Option<CommitId>, raw: Option<Vec<u8>> }`; `raw` is the tag object rebuilt by `tag_object::rebuild(&GitTagResponse) -> Vec<u8>` and kept only when its SHA-1 equals `object_sha`.
- `changelog_section(&self, id: &CommitId, version: &str) -> Option<String>` — `GET /contents/CHANGELOG.md?ref={id}` with `accept: application/vnd.github.raw`, at most 1 MiB; returns the lines after `## [<version>]` up to the next `## ` heading, at most 16 KiB (cut on a char boundary, then `"\n…(cut)"`), `None` if absent or not UTF-8.
- `create_tag(&self, body: &CreateTag) -> String` (the object id GitHub returns); `create_ref(&self, tag: &ReleaseTag, sha: &str) -> ()`.
- `release_for_tag(&self, tag: &ReleaseTag) -> Option<Release { id: u64, draft: bool, assets: Vec<Asset { id: u64, name: String, digest: Option<String> }> }>` — `GET /releases?per_page=100` (drafts appear only there), first page; refuses with `Unreadable` if more than one release has that tag.
- `upload_asset(&self, release: u64, name: &str, bytes: &[u8]) -> Asset` (on `api.uploads`, `content-type: application/octet-stream`); `delete_asset(&self, id: u64) -> ()`; `publish(&self, release: u64) -> ()` (`PATCH {"draft":false}`, refuses unless the answer says `draft: false`).
- Size caps: 1 MiB for the release list and contents, 64 KiB for all others.

- [ ] **Step 1: Write failing tests** against the fake: one per method for the good path, plus `on_default_branch_false_when_behind_or_diverged`, `tag_target_none_when_absent`, `tag_target_lightweight_has_no_raw`, `rebuild_matches_git` (a fixture tag object made with `git mktag` in the test from a known payload and SSH signature: `rebuild` of the matching API JSON gives the same bytes), `changelog_section_cut_at_16k`, `changelog_section_none_for_missing_version`, `release_for_tag_finds_draft`, `release_for_tag_refuses_two_matches`, `upload_goes_to_uploads_host`, `publish_refuses_answer_still_draft`.
- [ ] **Step 2: Run, see them fail.**
- [ ] **Step 3: Implement.** Paths are built with `Url::path_segments_mut`, never by string formatting, so a name can't add a path segment.
- [ ] **Step 4: Run tests and the full "Before you push" list; all pass.** No CHANGELOG line (nothing user-visible yet).
- [ ] **Step 5: Commit**, push, open PR 2.

---

## PR 3: The release grant

### Task 5: Wire types, migration, window

**Files:**
- Modify: `crates/proto/src/release.rs`, `crates/proto/src/lib.rs` (`Access::Release`), `crates/proto/src/grant.rs` (`GrantAccess::Release`), `crates/proto/src/window.rs`
- Create: `crates/broker/migrations/0010_release.sql`
- Modify: `fuzz/fuzz_targets/validated_names.rs` (the three new names and an `Access::Release` body)
- Test: `crates/proto/src/release/tests.rs`, `crates/proto/src/tests.rs`

**Interfaces:**
- `Access::Release { repository: RepoName, tag: ReleaseTag, commit: CommitId }`, serde kind `release`.
- `GrantAccess::Release(ReleaseGrant)`; `pub struct ReleaseGrant { repository: RepoName, tag: ReleaseTag, commit: CommitId, key_fingerprint: String, steps: ReleaseSteps, digest: String }`; `pub struct ReleaseSteps { tag: bool, manifest: Option<String>, publish: bool }` (`tag` false when the tag was already in place at request time; `manifest` the file name).
- `Window::RELEASE: [Window; 1] = [Window::D1]`, `Window::is_release()`.
- Step wire types: `ReleaseTarget { repository: RepoName, tag: ReleaseTag }` (body of tag and publish), `SignManifestRequest { repository, tag, name: String, content_b64: String }`, `TagResponse { grant_id, tag, object: String, commit: CommitId }`, `ManifestResponse { grant_id, name: String, signature_name: String, sha256: String }`, `PublishResponse { grant_id, tag }`; consts `NO_ACTIVE_GRANT`, `STEP_DONE`, `STEP_NOT_IN_GRANT`, `NOT_CONFIGURED`, `MAX_MANIFEST_BYTES: usize = 65_536`.
- Migration `0010_release.sql`:
  - `release_facts(request_id TEXT PRIMARY KEY REFERENCES requests(id), facts TEXT NOT NULL)` — the JSON the broker read from GitHub at request time.
  - `release_steps(grant_id TEXT PRIMARY KEY REFERENCES grants(id), tag_claimed_at INTEGER, manifest_claimed_at INTEGER, manifest_sha256 TEXT, signature_sha256 TEXT, publish_claimed_at INTEGER)`.

- [ ] **Step 1: Write failing tests** `release_access_round_trips` (exact JSON `{"kind":"release","repository":"example-owner/example-repo","tag":"v1.2.3","commit":"<40 hex>"}`), `release_access_refuses_bad_fields`, `release_grant_round_trips`, `release_window_is_one_day_only`.
- [ ] **Step 2: Run, see them fail.**
- [ ] **Step 3: Implement**; the migration applies in `cargo test` (startup applies migrations).
- [ ] **Step 4: Run tests; they pass.**
- [ ] **Step 5: Commit** `"Add the release grant's wire types and tables"`.

### Task 6: Creating a release request

**Files:**
- Create: `crates/broker/src/requests/release.rs`
- Modify: `crates/broker/src/requests/create.rs` (one match arm calling into it), `crates/broker/src/requests.rs` (`Destination::Release(ReleasePolicy)`), `requests/pending.rs`, `crates/broker/src/lib.rs` (`AppState` field only if needed)
- Test: `crates/broker/tests/release/main.rs`, `crates/broker/tests/release/request.rs`

**Interfaces:**
- `pub struct ReleaseFacts { commit_title: String, commit_date: String, on_default_branch: bool, changelog: Option<String>, tag_in_place: bool, previous_tag: Option<ReleaseTag> }` (serde, stored in `release_facts`).
- `pub struct ReleasePolicy { repository: RepoName, key_fingerprint: String, manifest: Option<String> (file name for the version), publish: bool, key_digest: String, app_digest: String }` with `digest()` = hash of key `destination_digest()` + app digest, and `steps(&self, tag_in_place: bool) -> ReleaseSteps`.
- `pub async fn check_release(state, access) -> Result<(ReleasePolicy, ReleaseFacts), RequestError>`: loads the key for the repository (absent → `Rejected(NOT_CONFIGURED)`), the release App, connects; refuses unless `on_default_branch`; looks up the tag: absent → `tag_in_place = false`; present → accepted only if it points at the commit and its `raw` object verifies (namespace `git`) against this repository's key, then `tag_in_place = true`; otherwise `Rejected("the tag exists on another commit or under another key")`. If `tag_in_place` and the repository has neither manifest nor publish, refuse ("nothing left to do"). `previous_tag` is the highest `v*` tag below this one by semver among the first 100 tags (`GET /tags`), for the compare link; absent is fine.
- Dedupe key `"{agent}|release|{repo lowercased}|{tag}"`, subject `"release {repo} {tag}"`. Window must be `D1` (anything else refused like other kinds' bad windows).

- [ ] **Step 1: Write failing tests** (fake GitHub + fake backend): `creates_a_pending_release_request`, `refuses_unconfigured_repository`, `refuses_commit_off_default_branch`, `refuses_tag_on_other_commit`, `refuses_tag_signed_by_other_key`, `refuses_lightweight_tag`, `accepts_tag_in_place_and_drops_tag_step`, `refuses_when_nothing_left`, `refuses_when_github_unreachable` (fixed message, nothing stored), `second_request_for_same_release_is_deduplicated`, `refuses_window_other_than_one_day`.
- [ ] **Step 2: Run, see them fail** (`cargo test -p warden-broker --all-features --test release --quiet 2>&1 | tail -30`).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests; they pass.**
- [ ] **Step 5: Commit** `"Check a release request against GitHub before asking the owner"`.

### Task 7: Approving it: approve, pending, history and grants pages

**Files:**
- Create: `crates/broker/src/approval/pages/release.rs`, `crates/broker/src/approval/release.rs` (approve-time re-check and grant building, keeping `approval/mod.rs` to dispatch lines)
- Modify: `approval/mod.rs` (`check_policy`, `api_scope`, `destination_access`, `windows_for`, grant building: dispatch only), `approval/pages/{approve,pending,history,grants}.rs` (dispatch), `approval/warden.js` (add `'release'` to the skipped kinds at :651), `approval/pages/tests.rs` (fixtures `release_request()`, `release_pages()` emitting `approve-release`, `approve-release-tag-in-place`, `pending-release`, `grants-release`, `history-release`)
- Test: `crates/broker/src/approval/pages/tests/release_page.rs`, `crates/broker/tests/release/approve.rs`

**Interfaces:**
- Approve page content (follow `docs/design-language.md`): repository, tag and full commit in the identifier type; commit title and date; "on the default branch"; the changelog section in a `<pre>` with every char HTML-escaped and control characters other than `\n` and `\t` shown as `\u{..}`; "no changelog section for this version" when `None`; a link `https://github.com/{repo}/compare/{previous}...{commit}` when `previous_tag` is known, else to the commit; the steps as a list in the spec's words ("sign and create tag v1.2.3", "sign warden-1.2.3-SHA256SUMS", "publish the draft"); "the tag is already in place on this commit" when the tag step is dropped. No window choice: "for at most 1 day, and it ends when the last step is done".
- At approve: re-read the key and App, compare `ReleasePolicy::digest()` with the binding (409 `DESTINATION_CHANGED` as for other kinds), re-run `check_release`, and refuse if `tag_in_place` or `on_default_branch` changed. The grant is `ReleaseGrant` with `steps` from the policy; insert a `release_steps` row in the same transaction as the grant.
- Grants page: release grants show repository, tag, and each step as "done" / "not yet"; not renewable (no Renew control).

- [ ] **Step 1: Write failing tests** `approve_page_shows_release_facts`, `approve_page_escapes_changelog` (input `<script>`, `\u{1b}[31m`, `&`: output has `&lt;script&gt;`, `\u{1b}`, `&amp;`), `approve_page_cut_changelog_note`, `approve_page_tag_in_place`, `approve_refuses_when_key_changed`, `approve_refuses_when_tag_appeared`, `approve_creates_grant_and_steps_row`, `grants_page_lists_steps`, `release_grant_has_no_renew`.
- [ ] **Step 2: Run, see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests; render and screenshot** with `scripts/screenshot-pages.sh <out-dir>` at the PR template's sizes, light and dark; run `scripts/check-grants-live.py <out-dir>`.
- [ ] **Step 5: Commit** `"Show and approve release requests"`.

### Task 8: Claiming steps, ending the grant, and the CLI request

**Files:**
- Create: `crates/broker/src/requests/release_steps.rs`, `crates/cli/src/release.rs`
- Modify: `crates/cli/src/cli.rs` (`RequestKind::Release`), `crates/cli/src/main.rs` (dispatch), `crates/cli/src/request.rs` (`request_release` calling the shared `request_grant`)
- Modify: `docs/agent-usage.md` (new "Releases" section, request part), `docs/configuration.md` (CLI table row), `docs/agent-protocol.md` (the `release` access kind), `CHANGELOG.md`
- Test: `crates/broker/tests/release/steps.rs`, `crates/cli/src/request/tests.rs`

**Interfaces:**
- `pub enum ReleaseStep { Tag, Manifest, Publish }`.
- `Requests::active_release(&self, agent: &AgentName, repo: &RepoName, tag: &ReleaseTag) -> Result<Option<ActiveRelease { grant_id: Id, grant: ReleaseGrant }>, StoreError>` — matches repo case-insensitively; at most one can be active (the dedupe key and the step design keep it so; two is a storage error, refuse).
- `Requests::claim_step(&self, grant: &Id, step: ReleaseStep, now: i64) -> Result<bool, StoreError>` — one `UPDATE release_steps SET <step>_claimed_at = ? WHERE grant_id = ? AND <step>_claimed_at IS NULL`; true when it claimed.
- `Requests::record_manifest(&self, grant: &Id, manifest_sha256: &str, signature_sha256: &str)`.
- `Requests::end_if_done(&self, grant: &Id, now: i64)` — sets `grants.not_after = now` when every step in `ReleaseSteps` is claimed.
- CLI: `warden request release <owner/name> <tag> --commit <sha> --goal "<goal>" [--session <label>] [--link <url>]`, validating all three locally with the proto types before calling.

- [ ] **Step 1: Write failing tests** `claim_step_once` (two concurrent claims via `tokio::join!`: exactly one true), `claim_step_survives_restart` (claim, reopen the store, claim again: false), `end_if_done_ends_grant_after_last_step`, `end_if_done_waits_for_all_steps`, `active_release_matches_case_insensitively`, CLI `request_release_validates_arguments`, `request_release_sends_access`.
- [ ] **Step 2: Run, see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests and the full "Before you push" list; all pass.**
- [ ] **Step 5: Commit**, push, open PR 3 with the screenshots attached.

---

## PR 4: The steps

All three handlers live in `crates/broker/src/api/release.rs` (routes added in `api.rs`: `POST /v1/release/tag`, `/v1/release/manifest`, `/v1/release/publish`, `agent(handler, BODY_LIMIT)`, the manifest with a limit of `MAX_MANIFEST_BYTES * 2`), and follow `api/github_token.rs`'s `audited`/`attempt` shape: find the active grant (403 `NO_ACTIVE_GRANT`), step in the grant (409 `STEP_NOT_IN_GRANT`), re-read key and App and compare digests with the grant (409 `DESTINATION_CHANGED`), run read-only preconditions, claim (409 `STEP_DONE`), act, audit, `end_if_done`. Audit variants in `audit.rs`: `ReleaseTagCreated { grant_id, agent, repository, tag, commit, object }`, `ReleaseManifestSigned { grant_id, agent, repository, tag, name, sha256 }`, `ReleasePublished { grant_id, agent, repository, tag }`, `ReleaseRefused { agent, grant_id: Option<Id>, step, reason }` (throttled through `requests/refusal_throttle.rs` like the other refusals).

### Task 9: The tag step

**Files:**
- Create: `crates/broker/src/release_signing.rs` (module doc: why this is kept apart from `commit_signing`), `crates/broker/src/release_signing/tag.rs`, `crates/broker/src/api/release.rs`
- Modify: `crates/broker/src/api.rs` (routes), `crates/broker/src/audit.rs` (variants)
- Test: `crates/broker/src/release_signing/tests.rs`, `crates/broker/tests/release/tag.rs`

**Interfaces:**
- `pub fn tag_payload(commit: &CommitId, tag: &ReleaseTag, tagger_name: &str, tagger_email: &str, time: i64, message: &str) -> Vec<u8>` — exactly `object <c>\ntype commit\ntag <t>\ntagger <name> <<email>> <time> +0000\n\n<message>\n`.
- `pub fn sign_tag(key: &ReleaseSigningKey, payload: &[u8]) -> Result<String, SignFailed>` — namespace `git`, SHA-512, PEM with LF.
- `pub fn tag_object_id(payload: &[u8], signature: &str) -> String` — SHA-1 of `tag <len>\0` + payload + signature.
- `CreateTag` body for `create_tag`: message = `<message>\n` + signature, tagger date `YYYY-MM-DDTHH:MM:SSZ` from `time`.
- Message: `<repo name> <version>` (e.g. `warden 0.12.0`).

- [ ] **Step 1: Write failing tests** `tag_payload_matches_git` (build the payload, sign with a test key, `git mktag` the result in a temp repo and `git verify-tag` it against an allowed-signers file: passes; `git cat-file` id equals `tag_object_id`), `tag_step_creates_signed_tag` (fake GitHub: tag object and ref created, ref points at object, audit entry), `tag_step_refuses_on_id_mismatch` (fake returns another id: no ref call recorded, step used, `ReleaseRefused`), `tag_step_runs_once` (second call 409 `STEP_DONE`), `tag_step_not_in_grant` (grant with tag in place: 409), `tag_step_refuses_without_grant` (403), `tag_step_refuses_when_key_changed` (409, step not used), `tag_step_refuses_after_revocation`.
- [ ] **Step 2: Run, see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests; they pass.**
- [ ] **Step 5: Commit** `"Sign and create a release tag under a release grant"`.

### Task 10: The manifest step

**Files:**
- Create: `crates/broker/src/release_signing/manifest.rs`, `fuzz/fuzz_targets/release_manifest.rs`, `fuzz/seeds/release_manifest/warden` (a real-shaped manifest with example digests)
- Modify: `crates/broker/src/api/release.rs`, `crates/broker/src/signed.rs` `fuzzing` module (expose `manifest::check`), `fuzz/Cargo.toml` (`[[bin]]`)
- Test: `crates/broker/src/release_signing/tests/manifest.rs`, `crates/broker/tests/release/manifest.rs`

**Interfaces:**
- `pub fn check(expected_name: &str, version: &str, name: &str, bytes: &[u8]) -> Result<(), ManifestError>` with the rules in Global Constraints; `ManifestError` has fixed messages naming the rule, never the content.
- `pub fn sign_manifest(key: &ReleaseSigningKey, namespace: &str, bytes: &[u8]) -> Result<String, SignFailed>`.
- Handler order: decode base64; `check`; precondition `release_for_tag` is `Some` and `draft`; claim; sign; delete existing assets named `<name>` or `<name>.sig`; upload both; `record_manifest` with both SHA-256 digests; audit.

- [ ] **Step 1: Write failing tests** for `check`: `accepts_warden_manifest` (file lines + `ghcr.io/example-owner/example-repo:1.2.3` line), `refuses_wrong_name`, `refuses_oversized`, `refuses_uppercase_hex`, `refuses_single_space`, `refuses_path_in_name` (`../x`, `a/b`), `refuses_image_with_other_tag`, `refuses_duplicate_name`, `refuses_empty`, `refuses_missing_final_newline`, `refuses_crlf`. Handler: `manifest_step_uploads_manifest_and_signature` (the uploaded `.sig` verifies with `ssh-keygen -Y verify` in namespace `warden-release`), `manifest_step_replaces_existing_assets`, `manifest_step_refuses_without_draft_and_keeps_step` (then a draft appears: the retry succeeds), `manifest_step_refuses_published_release`, `manifest_step_runs_once`, `manifest_step_not_in_tag_only_repository`. The fuzz target asserts that `check` never panics and that any accepted input re-parses line by line into the same names.
- [ ] **Step 2: Run, see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests; `scripts/fuzz.sh 60 release_manifest`; pass.**
- [ ] **Step 5: Commit** `"Sign and attach a release manifest under a release grant"`.

### Task 11: The publish step

**Files:**
- Modify: `crates/broker/src/api/release.rs`
- Test: `crates/broker/tests/release/publish.rs`

**Interfaces:**
- Preconditions (read-only, before claiming): release for the tag exists and is a draft; when the grant has a manifest, the manifest step was claimed and recorded, and the draft's assets named `<manifest>` and `<manifest>.sig` both exist with `digest` equal to `sha256:<recorded>`; a missing `digest` from GitHub refuses ("GitHub did not report the files' digests").
- Then claim, `publish`, audit, `end_if_done`.

- [ ] **Step 1: Write failing tests** `publish_step_publishes`, `publish_refuses_before_manifest`, `publish_refuses_replaced_manifest` (asset digest differs: refused, step not used), `publish_refuses_missing_digest`, `publish_refuses_already_published`, `publish_step_runs_once`, `publish_not_in_grant_when_publish_false`, `grant_ends_after_publish` (grant no longer active; grants page shows it ended).
- [ ] **Step 2: Run, see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests; they pass.**
- [ ] **Step 5: Commit** `"Publish a release draft under a release grant"`.

### Task 12: CLI commands and docs for the steps

**Files:**
- Modify: `crates/cli/src/release.rs`, `crates/cli/src/cli.rs` (`Cmd::Release { what: ReleaseCmd }`: `Tag { repository, tag }`, `SignManifest { repository, tag, file }`, `Publish { repository, tag }`), `crates/cli/src/main.rs`
- Create: `crates/cli/src/client/release.rs` (`impl Client` block: `release_tag`, `release_manifest`, `release_publish`)
- Modify: `docs/agent-usage.md` (the steps, an example session for a tag-only repository and for warden), `docs/agent-protocol.md` (the three endpoints, bodies, errors), `docs/configuration.md` (CLI rows), `docs/interfaces.md`, `docs/github-app.md` (the release App: permissions, ruleset bypass, installation per repository, `uploads.github.com` egress), `docs/deployment.md` (egress: `api.github.com` and `uploads.github.com`), `docs/threat-model.md` (release grant section, the accepted publish gap from the spec, the residual risk until #186), `docs/assurance-case.md`, `docs/security-assessment.md` (risk moves, date), `README.md`, `CHANGELOG.md`
- Test: `crates/cli/src/release/tests.rs`

**Interfaces:**
- `warden release sign-manifest` reads the file (refuses over `MAX_MANIFEST_BYTES` before sending), uses the file's base name as `name`, prints the response's `name`, `signature_name` and `sha256`. `tag` prints the tag and object id. `publish` prints the tag. Errors print the broker's fixed message and exit non-zero.

- [ ] **Step 1: Write failing tests** `sign_manifest_refuses_large_file_locally`, `sign_manifest_sends_base_name`, `commands_validate_repository_and_tag`.
- [ ] **Step 2: Run, see them fail.**
- [ ] **Step 3: Implement and write the docs.**
- [ ] **Step 4: Run tests and the full "Before you push" list; all pass.**
- [ ] **Step 5: Commit**, push, open PR 4.

---

## PR 5: Warden's releases on it

### Task 13: `sign-release.sh` through warden, and the release steps

**Files:**
- Modify: `scripts/sign-release.sh` (usage `scripts/sign-release.sh vX.Y.Z`; keeps every check; the tag check now verifies against `docs/release-signers` with identity `warden-release` instead of git's `user.signingkey`; builds the manifest in a temp dir, then runs `warden release sign-manifest pecheriere/warden vX.Y.Z <manifest>`, downloads the draft's manifest and `.sig` and verifies them against `docs/release-signers` before printing "Signed"; drops the local-key mode and the `gh release upload`), `scripts/test-sign-release.sh` (tests follow: a fake `warden` on `PATH`)
- Modify: `AGENTS.md` "Releases" (new steps 2–4: the agent asks for the release grant with `warden request release pecheriere/warden vX.Y.Z --commit <sha>`, runs `warden release tag`, waits for the workflow, runs `scripts/sign-release.sh vX.Y.Z`, then `warden release publish`; the owner approves on the phone; the rule that a tag or release needs the owner's yes for that version and commit stays: the phone approval is that yes), `docs/verifying-releases.md` (attestation check required, and why; older releases verify against `docs/release-signers` at their tag), `docs/release-signers` (the identity for new keys is `warden-release`; the new key line is added in Task 14), `CHANGELOG.md`
- Test: `scripts/test-sign-release.sh`

- [ ] **Step 1: Write failing script tests**: `signs_through_warden` (the fake `warden` receives the manifest path and the tag), `refuses_tag_not_signed_by_listed_key`, `refuses_when_returned_signature_does_not_verify`.
- [ ] **Step 2: Run `scripts/test-sign-release.sh`; they fail.**
- [ ] **Step 3: Implement and write the docs.**
- [ ] **Step 4: Run `scripts/test-sign-release.sh` and the full "Before you push" list; all pass.**
- [ ] **Step 5: Commit**, push, open PR 5. Merge it only after Task 14's step 4 (the key is listed) or together with that commit.

### Task 14: Owner setup and the first release (controller with the owner)

Not a subagent task: it needs the owner's GitHub account, vault and approvals.

- [ ] **Step 1:** Give the owner exact steps for: creating the release App (`contents: write`, `metadata: read`, no webhook), installing it on `pecheriere/warden` and `pecheriere/warden-app-test`, and creating `warden:github-release-app` and `warden:release-signing` (warden: `manifest` `warden-{version}-SHA256SUMS`, `manifest_namespace` `warden-release`, `publish` `true`, tagger as in today's tags) items.
- [ ] **Step 2:** Deploy the release containing PRs 1–4 to the Pi (owner approves the Pi change), and allow `uploads.github.com` through the Pi's egress relay. `warden doctor` on the broker shows `release-signing` and `release-app` passing.
- [ ] **Step 3:** End to end on `warden-app-test` with its own release item (tag-only, `publish` true): request, approve on the phone, tag, publish. Check the tag with `git verify-tag` against the item's public key.
- [ ] **Step 4:** Add the new warden key to `docs/release-signers` (`warden-release namespaces="git,warden-release" ssh-ed25519 …`) and to the tap's `release-signers` (tap PR, merged first), in PR 5.
- [ ] **Step 5:** With the owner's OK, change `protect-release-tags` on warden: rules creation, update, deletion, non-fast-forward; the release App as the only bypass actor; save before and after JSON.
- [ ] **Step 6:** The next warden release runs the new `AGENTS.md` steps. Then open the follow-up issue (retire the old key from `docs/release-signers` and the tap; move landfall) and close #187.

## PR tap: Task 15: Attestation check for warden in the tap

**Repository:** `pecheriere/homebrew-tap`. Read its `AGENTS.md` first.

**Files:**
- Modify: `scripts/formula.py` (before rendering warden's formula, run `gh attestation verify <archive> --repo pecheriere/warden --signer-workflow pecheriere/warden/.github/workflows/release.yml --source-ref refs/tags/v<version>` for each archive it puts in the formula, as `scripts/landfall.py` does for landfall; refuse on any failure), `scripts/test_formula.py`, `README.md`

- [ ] **Step 1: Write failing tests** `refuses_archive_without_attestation`, `refuses_attestation_from_other_ref`, `renders_when_attested` (the `gh` call is faked as in `test_landfall.py`).
- [ ] **Step 2: Run the tap's test command from its `AGENTS.md`; they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tap's checks; all pass.**
- [ ] **Step 5: Commit** (signed off), push, open the PR. It merges before the first warden-signed release.
