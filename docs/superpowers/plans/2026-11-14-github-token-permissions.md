# GitHub token permissions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** GitHub token grants hold a permission set the owner approved on the phone: an owner-configured default plus extras an agent asked for with a reason, capped by an owner allowlist and a fixed ceiling, with tokens that never exceed that set.

**Architecture:** A new proto module defines permissions, sets, the known names and the ceiling. Two optional fields on the `warden:github-app` item give the default and the allowlist; a backend call reads them without the key. Request creation computes the full set (default now, plus extras) and stores it beside the request in a new table; the approval page reads the installation's permissions, shows and binds the full set (digest v2), and the grant stores it. Minting asks GitHub for the grant's set (or a subset the agent names) and echoes what GitHub granted. The CLI keys its token cache by repository and asked set.

**Tech Stack:** Rust (pinned toolchain), axum, sqlx/SQLite, reqwest (no decompression), serde, clap, maud pages.

**Spec:** `docs/superpowers/specs/2026-11-14-github-token-permissions-design.md` (read it before any task). Background: `docs/threat-model.md` ("GitHub tokens"), `docs/github-app.md`, and the scoped-token plan `docs/superpowers/plans/2026-11-11-scoped-github-tokens.md` for how the code got its present shape.

Tags, as in the spec: **[call]** the spec's call; **[plan call]** a choice this plan makes where the spec left it to the builder, open to correction.

## Global Constraints

- Everything in `AGENTS.md`: no `#[allow]`/`#[expect]` without a reason comment, clippy `all`+`pedantic` denied, `unsafe_code` forbidden, no dead code, no `TODO`, secrets never logged or formatted into errors, fail closed: unreadable or ambiguous state refuses and audits.
- Files stay under about 800 lines (`tokei`). Already large: `crates/broker/src/approval/pages/tests.rs` (621 code), `policy/local.rs` (609), `requests/limits.rs` (543), `requests/renewal.rs` (439 code, 547 lines), `requests/create.rs` (449 code, 537 lines), `crates/cli/src/request.rs` (503). New logic goes in the new modules each task names; only dispatch lines go into these.
- One new migration only: `crates/broker/migrations/0013_github_permissions.sql`. Never edit 0001–0012.
- No new crate.
- A permission is `name:level`, `level` `read` or `write`; `admin` is refused. A set holds each name once and always holds `metadata:read`. Written form: sorted by name, `name:level`, joined with `,`, no spaces. `write` covers `read`. **[call]**
- The ceiling, which no configuration lifts: `administration`, `workflows`, `secrets`, `environments`, every `organization_*`. **[plan call]** `dependabot_secrets` and `codespaces_secrets` (if GitHub lists it for installation tokens) join the ceiling: they are repository secrets under another name, which the spec's anti-goal names.
- Legacy set: `contents:write,issues:write,metadata:read,pull_requests:write` (today's `PERMISSIONS`). Requests and grants stored before this change mean exactly that, never the configured default. Missing `default_permissions` means the legacy set; missing `extra_permissions` means no extras. **[call]**
- A bad permission field makes the App unusable exactly as a bad `installation_id` does today: GitHub tokens refused with the existing fixed error, doctor's `github-app` check fails naming the field, never quoting its value. SSH, APIs, signing and releases keep working.
- Request creation never reads the App's private key; it reads the permission fields through the new backend call.
- The broker never rewrites what the agent sent: the fingerprint stays the agent's. Derived values live in the new table.
- No text from GitHub goes into an error, a log line, a page or an audit entry, except values the broker parsed and checked (known permission names and levels, ids, `RepoName`s).
- Every refusal text is a fixed `pub const` in `crates/proto/src/github_token.rs` (or the new permissions module) so the CLI can recognise it, and carries nothing an agent or GitHub sent except a known permission name.
- Tests never depend on timing. GitHub is faked with `HttpsUpstream` (`crates/broker/src/testkit/upstream.rs`). Public repo: example names only (`example-owner/example-repo` id `1001`, `example-owner/homebrew-tap` id `1002`, `build-agent`).
- Each PR: a `CHANGELOG.md` line under `## [Unreleased]`, the docs its behaviour touches updated in the same PR, `.github/pull_request_template.md` filled in, approval page screenshots at the template's sizes light and dark (`scripts/screenshot-pages.sh`), commits `git commit -s` under the maintainer's configured identity, no AI attribution.
- Before each push, the full list in `AGENTS.md` "Before you push" passes, including `cargo update --workspace` in `fuzz/` only if a requirement changed (none should). Output kept short: `--quiet`, `| tail -40`.
- Implementers read narrowly (`rg`, line ranges). Budget per task: about 100 tool calls; past that, stop and report status and what is left. Stop every background command before returning.

## Review Focus

1. **Owner typos in the item fields.** `checks:read, actions:read` (spaces after commas), `Checks:Read`, a trailing comma, `checks:read,checks:write`, `metadata:write`, `workflows:write` in the allowlist, an empty field. Spaces around entries are accepted; the rest make the App unusable with a reason naming the field and doctor fails, and SSH grants still work. Tests in Tasks 1 and 2.
2. **A request or grant from 0.14 meets the new broker.** A pending request with no `github_permissions` row renders and approves with the legacy set (not the configured default); a page opened before the upgrade and approved after it is refused (digest v2) and works after a reload; an old grant mints with the legacy set and renews to the current default. Tests in Tasks 4, 5 and 6.
3. **The owner changes the default or allowlist after approval.** A widened default never widens an approved grant or a pending request; a narrowed allowlist makes the renewal (and a pending request's page) unapprovable, naming the extra. Tests in Tasks 4, 6 and 8.
4. **GitHub grants fewer permissions than asked** (the owner removed one from the App after approval). The token is served, the response and the `github_token_minted` entry carry GitHub's set, and the CLI caches it under the asked key. A wider answer, or an unknown name in it, is refused as today. Tests in Tasks 3 and 7.
5. **The credential helper races an explicit request with extras.** An automatic request for a repository that has a pending request with extras gets the fixed 409 text, and git shows it instead of hanging; the reverse order too. Tests in Tasks 8 and 11.

---

## Issue and PR split

The controller opens one issue per PR, each linking #276, and works them in order. Each PR is releasable alone.

| PR | Tasks | Delivers | Main after merge |
|---|---|---|---|
| A | 1–7 | the owner's default set: permission types, item fields, doctor, the installation check on the page, the full set stored, bound, granted and minted, renewal to the current default, the token response's `permissions` | releasable: no request wire change; old CLIs ignore the new response field |
| B | 8–12 | requested extras: wire field, allowlist, 409 on a pending request with other extras, the page marks extras, renewal keeps extras, narrowing at mint on the broker, the info flag, `warden request github --extra-permissions`, offers and `warden list`, grants page and `warden status`, prime and agent docs | releasable: the CLI checks the info flag before sending either new field |
| C | 13–14 | the CLI's cache v3 keyed by repository and set, `warden github token --permissions` and `--fresh` | releasable |

**Why the default lands with stored sets.** A configurable default that mints from the current configuration would widen every live grant when the owner widens the default, an anti-goal. So PR A stores the full set per request and grant and mints from the grant, from the first commit that reads the field. **Why broker-side narrowing is in PR B.** `GithubTokenRequest` refuses unknown fields, and one info flag (`github_token_permissions`) announces both new wire fields; shipping them in one broker release keeps one flag honest.

## PR A: The owner's default set

### Task 1: Permission types

**Files:**
- Create: `crates/proto/src/github_permissions.rs`, `crates/proto/src/github_permissions/tests.rs`
- Modify: `crates/proto/src/lib.rs` (module), `crates/proto/src/github_token.rs` (remove `PERMISSIONS`; `GithubTokenGrant.permissions`; `GithubTokenResponse.permissions`), `crates/proto/src/tests.rs` (`github_token_permissions_are_fixed` becomes a legacy-set test)

**Interfaces:**
- Produces:
  - `pub enum Level { Read, Write }` (`Ord`, `Read < Write`), `Display` `read`/`write`.
  - `pub struct Permission { name: &'static str, level: Level }` with `name()`, `level()`, `FromStr` (`name:level`), `Display`. Names come from `KNOWN: &[&str]`: GitHub's repository permissions for "Create an installation access token" minus the ceiling, with a comment citing the docs URL and the date read (left to the builder: the list). Errors: `PermissionError::{Unknown, Ceiling, Admin, Malformed}` with fixed `Display` naming the permission only when it is known or a ceiling name (never echo other input).
  - `pub const CEILING: &[&str]` and `fn under_ceiling(name: &str) -> bool` (exact names plus the `organization_` prefix).
  - `pub struct PermissionSet(BTreeMap<&'static str, Level>)`: `parse(&str) -> Result<Self, PermissionError>` (split on `,`, trim each entry, refuse empty entries and repeated names, add `metadata:read`, refuse `metadata:write`), `Display` canonical form, serde as the canonical string (`try_from = "String"`, `into = "String"`), `legacy() -> Self`, `covers(&self, p: &Permission) -> bool`, `covers_all(&self, other: &Self) -> bool`, `union(&self, other: &Self) -> Self` (higher level wins), `missing_from(&self, other: &Self) -> Vec<Permission>` (entries of `self` that `other` does not cover), `iter()`, `extras_beyond(&self, default: &Self) -> Self` (entries not covered by `default`, without `metadata`), `is_only_metadata()`.
  - `GithubTokenGrant.permissions: PermissionSet`, `#[serde(default = "PermissionSet::legacy")]`.
  - `GithubTokenResponse.permissions: Option<PermissionSet>`, `#[serde(default, skip_serializing_if = "Option::is_none")]` (absent from 0.14 brokers).

- [ ] **Step 1: Write the failing tests** in `github_permissions/tests.rs`: `parses_canonical_and_adds_metadata` (`"checks:read, actions:read"` → `"actions:read,checks:read,metadata:read"`), `refuses_typos` (each of `"Checks:read"`, `"checks:read,"`, `""`, `"checks"`, `"checks:admin"`, `"checks:read,checks:write"`, `"metadata:write"`, `"no_such:read"` errs; the error text for `no_such` does not contain `no_such`), `refuses_ceiling` (`workflows:write`, `administration:read`, `secrets:read`, `environments:read`, `organization_projects:read`, `dependabot_secrets:read` → `PermissionError::Ceiling`), `write_covers_read`, `union_takes_higher_level`, `extras_beyond_default_skips_covered_and_metadata`, `legacy_is_todays_four` (`legacy().to_string() == "contents:write,issues:write,metadata:read,pull_requests:write"`), `serde_round_trips_as_string`. In `github_token/tests.rs`: `grant_without_permissions_parses_as_legacy` (the JSON of a 0.14 grant) and `response_without_permissions_parses`.
- [ ] **Step 2:** `cargo test -p warden-broker-proto --quiet 2>&1 | tail -20` fails to compile (types missing).
- [ ] **Step 3:** Implement the module; replace every use of `PERMISSIONS` in the workspace with `PermissionSet::legacy()` (`rg -n PERMISSIONS crates`), keeping behaviour identical: `github_app.rs`, `github_app/answer.rs`, `api/github_token.rs`, approval page `permissions()`.
- [ ] **Step 4:** `cargo test --workspace --all-features --locked --quiet 2>&1 | tail -20` passes; clippy clean.
- [ ] **Step 5:** Commit `Add GitHub permission sets and the ceiling (#<issue A>)`.

### Task 2: Owner configuration on the App item, the backend call, doctor

**Files:**
- Modify: `crates/broker/src/policy/github_app.rs` (parse the two fields; `GithubAppKey.permissions`; `GithubTokenPolicy.permissions`), `crates/broker/src/policy/mod.rs` (trait method), `crates/broker/src/policy/onepassword.rs` (impl), `crates/broker/src/policy/local.rs` (impl: `NoGithubApp`), `crates/broker/src/testkit/backend.rs` (impl + setter), `crates/broker/src/doctor/github_app.rs` (reasons)
- Test: `crates/broker/tests/policy/github_app.rs`, unit tests in `policy/github_app.rs`

**Interfaces:**
- Consumes: `PermissionSet::parse`, `PermissionError` (Task 1).
- Produces:
  - `pub struct GithubPermissionPolicy { pub default: PermissionSet, pub allowed_extras: PermissionSet }` in `policy/github_app.rs`, re-exported from `policy`.
  - `fn parse_permission_fields(title: &str, fields: &[SecretField]) -> Result<GithubPermissionPolicy, PolicyError>`: labels `default_permissions` and `extra_permissions`; repeated label, present-but-empty, or any `PermissionError` → `PolicyError::GithubApp("item \"<title>\": field \"<label>\" …")` with a fixed reason per error kind, never the value. `allowed_extras` stores what is written (no `metadata` added there: **[plan call]** `metadata:read` in the allowlist is ignored, being always present).
  - `parse_item` also calls it; `GithubAppKey.permissions: GithubPermissionPolicy` with an accessor; `GithubTokenPolicy` gains nothing (the set lives on the request, not the policy).
  - `SecretBackend::github_permissions(&self) -> Result<GithubPermissionPolicy, PolicyError>`: 1Password reads the tagged item and runs only `parse_permission_fields` (the item's `private_key` field is never parsed or kept: the fetched `KeyItem` drops at the end of the call); local and the testkit with no App return `NoGithubApp`; the testkit honours `set_github_app_outage` and gains `set_github_permissions(Option<GithubPermissionPolicy>)` defaulting to the App's own.

- [ ] **Step 1: Failing tests:** `permission_fields_missing_mean_legacy_and_no_extras`; `permission_fields_parse` (`default_permissions = "contents:write,pull_requests:write,issues:write,checks:read"`, `extra_permissions = "actions:read,statuses:read"`); `bad_permission_field_makes_the_app_unusable` for each Review Focus 1 typo, asserting `PolicyError::GithubApp`, the field label in the reason and the value absent from it; `ceiling_in_allowlist_makes_the_app_unusable`; `github_permissions_does_not_need_the_key` (1Password fake: item with a garbage `private_key` and good permission fields → `github_permissions()` Ok, `github_app()` Err); doctor test: `github-app` fails with the field named; an SSH request still succeeds with a bad field (broker test).
- [ ] **Step 2:** Run them; they fail.
- [ ] **Step 3:** Implement as above.
- [ ] **Step 4:** Tests pass; clippy clean.
- [ ] **Step 5:** Commit `Read the default and allowed GitHub permissions from the App item (#<issue A>)`.

### Task 3: Minting a set, and reading the installation's permissions

**Files:**
- Modify: `crates/broker/src/github_app.rs`, `crates/broker/src/github_app/answer.rs`, `crates/broker/src/testkit/upstream.rs` (script `GET /app/installations/<id>`)
- Test: `crates/broker/src/github_app/tests.rs`

**Interfaces:**
- Produces:
  - `pub struct Minted { pub token: InstallationToken, pub granted: PermissionSet }`.
  - `pub async fn mint(api: &GithubApi, key: &GithubAppKey, repository_id: u64, permissions: &PermissionSet, now: i64) -> Result<Minted, MintError>`: body's `permissions` is the set; `check_minted(repository_id, asked: &PermissionSet) -> Result<PermissionSet, MintError>` returns GitHub's set after checking every entry is a known name at a level `asked` covers (unknown name or wider level → `WrongScope`, as today).
  - `pub async fn installation_permissions(api: &GithubApi, key: &GithubAppKey, now: i64) -> Result<InstallationPermissions, MintError>`: `GET /app/installations/{id}` with the App JWT, same client, size limit and no-redirect rules as `request`. `InstallationPermissions` keeps `HashMap<String, u8>` ranks privately and exposes only `missing(&self, wanted: &PermissionSet) -> Vec<Permission>`, so GitHub's own names never leave it.
  - `HttpsUpstream::script_github_installation(&self, response: Scripted)` and a helper `installation_json(permissions: &[(&str, &str)]) -> Vec<u8>`.

- [ ] **Step 1: Failing tests:** `mint_asks_for_the_set` (the scripted request body's `permissions` equals the set); `mint_returns_what_github_granted` (asked `checks:read,…`, GitHub answers without `checks` → Ok with the smaller set); `mint_refuses_wider_or_unknown_permission` (`checks:write` when `checks:read` asked; `"foo":"read"`); `installation_missing_lists_only_our_names` (installation has `contents:write`, `checks:read`, `organization_x:admin`; wanted `checks:write,actions:read` → `[checks:write, actions:read]`); `installation_read_failure_is_an_error` (500, malformed JSON, oversized body).
- [ ] **Step 2:** Run; they fail.
- [ ] **Step 3:** Implement; callers of `mint` pass `&PermissionSet::legacy()` for now (Task 7 switches them).
- [ ] **Step 4:** Tests pass.
- [ ] **Step 5:** Commit `Mint GitHub tokens for a permission set and read the installation's permissions (#<issue A>)`.

### Task 4: The full set stored with each request, bound and granted

**Files:**
- Create: `crates/broker/migrations/0013_github_permissions.sql`, `crates/broker/src/requests/github_permissions.rs`
- Modify: `crates/broker/src/requests/create.rs` (compute and attach), `crates/broker/src/requests/github_scope.rs` (`GithubPending`, digest v2), `crates/broker/src/approval/github_token.rs` (check, grant), `crates/broker/src/policy/github_app.rs` (`GithubTokenPolicy::grant` takes the set), `crates/broker/src/audit/event.rs` (`Approved.permissions`), the approval call site that writes `Approved`
- Test: `crates/broker/tests/github_token/permissions.rs` (new, added to `main.rs`)

**Interfaces:**
- Consumes: `SecretBackend::github_permissions` (Task 2), `installation_permissions` (Task 3).
- Produces:
  - Migration: `CREATE TABLE github_permissions (request_id TEXT PRIMARY KEY REFERENCES requests(id), permissions TEXT NOT NULL, beyond_default TEXT NOT NULL);` with a comment: no row means a request from before 0.15, which means the legacy set. `beyond_default` is the canonical set of extras the default did not cover (empty string when none) **[plan call]**: storing it keeps the page's marking stable when the owner later changes the default.
  - `pub struct StoredPermissions { pub full: PermissionSet, pub beyond_default: Vec<Permission> }` and `Requests::stored_permissions(&self, id: &Id) -> Result<StoredPermissions, RequestError>` (no row → legacy, empty; a row that does not parse → `RequestError::Corrupt`).
  - `Attached.permissions: Option<&StoredPermissions>`; `insert` writes the row in the same transaction as the request.
  - `check_github_token` reads `github_permissions()` (never `github_app()`), returns the `StoredPermissions` (default only in PR A).
  - `pub enum InstallationCheck { Holds, Missing(Vec<Permission>), Unreadable }`.
  - `GithubPending` gains `permissions: StoredPermissions` and `installation: InstallationCheck`; `github_pending` reads the installation each call (not stored: **[call]**). `digest_input` starts `"warden github-token scope v2\0"` and appends the full set's canonical form and `\0` after the repositories.
  - `approval::github_token::check` refuses `Missing` (fixed text naming the missing permissions, Task 5 renders it) and `Unreadable` (fixed text); `grant` passes `view.github.permissions.full` to `GithubTokenPolicy::grant(scope, permissions)`.
  - `AuditEvent::Approved` gains `#[serde(default, skip_serializing_if = "Option::is_none")] permissions: Option<String>` (canonical set), set for GitHub token grants only.

- [ ] **Step 1: Failing tests** (broker integration, faked GitHub): `request_stores_the_default_at_creation` (owner default `…,checks:read`; the grant made from it holds that set); `changed_default_does_not_touch_a_pending_request` (default widened between creation and approval → grant holds the creation-time set); `request_without_row_means_legacy` (insert a row as 0.14 would, no `github_permissions` row, set default to something else → grant holds legacy); `approval_refused_when_installation_lacks_a_permission` and `…when_installation_unreadable`; `approval_binds_the_set` (a digest computed with another set is refused); `creation_never_reads_the_key` (`github_app_reads()` unchanged by `create`); `approved_entry_records_permissions`.
- [ ] **Step 2:** Run; they fail.
- [ ] **Step 3:** Implement. `github_permissions.rs` holds `StoredPermissions`, its storage, and the `InstallationCheck` computation, so `create.rs` and `github_scope.rs` gain only call lines.
- [ ] **Step 4:** `cargo test -p warden-broker --all-features --locked --quiet 2>&1 | tail -30` passes, including the existing `github_token` suite (scripts now also answer the installation read: add it to the shared fixture, not per test).
- [ ] **Step 5:** Commit `Store, bind and grant each GitHub request's permission set (#<issue A>)`.

### Task 5: The approval page shows the set

**Files:**
- Modify: `crates/broker/src/approval/pages/github_token.rs`, `crates/broker/src/approval/pages/tests/github_fixtures.rs`
- Test: `crates/broker/tests/github_token/pages.rs`

**Interfaces:**
- Consumes: `GithubPending.permissions`, `.installation`, `ReplacedGrant.scope` plus the replaced grant's permissions (add `permissions: PermissionSet` to `ReplacedGrant`, read from the grant view).
- Produces: `fn permissions(set: &PermissionSet, beyond_default: &[Permission]) -> Markup` replacing today's constant list (PR A passes an empty `beyond_default`; Task 10 styles it); `not_approvable` renders `Missing` as "this request cannot be approved: the App does not hold <names> on GitHub" and `Unreadable` as "this request cannot be approved: the broker could not read the App's permissions on GitHub" **[plan call]** (exact copy); `replaced` lists each replaced grant's set.

- [ ] **Step 1: Failing tests:** `page_lists_the_full_set`, `page_says_which_permissions_the_app_lacks` (and the approve button absent), `page_says_when_installation_unreadable`, `replaced_grant_shows_its_permissions`.
- [ ] **Step 2:** Run; they fail.
- [ ] **Step 3:** Implement following `docs/design-language.md`.
- [ ] **Step 4:** Tests pass; render with `scripts/screenshot-pages.sh <out>` and keep the screenshots for the PR.
- [ ] **Step 5:** Commit `Show the permission set on the GitHub approval page (#<issue A>)`.

### Task 6: Renewal follows the current default

**Files:**
- Modify: `crates/broker/src/requests/renewal.rs` (one call line), `crates/broker/src/requests/github_permissions.rs` (`renewal_permissions`)
- Test: `crates/broker/tests/github_token/renewal.rs`

**Interfaces:**
- Produces: `Requests::renewal_permissions(&self, grant: &GithubTokenGrant) -> Result<StoredPermissions, RequestError>`: the current default (PR A; Task 9 adds the grant's extras), attached by `create_renewal`. When a renewal finds a pending request in the slot, it keeps that request's stored set.

- [ ] **Step 1: Failing tests:** `renewal_uses_the_current_default` (grant holds legacy; default now `…,checks:read`; the renewal's grant holds the new default); `renewal_of_legacy_grant_with_narrowed_default` (default narrowed to `contents:read`: renewal page approvable, grant holds `contents:read,metadata:read`); `renewal_page_shows_the_difference` (page lists the grant's set and the new set when they differ: copy "was <old set>" **[plan call]**).
- [ ] **Step 2–4:** Run (fail), implement, run (pass).
- [ ] **Step 5:** Commit `Renew GitHub grants with the current default permissions (#<issue A>)`.

### Task 7: Mint the grant's set, echo GitHub's answer; docs for PR A

**Files:**
- Modify: `crates/broker/src/api/github_token.rs`; docs `README.md`, `docs/github-app.md`, `docs/1password-items.md`, `docs/configuration.md`, `docs/agent-protocol.md` (response field), `docs/interfaces.md`, `docs/upgrading.md`, `docs/threat-model.md`, `docs/assurance-case.md`, `docs/security-assessment.md` (and its date), `CHANGELOG.md`
- Test: `crates/broker/tests/github_token/mint.rs`, `crates/broker/tests/github_token_logs.rs`

**Interfaces:**
- Consumes: `mint(…, &grant.permissions, …)` (Task 3), `GithubTokenGrant.permissions` (Task 1).
- Produces: `GithubTokenResponse.permissions = Some(minted.granted)`; `GithubTokenMinted.permissions` = GitHub's granted set as `name:level` strings.

- [ ] **Step 1: Failing tests:** `mint_uses_the_grant_set_not_the_current_default` (grant with `checks:read`; owner narrows default; the body GitHub receives still holds `checks:read`); `response_echoes_granted` (GitHub answers without `checks` → response and audit entry lack it); `legacy_grant_mints_legacy`.
- [ ] **Step 2–4:** Run (fail), implement, run (pass).
- [ ] **Step 5:** Docs: the item fields, their format and refusal, the ceiling and why, "old grants keep four, renewals take the default" in upgrading, the risk that moves (an owner-configured default can now be wider than four) in the threat model and assessment. CHANGELOG line, noting migration 0013 and the new `Approved.permissions` field (an older `audit verify` refuses it).
- [ ] **Step 6:** Full "Before you push" list; commit `Mint the grant's GitHub permissions and echo GitHub's (#<issue A>)`; push; open PR A with screenshots; two reviewers per the controller's rules.

## PR B: Requested extras

### Task 8: Extras on the wire, the allowlist, the pending-slot rule

**Files:**
- Modify: `crates/proto/src/github_token.rs` (`GithubTokenAccess.extra_permissions`, `GithubTokenGrant.extra_permissions`, consts), `crates/broker/src/requests/github_permissions.rs` (check and compute), `crates/broker/src/requests/create.rs` (call lines, slot rule), `crates/broker/src/requests.rs` (`RequestError::OtherPermissionsPending`), `crates/broker/src/api.rs` (`status_of` → 409)
- Test: `crates/proto/src/github_token/tests.rs`, `crates/broker/tests/github_token/permissions.rs`

**Interfaces:**
- Produces:
  - `GithubTokenAccess.extra_permissions: Option<PermissionSet>` (wire `extra_permissions`, canonical string, absent when `None`; `RawGithubTokenAccess` gains it so `deny_unknown_fields` still refuses anything else). `GithubTokenAccess::new(repositories, automatic, extra_permissions)`; `automatic` with extras → `ParseError` (**[call]** automatic requests send none). The parsed extras may not be only `metadata:read`.
  - `GithubTokenGrant.extra_permissions: Option<PermissionSet>` (`default`, skip if none): the agent's extras, for renewal. `GithubTokenPolicy::grant(scope, permissions, extra_permissions: Option<PermissionSet>)`, fed from the request's access by `approval::github_token::grant`.
  - Consts: `EXTRA_NOT_ALLOWED: &str = "this broker does not allow that extra GitHub permission: "` followed by the known name (or the level allowed), `OTHER_PERMISSIONS_PENDING: &str = "a request for these repositories with other permissions is pending; cancel it with `warden request cancel <id>` or wait for it"` with the pending id appended **[plan call]** (an id is the broker's, not agent text).
  - `fn check_extras(extras: &PermissionSet, policy: &GithubPermissionPolicy) -> Result<(), Permission>` and `fn full_set(default: &PermissionSet, extras: Option<&PermissionSet>) -> StoredPermissions`.
  - Slot rule: before returning a pending request in a `github_token` slot, compare its stored access's `extra_permissions` (canonical) with the new one's; different → `OtherPermissionsPending(id)`. Same in `create_renewal`.
  - Subject (and so the `request_created` summary and the owner's notification): `github token for <names> +<extras canonical without metadata>` when extras are present.
  - A refused extra writes the existing refused-request entry kind (left to the builder: follow `record_refusal`/`github_token_refused`).

- [ ] **Step 1: Failing tests:** proto: `access_with_extras_round_trips`, `automatic_with_extras_refused`, `access_refuses_ceiling_extra`, `fingerprint_covers_extras` (two requests differing only in extras have different fingerprints). Broker: `extra_outside_allowlist_refused`, `extra_above_allowed_level_refused` (`checks:write` when `checks:read` allowed), `full_set_is_default_plus_extras`, `extra_covered_by_default_not_marked` (`beyond_default` empty), `pending_with_other_extras_is_409` (both orders, including an automatic request against a pending request with extras: Review Focus 5), `pending_with_same_extras_returns_it`, `summary_names_extras`.
- [ ] **Step 2–4:** Run (fail), implement, run (pass).
- [ ] **Step 5:** Commit `Let GitHub token requests name extra permissions within the owner's allowlist (#<issue B>)`.

### Task 9: Render-time recheck and renewal with extras

**Files:**
- Modify: `crates/broker/src/requests/github_permissions.rs`, `crates/broker/src/requests/github_scope.rs` (field), `crates/broker/src/approval/github_token.rs` (check), `crates/broker/src/requests/renewal.rs` (pass the grant's extras into the renewal access)
- Test: `crates/broker/tests/github_token/renewal.rs`, `…/permissions.rs`

**Interfaces:**
- Produces: `GithubPending.not_allowed: Vec<Permission>`, the request's extras that the current allowlist or ceiling refuses, read through `github_permissions()` at each render **[plan call]** (the spec asks it of renewals; doing it for every request means an owner who narrows the allowlist is never shown a request that would no longer be accepted). `check` refuses when non-empty, naming them. `renewal_permissions` = current default ∪ the grant's extras; a renewal is created without checking extras, so the page can say which one is no longer allowed.

- [ ] **Step 1: Failing tests:** `renewal_keeps_extras`, `renewal_with_disallowed_extra_is_unapprovable_and_says_which`, `pending_request_unapprovable_after_allowlist_narrowed`.
- [ ] **Step 2–4:** Run (fail), implement, run (pass).
- [ ] **Step 5:** Commit `Recheck extras on the approval page and keep them on renewal (#<issue B>)`.

### Task 10: The page marks extras; grants page and status show them

**Files:**
- Modify: `crates/broker/src/approval/pages/github_token.rs` (`permissions` markup), `crates/broker/src/approval/pages/grants.rs`, the page CSS the design language names, `crates/cli/src/commands.rs` (status line)
- Test: `crates/broker/tests/github_token/pages.rs`, `crates/cli/src/commands.rs` tests

**Interfaces:**
- Consumes: `StoredPermissions.beyond_default`, `GithubTokenGrant.extra_permissions`.
- Produces: read extras in one style, write extras in a stronger one, and "N beyond the default" **[call]**; the grants page lists each GitHub grant's extras; `warden status` appends ` +<extras>` to a GitHub grant's line.

- [ ] **Step 1: Failing tests:** `page_marks_read_and_write_extras_apart`, `page_counts_extras_beyond_default`, `grants_page_shows_extras`, `status_line_shows_extras`.
- [ ] **Step 2–4:** Run (fail), implement, run (pass); screenshots light and dark at the template's sizes.
- [ ] **Step 5:** Commit `Mark extra GitHub permissions on the approval and grants pages (#<issue B>)`.

### Task 11: Narrowing at mint, the info flag, offers, and the CLI request

**Files:**
- Modify: `crates/proto/src/github_token.rs` (`GithubTokenRequest.permissions`, `PERMISSIONS_NOT_IN_GRANT`), `crates/proto/src/lib.rs` (`InfoResponse.github_token_permissions`), `crates/proto/src/offers.rs` (`GithubOffer`), `crates/broker/src/api.rs` (flag), `crates/broker/src/api/github_token.rs`, `crates/broker/src/api/offers.rs`, `crates/cli/src/cli.rs` (`--extra-permissions`), `crates/cli/src/request/github.rs`, `crates/cli/src/client/github.rs` (`require_permissions`), `crates/cli/src/github_token/cache.rs` (`discard_repositories`), `crates/cli/src/list.rs`
- Test: `crates/broker/tests/github_token/mint.rs`, `crates/cli/tests/e2e_github_token.rs`, `crates/cli/tests/e2e_offers.rs`, `crates/cli/src/list/tests.rs`

**Interfaces:**
- Produces:
  - `GithubTokenRequest.permissions: Option<PermissionSet>`; the broker refuses a set the grant's full set does not cover with 403 `PERMISSIONS_NOT_IN_GRANT` (fixed text + the first such known name), audited as `github_token_refused`; absent means the grant's full set.
  - `InfoResponse.github_token_permissions: bool` (`#[serde(default)]`), `true` from this broker.
  - `GithubOffer.default_permissions: Option<PermissionSet>` and `extra_permissions: Option<PermissionSet>` (both `default`, skipped when none), filled through `github_permissions()`; a bad field leaves both `None` and the offers part reads as unavailable, as other unreadable parts do.
  - CLI: `warden request github <owner/name>... --extra-permissions <set>`; parsed with `PermissionSet::parse` (usage error, exit 64, on a bad value); refused with "upgrade the broker" when `/v1/info` lacks the flag; the CLI recognises `OTHER_PERMISSIONS_PENDING` and prints it as is. When the request is approved, `cache::discard_repositories(&repositories)` drops every cached entry for them (failure reported on stderr, never fatal). `warden list` shows the default set and the allowed extras under GitHub.

- [ ] **Step 1: Failing tests:** broker `narrowed_mint_asks_for_the_subset`, `narrowing_outside_grant_is_403_and_audited`; CLI e2e `extra_permissions_success_scenario` (request with `checks:read,actions:read` → approved → `warden github token --repo` mints a token whose response holds both, not served from an older cached entry), `extra_permissions_against_old_broker_says_upgrade`, `bad_extra_permissions_is_usage_error`, `list_shows_default_and_extras`.
- [ ] **Step 2–4:** Run (fail), implement, run (pass).
- [ ] **Step 5:** Commit `Request extra GitHub permissions from the CLI and narrow at mint (#<issue B>)`.

### Task 12: Prime and docs for PR B

**Files:**
- Modify: `docs/agent-instructions.md` (the GitHub section: ask for extras only when the task needs them, name them with `--extra-permissions`, say why in the goal), the prime template that includes it (`crates/cli/src/prime/template.rs` markers, if the section is outside them), `docs/agent-usage.md`, `docs/agent-protocol.md` (both wire fields, the flag, the 409 and 403 texts), `docs/configuration.md` (CLI table), `docs/interfaces.md`, `docs/threat-model.md` (what an agent can now hold), `docs/assurance-case.md`, `docs/security-assessment.md` and its date, `README.md`, `CHANGELOG.md`
- Test: `crates/cli/src/prime/tests.rs` (the doc and prime stay in step, as the existing test checks)

- [ ] **Step 1:** Update the docs; run the prime tests and `cargo doc` (warnings denied).
- [ ] **Step 2:** Full "Before you push" list; commit `Document requested GitHub permissions (#<issue B>)`; push; PR B with screenshots; two reviewers.

## PR C: The CLI's cache

### Task 13: Cache v3, `--permissions` and `--fresh`

**Files:**
- Modify: `crates/cli/src/github_token/cache.rs`, `crates/cli/src/github_token.rs` (`serve_from`, `cached_or_mint`, `print_token`), `crates/cli/src/cli.rs` and `crates/cli/src/main.rs` (`GithubCmd::Token` flags), `crates/cli/src/client.rs` (`github_token` takes the set)
- Test: `crates/cli/src/github_token/tests.rs`, `crates/cli/tests/e2e_github_token.rs`

**Interfaces:**
- Produces:
  - `VERSION: u8 = 3`; a version 1 or 2 file is ignored and replaced.
  - `pub(super) enum AskedSet { Full, Exactly(PermissionSet) }` with `key(&self) -> String` (`"full"` or the canonical form). Entries carry `asked: String` and `grant_id`; `lookup(repository, asked, now)`; `put` replaces an entry with the same repository and key, and when the new entry's `grant_id` differs from any entry for that repository, drops all of that repository's entries first. `MAX_ENTRIES` stays 32 (left to the builder: confirm the byte cap still holds with the longer key).
  - `warden github token [--repo o/r] [--permissions <set>] [--fresh]`: `--permissions` is parsed (exit 64 on error) and needs the info flag; `--fresh` skips lookup and replaces that entry. The git helper and the `gh` wrapper always ask `Full`. Entries served while 5 minutes remain, dropped once expired (unchanged).

- [ ] **Step 1: Failing tests:** `cache_keys_by_repository_and_set` (a `Full` entry does not answer an `Exactly(checks:read)` lookup, and both coexist); `fresh_skips_and_replaces`; `new_grant_id_drops_the_repository_entries`; `version_2_file_is_replaced`; e2e `permissions_flag_narrows` and `permissions_flag_against_old_broker_says_upgrade`.
- [ ] **Step 2–4:** Run (fail), implement, run (pass).
- [ ] **Step 5:** Commit `Key the GitHub token cache by permission set; add --permissions and --fresh (#<issue C>)`.

### Task 14: Docs for PR C

- [ ] **Step 1:** `docs/configuration.md` (CLI table, cache file version 3), `docs/agent-usage.md` and `docs/agent-instructions.md` (`--permissions` to narrow, `--fresh`), `docs/interfaces.md`, `CHANGELOG.md`.
- [ ] **Step 2:** Full "Before you push" list; commit `Document narrowed and fresh GitHub tokens (#<issue C>)`; push; PR C; two reviewers. After it merges, close #276.
