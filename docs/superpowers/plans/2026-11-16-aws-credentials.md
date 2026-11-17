# AWS credentials Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new access kind, AWS credentials: the owner approves on the phone, and the broker mints temporary STS credentials from a role the owner listed, narrowed by the target's preset or by a custom session policy the agent wrote, which the agent's AWS tools fetch through `credential_process`.

**Architecture:** The proto crate gains IAM policy documents (parse, canonical form, digest, custom-policy rules) and the AWS access, grant and mint wire types, plus a `once` window only AWS accepts. The broker reads a `warden:aws` key item and `warden:aws-target` items from 1Password, creates and approves AWS requests whose identity is (agent, target, policy digest), stores the role and the policy on the grant, and mints through a hand-rolled SigV4 `AssumeRole` call, audited and rate-limited per agent. The CLI requests, mints into a 0600 cache, and writes `credential_process` profiles.

**Tech Stack:** Rust (pinned toolchain), axum, sqlx/SQLite, reqwest (no decompression), serde/serde_json, aws-lc-rs (HMAC) and sha2, jiff, clap, maud pages.

**Spec:** `docs/superpowers/specs/2026-11-16-aws-credentials-design.md` (read it before any task). Patterns to copy: the GitHub token pipeline (`crates/proto/src/github_token.rs`, `crates/broker/src/api/github_token.rs`, `crates/broker/src/requests/github_token.rs`, `crates/broker/src/github_app.rs`, `crates/cli/src/github_token/cache.rs`) and `docs/superpowers/plans/2026-11-14-github-token-permissions.md` for how such a feature landed.

Tags: **[call]** the spec's call; **[plan call]** a choice this plan makes where the spec left it to the builder, open to correction; **[guess]** a spec assumption a step checks.

## Global Constraints

- Everything in `AGENTS.md`: clippy `all`+`pedantic` denied, `unsafe_code` forbidden, no `#[allow]`/`#[expect]` without a reason comment, no dead code, no `TODO`, fail closed (unreadable or ambiguous state refuses and audits).
- Secrets: the broker's secret access key, every minted secret access key and session token live in `secrecy::SecretString` or `Zeroizing` from the HTTP body to the response, never in `Debug`, a log, an audit entry, an error, a page or a file other than the CLI's 0600 cache. The broker's access key id is never printed either **[plan call]**. No text STS sent goes into an error, log, page or audit entry except values parsed and checked (ARNs compared, the returned `AccessKeyId`, known error codes mapped to fixed texts).
- Every refusal text an agent sees is a fixed `pub const` in `crates/proto/src/aws.rs` or `crates/proto/src/aws_policy*.rs`, quoting nothing the agent sent except a known service name.
- Files stay under about 800 lines (`wc -l`). Near the limit today: `policy/local.rs` 780, `testkit/upstream.rs` 798, `doctor/mod.rs` 756, `requests.rs` 749, `testkit/backend.rs` 743, `approval/mod.rs` 742, `requests/renewal.rs` 574, `requests/create.rs` 592. Already over: `crates/broker/src/main.rs` 812, `crates/cli/src/doctor.rs` 846 (Task 13 splits it), `approval/passkeys.rs` 820 (untouched). New logic goes in the new modules each task names; only dispatch lines go into the files above.
- One new migration only: `crates/broker/migrations/0014_aws_credentials.sql`. Never edit 0001–0013.
- No new crate. SigV4 is hand-rolled on `aws-lc-rs` (HMAC-SHA256) and `sha2` **[call]**: `aws-sigv4` pulls `aws-smithy-*` and `aws-credential-types`, more than one form POST needs; Task 7's PR says so.
- STS is reached only at `https://sts.<region>.amazonaws.com/` (regional endpoint), JSON answers (`Accept: application/json`), through `github_http::{client, send, read_body}` (HTTPS only, no redirects, no proxy, encoded answers refused, bounded body).
- Windows: `once` (one credential, grant lasts 15 minutes), `15m`, `30m`, `1h`, `4h`, `1d`, `7d`, `30d`, capped by the target's `max_window`. Sensitive (preset marked `sensitive = yes`, or a custom policy reaching a listed dangerous action): only `once`, `15m`, `30m`, `1h`. Default `1h` either way. **[call]**
- Credential lifetime: grant's remaining time clamped to `[900, 3600]` seconds. `RoleSessionName` `warden-<grant id>` (39 characters, no truncation needed), `SourceIdentity` `warden-<agent>` (at most 39), session tags `warden-grant`, `warden-agent`, `warden-target`.
- Policy limits: custom and preset at most 1,800 characters in canonical form; the raw text an agent sends at most 10,240 bytes **[plan call]**. Version `2012-10-17` only.
- Role ARNs: `arn:aws:iam::<12 digits>:role/<path/>name`, partition `aws` only **[call]**; regions in `aws-cn` or `aws-us-gov` (`cn-*`, `us-gov-*`) refused.
- Tests never depend on timing; STS is faked at the HTTP level through `HttpsUpstream`; no test or CI step calls real AWS. Public repo: account `111122223333`, role `warden/build-box`, target `build`, agent `build-agent`, access key ids `AKIAIOSFODNN7EXAMPLE`, AWS's documented example secret.
- Each PR: `CHANGELOG.md` line under `## [Unreleased]`, the docs its behaviour touches in the same PR (AGENTS.md "Changes and pull requests"), `.github/pull_request_template.md` filled in, approval page screenshots at the template's sizes light and dark (`scripts/screenshot-pages.sh`, Playwright headless shell only, never the installed Chrome), commits `git commit -s` under the maintainer's configured identity, no AI attribution.
- While iterating: `cargo nextest run -p <crate> -E 'test(<name>)'`, output short (`--quiet`, `| tail -40`). Before each push the full "Before you push" list in `AGENTS.md`; `fuzz/Cargo.lock` only if a requirement changed (Task 9 adds a target, not a requirement). Never set `CARGO_TARGET_DIR`.
- Implementers read narrowly (`rg`, line ranges). Budget per task: about 100 tool calls; past that, stop and report status and what is left. Stop every background command before returning. Every `gh` call uses `GH_TOKEN=$(warden github token --repo pecheriere/warden)`.

## Review Focus

1. **Case and wildcard tricks in a custom policy.** `IAM:CreateUser`, `Iam:*`, `sts:assumerole`, `S3:PUTBUCKETPOLICY`, `s3:Put?ucketPolicy`, `ec2:Modify*Attribute`, `ssm:*Command`, `ec2-instance-connect:Send*`, `ram:*`, `"Action": "*"`, `"*:*"`, `"e*:Run*"`, an action with no colon. IAM matches actions case-insensitively, so the identity refusal and the dangerous-list match are case-insensitive and `?` is a wildcard like `*`. Tests in Task 9.
2. **`once` leaking into other kinds, or used twice.** `Window::Once` sorts below `15m`, so the shared `check_window` (`window > max`) would admit it for SSH and API: it is refused by name for every non-AWS kind, at creation and at approval. A spent `once` grant is never the "live grant" a new request is answered with, and its second mint is refused; an STS error answer releases the claim, a transport failure keeps it. Tests in Tasks 4, 5 and 8.
3. **Asking again while holding a grant.** The same custom policy re-ordered or re-spaced has the same digest (canonical form sorts actions, resources and condition values); a shorter request with the same identity is answered with the live grant and rings nobody; a longer one rings and its approval ends the old one ("renewed"); a different policy on the same target, or the preset next to a custom grant, lives side by side; approval never ends a grant that ends later. Tests in Tasks 1 and 5.
4. **The owner edits the target after approval.** A changed preset never changes what an approved grant mints (the grant stores it); a changed `role_arn`, or a deleted target, refuses the mint with `TARGET_CHANGED` **[plan call]**; a page opened before any edit refuses approval with the existing `DESTINATION_CHANGED`. Tests in Tasks 5 and 8.
5. **STS answers that look wrong or leak.** An error body whose `Message` quotes an ARN or a key, an `Expiration` later than asked plus 60 s, an `AssumedRoleUser.Arn` naming another account, role, session or carrying the role's path, a gzip-labelled body, an oversized body, an XML or HTML body, `PackedPolicyTooLarge`: each is refused with a fixed text, audited, and nothing STS wrote reaches the agent or a log. Tests in Tasks 7 and 8.

---

## Pull request split

The controller opens one bead per PR and works them in order. Each PR is mergeable and green alone.

| PR | Tasks | Delivers | Main after merge |
|---|---|---|---|
| 1 | 1–3 | IAM policy documents and role ARNs in proto; the `warden:aws` and `warden:aws-target` items, backend calls; doctor's item checks | releasable: nothing on the wire changes |
| 2 | 4–8 | the `aws` access kind on the wire, `once`, preset requests, identity and live-grant answers, approval and grants pages for presets, renewal of long grants, SigV4 and STS, `POST /v1/aws/credentials`, rate limit, audit, doctor's `GetCallerIdentity`; `docs/aws.md` setup | releasable: custom policies refused with a fixed text; `aws_credentials` not yet announced, so no CLI sends anything |
| 3 | 9–10 | custom-policy rules, the dangerous list, custom requests, the custom approval page, `aws_credentials: true` in `/v1/info`, the `aws_policy` fuzz target | releasable |
| 4 | 11–14 | `warden request aws`, `warden aws credentials`, `warden aws exec`, the cache, `warden setup aws`, client doctor, offers, `warden list`, `warden status` | releasable |
| 5 | 15 | the narrative docs: README, `docs/design.md` access-mode section, `site/index.html`, the finished `docs/aws.md` | releasable |

**Why this differs from the spec's suggested split.** (a) Doctor's `GetCallerIdentity` needs SigV4, so it moves from PR 1 to PR 2. (b) Requests, grants and the approval page for presets are in no suggested PR, but minting cannot be tested or used without them; they land in PR 2 with a page that renders the preset's statements, and PR 3 adds the custom parts. (c) `AGENTS.md` requires the reference docs (`agent-protocol`, `interfaces`, `configuration`, `1password-items`, `deployment`, `threat-model`, `assurance-case`, `security-assessment`, `upgrading`, `agent-usage`, `agent-instructions`) in the PR whose behaviour they describe, so PRs 1–4 carry them and PR 5 keeps the narrative docs. `docs/aws.md` starts in PR 2 because its manual test against a real role follows that setup. (d) The spec asks the first minting PR to record a manual test of preset, custom, a refused action and expiry; custom exists only from PR 3, so PR 2 records preset, a refused action and expiry, and PR 3 records custom and a refused sensitive action.

## PR 1: Policy documents, items, doctor

### Task 1: IAM policy documents, role ARNs, the AWS max window

**Files:**
- Create: `crates/proto/src/aws_policy.rs`, `crates/proto/src/aws_policy/tests.rs`, `crates/proto/src/aws.rs` (role ARN and digest only in this task), `crates/proto/src/aws/tests.rs`
- Modify: `crates/proto/src/lib.rs` (`pub mod aws; pub mod aws_policy;`), `crates/proto/src/window.rs` (`Window::aws_max`)

**Interfaces:**
- Produces (in `aws_policy`):
  - `pub const MAX_POLICY_CHARS: usize = 1800;`, `pub const MAX_POLICY_INPUT_BYTES: usize = 10_240;`, `pub const VERSION: &str = "2012-10-17";`
  - `pub enum Effect { Allow, Deny }`; `pub enum ActionList { Action(Vec<String>), NotAction(Vec<String>) }`; `pub enum ResourceList { Resource(Vec<String>), NotResource(Vec<String>) }`; `pub enum Scalar { Str(String), Bool(bool), Num(serde_json::Number) }`; `pub struct Condition { pub operator: String, pub key: String, pub values: Vec<Scalar> }`; `pub struct Statement { pub sid: Option<String>, pub effect: Effect, pub actions: ActionList, pub resources: ResourceList, pub conditions: Vec<Condition> }`.
  - `pub struct PolicyDocument` with `parse(text: &str) -> Result<Self, PolicyError>`, `statements(&self) -> &[Statement]`, `Display` = canonical form, `canonical(&self) -> String`, `digest(&self) -> PolicyDigest`.
  - Canonical form **[plan call]**: no whitespace; `{"Version":"2012-10-17","Statement":[…]}`; each statement's keys in the order `Sid`, `Effect`, `Action`/`NotAction`, `Resource`/`NotResource`, `Condition`; action and resource lists always arrays, sorted bytewise, exact duplicates removed; `Condition` operators and keys sorted, values always arrays, sorted by their JSON text; statements keep their order. Re-encoding the canonical form yields itself.
  - Parse rules: valid JSON whose input is at most `MAX_POLICY_INPUT_BYTES`; repeated keys in any object refused (a custom map visitor, since `serde_json::Value` keeps the last); `Version` exactly `VERSION`; `Statement` a non-empty array or one object; statement keys only `Sid`, `Effect`, `Action`, `NotAction`, `Resource`, `NotResource`, `Condition` (so `Principal` and `NotPrincipal` are refused: a session policy cannot hold them); exactly one of `Action`/`NotAction` and of `Resource`/`NotResource`, each a non-empty string or array of non-empty strings; `Effect` exactly `Allow` or `Deny`; `Condition` an object of operator to object of key to scalar or array of scalars, no `null`, no nested objects; no string anywhere holds a control character or a character `crate::is_hidden_char` flags; canonical form at most `MAX_POLICY_CHARS` characters (`chars().count()`).
  - `pub enum PolicyError { TooLarge, NotJson, DuplicateKey, NotADocument, Version, NoStatement, UnknownKey(&'static str), Effect, Actions, Resources, Condition, HiddenCharacter, TooLong }` with fixed `Display` texts; `UnknownKey` names the key only when it is `Principal` or `NotPrincipal` (otherwise `"an unknown key"`), never other input.
- Produces (in `aws`):
  - `pub enum PolicyDigest { Preset, Custom(String) }`, serde as a string: `preset`, or 64 lowercase hex; `short(&self) -> &str` (`preset`, or the first 8 hex).
  - `pub struct RoleArn` (serde as string, `try_from = "String"`): `parse` per Global Constraints, name and each path segment `[A-Za-z0-9+=,.@_-]`, name 1–64 characters, whole ARN at most 2,048; `account(&self) -> &str`, `name(&self) -> &str`, `assumed_role_arn(&self, session: &str) -> String` = `arn:aws:sts::<account>:assumed-role/<name>/<session>` (no path: see spec "AWS facts"). Errors are `ParseError` with fixed reasons.
- Produces (in `window.rs`): `Window::aws_max(s: &str) -> Result<Window, ParseError>` accepting `15m`, `30m`, `1h`, `4h`, `1d`, `7d`, `30d`; kept apart from `FromStr` as `commit_signing` is.

- [ ] **Step 1: Write the failing tests** in `aws_policy/tests.rs`: `canonical_form_is_compact_and_ordered` (an input with `Resource` before `Effect`, a single-string `Action`, whitespace → the exact canonical string); `reordering_and_spacing_give_the_same_digest` (two writings of one policy, `["ec2:StopInstances","ec2:StartInstances"]` vs reversed with newlines → equal `digest()`); `canonical_is_a_fixed_point` (`parse(canonical(x)).canonical() == canonical(x)`); `refuses_malformed` (each of: not JSON, `"Version":"2008-10-17"`, no `Statement`, `"Statement":[]`, `"Effect":"allow"`, both `Action` and `NotAction`, empty `Action` array, `"Condition":{"StringEquals":{"k":null}}`, nested object in a condition value, `Principal` → the matching `PolicyError`); `refuses_duplicate_keys` (`{"Effect":"Deny","Effect":"Allow",…}`); `refuses_hidden_characters` (a resource holding U+202E and one holding U+0000); `refuses_long_policy` (1,801 canonical characters → `TooLong`; exactly 1,800 passes); `refuses_oversized_input` (10,241 bytes of padding whitespace → `TooLarge` before parsing); `error_text_never_echoes_input` (a policy with key `"Secretkey12345"` → the error text lacks it); `not_action_and_not_resource_parse` (the preset may use them). In `aws/tests.rs`: `role_arn_parses_path_and_name` (`arn:aws:iam::111122223333:role/warden/build-box` → account `111122223333`, name `build-box`, `assumed_role_arn("warden-abc")` = `arn:aws:sts::111122223333:assumed-role/build-box/warden-abc`); `role_arn_refuses` (`aws-cn` and `aws-us-gov` partitions, `user/` instead of `role/`, an 11-digit account, an empty name, a name of 65 characters, `role/a b`); `digest_serde` (`"preset"` round-trips; a 64-hex value round-trips; uppercase hex and 63 characters refused). In `crates/proto/src/tests.rs` (window tests): `aws_max_parses_aws_windows_only` (`90d` and `once` refused).
- [ ] **Step 2:** `cargo nextest run -p warden-broker-proto --quiet 2>&1 | tail -20` fails to compile.
- [ ] **Step 3:** Implement as above. Comment at the top of `aws_policy.rs`: the IAM JSON policy grammar page and the `AssumeRole` `Policy` limits, with the URLs and the date read, as `github_permissions.rs` does.
- [ ] **Step 4:** Tests pass; `cargo clippy -p warden-broker-proto --all-targets -- -D warnings` clean.
- [ ] **Step 5:** Commit `Parse IAM policy documents and role ARNs (#<bead 1>)`.

### Task 2: The `warden:aws` and `warden:aws-target` items and their backend calls

**Files:**
- Create: `crates/broker/src/policy/aws.rs` (types and item parsers, with unit tests in `crates/broker/src/policy/aws/tests.rs`), `crates/broker/src/policy/onepassword/aws.rs` (Connect reads), `crates/broker/src/policy/local/backend.rs` (the `impl SecretBackend for LocalBackend` block moved out of `local.rs`, lines 672–775, unchanged apart from the new methods), `crates/broker/src/testkit/backend/aws.rs` (fake state and setters)
- Modify: `crates/broker/src/policy/mod.rs` (module, re-exports, `PolicyError::{NoAws, Aws(String), UnknownAwsTarget(String)}`, four trait methods), `crates/broker/src/policy/onepassword.rs` (tags `warden:aws` and `warden:aws-target`, `ItemSummary.updated_at`, impl lines calling `onepassword/aws.rs`), `crates/broker/src/policy/onepassword/probe.rs` (`probe_aws`), `crates/broker/src/policy/local.rs` (`mod backend;`), `crates/broker/src/testkit/backend.rs` (impl lines), `crates/broker/src/requests.rs` (`RequestError` mapping of the new `PolicyError` variants beside `NoGithubApp`)
- Test: `crates/broker/tests/policy/aws.rs` (new, added to `tests/policy/main.rs`, against the Connect fake in `tests/policy/connect.rs`)

**Interfaces:**
- Consumes: `PolicyDocument::parse`, `RoleArn` (Task 1), `Listing::parse`, `values_by_label`/`required_field` (`policy/onepassword/items.rs`), `invalid(item, field, reason)`.
- Produces (in `policy/aws.rs`, re-exported from `policy`):
  - `pub struct Region(String)`: `^[a-z]{2}(-[a-z]+)+-[0-9]$`, `cn-*` and `us-gov-*` refused; `as_str()`.
  - `pub struct AwsKey` (no `Clone`, `Debug` prints neither key part): `access_key_id(&self) -> &str` (`AKIA` + 16 of `[A-Z0-9]` **[plan call]**), `secret_access_key(&self) -> &SecretString` (40 characters), `region(&self) -> &Region`, `updated_at(&self) -> Option<i64>`.
  - `pub struct AwsTarget { pub name: TargetName, pub role_arn: RoleArn, pub max_window: Window, pub preset: Option<PolicyDocument>, pub custom: bool, pub sensitive: bool, pub listing: Listing, pub description: Option<String> }` and `destination_digest(&self) -> String` over name, role ARN, the preset's canonical form (or empty), max window label, `custom`, `sensitive` (with `digest_parts`, `policy/mod.rs`).
  - `pub(in crate::policy) fn parse_key_item(title: &str, fields: &[SecretField], updated_at: Option<i64>) -> Result<AwsKey, PolicyError>`: fields `access_key_id`, `secret_access_key`, `region`; a missing, repeated or malformed one → `PolicyError::Aws("item \"<title>\": field \"<label>\" …")`, never the value.
  - `pub(in crate::policy) fn parse_target_item(title: &str, fields: &[SecretField]) -> Result<AwsTarget, PolicyError>`: title a `TargetName`; `role_arn` (required), `max_window` (required, `Window::aws_max`), `policy` (optional, `PolicyDocument::parse`), `custom` (`allow` trimmed means true; absent or anything else false **[call]**), `sensitive` (`yes` trimmed means true; anything else false), `list` (`Listing::parse`; `Invalid` refuses the item, as the local backend does), `description` (optional, at most 120 characters, no control or hidden characters **[plan call]**). Each failure → `PolicyError::Invalid { item, field, reason }`, reason fixed.
  - `pub struct AwsProbe { pub key: AwsKeyProbe, pub targets: Vec<AwsTargetProbe> }`, `pub enum AwsKeyProbe { Loaded { updated_at: Option<i64> }, NotConfigured, Invalid(String), Unknown(String) }`, `pub struct AwsTargetProbe { pub title: String, pub problem: Option<String> }`.
- Produces (trait `SecretBackend`):
  - `async fn aws_key(&self) -> Result<AwsKey, PolicyError>`: exactly one item tagged `warden:aws` (`tagged_item`), none → `NoAws`, two → `Aws("2 items are tagged …")`.
  - `async fn has_aws(&self) -> Result<bool, PolicyError>`: tag present, item not read (creation never reads the key, as `has_github_app`).
  - `async fn aws_target(&self, name: &TargetName) -> Result<AwsTarget, PolicyError>`: the one item tagged `warden:aws-target` titled `name` (`tagged_titled`), none → `UnknownAwsTarget`.
  - `async fn list_aws_targets(&self) -> Result<Vec<AwsTarget>, PolicyError>`: every valid target; an invalid one is skipped (as `listed_targets` uses `kept`) so others stay usable.
  - `OnePasswordConnect::probe_aws(&self) -> AwsProbe` (not a trait method; doctor calls it as it calls `probe_github_app`).
  - Local backend: `NoAws`, `false`, `UnknownAwsTarget`, empty list. Testkit: `FakeBackend::set_aws_key(Option<AwsKey>)`, `set_aws_target(AwsTarget)`, `remove_aws_target(&TargetName)`, `set_aws_outage(Option<&str>)`; `AwsKey::for_tests(region: &str) -> AwsKey` behind `testkit` with the documented example key.
- `ItemSummary` gains `#[serde(default, rename = "updatedAt")] updated_at: Option<String>`, parsed with `jiff::Timestamp` to Unix seconds; unparseable → `None`.

- [ ] **Step 1: Failing tests:** unit: `key_item_parses` (example key, region `eu-west-1`); `key_item_refuses_each_bad_field` (missing `secret_access_key`, `access_key_id` `ASIA…`, 39-character secret, region `cn-north-1`, `us-gov-west-1`, `EU-WEST-1`), asserting the label is in the reason and the value is not; `target_item_parses` (all fields, `custom = " allow "`, `sensitive = "yes"`); `target_custom_and_sensitive_default_off` (absent, `Allow`, `true` → false); `target_refuses_each_bad_field` (`role_arn` of a user, `max_window = "90d"`, `max_window = "once"`, unparseable `policy`, 1,801-character `policy`, `list = "some"`, a description with U+202E). Integration (Connect fake): `two_aws_items_make_aws_unusable`; `bad_target_is_skipped_others_listed`; `aws_target_unknown`; `has_aws_does_not_read_the_item` (the item body route is never called); `ssh_still_works_with_a_bad_aws_item`.
- [ ] **Step 2:** Run; they fail.
- [ ] **Step 3:** Move the `LocalBackend` impl block to `policy/local/backend.rs` in its own commit first (`Move the local backend's trait impl to its own file`), then implement the above.
- [ ] **Step 4:** `cargo nextest run -p warden-broker --all-features -E 'test(aws) | test(policy)' --quiet 2>&1 | tail -30` passes; clippy clean.
- [ ] **Step 5:** Commit `Read AWS keys and targets from 1Password (#<bead 1>)`.

### Task 3: Doctor checks the items; docs for PR 1

**Files:**
- Create: `crates/broker/src/doctor/aws.rs`
- Modify: `crates/broker/src/doctor/mod.rs` (`mod aws;`, `Environment::aws(&self) -> AwsProbe`, one call in `examine` for each backend), `crates/broker/src/doctor/live.rs` (impl), `crates/broker/src/doctor/tests.rs` (fake env field), `docs/1password-items.md`, `docs/configuration.md` (doctor check names, if that table lists them), `CHANGELOG.md`
- Test: `crates/broker/src/doctor/tests.rs`

**Interfaces:**
- Consumes: `AwsProbe` (Task 2).
- Produces: `pub(super) fn checks(probe: Option<AwsProbe>, backend: Backend, now: i64) -> Vec<Check>` (reuse `github_app::Backend` by moving it to `doctor/mod.rs` as `pub(super) enum Backend` **[plan call]**, so both modules share it). Checks:
  - `aws`: pass "No AWS key: AWS credentials are off. …" when not configured; pass when loaded; fail with the reason when invalid; could-not-check when unknown or Connect is down. When `updated_at` is more than 90 days before `now`: a warning (`Check::warn` if `warden_broker_proto::doctor` has it, else a pass whose text says rotate: left to the builder) naming the age in days and pointing at `docs/1password-items.md` (Task 8 repoints it at `docs/aws.md`). When `updated_at` is `None`: the text says the key's age could not be read.
  - `aws-targets`: pass naming how many targets load; fail listing each bad item's reason (item title and field, never a value); pass "none" when there are no target items.
  - Local backend: `aws` passes saying AWS needs the 1Password backend.

- [ ] **Step 1: Check the [guess]:** read 1Password Connect's API reference for `GET /v1/vaults/{id}/items` and confirm the summary carries `updatedAt` (RFC 3339). Record the URL and date in a comment on `ItemSummary.updated_at`. If it does not, read it from `GET /v1/vaults/{id}/items/{itemId}` instead and adjust Task 2's parsing; if neither, the age check reports "could not check" and the spec's warning is noted as not possible in the PR.
- [ ] **Step 2: Failing tests:** `aws_absent_passes_and_says_how`, `aws_loaded_passes`, `aws_invalid_fails_with_reason`, `aws_key_older_than_90_days_warns` (`updated_at = now - 91 * 86_400`), `aws_key_age_unknown_says_so`, `aws_targets_lists_each_bad_item`, `aws_targets_reason_never_quotes_a_value`, `local_backend_says_aws_needs_1password`.
- [ ] **Step 3:** Run; they fail. Implement; run; they pass.
- [ ] **Step 4: Docs:** `docs/1password-items.md` gains both items (fields, formats, defaults, that two `warden:aws` items disable AWS, that a bad target is skipped and named by doctor), saying AWS credentials are not requestable yet in this release. CHANGELOG under Added: "`warden-server doctor` checks the `warden:aws` key item (including its age) and `warden:aws-target` items, ahead of AWS credentials."
- [ ] **Step 5:** Full "Before you push" list; commit `Check AWS items in doctor (#<bead 1>)`; push; open PR 1; two reviewers.

## PR 2: Preset requests, grants and minting

### Task 4: The `aws` kind and the `once` window on the wire

**Files:**
- Modify: `crates/proto/src/window.rs`, `crates/proto/src/aws.rs`, `crates/proto/src/lib.rs` (`Access::Aws`, `CreateRequest::check_new`), `crates/proto/src/grant.rs` (`GrantAccess::Aws`), `crates/broker/src/requests.rs` (`check_window` refuses `Once`, `window_label`), `crates/broker/src/approval/pages.rs` (`window_words`), and every exhaustive match the compiler names (`rg -n 'Access::Release|GrantAccess::Release' crates`: about 25 sites in broker and CLI; non-AWS sites refuse or skip AWS exactly as they do `Release` where that fits)
- Test: `crates/proto/src/aws/tests.rs`, `crates/proto/src/tests.rs`, `crates/broker/tests/requests/once_window.rs` (new, added to `tests/requests/main.rs`)

**Interfaces:**
- Produces (`window.rs`): `Window::Once` as the **first** variant (serde and label `once`, `secs() == 900`); `pub const AWS: [Self; 8]` (`Once` … `D30`), `pub const AWS_SENSITIVE: [Self; 4]` (`Once`, `M15`, `M30`, `H1`), `pub const AWS_DEFAULT: Self = Self::H1`, `is_aws(self)`, `is_aws_sensitive(self)`, `aws_request(s) -> Result<Self, ParseError>` (the eight labels). `FromStr` unchanged (no `once`).
- Produces (`aws.rs`):
  - `pub struct AwsAccess { pub target: TargetName, pub policy: Option<String> }` with `#[serde(try_from = "RawAwsAccess")]`, `RawAwsAccess` `deny_unknown_fields` (the `GithubTokenAccess` pattern: `Access` is internally tagged, so the variant is a newtype; wire shape `{"kind":"aws","target":"build","policy":"…"}` as the spec gives it). `policy` present must be non-empty and at most `MAX_POLICY_INPUT_BYTES`. Methods `digest(&self) -> Result<PolicyDigest, PolicyError>` (`Preset` when `None`, else `Custom(parse(text).digest())`), `slot(&self) -> Result<String, PolicyError>` (`<target>|<digest>`), `summary(&self, digest: &PolicyDigest) -> String` (`aws build (preset)` / `aws build (custom policy 1a2b3c4d)`).
  - `pub struct AwsGrant { pub target: TargetName, pub role_arn: RoleArn, pub policy: Option<String>, pub policy_digest: PolicyDigest, pub custom: bool, pub window: Window, pub sensitive: bool }`: `policy` is the canonical text minted with (custom, or the preset at approval), `None` for the role as it is.
  - `pub struct AwsCredentialsRequest { pub target: TargetName, pub policy_digest: PolicyDigest }` (`deny_unknown_fields`), `pub const CREDENTIALS_PATH: &str = "v1/aws/credentials";`.
  - `pub struct AwsCredentialsResponse { pub access_key_id: String, pub secret_access_key: String, pub session_token: String, pub expires_at: i64, pub grant_id: Id, pub grant_not_after: i64 }` with a `Debug` that redacts the secret key and token.
  - Fixed texts: `NO_ACTIVE_GRANT = "no active AWS grant for this agent, target and policy"`, `NOT_CONFIGURED = "AWS credentials are not configured on this broker"`, `HOURLY_LIMIT`, `TARGET_CHANGED = "the AWS target changed; request a new grant"`, `CUSTOM_NOT_ALLOWED = "this AWS target does not allow custom policies"`, `CUSTOM_UNSUPPORTED = "this broker does not accept custom AWS policies yet"` (deleted in Task 10), `SENSITIVE_WINDOW = "a sensitive AWS grant lasts at most 1h: ask for once, 15m, 30m or 1h"`, `ONCE_ONLY_AWS = "the window once is only for AWS credentials"`, `STS_UNAVAILABLE`, `STS_ACCESS_DENIED` (points at the role's trust policy in `docs/aws.md`), `PACKED_POLICY_TOO_LARGE`, `ANSWER_REFUSED`.
- `Access::Aws(aws::AwsAccess)` (`#[serde(rename = "aws")]`); `GrantAccess::Aws(aws::AwsGrant)`.
- `requests.rs` `check_window` returns `Err(ONCE_ONLY_AWS)` for `Window::Once` before comparing; the commit signing, GitHub token and release checks already list their windows (assert it in tests).

- [ ] **Step 1: Failing tests:** proto: `aws_access_round_trips_and_refuses_unknown_fields` (`{"kind":"aws","target":"build","extra":1}` refused), `empty_or_oversized_policy_refused`, `digest_of_preset_and_custom`, `fingerprint_covers_policy` (two requests differing only in `policy` have different fingerprints), `once_is_only_parsed_by_aws_request` (`Window::from_str("once")`, `github_token_request`, `commit_signing` refuse it), `once_sorts_first_and_lasts_15m`. Broker (`once_window.rs`): `once_refused_for_every_other_kind` (SSH, API, commit signing, GitHub token, release each answer 400 with `ONCE_ONLY_AWS` or their own window refusal; nothing stored).
- [ ] **Step 2:** Run; they fail.
- [ ] **Step 3:** Implement. Until Task 5, `check_against_policy` answers `Access::Aws` with `RequestError::Rejected(NOT_CONFIGURED)` (Task 5 replaces that arm in the same PR).
- [ ] **Step 4:** Workspace tests pass; clippy clean.
- [ ] **Step 5:** Commit `Add the AWS access kind and the once window to the protocol (#<bead 2>)`.

### Task 5: Creating, approving and renewing preset requests

**Files:**
- Create: `crates/broker/migrations/0014_aws_credentials.sql`, `crates/broker/src/requests/aws.rs`, `crates/broker/src/requests/destination.rs` (`Destination` and its `impl`, moved from `requests.rs` lines 273–350, then `Destination::Aws` added), `crates/broker/src/approval/aws.rs`
- Modify: `crates/broker/src/requests.rs` (`mod destination; pub use`), `crates/broker/src/requests/create.rs` (one arm), `crates/broker/src/requests/pending.rs` (`destination` arm), `crates/broker/src/requests/decide.rs` (`end_replaced` and `approval_events` arms), `crates/broker/src/requests/renewal.rs` (AWS renewal), `crates/broker/src/requests/grants.rs` (`ActiveGrant.aws_mints`), `crates/broker/src/approval/mod.rs` (`check_policy` arm), `crates/broker/src/approval/grant.rs` (arm), `crates/broker/src/audit/event.rs` (`Approved.aws_policy_digest`, `AwsRenewalNotified`)
- Test: `crates/broker/tests/aws/main.rs` (new test binary: `create.rs`, `identity.rs`, `approve.rs`, `renewal.rs`), fixtures in `crates/broker/src/testkit/broker.rs` (`TestBroker::with_aws(target: AwsTarget)`)

**Interfaces:**
- Consumes: `AwsAccess`, `AwsGrant`, `Window::AWS*` (Task 4); `SecretBackend::{has_aws, aws_target}` (Task 2).
- Produces:
  - Migration **[plan call]**:
    ```sql
    -- AWS credentials are limited per agent per hour, counted as GitHub tokens are
    -- (github_token_mints): the hour (Unix seconds / 3600) and the mints that hour.
    CREATE TABLE aws_mints (agent TEXT PRIMARY KEY, mint_hour INTEGER NOT NULL, mint_count INTEGER NOT NULL);
    -- The credentials minted under each AWS grant. A `once` grant mints one.
    CREATE TABLE aws_grant_mints (grant_id TEXT PRIMARY KEY REFERENCES grants(id), mints INTEGER NOT NULL);
    ```
  - `Destination::Aws(AwsTarget)`: `digest()` = `AwsTarget::destination_digest`; `max_window()` = the target's; `check_request_window(window, Access::Aws(a))` = `aws::check_window(window, target.max_window, sensitive)` where sensitive is `target.sensitive && a.policy.is_none()` in this PR (Task 10 adds the custom verdict); `check_window` refuses a window not in `Window::AWS` or above the max.
  - `pub(super) fn check_window(window: Window, max: Window, sensitive: bool) -> Result<(), String>` in `requests/aws.rs`: not `is_aws` → refused; `Once` always within the max; sensitive and not `is_aws_sensitive` → `SENSITIVE_WINDOW`.
  - `Requests::check_aws(&self, agent: &AgentName, access: &AwsAccess, window: Window) -> Result<Checked, RequestError>`: `has_aws()` false → `Rejected(NOT_CONFIGURED)`; `aws_target` (unknown → `RequestError::UnknownTarget`); `policy` present → `Rejected(CUSTOM_UNSUPPORTED)` in this PR; window check; dedupe key `<agent>|aws|<target>|<digest>`; subject `access.summary(&digest)`; `existing` = `live_aws_answer(…)`. No AWS call.
  - `Requests::live_aws_answer(&self, agent: &AgentName, target: &TargetName, digest: &PolicyDigest, window: Window) -> Result<Option<CreatedResponse>, RequestError>`: the agent's usable grant with that identity (not revoked, `not_after > now`, and not a `once` grant with `mints >= 1`) whose `not_after >= now + window.secs()`, or any usable one when `window == Once`, answered as `CreatedResponse { id: <its request id>, fingerprint: <its request's>, created: Some(false) }`; the CLI's poll then sees it approved. Rings nobody, stores nothing.
  - `Requests::active_aws_for(&self, agent: &AgentName, target: &TargetName, digest: &PolicyDigest) -> Result<Option<ActiveAws>, RequestError>` with `pub struct ActiveAws { pub grant_id: Id, pub grant: AwsGrant, pub not_after: i64, pub mints: i64 }`: the usable grant ending last (`ORDER BY not_after DESC, id`), joined on `aws_grant_mints`. Queries match on `json_extract(view, '$.access.kind') = 'aws'`, `'$.access.target'` and `'$.access.policy_digest'`.
  - Approval: `approval::aws::check(view: &PendingView) -> Result<(), String>` (the access is `Aws` and, in this PR, preset); `approval::aws::grant(view: &PendingView, target: &AwsTarget, window: Window, now: i64) -> Result<GrantView, GrantFailure>` builds `AwsGrant { role_arn: target.role_arn, policy: target.preset.map(canonical), policy_digest: Preset, custom: false, window, sensitive: target.sensitive }`. The preset and role are those the owner's page showed: `pending_for_token` read them fresh and the passkey bound `destination_digest`.
  - `decide.rs`: for `GrantAccess::Aws`, `end_replaced` calls `requests::aws::end_same_identity(tx, agent, &grant.grant_id, aws, grant.not_after, now) -> Result<Vec<Id>, RequestError>`, which ends the agent's other live grants with the same target and digest whose `not_after` is earlier than the new grant's, writing `GrantRevoked { by: "renewed" }` through `approval_events`; it never ends one that ends later **[plan call]**: no binding of replaced ids is needed because a same-identity grant holds the same powers, and the mint uses the grant ending last. `AuditEvent::Approved` gains `#[serde(default, skip_serializing_if = "Option::is_none")] aws_policy_digest: Option<String>`.
  - Renewal: rename `OneAtATime` to `Renewable` with a third variant `Aws` (kind `aws`, subject `aws`, name `AWS credentials`, notice "this agent's AWS tools are refused new credentials once it ends; those already issued last up to an hour", windows `[D1, D7, D30]`, no short windows, `notified` → `AwsRenewalNotified`); `replaced_kind` stays commit signing only; `renewable(GrantAccess::Aws(g))` is `g.window >= Window::D1`; `ENDING_SOON` and `renew_grant`'s query add `'aws'` with `window_secs >= 86400`; the renewal's access is `AwsAccess { target, policy: grant.policy if custom else None }` (canonical text re-parses to the same digest: Task 1's fixed point).
  - `ActiveGrant.aws_mints: Option<i64>` (the grants page shows mints so far).

- [ ] **Step 1: Failing tests** (`tests/aws/`, faked backend, no STS): `create.rs`: `preset_request_rings_once`, `unknown_target_400`, `not_configured_400`, `window_over_max_400`, `sensitive_preset_refuses_4h` and `sensitive_preset_allows_once`, `custom_refused_in_this_pr`, `duplicate_pending_returned`; `identity.rs`: `shorter_request_answered_with_live_grant` (live `1d` grant, a `1h` request → its request id, `created: false`, no doorbell, no new row), `once_answered_with_live_grant`, `spent_once_not_answered` (live `once` grant with one mint row → a new `once` request rings), `longer_request_rings_and_replaces` (approve `7d` over a live `1d` → the `1d` grant revoked by `renewed`), `approval_never_ends_a_later_grant`, `preset_and_other_target_live_side_by_side`; `approve.rs`: `grant_stores_role_and_preset` (grant view holds the role ARN and the preset's canonical text), `edited_preset_after_approval_does_not_change_grant`, `page_opened_before_edit_is_destination_changed` (change `policy` between begin and finish → 409), `approved_entry_records_digest`; `renewal.rs`: `aws_1d_grant_gets_ending_soon_notice`, `aws_1h_grant_gets_none`, `renewal_keeps_target_and_digest`.
- [ ] **Step 2:** Run; they fail.
- [ ] **Step 3:** Move `Destination` to `requests/destination.rs` in its own commit (`Move Destination to its own file`), then implement. `create.rs`, `pending.rs`, `decide.rs`, `renewal.rs`, `approval/mod.rs` and `grant.rs` gain only dispatch lines; the logic lives in `requests/aws.rs` and `approval/aws.rs`.
- [ ] **Step 4:** `cargo nextest run -p warden-broker --all-features --quiet 2>&1 | tail -30` passes (existing suites included: `Once` and the new arms touch them).
- [ ] **Step 5:** Commit `Create, approve and renew AWS preset requests (#<bead 2>)`.

### Task 6: The approval and grants pages for presets

**Files:**
- Create: `crates/broker/src/approval/pages/aws.rs`, `crates/broker/src/approval/pages/aws_policy.rs`, `crates/broker/src/approval/pages/tests/aws_page.rs`, `crates/broker/src/approval/pages/tests/aws_fixtures.rs`
- Modify: `crates/broker/src/approval/pages.rs` (`access_line`, `destination_access`, `grant_access`, `windows_for`, `window_words` arms), `crates/broker/src/approval/pages/approve.rs` (headline for AWS), `crates/broker/src/approval/pages/grants.rs`, `crates/broker/src/approval/warden.css` (only if `docs/design-language.md` has no existing class for a statement list)
- Test: the two test files above

**Interfaces:**
- Consumes: `Destination::Aws`, `AwsAccess`, `AwsGrant`, `ActiveGrant.aws_mints` (Task 5); `PolicyDocument::statements` (Task 1).
- Produces:
  - `pub(super) fn access(target: &AwsTarget, access: &AwsAccess) -> Markup`: headline is the target name and its description; then "the preset of <target>", the role ARN, and the preset's statements, or "the role as it is" when the target has no preset. A sensitive preset is in the danger colour with "the owner marked this preset sensitive" and the description **[plan call: copy]**.
  - `pub(super) fn statements(doc: &PolicyDocument, marked: &[MarkedAction]) -> Markup` in `aws_policy.rs`: one line per statement: allow or deny, actions grouped by service (`ec2: StartInstances, StopInstances`), resources, conditions as key, operator, values; `NotAction`/`NotResource` read "every action except …" / "every resource except …"; then the canonical JSON folded in `<details>`. `pub(super) struct MarkedAction { pub action: String, pub reason: &'static str }` is empty in this PR (Task 10 fills it).
  - `window_words(Window::Once) == "one credential, 15 minutes"`; `windows_for(Destination::Aws(t), req)` = `AWS_SENSITIVE` when sensitive, else `AWS` up to the max; the default is `default_window(choices, asked, max)`, the request asking `1h` unless the agent said otherwise.
  - `pub(super) fn grant_access(grant: &AwsGrant, mints: Option<i64>) -> Markup` for the grants page: target, kind (preset / custom with short digest), window, mints so far.

- [ ] **Step 1: Failing tests:** `preset_page_shows_role_and_statements`, `role_as_it_is_page`, `not_action_page_reads_every_action_except`, `sensitive_preset_page_is_red_with_short_windows_only`, `once_reads_one_credential_15_minutes`, `statement_text_is_escaped` (a resource holding `<script>` renders escaped), `grants_page_lists_aws_grant_with_mints`.
- [ ] **Step 2–4:** Run (fail), implement following `docs/design-language.md`, run (pass). Render with `scripts/screenshot-pages.sh <out>` at the template's sizes, light and dark; keep them for the PR.
- [ ] **Step 5:** Commit `Show AWS preset requests and grants on the owner's pages (#<bead 2>)`.

### Task 7: SigV4 and the STS client

**Files:**
- Create: `crates/broker/src/aws.rs` (`pub mod sigv4; pub mod sts;`, `StsApi`), `crates/broker/src/aws/sigv4.rs`, `crates/broker/src/aws/sigv4/tests.rs`, `crates/broker/src/aws/sts.rs`, `crates/broker/src/aws/sts/tests.rs`, `crates/broker/src/testkit/upstream/github.rs` (the GitHub route helpers and handlers moved out of `upstream.rs`, lines ~540–620), `crates/broker/src/testkit/upstream/sts.rs` (the STS fake)
- Modify: `crates/broker/src/lib.rs` (`pub mod aws;`, `AppState.aws: StsApi`), `crates/broker/src/main.rs` (`aws: StsApi::public()`, one line; the file is already over 800 lines, see the report), `crates/broker/src/testkit/broker.rs` (pinned `StsApi`), `crates/broker/src/testkit/upstream.rs` (route arm `POST /` with form content type → STS fake), `crates/broker/src/github_http.rs` (module doc says GitHub and STS)
- Test: the two `tests.rs` files

**Interfaces:**
- Consumes: `AwsKey`, `Region` (Task 2), `RoleArn` (Task 1), `github_http::{client, send, read_body, MAX_RESPONSE_BYTES}`.
- Produces:
  - `pub struct StsApi { base: Option<Url>, ca_pem: Option<Vec<u8>> }`: `public()`, `pinned(base: Url, ca_pem: Vec<u8>)` (tests), `endpoint(&self, region: &Region) -> Url` (`https://sts.<region>.amazonaws.com/`, or the pinned base).
  - `sigv4`: `pub(crate) struct Signing<'a> { pub method: &'a str, pub host: &'a str, pub path: &'a str, pub query: &'a str, pub headers: &'a [(&'a str, &'a str)], pub body: &'a [u8], pub region: &'a str, pub service: &'a str, pub amz_date: &'a str }`; `pub(crate) fn canonical_request(s: &Signing<'_>) -> String`; `pub(crate) fn string_to_sign(s: &Signing<'_>, canonical: &str) -> String`; `pub(crate) fn authorization(s: &Signing<'_>, access_key_id: &str, secret: &SecretString) -> Zeroizing<String>`; `pub(crate) fn amz_date(now: i64) -> String` (jiff, `YYYYMMDD'T'HHMMSS'Z'`). Derived keys are `Zeroizing<Vec<u8>>`.
  - `sts`: `pub(crate) struct AssumeRole<'a> { pub role_arn: &'a RoleArn, pub session_name: &'a str, pub duration_secs: u32, pub policy: Option<&'a str>, pub source_identity: &'a str, pub tags: [(&'static str, &'a str); 3] }`; `pub(crate) async fn assume_role(api: &StsApi, key: &AwsKey, call: &AssumeRole<'_>, now: i64) -> Result<StsCredentials, StsError>`; `pub(crate) struct StsCredentials { pub access_key_id: String, pub secret_access_key: SecretString, pub session_token: SecretString, pub expires_at: i64, pub assumed_role_arn: String }` (redacting `Debug`); `pub(crate) async fn caller_identity(api: &StsApi, key: &AwsKey, now: i64) -> Result<String, StsError>` (the ARN); `pub(crate) enum StsError { Key, Unreachable, AccessDenied, PackedPolicyTooLarge, MalformedPolicy, InvalidKey, RegionDisabled, Refused(u16), Malformed, TooLarge, Compressed }` with fixed `Display`.
  - Request: `POST /`, form body `Action=AssumeRole&Version=2011-06-15&RoleArn=…&RoleSessionName=…&DurationSeconds=…&Policy=…&SourceIdentity=…&Tags.member.N.Key/Value=…` (`url::form_urlencoded`), headers `content-type: application/x-www-form-urlencoded; charset=utf-8`, `host`, `x-amz-date`, `accept: application/json`; signed headers `content-type;host;x-amz-date`.
  - Answer: JSON only. An error answer's `Error.Code` is mapped (`AccessDenied`, `PackedPolicyTooLarge`, `MalformedPolicyDocument`, `InvalidClientTokenId`/`SignatureDoesNotMatch` → `InvalidKey`, `RegionDisabledException`, anything else → `Refused(status)`); `Message` is never read into a `String` that outlives the parse. A success answer's credentials are deserialized into `SecretString` fields directly.
  - Testkit: `HttpsUpstream::script_sts(&self, response: Scripted)`, `sts_received(&self) -> Vec<Received>`, `assume_role_json(access_key_id: &str, expiration: i64, arn: &str) -> Vec<u8>`, `sts_error_json(code: &str, message: &str) -> Vec<u8>`, `caller_identity_json(arn: &str) -> Vec<u8>`.

- [ ] **Step 1: Check the [guess]es** against AWS's documentation (the STS `AssumeRole` and `GetCallerIdentity` API references, "Signature Version 4 signing process", "Query requests for STS", "Session tags", `SourceIdentity`, IAM "role chaining", the JSON answer format and whether `Expiration` comes as epoch seconds or a timestamp string): record each page URL and the date in comments in `sts.rs`. Where a fact differs from the spec, the step that relies on it changes and the PR says so.
- [ ] **Step 2: Failing tests:** `sigv4/tests.rs`: AWS's published SigV4 test-suite vectors `get-vanilla`, `get-vanilla-query-order-key-case`, `post-vanilla`, `post-x-www-form-urlencoded`, `post-x-www-form-urlencoded-parameters`, `post-header-key-sort`, each asserting the canonical request, string to sign and `Authorization` header exactly (vectors inline as constants with the source URL and licence in a comment), plus `amz_date_formats_utc`. `sts/tests.rs` (against `HttpsUpstream`): `assume_role_sends_signed_form` (body fields, tags, signed headers present, the secret key absent from every received header and body); `assume_role_parses_credentials`; `error_codes_map_to_fixed_errors` (each mapped code, and an unknown code → `Refused(403)`); `error_message_never_surfaces` (a `Message` holding `AKIA…` and `arn:aws:iam::111122223333:…`: the error's `Display` and `Debug` lack both); `refuses_xml_html_compressed_and_oversized` (`Content-Encoding: gzip`, body over `MAX_RESPONSE_BYTES`, an XML body, an HTML body); `caller_identity_returns_arn`; `credentials_debug_is_redacted`.
- [ ] **Step 3:** Run; they fail.
- [ ] **Step 4:** Move the GitHub routes out of `testkit/upstream.rs` in its own commit (`Move the GitHub fake's routes to their own file`), then implement.
- [ ] **Step 5:** Tests pass; clippy clean.
- [ ] **Step 6:** Commit `Sign STS calls and assume roles (#<bead 2>)`.

### Task 8: Minting, rate limit, audit, doctor's STS check; docs for PR 2

**Files:**
- Create: `crates/broker/src/api/aws.rs`, `crates/broker/tests/aws/mint.rs`, `crates/broker/tests/aws_logs.rs`, `docs/aws.md`
- Modify: `crates/broker/src/api.rs` (route `/v1/aws/credentials`, `agent(post(aws::credentials), BODY_LIMIT)`), `crates/broker/src/requests/aws.rs` (`take_aws_mint`, `claim_aws_mint`, `release_aws_once`, `record_aws_refusal`), `crates/broker/src/requests.rs` (`aws_per_hour`, `aws_refusals` throttle fields, `with_aws_per_hour`), `crates/broker/src/audit/event.rs` (`AwsCredentialsMinted`, `AwsCredentialsRefused`, `AwsCredentialsRefusalsHeld`), `crates/broker/src/doctor/aws.rs`, `crates/broker/src/doctor/mod.rs` (`Environment::aws_identity`), `crates/broker/src/doctor/live.rs`; docs `docs/agent-protocol.md`, `docs/interfaces.md`, `docs/deployment.md` ("Lock warden's egress" gains `sts.<region>.amazonaws.com:443`), `docs/1password-items.md` (points at `docs/aws.md`), `docs/upgrading.md` (migration 0014; an older `audit verify` refuses the new entry kinds and the `aws_policy_digest` field), `docs/threat-model.md`, `docs/assurance-case.md`, `docs/security-assessment.md` (and its date), `site/index.html` (its "the one credential the agent holds" sentence is no longer true), `CHANGELOG.md`

**Interfaces:**
- Consumes: `active_aws_for`, `ActiveAws` (Task 5), `assume_role`, `caller_identity`, `StsError` (Task 7), `AwsCredentialsRequest/Response` and the fixed texts (Task 4).
- Produces:
  - `pub(super) async fn credentials(State, AuthedAgent, body: Result<ApiJson<serde_json::Value>, Failure>) -> Result<Json<AwsCredentialsResponse>, Failure>`, run on its own task as `api/github_token.rs::mint` is, every refusal recorded with `record_aws_refusal(agent, grant_id, reason)` (fixed text, throttled like `github_refusals`).
  - Order: parse (bad body → 400 fixed text) → `active_aws_for` (none → 403 `NO_ACTIVE_GRANT`) → `aws_key()` (none → 503 `NOT_CONFIGURED`) → `aws_target(&grant.target)` must exist with the same `role_arn` (else 409 `TARGET_CHANGED`) → `take_aws_mint(agent)` (60 per hour, `MINTS_PER_HOUR`; else 429 `HOURLY_LIMIT`) → `claim_aws_mint(&grant_id, once)` (an `INSERT … ON CONFLICT DO UPDATE SET mints = mints + 1 WHERE NOT once OR mints < 1`; refused → 403 `NO_ACTIVE_GRANT`) → `assume_role` with duration `clamp(not_after - now, 900, 3600)` → on an `StsError` from an STS error answer, `release_aws_once` (a `once` grant can try again), on `Unreachable` keep the claim (STS may have issued) → check the answer: `expires_at <= now + duration + 60` and `assumed_role_arn == grant.role_arn.assumed_role_arn(session)`, else 502 `ANSWER_REFUSED` audited with which check failed (fixed words) → append `AwsCredentialsMinted { grant_id, agent, target, role_arn, session_name, access_key_id, expires_at }` (failure → nothing returned) → re-read `active_aws_for`: a grant revoked meanwhile gets nothing (409, as GitHub's `ended`) → respond.
  - Status mapping: `AccessDenied` and `MalformedPolicy` → 409 `STS_ACCESS_DENIED`; `PackedPolicyTooLarge` → 409 `PACKED_POLICY_TOO_LARGE`; the rest → 503 `STS_UNAVAILABLE`.
  - Doctor: check `aws-sts`: `caller_identity` must return `arn:aws:iam::<12 digits>:user/…`; `:root` fails ("the key belongs to the account root: create an IAM user, docs/aws.md"); a role or other ARN fails; STS unreachable is could-not-check. Only run when the `aws` check loaded a key.

- [ ] **Step 1: Failing tests** (`tests/aws/mint.rs`, scripted STS): `mint_returns_credentials_and_audits` (the entry holds the access key id, never the secret or token; `rg` the whole log text for both); `mint_sends_session_name_identity_tags_and_policy` (the STS fake received `RoleSessionName=warden-<grant id>`, `SourceIdentity=warden-build-agent`, three tags, the stored canonical `Policy`; no `Policy` for the role as it is); `duration_is_remaining_clamped` (grant ending in 5 minutes → 900; in 3 days → 3600); `once_mints_once` (second call 403); `once_failed_by_sts_can_retry` (first answer `AccessDenied`, second succeeds); `once_unreachable_stays_spent`; `revoked_grant_mints_nothing`; `preset_edit_after_approval_mints_stored_policy`; `deleted_target_or_changed_role_is_target_changed`; `hourly_limit_429` (with `with_aws_per_hour(2)`); `expiration_too_late_refused_and_audited`; `wrong_arn_refused` (other account, other role, other session, role path included); `packed_policy_too_large_is_plain`; `sts_message_never_reaches_agent_or_log` (`aws_logs.rs`: a `Message` with `AKIA…` and an ARN; the response, the tracing output and the audit log lack both). Doctor: `aws_sts_user_passes`, `aws_sts_root_fails`, `aws_sts_role_fails`, `aws_sts_unreachable_could_not_check`.
- [ ] **Step 2–4:** Run (fail), implement, run (pass).
- [ ] **Step 5: Docs.** `docs/aws.md`: the IAM user and its inline policy (`sts:AssumeRole`, `sts:TagSession`, `sts:SetSourceIdentity` on `arn:aws:iam::111122223333:role/warden/*`, optional `aws:SourceIp`), a target role's trust policy (those three actions, conditions on `aws:RequestTag/warden-grant` and `sts:SourceIdentity`), maximum session duration exactly 1 hour, what the conditions do and do not protect (spec "What the owner sets up"), roles in other accounts, rotation, emergency revocation ("revoke active sessions" by hand), a budget alarm as a suggestion, egress. `agent-protocol.md`: the `aws` kind (preset), windows with `once`, `POST /v1/aws/credentials`, every fixed text. `interfaces.md`: the endpoint and STS egress. Threat model: the new asset (the broker's key), the residual of one credential lifetime after revoke (an hour, 15 minutes for `once`), the owner's trust in role policies warden cannot see, the session-ARN resource-policy exception, a leaked key's limits. Assurance case and security assessment (date) follow. CHANGELOG under Added: AWS credentials for preset targets, migration 0014, new audit entry kinds.
- [ ] **Step 6: Manual test** against a real throwaway role in a scratch account, recorded in the PR (what was run and what it showed): a preset grant, `aws sts get-caller-identity` showing the session name and source identity, a call outside the preset refused by AWS, the credential expiring at the reported time, CloudTrail showing the tags. Redact account ids to `111122223333` in the PR text.
- [ ] **Step 7:** Full "Before you push" list; commit `Mint AWS credentials under preset grants (#<bead 2>)`; push; open PR 2 with screenshots; two reviewers.

## PR 3: Custom policies

### Task 9: Custom-policy rules and the dangerous list

**Files:**
- Create: `crates/proto/src/aws_policy/rules.rs`, `crates/proto/src/aws_policy/dangerous.rs`, `crates/proto/src/aws_policy/rules/tests.rs`, `fuzz/fuzz_targets/aws_policy.rs`, `fuzz/seeds/aws_policy/` (two or three seed policies)
- Modify: `crates/proto/src/aws_policy.rs` (`pub mod rules; mod dangerous;`), `fuzz/Cargo.toml` (`[[bin]] aws_policy`)

**Interfaces:**
- Consumes: `PolicyDocument`, `Statement`, `Effect`, `ActionList` (Task 1).
- Produces:
  - `pub const IDENTITY_SERVICES: [&str; 8] = ["iam", "sts", "organizations", "account", "cloudtrail", "sso", "sso-directory", "identitystore"];` **[call]**
  - `pub struct DangerousAction { pub service: &'static str, pub action: Option<&'static str>, pub reason: &'static str }` (`action: None` means every action of the service) and `pub const DANGEROUS: &[DangerousAction]` holding exactly the spec's list **[call: list to review]** (`ram` and `ec2-instance-connect` as `None`), each with its reason as a short phrase the page shows ("lets anyone the policy names into the bucket after the grant ends", …).
  - `pub struct Hit { pub pattern: String, pub listed: &'static DangerousAction }` and `pub struct Verdict { pub hits: Vec<Hit> }` with `sensitive(&self) -> bool`.
  - `pub fn check_custom(doc: &PolicyDocument) -> Result<Verdict, RuleError>`: every statement uses `Action` and `Resource` (not `NotAction`, `NotResource`); in `Allow` statements every action is `service:pattern` where `service` is non-empty and holds no `*` or `?`; the service, lowercased, is not in `IDENTITY_SERVICES`; each pattern is matched, case-insensitively with `*` and `?` as wildcards, against every listed action of its service (a `None` entry matches any pattern of that service); `Deny` statements are not checked beyond parsing. `pub enum RuleError { NotAction, NotResource, ServiceNotLiteral, IdentityService(&'static str) }` with fixed `Display`; `IdentityService` names the listed service only.
  - Fuzz target: `PolicyDocument::parse` then, if it parses, `parse(canonical)` equals it and `check_custom` does not panic.

- [ ] **Step 1: Failing tests** (`rules/tests.rs`): `ordinary_policy_passes_with_no_hits` (`ec2:StartInstances`, `ec2:StopInstances`, `ec2:Describe*` on `*`); `identity_services_refused_any_case` (`iam:PassRole`, `IAM:CreateUser`, `Iam:*`, `sts:assumerole`, `organizations:*`, `account:*`, `cloudtrail:StopLogging`, `sso:*`, `sso-directory:*`, `identitystore:*`); `kms_is_allowed` (`kms:GenerateDataKey*` passes; `kms:CreateGrant` passes and is a hit); `service_must_be_literal` (`*`, `*:*`, `e*:Run*`, `?c2:RunInstances`, `RunInstances` with no colon); `not_action_and_not_resource_refused` (also in `Deny`); `deny_may_name_anything` (`Deny` with `"*"` and `iam:*` passes); `wildcards_reach_listed_actions` (`ec2:*`, `s3:Put*`, `s3:Put?ucketPolicy`, `S3:PUTBUCKETPOLICY`, `ssm:Send*`, `ssm:*Command`, `ec2:Modify*Attribute`, `ram:Get*`, `ec2-instance-connect:Send*` each produce the expected `Hit`s); `unrelated_wildcard_is_no_hit` (`s3:Get*`, `ec2:Describe*`); `every_listed_entry_has_a_reason` (non-empty, no trailing full stop).
- [ ] **Step 2–4:** Run (fail), implement, run (pass). `scripts/fuzz.sh 60 aws_policy` runs clean.
- [ ] **Step 5:** Commit `Check custom AWS policies: identity services and dangerous actions (#<bead 3>)`.

### Task 10: Custom requests, the custom approval page, the info flag; docs for PR 3

**Files:**
- Modify: `crates/proto/src/aws.rs` (delete `CUSTOM_UNSUPPORTED`), `crates/proto/src/lib.rs` (`InfoResponse.aws_credentials: bool`, `#[serde(default)]`), `crates/broker/src/api.rs` (`aws_credentials: true`), `crates/broker/src/requests/aws.rs` (custom path), `crates/broker/src/requests/destination.rs` (sensitive includes the verdict), `crates/broker/src/approval/aws.rs` (custom check and grant), `crates/broker/src/approval/pages/aws.rs`, `crates/broker/src/approval/pages/aws_policy.rs` (marked actions), `crates/broker/src/approval/pages.rs` (`windows_for`); docs `docs/agent-protocol.md`, `docs/interfaces.md`, `docs/aws.md`, `docs/threat-model.md`, `docs/assurance-case.md`, `docs/security-assessment.md` (and its date), `CHANGELOG.md`
- Test: `crates/broker/tests/aws/custom.rs`, `crates/broker/src/approval/pages/tests/aws_page.rs`

**Interfaces:**
- Consumes: `check_custom`, `Verdict`, `Hit`, `RuleError` (Task 9).
- Produces:
  - `pub(crate) fn custom_verdict(access: &AwsAccess) -> Option<Result<(PolicyDocument, Verdict), String>>` in `requests/aws.rs`: `None` for the preset; parse and rule errors as their fixed texts.
  - Creation: a custom policy on a target without `custom` → 400 `CUSTOM_NOT_ALLOWED`; a parse or rule failure → 400 with its fixed text, audited as `AwsCredentialsRefused`-style request refusal (reuse `record_aws_refusal` with `grant_id: None`) so probing shows in the log; sensitive = `target.sensitive && preset` or `verdict.sensitive()` for custom; window rules as before.
  - Approval: `check` re-runs the target's `custom` flag and `custom_verdict` (both read fresh); `grant` stores the canonical custom text, `custom: true`, `policy_digest: Custom(..)`, `sensitive: verdict.sensitive()`.
  - Page: custom shows a highlighted notice "The agent wrote this policy" **[call: copy]**, then `statements(doc, marked)` where each statement action matching a hit is in the danger colour, followed by a list "Listed dangerous actions this policy reaches", each `pattern: reason`; a sensitive custom request is red with only the short windows. Nothing on the page says a custom policy is safe.
  - `/v1/info` `aws_credentials: true`.

- [ ] **Step 1: Failing tests:** `custom.rs`: `custom_on_target_without_custom_refused`; `custom_rule_failures_are_400_and_audited` (identity service, `NotAction`, literal service, 1,801 characters); `sensitive_custom_only_short_windows` (`s3:PutBucketPolicy` with `4h` → 400 `SENSITIVE_WINDOW`; with `1h` rings); `custom_grant_stores_canonical_and_mints_it` (the STS fake receives the canonical form, not the agent's text); `custom_and_preset_live_side_by_side`; `same_custom_reordered_answered_with_live_grant`; `target_custom_turned_off_before_approval_refuses_approval`; `info_announces_aws_credentials`. Pages: `custom_page_shows_agent_wrote_notice`, `dangerous_actions_marked_with_reasons`, `sensitive_custom_page_red_short_windows`, `page_never_says_safe` (the rendered text has no "safe").
- [ ] **Step 2–4:** Run (fail), implement, run (pass); screenshots light and dark at the template's sizes.
- [ ] **Step 5: Docs:** `agent-protocol.md` (the `policy` field, the rules, every refusal text, the info flag); `interfaces.md` (the flag); `docs/aws.md` and the threat model state that the list is not complete and the owner's reading of the page is the control for unlisted dangerous actions; assurance case and security assessment (date). CHANGELOG under Added: custom AWS session policies, refusing identity services and marking listed dangerous actions.
- [ ] **Step 6: Manual test** recorded in the PR: a custom policy grant used with `aws`, and a sensitive action outside it refused by AWS.
- [ ] **Step 7:** Full "Before you push" list (fuzz lint included: the PR changes `fuzz/`); commit `Accept custom AWS session policies (#<bead 3>)`; push; PR 3 with screenshots; two reviewers.

## PR 4: The CLI

### Task 11: The client calls and `warden request aws`

**Files:**
- Create: `crates/cli/src/client/aws.rs`, `crates/cli/src/request/aws.rs`, `crates/cli/src/aws.rs` (policy file reading only in this task), `crates/cli/src/aws/tests.rs`, `crates/cli/tests/e2e_aws.rs`
- Modify: `crates/cli/src/client.rs` (`mod aws;`), `crates/cli/src/request.rs` (`mod aws;`), `crates/cli/src/cli.rs` (`RequestKind::Aws`), `crates/cli/src/main.rs` (dispatch, `mod aws;`), `crates/cli/src/guidance.rs` (recognise `NO_ACTIVE_GRANT`, `CUSTOM_NOT_ALLOWED`, `SENSITIVE_WINDOW`)

**Interfaces:**
- Consumes: `AwsAccess`, `PolicyDocument`, `PolicyDigest`, `Window::aws_request`, `AwsCredentialsRequest/Response`, `InfoResponse.aws_credentials` (PRs 1–3).
- Produces:
  - `pub(crate) fn read_policy(path: &Path) -> Result<(String, PolicyDigest)>` in `aws.rs`: refuses a file over `MAX_POLICY_INPUT_BYTES` before reading it whole, a parse error with its fixed text and the path; returns the text as written and its digest.
  - `Client::require_aws(&self) -> Result<()>` (an old broker → error "this broker does not offer AWS credentials; upgrade it"), `Client::aws_credentials(&self, target: &TargetName, digest: &PolicyDigest) -> Result<AwsCredentialsResponse, CallError>`.
  - `RequestKind::Aws { target: TargetName, #[arg(long)] policy: Option<PathBuf>, #[arg(long = "for", value_parser = Window::aws_request)] window: Option<Window>, #[arg(long)] goal: Goal, #[command(flatten)] context: RequestContext }`; the window defaults to `Window::AWS_DEFAULT`.
  - `pub(crate) async fn request_aws(…) -> Result<()>`: `require_aws` first, then create and wait as the other kinds do; an answer with `created: Some(false)` whose status is approved prints "already granted until <local time>".

- [ ] **Step 1: Failing tests:** unit: `read_policy_returns_text_and_digest`, `read_policy_refuses_large_file_unread`, `read_policy_refuses_bad_json_naming_path`. e2e (`e2e_aws.rs`, test broker with an AWS target): `request_aws_preset_approved`, `request_aws_with_policy_file`, `request_aws_against_old_broker_says_upgrade` (nothing reaches the broker's create route), `request_aws_answered_by_live_grant_prints_until`, `bad_window_is_usage_error` (`--for 90d` → exit 64).
- [ ] **Step 2–4:** Run (fail), implement, run (pass).
- [ ] **Step 5:** Commit `Request AWS credentials from the CLI (#<bead 4>)`.

### Task 12: `warden aws credentials`, `warden aws exec` and the cache

**Files:**
- Create: `crates/cli/src/aws/cache.rs`, `crates/cli/src/aws/tests/cache.rs`
- Modify: `crates/cli/src/aws.rs`, `crates/cli/src/cli.rs` (`Cmd::Aws { what: AwsCmd }`), `crates/cli/src/main.rs` (dispatch; `runs_housekeeping` false for `credentials`)
- Test: `crates/cli/src/aws/tests.rs`, `crates/cli/src/aws/tests/cache.rs`, `crates/cli/tests/e2e_aws.rs`

**Interfaces:**
- Consumes: `read_policy`, `Client::aws_credentials` (Task 11).
- Produces:
  - `pub(crate) enum AwsCmd { Credentials { target: TargetName, #[arg(long)] policy: Option<PathBuf> }, Exec { target: TargetName, #[arg(long)] policy: Option<PathBuf>, #[arg(last = true, required = true)] command: Vec<OsString> } }`.
  - Cache (`aws/cache.rs`) **[plan call]**: file `aws-credentials.json` in the same state directory as `github-token.json`, `VERSION: u8 = 1`, `MAX_CACHE_BYTES = 64 * 1024`, `MAX_ENTRIES = 32`, `MAX_TOKEN_BYTES = 4096`, `MIN_LEFT_SECS = 900`; the GitHub cache's identity, ownership, 0600 mode, size and version checks (a file failing any is ignored and replaced); entries keyed by `<target>|<digest>` with `grant_id`, the four credential fields (secrets in `Zeroizing<String>`), `expires_at`, `grant_not_after`. `Cache::lookup(&self, target: &TargetName, digest: &PolicyDigest, now: i64) -> Option<&Entry>` serves an entry while `expires_at > now` and either `expires_at - now >= MIN_LEFT_SECS` or `expires_at >= grant_not_after` (near the grant's end it serves the last credential to its expiry rather than mint again); `put` replaces the key's entry; `drop_expired`; `discard(grant: &Id)`.
  - `credentials`: cache hit → print; else `require_aws`, mint, cache (a write failure is reported on stderr, never fatal), print `{"Version":1,"AccessKeyId":…,"SecretAccessKey":…,"SessionToken":…,"Expiration":"<RFC 3339 UTC>"}` (jiff). `NO_ACTIVE_GRANT` → exit `EXIT_NO_GRANT` (5) at once, message "no AWS grant for target <t> (preset|this policy): ask with `warden request aws <t> [--policy <file>] --goal \"…\"`". It never creates a request and never waits.
  - `exec`: same credentials, then runs the command with `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` set (the env is built for the child, never `std::env::set_var`), and exits with the child's code (128 + signal when killed).

- [ ] **Step 1: Check the [guess]:** read botocore's credential-refresh code (`botocore/credentials.py`, `RefreshableCredentials`, advisory 15 and mandatory 10 minutes) and its `ProcessProvider`, and aws-sdk-go-v2's process provider timeout. Record the source links and the commit read in a comment on `MIN_LEFT_SECS`. Settle what botocore does when the refreshed credential is still inside the mandatory window (served near the grant's end): if it raises, `lookup` mints instead once inside 10 minutes and the PR says so.
- [ ] **Step 2: Failing tests:** cache: `serves_while_15_minutes_left`, `mints_again_under_15_minutes`, `serves_to_expiry_near_grant_end`, `expired_entry_dropped`, `other_digest_not_served`, `bad_mode_or_owner_file_ignored`, `oversized_file_ignored`, `old_version_replaced`, `secrets_absent_from_debug`. Unit: `credential_process_json_shape` (exact keys, RFC 3339 `Z`). e2e: `credentials_mint_then_serve_from_cache` (the broker's mint route called once for two runs), `credentials_without_grant_exits_5_and_files_nothing` (no request created), `credentials_after_once_spent_exits_5`, `exec_sets_env_and_returns_child_code` (`sh -c 'test -n "$AWS_SESSION_TOKEN"; exit 3'` → 3).
- [ ] **Step 3–5:** Run (fail), implement, run (pass).
- [ ] **Step 6:** Commit `Serve AWS credentials to tools: credentials, exec and the cache (#<bead 4>)`.

### Task 13: `warden setup aws` and the client doctor

**Files:**
- Create: `crates/cli/src/setup_aws.rs`, `crates/cli/src/setup_aws/tests.rs`, `crates/cli/src/doctor/aws.rs`, `crates/cli/src/doctor/tests.rs` (the inline test module of `doctor.rs`, lines 468–846, moved unchanged: the file is already 846 lines)
- Modify: `crates/cli/src/cli.rs` (`SetupWhat::Aws { target, policy }`), `crates/cli/src/main.rs` (dispatch), `crates/cli/src/doctor.rs` (`mod aws;`, two check calls, `#[cfg(test)] mod tests;`)

**Interfaces:**
- Consumes: `read_policy` (Task 11), `exe_path` helpers (`crates/cli/src/exe_path.rs`), `InfoResponse.aws_credentials`.
- Produces:
  - `pub(crate) fn profile_name(target: &TargetName, digest: &PolicyDigest) -> String`: `warden-<target>`, or `warden-<target>-<digest.short()>` with a policy.
  - `pub(crate) const MARKER: &str = "# Written by `warden setup aws`, which may replace it.";`
  - `pub(crate) fn add_profile(config: &str, profile: &str, command: &str) -> Result<String, SetupError>` (pure): appends `MARKER`, `[profile <name>]`, `credential_process = <command>`; replaces the section only when the line above its header is `MARKER`; refuses (`SetupError::NotOurs`) when a section of that name exists without it; touches no other byte of the file.
  - `pub(crate) fn run(target: &TargetName, policy: Option<&Path>, config_path: &Path) -> Result<()>`: `config_path` is `$AWS_CONFIG_FILE` or `~/.aws/config`, resolved in `main` **[plan call]**; the policy path is made absolute; the command is this binary's path and `aws credentials <target> [--policy <abs path>]`, quoted for botocore; written through a temporary file and rename, mode kept, the directory created 0700 if missing.
  - Client doctor: `aws-broker` (pass when `/v1/info` says `aws_credentials`, else pass "the broker does not offer AWS"); `aws-profiles` (each marked profile's `credential_process` starts with this binary's path; a stale one fails with "run `warden setup aws <target>` again").

- [ ] **Step 1: Check the [guess]:** read how botocore splits `credential_process` (`shlex`-style, quoting rules) and record it in a comment on the quoting function; the tests below use a path with a space.
- [ ] **Step 2: Failing tests:** `profile_name_with_and_without_policy`; `adds_profile_and_leaves_the_rest_byte_for_byte` (a config with `[default]`, comments and another profile); `replaces_its_own_profile`; `refuses_profile_it_did_not_write`; `never_touches_default` (asking for a target named `default` writes `warden-default`); `quotes_paths_with_spaces`; `creates_missing_file_and_dir`; doctor: `profile_pointing_elsewhere_fails`, `aws_broker_flag_reported`.
- [ ] **Step 3:** Move `doctor.rs`'s test module to `doctor/tests.rs` in its own commit (`Move the client doctor's tests to their own file`), then implement; run (pass).
- [ ] **Step 4:** Commit `Write AWS credential_process profiles and check them in doctor (#<bead 4>)`.

### Task 14: Offers, `warden list`, `warden status`; docs for PR 4

**Files:**
- Modify: `crates/proto/src/offers.rs` (`Offers.aws_targets`, `AwsTargetOffer`, `OfferPart::AwsTargets`), `crates/broker/src/api/offers.rs`, `crates/cli/src/list.rs`, `crates/cli/src/recover.rs` (`broker_grant_line` arm), docs `docs/agent-usage.md`, `docs/agent-instructions.md` (an AWS section: ask with `warden request aws`, use `warden setup aws` profiles or `warden aws exec`, never wait on a prompt inside a tool run; prime includes it), `docs/configuration.md` (CLI table, cache file), `docs/interfaces.md` (the cache file and the `~/.aws/config` profiles), `docs/agent-protocol.md` (offers field), `CHANGELOG.md`
- Test: `crates/broker/src/api/offers/tests.rs`, `crates/cli/src/list/tests.rs`, `crates/cli/tests/e2e_offers.rs`, `crates/cli/src/prime/tests.rs`

**Interfaces:**
- Produces:
  - `pub struct AwsTargetOffer { pub name: TargetName, pub description: Option<String>, pub max_window: Window, pub custom: bool, pub sensitive: bool, pub role_arn: Option<String> }` (`role_arn` only for a `full` listing); `Offers.aws_targets: Vec<AwsTargetOffer>` with `#[serde(default)]` (older brokers); filled from `list_aws_targets`, only `is_listed()` ones; a backend failure lists `OfferPart::AwsTargets` in `unavailable`.
  - `warden list` gains an "AWS targets" section: name, description, longest window, `custom policies allowed` when so, `sensitive` marker, role ARN when given.
  - `warden status`'s broker grant line for AWS: `aws <target> preset|custom <short digest> <window> grant <id> until <time>`.

- [ ] **Step 1: Failing tests:** `offers_list_aws_targets_by_listing` (hidden absent, `name` without role ARN), `offers_aws_unavailable_on_backend_failure`, `list_shows_aws_targets`, `status_line_for_aws_grant`, `prime_includes_aws_section` (the existing doc-and-prime check).
- [ ] **Step 2–4:** Run (fail), implement, run (pass).
- [ ] **Step 5: Docs** as listed. CHANGELOG under Added: `warden request aws`, `warden aws credentials`, `warden aws exec`, `warden setup aws`, AWS targets in `warden list` and grants in `warden status`.
- [ ] **Step 6:** Full "Before you push" list; commit `List AWS targets and show AWS grants in the CLI (#<bead 4>)`; push; PR 4; two reviewers.

## PR 5: Narrative docs

### Task 15: README, design, site, the finished guide

**Files:**
- Modify: `README.md` (AWS credentials among what warden grants, with one example), `docs/design.md` (a new access-mode section: why STS and not the proxy, the identity of a grant, minting, revocation residual), `site/index.html` (AWS in the intro and the bounded-grants list, no version, no setup commands), `docs/aws.md` (day-to-day use from the CLI, linking `agent-usage.md`; "What warden does not do": no proxy, no cost limits, no IAM management, no early revocation, no console links), `docs/roadmap.md` (if it lists AWS), `CHANGELOG.md` (only if a user-visible line is missing)

- [ ] **Step 1:** Write the docs; read each AWS claim in README, site, design and `docs/aws.md` against the code and the earlier PRs' reference docs (windows, refusals, residuals), and fix any disagreement.
- [ ] **Step 2:** `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked` and the prime tests pass (the site and docs carry no code, but prime includes `agent-instructions.md`).
- [ ] **Step 3:** Commit `Document AWS credentials (#<bead 5>)`; push; PR 5; one reviewer. After release, remind the owner that the dotfiles `rules/warden.md` gains the AWS usage line.

## Self-review notes

- Spec coverage: Goals 1–5 → Tasks 4–8, 9–10, 11–14; items → 2; owner's AWS setup → 8 (`docs/aws.md`); wire and creation checks → 4, 5, 10; identity, live-grant answer, pending dedupe → 5; preset read at approval → 5; windows and `once` → 4, 5, 8; ending-soon and renewal → 5; custom rules and list → 9, 10; minting fields, answer checks, rate limit, audit → 8; SigV4 → 7; egress → 8; revocation → 8 (docs), 5 (stops new mints at once: `active_aws_for` excludes revoked); CLI → 11–14; `/v1/info` flag → 10, 11; approval page → 6, 10; doctor → 3, 8, 13; docs → each PR, 15.
- Every **[guess]** is a step: AWS facts and STS JSON (Task 7 Step 1), Connect's `updatedAt` (Task 3 Step 1), botocore refresh and process timeout (Task 12 Step 1), `credential_process` quoting (Task 13 Step 1). The Roles Anywhere guess concerns a set-aside approach and needs no step.
