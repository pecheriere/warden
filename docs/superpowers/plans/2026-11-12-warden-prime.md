# warden list and warden prime Implementation Plan (#246)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An agent learns what warden offers from the broker and the installed CLI: `GET /v1/offers`, `GET /v1/offers/repository/{owner}/{name}`, `warden list` and `warden prime [--brief]`, with a per-item `list` field deciding how much each target and secret shows.

**Architecture:** The shared item parsers (`parse_target`, `parse_api_secret`) read a new `list` field into a `Listing` on `SshTarget` and `ApiSecretPolicy`, so both backends get it at once. New `SecretBackend` methods list every valid target and secret and say, from item summaries alone, whether release signing is set up. Two new agent-authenticated routes in `crates/broker/src/api/offers*.rs` map that to wire types in `crates/proto/src/offers.rs`. The CLI gets `warden list` and `warden prime`, the latter rendering `docs/agent-instructions.md` (embedded with `include_str!`) through section markers.

**Tech Stack:** Rust 2024, axum, serde, reqwest, clap, tokio; 1Password Connect and local-file backends.

**Spec:** `docs/superpowers/specs/2026-11-12-warden-prime-design.md` (approved 2026-11-12). Read it before each task: it holds the reasons; this plan holds the names.

## Global Constraints

- Public repository: generic names only (`web-01`, `switch-01`, `home-api`, `example-org/example-repo`, `*.example.internal`, `192.0.2.0/24`). No real hostnames, tailnet names, user names.
- Never put a secret, a relay credential, an API secret value, a private key, a 1Password item id or a vault name in any response, log line or error.
- `list` values are exactly `full`, `name`, `hidden`, after trimming whitespace like other fields; case-sensitive. Missing → `full`. Anything else → listed as hidden (1Password) / a policy problem that refuses the file (local backend).
- `list` decides listing only, never access: a `hidden` or invalid-`list` item is still requestable.
- `prime` and `prime --brief` exit 0 whatever the broker does; the offers calls they make get 3 seconds in all.
- Per-repository answers are cached in memory for 5 minutes (300 s) per repository; `unavailable` answers are not cached. Time comes from `AppState::clock`.
- Clippy `all` + `pedantic` denied, `unsafe_code` forbidden, no `#[allow]`/`#[expect]` without a reason comment, no `unwrap`/`expect` outside tests.
- Files stay under about 800 lines. `crates/broker/src/api.rs` (802) and `crates/cli/src/client.rs` (727) get only route/one-line additions; new code goes in new modules.
- Tests never depend on timing: wait on conditions; the cache takes the injected clock.
- Every commit `git commit -s`, no AI attribution. CHANGELOG line under `## [Unreleased]`.
- Run per task: `cargo fmt --check`, `cargo clippy -p <crate> --all-targets --all-features --locked -- -D warnings`, `cargo test -p <crate> --all-features --locked <filter> 2>&1 | tail -30`. Whole-workspace commands from AGENTS.md "Before you push" run in Task 8.
- Never set `CARGO_TARGET_DIR` or other `CARGO_*` variables.

## Review Focus

1. A 1Password item tagged `warden:ssh-target` whose title is not a valid target name, or two items with the same title: `GET /v1/offers` skips them and still answers 200 with the rest (Task 2 test `listing_skips_unusable_items`).
2. A `list` value of `Full`, `" name "`, `hidden\n` or `yes`: trimmed values match; `Full` and `yes` list as hidden in 1Password and refuse the local policy file (Task 1 tests).
3. A broker older than this change: `warden list` exits 1 with "too old … upgrade"; `warden prime` prints the rules plus the "too old" line and exits 0 (Task 6/7 tests on a 404).
4. `warden list` or `prime` run outside a git checkout, in a checkout with no remote, or with a non-GitHub remote: the "this repository" section is left out, nothing from git reaches stderr, exit code unchanged (Task 6 test `no_repository_section_outside_github_checkout`).
5. A broker that accepts the connection and never answers: `warden prime --brief` returns within ~3 s, prints the rules and the "cannot be reached" line, exits 0 (Task 7 test against a listener that never responds).

---

### Task 1: The `list` field on items (both backends)

**Files:**
- Create: `crates/broker/src/policy/listing.rs` (the `Listing` type and its parser, with `#[cfg(test)] mod tests` inline)
- Modify: `crates/broker/src/policy/mod.rs` (add `mod listing; pub use listing::Listing;`, field `listing: Listing` on `SshTarget`)
- Modify: `crates/broker/src/policy/api.rs` (field `listing: Listing` on `ApiSecretPolicy`)
- Modify: `crates/broker/src/policy/onepassword/items.rs` (`parse_target` and `parse_api_secret` read `list`; add `"list"` to `parse_api_secret`'s `LABELS`)
- Modify: `crates/broker/src/policy/local.rs` (`TargetEntry` and `ApiEntry` gain `list: Option<String>`, passed as a plain field; `Files::probe` reports `Listing::Invalid` as a problem)
- Modify: every constructor of `SshTarget` / `ApiSecretPolicy` the compiler names (testkit, demo, tests)
- Docs: `docs/1password-items.md` (field `list` in SSH target and API secret sections), `docs/local-backend.md` (`list` in `[targets.<name>]` and `[api_secrets.<name>]`)
- Test: `crates/broker/src/policy/onepassword/items` tests (wherever `parse_target` tests live: `rg -n 'fn .*parse_target|parse_target\(' crates/broker/src/policy`), `crates/broker/src/policy/local/tests/entries.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum Listing { Full, Name, Hidden, Invalid }
  impl Listing {
      /// From the item's `list` field: None or blank → Full; trimmed "full"/"name"/"hidden"; else Invalid.
      #[must_use] pub fn parse(value: Option<&str>) -> Self;
      /// Whether `warden list` shows the item at all (Full or Name).
      #[must_use] pub const fn is_listed(self) -> bool;
      /// Whether it shows where the item points (Full only).
      #[must_use] pub const fn shows_destination(self) -> bool;
  }
  pub struct SshTarget { /* existing fields */ pub listing: Listing }
  pub struct ApiSecretPolicy { /* existing fields */ pub listing: Listing }
  ```
- `destination_digest` of both types is unchanged (it lists its parts explicitly; `listing` must not join them).

- [ ] **Step 1: Write the failing tests.** In `listing.rs`: `missing_or_blank_is_full` (`None`, `Some("")`, `Some("  ")` → `Full`), `known_values_trimmed` (`" name "` → `Name`, `"hidden\n"` → `Hidden`, `"full"` → `Full`), `anything_else_is_invalid` (`"Full"`, `"yes"`, `"visible"` → `Invalid`), `only_full_and_name_are_listed`, `only_full_shows_destination`. In the 1Password item tests: `target_list_field_is_read` (an item with `list = name` gives `listing == Listing::Name`), `api_secret_list_field_is_read`, `invalid_list_keeps_item_usable` (`list = Full` → `Ok`, `listing == Listing::Invalid`), `list_does_not_change_destination_digest` (same item with and without `list` → equal digests). In local tests: `local_list_field_is_read`, `local_bad_list_is_a_probe_problem` (`list = "yes"` → `probe().problems()` names the entry and field `list`, never the value), `local_non_string_list_refuses_file` (`list = true` → the file does not load).
- [ ] **Step 2: Run them and see them fail** (compile errors on `Listing`): `cargo test -p warden-broker --all-features --locked listing 2>&1 | tail -30`.
- [ ] **Step 3: Implement** `Listing` in `listing.rs`; read `list` through the existing `by_label` / `get` helpers (blank counts as absent) in both parsers; add the field to both structs; in `local.rs` push `plain_field("list", value)` like `mode`, and in `Files::probe` add a problem `"[targets.<name>]: list must be full, name or hidden"` (same wording style as neighbours, `[api_secrets.<name>]` for secrets) when the parsed target or secret has `Listing::Invalid`. Fix every constructor the compiler names with `listing: Listing::Full`.
- [ ] **Step 4: Run the tests and see them pass**, then `cargo clippy -p warden-broker --all-targets --all-features --locked -- -D warnings` and `cargo test -p warden-demo --all-features --locked 2>&1 | tail -5`.
- [ ] **Step 5: Write the docs** (field table rows and one example each; say `list` decides listing only, and that a bad value in the local backend refuses the file).
- [ ] **Step 6: Commit** `git commit -s -m "Read a list field on target and API secret items (#246)"`.

### Task 2: Backend listing methods

**Files:**
- Modify: `crates/broker/src/policy/mod.rs` (four trait methods)
- Create: `crates/broker/src/policy/onepassword/listing.rs` (1Password impls, called from the trait impl in `onepassword.rs`)
- Modify: `crates/broker/src/policy/onepassword.rs` (trait impl delegates; `mod listing;`)
- Modify: `crates/broker/src/policy/local.rs` (impls over the policy file; release methods return `Ok(false)`)
- Modify: `crates/broker/src/testkit/backend.rs` (`FakeBackend` impls from its configured targets/secrets/keys), `crates/demo/src/parts.rs` (`DemoBackend`)
- Test: `crates/broker/src/policy/onepassword` tests next to the existing Connect-fixture tests (`rg -n 'tagged_titled|fn .*target.*connect' crates/broker/src/policy/tests.rs crates/broker/src/policy/onepassword`), `crates/broker/src/policy/local/tests/entries.rs`

**Interfaces:**
- Consumes: `Listing`, `SshTarget::listing`, `ApiSecretPolicy::listing` (Task 1).
- Produces, on `SecretBackend`:
  ```rust
  /// Every valid SSH target, in name order. Items that fail validation, have
  /// an invalid title or share a title are skipped (logged by name only).
  /// # Errors  PolicyError::Unavailable when the backend cannot be read.
  async fn list_ssh_targets(&self) -> Result<Vec<SshTarget>, PolicyError>;
  /// As above, for API secrets. The values are read and dropped as by `api_secret`.
  async fn list_api_secrets(&self) -> Result<Vec<ApiSecretPolicy>, PolicyError>;
  /// Whether at least one release signing item exists, from item summaries; reads no key.
  async fn has_release_signing(&self) -> Result<bool, PolicyError>;
  /// Whether a release App item exists, from item summaries; reads no key.
  async fn has_release_app(&self) -> Result<bool, PolicyError>;
  ```
  The returned values carry no credential (the existing types never do; the credential is split off by the parsers).

- [ ] **Step 1: Write the failing tests:** `listing_returns_valid_items_in_name_order`, `listing_skips_unusable_items` (an item with a bad title, two items with one title, an item missing `users`: all absent, the rest present, `Ok`), `listing_keeps_hidden_and_invalid_items` (filtering is the API's job: the backend returns them with their `listing`), `listing_unavailable_when_connect_down`, `release_presence_reads_no_key` (Connect fixture counts item-body fetches: `has_release_signing`/`has_release_app` fetch zero bodies), and the local equivalents (`local_listing_returns_entries`, `local_has_no_release`).
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement.** 1Password: `self.tagged(TARGET_TAG)` (and `API_TAG`), for each summary build the name with `TargetName::try_from` / `SecretName::try_from` and call the existing `target_item` / `api_item`; map `PolicyError::Invalid`/`NotFound`/`UnknownSecret` to "skip, `tracing::warn!(item = %name, "item left out of the listing")`"; propagate `Unavailable`. Release presence: `!self.tagged(<release signing tag>).await?.is_empty()` and the same for the release App tag (constants already in `onepassword.rs` / `onepassword/release.rs`). Local: iterate `policy.targets` / `policy.api_secrets` with `parse_target` / `parse_api`, skipping entries that fail (the probe already refuses those at startup).
- [ ] **Step 4: Run the tests and see them pass**; clippy for `warden-broker` and `warden-demo`.
- [ ] **Step 5: Commit** `git commit -s -m "List targets and API secrets from both backends (#246)"`.

### Task 3: Wire types

**Files:**
- Create: `crates/proto/src/offers.rs` (+ `#[cfg(test)] mod tests` inline)
- Modify: `crates/proto/src/lib.rs` (`pub mod offers;`)

**Interfaces:**
- Produces (all `Debug, Clone, PartialEq, Eq, Serialize, Deserialize`; enums `#[serde(rename_all = "snake_case")]`):
  ```rust
  pub struct Offers {
      pub ssh_targets: Vec<SshTargetOffer>,
      pub api_secrets: Vec<ApiSecretOffer>,
      pub github: GithubOffer,
      pub commit_signing: Availability,
      pub releases: Availability,
      pub unavailable: Vec<OfferPart>,
  }
  pub struct SshTargetOffer { pub name: TargetName, pub users: Vec<UnixUser>, pub max_window: Window,
                              pub mode: SshModeName, pub destination: Option<Destination> }
  pub enum SshModeName { Cert, Relay }
  pub struct Destination { pub host: String, pub port: u16 }
  pub struct ApiSecretOffer { pub name: SecretName, pub origin: Option<String>, pub methods: Vec<String>,
                              pub path_prefix: String, pub max_window: Window }
  pub struct GithubOffer { pub configured: bool, pub max_window: Option<Window> }
  pub struct Availability { pub available: bool }
  pub enum OfferPart { SshTargets, ApiSecrets, Github, CommitSigning, Releases }
  pub struct RepositoryOffer { pub repository: RepoName, pub github_token: GithubTokenStatus,
                               pub commit_signing: bool, pub release: ReleaseStatus }
  pub enum GithubTokenStatus { Covered, NotCovered, NotConfigured, Unavailable }
  pub enum ReleaseStatus { Ready, NoKey, NoReleaseApp, Unavailable }
  ```
  `Offers::path() -> &'static str` = `"v1/offers"`; `RepositoryOffer::path(repo: &RepoName) -> String` = `"v1/offers/repository/{owner}/{name}"` (both parts already validated by `RepoName`, so no further encoding).

- [ ] **Step 1: Write the failing tests:** `offers_round_trip` (the spec's example JSON, without the comments, deserializes and re-serializes equal), `repository_offer_round_trip`, `enum_spellings` (`"not_covered"`, `"no_release_app"`, `"api_secrets"`, `"relay"`), `unknown_fields_are_ignored` (a newer broker may add fields: deserializing with an extra key works; do not use `deny_unknown_fields` here).
- [ ] **Step 2: Run and see them fail.** `cargo test -p warden-broker-proto --all-features --locked offers 2>&1 | tail -20`
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run and see them pass**; clippy for `warden-broker-proto`.
- [ ] **Step 5: Commit** `git commit -s -m "Wire types for what the broker offers (#246)"`.

### Task 4: `GET /v1/offers`

**Files:**
- Create: `crates/broker/src/api/offers.rs` (handler and mapping), `crates/broker/src/api/offers/tests.rs`
- Modify: `crates/broker/src/api.rs` (`mod offers;` and one route next to `/v1/grants`: `.route("/v1/offers", agent(get(offers::list), BODY_LIMIT))`)
- Docs: `docs/agent-protocol.md` (the route, its body, that it asks no one and is not audited), `docs/interfaces.md`

**Interfaces:**
- Consumes: the four backend methods (Task 2), `Offers` and friends (Task 3), `AuthedAgent`, `Failure`, `BACKEND_UNAVAILABLE`.
- Produces: `pub(super) async fn list(State(state): State<AppState>, AuthedAgent(agent): AuthedAgent) -> Result<Json<Offers>, Failure>`.

- [ ] **Step 1: Write the failing tests** (through the testkit broker, `crates/broker/src/testkit/broker.rs` `with_secret_backend`): `offers_need_an_agent` (unauthenticated → the same status `/v1/grants` gives), `full_name_hidden_invalid` (four targets, one per `Listing`: `full` has `destination`, `name` has `destination: null`, `hidden` and `invalid` absent; same for API secrets with `origin`), `relay_target_shows_destination_when_full`, `github_and_signing_flags` (`github.configured`, `github.max_window` from `state.requests.github_token_max()` only when configured, `commit_signing.available`, `releases.available` true only when both `has_release_signing` and `has_release_app`), `partial_failure_names_the_part` (fake backend whose `list_api_secrets` is `Unavailable` → 200, `api_secrets` empty, `unavailable == [ApiSecrets]`), `all_unavailable_is_backend_unavailable` (every part unavailable → the `BACKEND_UNAVAILABLE` error the other agent calls give), `no_secret_in_response` (fake backend secrets, relay credential and host key body: none of their bytes appears in the serialized body), `listing_writes_no_audit_entry`, `creates_no_request_and_notifies_no_one`.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Implement** the handler: call each source, collect `OfferPart` for each `Unavailable`; map with `Listing::is_listed` / `shows_destination`; `origin` is `ApiSecretPolicy::origin` serialized as the tuple origin (`https://host[:port]`); methods as their uppercase names; `tracing::info!(agent = %agent, "offers listed")`.
- [ ] **Step 4: Run and see them pass**; clippy.
- [ ] **Step 5: Docs**, then commit `git commit -s -m "GET /v1/offers: what an agent may request (#246)"`.

### Task 5: `GET /v1/offers/repository/{owner}/{name}`

**Files:**
- Create: `crates/broker/src/api/offers/repository.rs` (handler), `crates/broker/src/offers_cache.rs` (the cache, with inline tests)
- Modify: `crates/broker/src/lib.rs` (`pub mod offers_cache;`, `AppState` field `pub repository_offers: Arc<RepositoryOfferCache>`), the three `AppState { … }` constructions (`crates/broker/src/main.rs`, `crates/broker/src/testkit/broker.rs`, `crates/demo/src/lib.rs`), `crates/broker/src/api.rs` (one route)
- Docs: `docs/agent-protocol.md`, `docs/interfaces.md`

**Interfaces:**
- Consumes: `github_app::resolve(&state.github, &key, &[repo], now)`, `SecretBackend::github_app`, `release_signing`, `has_release_app`, `has_commit_signing_key`, `RepositoryOffer` (Task 3), `state.clock`.
- Produces:
  ```rust
  pub struct RepositoryOfferCache { /* Mutex<HashMap<RepoName, (i64, RepositoryOffer)>> */ }
  impl RepositoryOfferCache {
      pub const TTL_SECS: i64 = 300;
      #[must_use] pub fn new() -> Self;
      /// The cached answer if stored less than TTL_SECS before `now`.
      pub fn get(&self, repo: &RepoName, now: i64) -> Option<RepositoryOffer>;
      /// Stores `offer` unless its github_token or release is Unavailable.
      pub fn put(&self, offer: RepositoryOffer, now: i64);
  }
  pub(super) async fn answer(State(state): State<AppState>, AuthedAgent(agent): AuthedAgent,
                             Path((owner, name)): Path<(String, String)>) -> Result<Json<RepositoryOffer>, Failure>;
  ```
  Use `std::sync::Mutex` (held only for a map lookup, never across `.await`); bound the map at 256 entries by dropping expired entries on `put`, then the oldest.

- [ ] **Step 1: Write the failing tests.** Cache (inline): `fresh_answer_is_returned`, `answer_expires_after_ttl` (`now + 300` → `None`), `unavailable_is_not_cached`, `map_is_bounded`. Handler (with `TestBroker::with_github` and a fake GitHub): `invalid_name_is_refused` (`Example..Org/x` → 400 before any GitHub call), `covered_repository`, `not_covered_repository` (fake GitHub answers as for a repository outside the installation → `not_covered`), `github_unreachable_is_unavailable_and_not_cached`, `no_app_is_not_configured`, `release_ready` / `release_no_key` / `release_no_release_app`, `second_call_within_ttl_makes_no_github_call` (fake counts requests), `no_token_in_response`.
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Implement.** Map `resolve`: `Ok` → `Covered`; `Err(MintError::NotAccessible)` → `NotCovered`; any other `MintError` → `Unavailable`. **Check first** (spec **[guess]**): which `MintError` GitHub's answer for a repository outside the installation produces today (`crates/broker/src/github_app/answer.rs`, its tests). If it is not a distinct variant, add one rather than treat a refusal as `NotCovered`. `PolicyError::NoGithubApp` → `NotConfigured`. Release: `release_signing(&repo)` `Ok` + `has_release_app` true → `Ready`, false → `NoReleaseApp`; `Err(NoReleaseKey)` → `NoKey`; anything else → `Unavailable`. Never log the token.
- [ ] **Step 4: Run and see them pass**; clippy for `warden-broker` and `warden-demo`.
- [ ] **Step 5: Docs**, then commit `git commit -s -m "Answer whether warden covers one repository (#246)"`.

### Task 6: `warden list`

**Files:**
- Create: `crates/cli/src/client/offers.rs` (client methods), `crates/cli/src/list.rs` (command, text rendering, repository detection) with tests in `crates/cli/src/list/tests.rs`
- Modify: `crates/cli/src/client.rs` (`mod offers;` only), `crates/cli/src/cli.rs` (`Cmd::List { json: bool, repo: Option<String> }` with doc comment "Show what this agent may ask the broker for. Asks no one and changes nothing."), `crates/cli/src/main.rs` (dispatch)
- Docs: `docs/configuration.md` (CLI commands table), `docs/agent-usage.md` (a "What warden offers here" part)

**Interfaces:**
- Consumes: `Offers`, `RepositoryOffer` (Task 3); `github_repo::origin_url(dir: &Path) -> Option<String>`, `github_repo::from_remote_url(&str) -> Option<RepoName>`, `github_repo::from_gh_value` for `--repo`.
- Produces:
  ```rust
  // client/offers.rs, on Client:
  /// None from a broker without the route (404).
  pub async fn offers(&self) -> Result<Option<Offers>, CallError>;
  pub async fn repository_offer(&self, repo: &RepoName) -> Result<Option<RepositoryOffer>, CallError>;
  // list.rs:
  /// The repository of the checkout in `dir`, if its origin is on GitHub. Never prints.
  #[must_use] pub fn checkout_repository(dir: &Path) -> Option<RepoName>;
  /// Text for a person or an agent; sections with nothing in them are left out.
  #[must_use] pub fn render(offers: &Offers, repo: Option<&RepositoryOffer>) -> String;
  pub async fn run(json: bool, repo: Option<String>) -> anyhow::Result<ExitCode>;
  ```
  `--json` prints `{"offers": <Offers>, "repository": <RepositoryOffer|null>}`.

- [ ] **Step 1: Write the failing tests:** `render_full_and_name_items` (snapshot-style string compare: a `full` target line shows `host:port`, a `name` one does not), `render_leaves_out_empty_sections`, `render_marks_unavailable_parts` ("API secrets: could not be read"), `render_repository_section` (each `GithubTokenStatus` and `ReleaseStatus` worded once), `no_repository_section_outside_github_checkout` (temp dir with no git, with a non-GitHub remote, with no remote → `checkout_repository` is `None` and git's stderr is not inherited), `old_broker_exits_1_with_upgrade_hint` (404 → exit 1, message contains "too old" and "upgrade"), `bad_repo_flag_exits_64`, `json_shape`.
- [ ] **Step 2: Run and see them fail.** `cargo test -p warden-broker-cli --all-features --locked list 2>&1 | tail -30`
- [ ] **Step 3: Implement.** `checkout_repository` = `origin_url(dir).and_then(|u| from_remote_url(&u))` (confirm `origin_url` does not inherit stderr; if it does, pipe it). Exit codes: 0, 1 (unreachable, refused login, too old), 64 (arguments).
- [ ] **Step 4: Run and see them pass**; clippy for `warden-broker-cli`.
- [ ] **Step 5: Docs**, then commit `git commit -s -m "warden list: what this agent may ask for (#246)"`.

### Task 7: `warden prime` and the instruction template

**Files:**
- Create: `crates/cli/src/prime.rs` (command), `crates/cli/src/prime/template.rs` (marker parser, inline tests), `crates/cli/src/prime/tests.rs`
- Modify: `docs/agent-instructions.md` (markers; the paragraph saying the agent "cannot list them, and it should not guess" replaced by `warden list` / `warden prime`; the hook command and the one-line rule; a brief section), `crates/cli/src/cli.rs` (`Cmd::Prime { brief: bool }`, doc comment "Print instructions for an agent: when and how to ask warden for access, with what this broker offers."), `crates/cli/src/main.rs` (dispatch; `Prime` must not require configuration to exist: see `main.rs:112` for how `Doctor` is exempted)
- Docs: `docs/agent-usage.md` (session-start hook and the rule), `docs/configuration.md` (CLI table)

**Interfaces:**
- Consumes: `Client::offers`, `Client::repository_offer`, `list::checkout_repository`, `list::render` (Task 6).
- Produces:
  ```rust
  // prime/template.rs
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
  pub enum Section { Ssh, Api, Signing, Github, Release, Brief }
  pub struct Template { /* parsed doc */ }
  impl Template {
      /// The fenced block of docs/agent-instructions.md, parsed. Errors name the marker and line.
      pub fn parse(doc: &str) -> Result<Self, TemplateError>;
      /// The full text: sections in `keep` (Brief never), offers text at the marker.
      #[must_use] pub fn full(&self, keep: &HashSet<Section>, offers: &str) -> String;
      /// The Brief section, offers text at its marker.
      #[must_use] pub fn brief(&self, offers: &str) -> String;
  }
  pub const DOC: &str = include_str!("../../../../docs/agent-instructions.md");
  // prime.rs
  pub const OFFERS_TIMEOUT: Duration = Duration::from_secs(3);
  pub async fn run(brief: bool) -> ExitCode; // always ExitCode::SUCCESS
  ```
  Markers, each on its own line: `<!-- warden:section <name> -->`, `<!-- warden:end -->`, `<!-- warden:offers -->`. Names: `ssh`, `api`, `signing`, `github`, `release`, `brief`. Sections do not nest. Text outside sections prints in `full`.

- [ ] **Step 1: Write the failing tests.** Template: `parses_the_real_doc` (`Template::parse(DOC)` is `Ok` and has every `Section`), `unbalanced_marker_is_an_error`, `unknown_section_is_an_error`, `nested_section_is_an_error`, `full_drops_sections_not_kept`, `full_never_contains_brief`, `offers_marker_replaced`. Command (with a fake broker from `crates/cli/tests/common` or a local axum server): `prime_keeps_sections_offered` (no GitHub App → no GitHub section; signing available → signing section), `prime_includes_repository_answer_in_github_checkout`, `brief_does_not_ask_about_repository` (fake counts calls: only `/v1/offers`), `brief_is_short` (≤ 15 lines with three items), `broker_unreachable_prints_rules_and_exits_0` (contains "cannot be reached" and "warden doctor"), `broker_hangs_returns_within_timeout` (a listener that accepts and never answers; assert the command finishes and prints the "cannot be reached" line; do not assert elapsed time), `old_broker_prints_rules_and_too_old_line`, `not_set_up_prints_one_line_and_exits_0`.
  Also update `documented_commands_match_the_cli` in `crates/cli/src/guidance.rs` if marker lines confuse it (they are HTML comments, not commands).
- [ ] **Step 2: Run and see them fail.**
- [ ] **Step 3: Implement.** The offers text in `full` is `list::render`; in `brief` one line per kind (names only, no destinations: "SSH: web-01 (deploy), switch-01 (admin)"; "API: home-api"; "GitHub tokens: on"; "Commit signing: on"; "Releases: on"). Wrap the client calls in `tokio::time::timeout(OFFERS_TIMEOUT, …)`. A section is kept when the broker offers that kind: `Ssh` ⇐ any listed target, `Api` ⇐ any listed secret, `Github` ⇐ `github.configured`, `Signing` ⇐ `commit_signing.available`, `Release` ⇐ `releases.available`. Without offers (unreachable, refused, too old), keep every section and append the matching line from the spec.
- [ ] **Step 4: Edit `docs/agent-instructions.md`**: wrap each existing section ("Commits, if this machine signs through warden" → `signing`, "GitHub, if…" → `github`, "Releases, if…" → `release`; the SSH and API request examples → `ssh` / `api`), put `<!-- warden:offers -->` where "Available here: <…>" is, add the `brief` section (the ~10 lines from the spec), and above the block say that `warden prime` prints it, with the hook command (`warden prime --brief`, for keys that sign without a prompt) and the one-line rule for agents without hooks.
- [ ] **Step 5: Run the tests and see them pass**; clippy for `warden-broker-cli`.
- [ ] **Step 6: Commit** `git commit -s -m "warden prime: instructions for an agent from the installed CLI (#246)"`.

### Task 8: End to end, threat model, release notes

**Files:**
- Create: `crates/cli/tests/e2e_offers.rs`
- Modify: `docs/threat-model.md`, `docs/security-assessment.md` (and its date), `docs/assurance-case.md` if it lists agent routes (`rg -n 'v1/grants' docs/assurance-case.md`), `README.md` where it shows pasting the instruction block, `CHANGELOG.md`, `site/index.html` only if it describes pasting instructions (`rg -n -i 'paste|instructions' site/index.html`)

**Interfaces:**
- Consumes: everything above; the e2e harness in `crates/cli/tests/common`.

- [ ] **Step 1: Write the e2e test:** a testkit broker with one target per `Listing`, one API secret `full`, commit signing on, a fake GitHub covering `example-org/example-repo`; run the built `warden` binary: `warden list --json` (hidden and invalid items absent, `name` item without destination), `warden list --repo example-org/example-repo` (covered), `warden prime` (contains the GitHub and signing sections and `web-01`), `warden prime --brief` (short, names only).
- [ ] **Step 2: Run it and see it pass** (`cargo test -p warden-broker-cli --all-features --locked --test e2e_offers 2>&1 | tail -20`).
- [ ] **Step 3: Threat model and security assessment:** the listing hands any agent key the names and, by default, the destinations of what warden covers; why acceptable (an agent on the host already sees the network; listing grants no access); `name` and `hidden` as the owner's controls; `hidden` does not hide existence from a guess (the broker already answers `unknown target`); the repository route answers one guess at a time and never enumerates; neither route is audited, and why. Update the assessment's date.
- [ ] **Step 4: CHANGELOG** under `## [Unreleased]`: `warden list`, `warden prime`, the `list` item field, the two routes. README: point to `warden prime` where it tells people to paste the block.
- [ ] **Step 5: Run every check in AGENTS.md "Before you push"** (one at a time, not in parallel; `| tail -30` each). All must pass.
- [ ] **Step 6: Commit** `git commit -s -m "End-to-end test and threat model for warden list and prime (#246)"`.
