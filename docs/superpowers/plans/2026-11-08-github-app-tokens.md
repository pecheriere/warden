# GitHub App tokens for agents — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A standing `github_token` grant lets an agent get hour-long installation tokens of an "agent" GitHub App from the broker, so plain `git` (HTTPS) and plain `gh` work without the owner's credentials (#185).

**Architecture:** A new grant kind modelled on commit signing: approved once for up to 30 days, looked up on every call, no local grant state. The broker reads the App (id, installation id, RSA key) from a tagged 1Password item, signs an RS256 JWT with `aws-lc-rs`, calls GitHub's `POST /app/installations/{id}/access_tokens` with fixed permissions through a hardened client, audits the mint and returns the token. The CLI caches it and serves it to git as a credential helper and to `gh` through a wrapper.

**Tech Stack:** Rust workspace (axum broker, clap CLI), reqwest 0.13 with rustls, aws-lc-rs, jiff, SQLite (no schema change), maud pages.

**Spec:** `docs/superpowers/specs/2026-11-08-agent-access-model-design.md` (section "Routine"). Read it, `AGENTS.md`, `docs/threat-model.md` and `~/.claude/rules/rust.md` before starting.

## Global Constraints

- Every commit `git commit -s`; no AI attribution trailers (public repo).
- Clippy `all` + `pedantic` denied, `unsafe_code` forbidden, no `#[allow]`/`#[expect]` without a comment saying why.
- No file over about 800 lines of code; new code goes in new files next to the commit signing equivalents, never appended to `requests/commit_signing.rs`, `audit.rs` or `cli/src/client.rs` beyond a few lines.
- The token, the JWT and the App private key never appear in logs, errors, audit entries or `Debug` output. Keep them in `Zeroizing`/`SecretString`. No upstream response text in errors.
- reqwest gains no decompression feature. New dependencies go in `[workspace.dependencies]` with a comment, must be at least 7 days old, and pass `cargo deny check`.
- RSA signing uses `aws-lc-rs` only, never the `rsa` crate.
- Grant window values: `1d`, `7d`, `30d`; server maximum `WARDEN_GITHUB_TOKEN_MAX_WINDOW`, default `30d`. All other kinds keep their 4-hour cap.
- Fixed token permissions: `contents: write`, `pull_requests: write`, `issues: write`, `metadata: read`. No `workflows`, no `administration`.
- Token lifetime is GitHub's (1 hour); the CLI re-mints when less than 5 minutes remain.
- 1Password item: tag `warden:github-app`, optional, more than one is an error; fields with ids `app_id`, `installation_id`, `private_key` (PEM, PKCS#1 `RSA PRIVATE KEY` as GitHub downloads it, or PKCS#8).
- Tests do not depend on timing (manual clock, wait on conditions).
- Every check in AGENTS.md "Before you push" passes before each push.

## Review Focus

1. **Grant revoked between mint and response** → the token is not returned (409 `grant revoked`), and the audit still records the mint. Test in Task 5.
2. **GitHub answers with an error, a redirect, a huge or compressed body, or a malformed `expires_at`** → a fixed refusal message, nothing from the body echoed, a `GithubTokenRefused` audit entry. Tests in Task 3 and Task 5.
3. **The 1Password item is missing, duplicated, or has a non-RSA / encrypted / malformed key** → requests are refused with "not configured" or "unavailable", never a panic, and the doctor reports which. Tests in Task 2.
4. **Credential helper called for another host, or with `store`/`erase`** → it prints nothing and exits 0, so git falls through to other helpers and never sends the token elsewhere. Test in Task 6.
5. **A cached token file that is corrupt, expired, or readable by others** → ignored and replaced, never served; the file is created 0600. Test in Task 6.

---

### Task 1: Wire types for the `github_token` kind

**Files:**
- Create: `crates/proto/src/github_token.rs`
- Modify: `crates/proto/src/lib.rs` (`Access`, module list), `crates/proto/src/grant.rs` (`GrantAccess`), `crates/proto/src/window.rs`
- Test: `crates/proto/src/tests.rs`

**Interfaces:**
- Produces:
  - `Access::GithubToken {}` with `#[serde(rename = "github_token")]`
  - `GrantAccess::GithubToken(GithubTokenGrant)` with `#[serde(rename = "github_token")]`
  - `pub struct GithubTokenGrant { pub app_id: String, pub installation_id: u64, pub digest: String }`
  - `pub struct GithubTokenResponse { pub token: String, pub expires_at: i64, pub grant_id: Id }` (token is a secret on the CLI side; `Debug` redacts it)
  - constants `github_token::NO_ACTIVE_GRANT`, `github_token::NOT_CONFIGURED`, `github_token::PERMISSIONS: [(&str, &str); 4]`
  - `Window::GITHUB_TOKEN: [Window; 3] = [D1, D7, D30]`, `Window::GITHUB_TOKEN_DEFAULT = D30`, `Window::is_github_token(self) -> bool`, `Window::github_token(&str) -> Result<Window, String>` (strict, `1d|7d|30d`)

- [ ] **Step 1: Write the failing tests** in `crates/proto/src/tests.rs`:
  `github_token_access_serde_shape` (`{"kind":"github_token"}` round-trips), `github_token_grant_serde_shape` (fields `app_id`, `installation_id`, `digest` under `kind: github_token`), `github_token_window_parser` (accepts `1d`,`7d`,`30d`; rejects `90d`,`4h`,`30D`," 30d"), `github_token_response_debug_redacts` (`format!("{r:?}")` does not contain the token).
- [ ] **Step 2: Run** `cargo test -p warden-broker-proto github_token` — expect FAIL (types missing).
- [ ] **Step 3: Implement** the types above, mirroring `commit_signing.rs`. Fix every non-exhaustive match the compiler reports in other crates with a `todo`-free placeholder that refuses: for the broker and CLI, add the arm returning the same "not supported" path the kind would take if unconfigured; later tasks replace them. List each touched match in the commit message.
- [ ] **Step 4: Run** `cargo test -p warden-broker-proto` and `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` — expect PASS.
- [ ] **Step 5: Commit** "Add wire types for GitHub token grants".

### Task 2: Load the GitHub App from the secret backend

**Files:**
- Create: `crates/broker/src/policy/github_app.rs`
- Modify: `crates/broker/src/policy/mod.rs` (`SecretBackend`, `PolicyError`), `crates/broker/src/policy/onepassword.rs`, `crates/broker/src/policy/local.rs` (returns not configured), `crates/broker/src/testkit/backend.rs`, `crates/demo/src/parts.rs`, `crates/broker/src/requests.rs` (`From<PolicyError>`), `Cargo.toml` + `crates/broker/Cargo.toml` (`aws-lc-rs`), `deny.toml` (reword the RUSTSEC-2023-0071 comment: warden now holds an RSA key but signs only with aws-lc-rs; the `rsa` crate is never used with a private key)
- Create: `crates/broker/src/doctor/github_app.rs`; Modify: `crates/broker/src/doctor/{mod,live,local}.rs`, `crates/proto/src/doctor.rs`
- Test: `crates/broker/tests/policy/github_app.rs` (wiremock Connect, as `tests/policy/connect.rs`), unit tests in `github_app.rs`

**Interfaces:**
- Produces:
  - `pub struct GithubAppKey { app_id: String, installation_id: u64, key: aws_lc_rs::rsa::KeyPair }` with redacted `Debug`; `GithubAppKey::new(app_id: String, installation_id: u64, pem: &[u8]) -> Result<Self, PolicyError>`; `fn sign_rs256(&self, message: &[u8]) -> Result<Vec<u8>, PolicyError>`; `fn policy(&self, max_window: Window) -> GithubTokenPolicy`
  - `pub struct GithubTokenPolicy { pub app_id: String, pub installation_id: u64, pub max_window: Window }` with `destination_digest(&self) -> String` (sha256 over `"warden github-token v1\0" || app_id || "\0" || installation_id`) and `grant(&self) -> GithubTokenGrant`
  - `SecretBackend::github_app(&self) -> Result<GithubAppKey, PolicyError>` and `SecretBackend::has_github_app(&self) -> Result<bool, PolicyError>`
  - `PolicyError::NoGithubApp` (maps to `RequestError::Rejected(github_token::NOT_CONFIGURED)`) and `PolicyError::GithubApp(String)` (maps to `Unavailable`; the string is a fixed reason, never key material)
  - `FakeBackend::set_github_app(Option<GithubAppKey>)`, `FakeBackend::set_github_app_outage(Option<&str>)`, `FakeBackend::github_app_reads() -> usize`
  - testkit helper `testkit::github_app_key() -> (GithubAppKey, Vec<u8> /* public key DER for verifying in tests */)` from a fixed 2048-bit test key committed under `crates/broker/src/testkit/` (generated once, test-only)

- [ ] **Step 1: Write the failing tests:** `github_app_key_accepts_pkcs1_and_pkcs8`, `github_app_key_rejects_ec_ed25519_encrypted_and_short_keys` (refuse RSA under 2048 bits), `github_app_debug_redacts`, `digest_changes_with_app_or_installation`; Connect tests `github_app_absent_is_not_configured`, `two_github_app_items_is_an_error`, `github_app_missing_field_is_invalid`, `github_app_non_numeric_installation_is_invalid`, `github_app_read_once_per_call` ; doctor test `doctor_reports_github_app_states` (Loaded / NotConfigured / Invalid / Unknown).
- [ ] **Step 2: Run** `cargo test -p warden-broker --all-features github_app` — expect FAIL.
- [ ] **Step 3: Implement.** PKCS#1 PEM → `KeyPair::from_der`; PKCS#8 → `from_pkcs8`; decode PEM with `rustls-pki-types`. Read the item with the existing `tagged`/required-field helpers (`items.rs`), body in `Zeroizing`. The local-file backend returns `NoGithubApp` (documented as 1Password only). The demo returns `NoGithubApp`.
- [ ] **Step 4: Run** the tests, `cargo deny check`, `python3 -I .github/scripts/crate_age.py --base main` — expect PASS.
- [ ] **Step 5: Commit** "Load the agent GitHub App from 1Password".

### Task 3: Mint installation tokens from GitHub

**Files:**
- Create: `crates/broker/src/github_app.rs` (JWT + client), `crates/broker/src/github_app/tests.rs`
- Modify: `crates/broker/src/testkit/upstream.rs` (route `POST /app/installations/{id}/access_tokens` with scripted responses), `crates/broker/src/lib.rs`

**Interfaces:**
- Consumes: `GithubAppKey::sign_rs256`, `github_token::PERMISSIONS`
- Produces:
  - `pub struct GithubApi { base: Url, ca_pem: Option<Vec<u8>>, limits: ProxyLimits }` with `GithubApi::public() -> Self` (`https://api.github.com`, system roots) and `GithubApi::pinned(base: Url, ca_pem: Vec<u8>) -> Self` (tests)
  - `pub struct InstallationToken { pub token: SecretString, pub expires_at: i64 }`
  - `pub async fn mint(api: &GithubApi, key: &GithubAppKey, now: i64) -> Result<InstallationToken, MintError>`
  - `fn jwt(key: &GithubAppKey, now: i64) -> Result<Zeroizing<String>, MintError>`: header `{"alg":"RS256","typ":"JWT"}`, claims `{"iat": now-60, "exp": now+540, "iss": app_id}`, base64url without padding
  - `pub enum MintError { Key, Unreachable, Refused(u16), Malformed, TooLarge, Compressed }` with fixed `Display` messages and no upstream text

- [ ] **Step 1: Write the failing tests:** `jwt_verifies_with_public_key_and_has_claims` (verify RS256 with the `rsa` dev-dependency, verification only; check `iat`, `exp`, `iss`), `mint_sends_fixed_permissions_and_headers` (upstream received `Authorization: Bearer <jwt>`, `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`, a `User-Agent`, body permissions exactly the four fixed ones, no `repositories` field), `mint_parses_token_and_expiry` (201 `{"token":"ghs_test","expires_at":"2026-11-08T13:00:00Z"}` → `expires_at` epoch), and the refusals: `mint_refuses_non_201_without_echo` (401 with a body containing `SECRET-ECHO` → `Refused(401)`, `Display` lacks the body), `mint_refuses_redirect`, `mint_refuses_gzip`, `mint_refuses_oversize` (over 64 KiB), `mint_refuses_bad_expiry` (`"tomorrow"`), `mint_refuses_expired_or_far_future` (`expires_at` ≤ now, or > now + 2h).
- [ ] **Step 2: Run** `cargo test -p warden-broker --all-features github_app::` — expect FAIL.
- [ ] **Step 3: Implement.** Build the client like `proxy/client.rs::client_for` (https only, no redirects, no proxy, no retries, 10 s connect / 30 s total, pinned CA when set); read the body in chunks capped at 64 KiB; refuse any `Content-Encoding` but identity; parse `expires_at` with `jiff::Timestamp`. Sign the JWT off the async runtime.
- [ ] **Step 4: Run** the tests — expect PASS.
- [ ] **Step 5: Commit** "Mint GitHub App installation tokens".

### Task 4: Requests, approval and the 30-day maximum

**Files:**
- Create: `crates/broker/src/requests/github_token.rs`, `crates/broker/src/approval/pages/github_token.rs`
- Modify: `crates/broker/src/requests.rs` (`Destination::GithubToken(GithubTokenPolicy)`, `Requests.github_token_max`, `with_github_token_max`), `requests/create.rs` (arm, dedupe key `"{agent}|github_token"`), `requests/decide.rs:277` (renews for this kind too), `requests/pending.rs`, `approval/mod.rs` (`check_policy`, `approve_finish`), `approval/pages.rs` and `pages/{grants,history,pending,approve}.rs`, `config.rs` (`WARDEN_GITHUB_TOKEN_MAX_WINDOW`), `config/tests.rs`, `main.rs`, `testkit/broker.rs` (`with_github_token_max`), `testkit/broker/requests.rs` (`github_token_request(goal, window)`)
- Test: `crates/broker/tests/github_token/{main,windows,pages}.rs`

**Interfaces:**
- Consumes: `SecretBackend::github_app`, `GithubTokenPolicy`
- Produces:
  - `pub struct ActiveGithubToken { pub grant_id: Id, pub grant: GithubTokenGrant }`
  - `Requests::active_github_token(&self, agent: &AgentName) -> Result<Option<ActiveGithubToken>, RequestError>` (SQL like `ACTIVE_FOR_AGENT` with kind `github_token`)
  - `requests::github_token::check_window(window: Window, max: Window) -> Result<(), String>`
  - one active grant per agent: approving a new one ends the previous (generalise `end_renewed` over the kind string rather than copying it)

- [ ] **Step 1: Write the failing tests:** `request_refused_when_app_not_configured`, `window_must_be_1d_7d_or_30d`, `window_above_server_max_refused` (max `7d`, request `30d`), `config_rejects_bad_github_token_max` (`90d`, `4h`, empty → error naming the variable), `approving_new_grant_ends_previous`, `approval_page_names_app_installation_and_permissions` (page text contains the installation id, the four permissions, "tokens last 1 hour and cannot be recalled when revoked"), `destination_changed_between_page_and_approve` (App changed in the fake backend → approve refused), `grants_page_shows_github_token_grant_and_end`.
- [ ] **Step 2: Run** `cargo test -p warden-broker --all-features --test github_token` — expect FAIL.
- [ ] **Step 3: Implement** by mirroring the commit signing arms. Page wording follows `docs/design-language.md`; warn with the modify badge that the agent can push and merge on every repository the App is installed on.
- [ ] **Step 4: Run** the tests and `scripts/screenshot-pages.sh <scratch-dir>`; keep the screenshots for the PR — expect PASS.
- [ ] **Step 5: Commit** "Approve GitHub token grants for up to 30 days".

### Task 5: The mint endpoint and its audit

**Files:**
- Create: `crates/broker/src/api/github_token.rs`, `crates/broker/src/audit/github_token.rs` (event structs, if `audit.rs` would pass 800 lines of code otherwise)
- Modify: `crates/broker/src/api.rs` (route `/v1/github-token`, `POST`, `BODY_LIMIT`; `api_grant_status` arm), `crates/broker/src/audit.rs` (`AuditEvent::GithubTokenMinted`, `AuditEvent::GithubTokenRefused`), `AppState` (holds `GithubApi`), `main.rs` (`GithubApi::public()`), `testkit/broker.rs` (`with_github_api(GithubApi)`), `docs/agent-protocol.md`
- Test: `crates/broker/tests/github_token/mint.rs`

**Interfaces:**
- Consumes: `Requests::active_github_token`, `SecretBackend::github_app`, `github_app::mint`
- Produces:
  - `POST /v1/github-token`, empty JSON object body, signed like every agent route → `200 GithubTokenResponse`; `403 NO_ACTIVE_GRANT`; `409 grant revoked|grant expired` (the prefixes `cli/src/client.rs::failure` already classifies); `409 KEY_CHANGED`-style text when the App's digest differs from the grant's; `503` with a fixed message when GitHub or the backend fails
  - `AuditEvent::GithubTokenMinted { grant_id: Id, agent: AgentName, installation_id: u64, permissions: Vec<String>, expires_at: i64 }` written before the token is returned
  - `AuditEvent::GithubTokenRefused { agent: AgentName, grant_id: Option<Id>, reason: String }` (fixed reasons only)

- [ ] **Step 1: Write the failing tests:** `mint_returns_token_under_grant`, `mint_without_grant_is_403_and_audited`, `mint_after_revoke_is_409`, `revoked_during_mint_not_returned` (revoke while the fake upstream holds the request, release it, expect 409 and a `GithubTokenMinted` entry), `app_changed_since_approval_is_409`, `upstream_failure_is_503_without_echo_and_audited`, `audit_never_contains_token_or_jwt` (scan `audit.jsonl` for `ghs_test` and `eyJ`), `client_disconnect_still_audits` (as the commit signing test does with `tokio::spawn`).
- [ ] **Step 2: Run** `cargo test -p warden-broker --all-features --test github_token mint` — expect FAIL.
- [ ] **Step 3: Implement** following `api/commit_signing.rs::attempt` step by step: active grant → read App → digest check → mint → audit → re-check grant → respond.
- [ ] **Step 4: Run** the tests, then the full `cargo test --workspace --all-features --locked` — expect PASS.
- [ ] **Step 5: Commit** "Serve GitHub tokens to agents under a grant".

### Task 6: CLI: request, token cache, git credential helper, `gh` wrapper, setup

**Files:**
- Create: `crates/cli/src/github_token.rs` (client call + cache), `crates/cli/src/git_credential.rs`, `crates/cli/src/setup_github.rs`
- Modify: `crates/cli/src/client.rs` (`Client::github_token`; move code out first if it would pass 800 lines of code), `cli.rs` (`RequestKind::Github { window, goal, context }` with `--for` default `30d` parsed by `Window::github_token`; `Cmd::Github { what: GithubCmd::Token }`; `SetupWhat::Github`), `main.rs` (dispatch; `git_credential::is_program_call` before clap, like `git_signing`), `request.rs` (`request_github`), `recover.rs`, `install.rs`, `doctor.rs` (a "github token grant" check)
- Test: `crates/cli/tests/e2e_github_token.rs`, unit tests in each new file

**Interfaces:**
- Consumes: `POST /v1/github-token`, `GithubTokenResponse`, `agent::state_dir()`, `EXIT_NO_GRANT` (5)
- Produces:
  - `warden request github [--for 1d|7d|30d] --goal <text>`: waits like `request signing`, same exit codes
  - `warden github token`: prints the token on stdout (for the wrapper), exit 5 with "Ask the owner with: warden request github ..." when there is no grant
  - `pub fn cached_or_mint(client: &Client, now: i64) -> Result<Zeroizing<String>>`: cache file `state_dir()/github-token.json` `{token, expires_at, grant_id}`, created 0600 with `create_new` + rename; served only if mode is 0600, it parses, and `expires_at - now >= 300`
  - `warden git-credential <get|store|erase>` (what git runs for `!<exe> git-credential`): for `get` with `protocol=https` and `host=github.com` prints `username=x-access-token` and `password=<token>`; anything else prints nothing and exits 0
  - `warden setup github`: sets, in the global git config, `credential.https://github.com.helper` to an empty value then `!<this exe> git-credential` (so earlier helpers are not consulted); writes `~/.local/bin/gh` (0755) that runs `GH_TOKEN="$(<exe> github token)" || exit $?; export GH_TOKEN; exec <real gh> "$@"`, where `<real gh>` is the first `gh` on `PATH` that is not this wrapper, resolved at setup; refuses to overwrite a `~/.local/bin/gh` it did not write; warns if `~/.local/bin` is not before the real `gh` on `PATH`; prints every change it made

- [ ] **Step 1: Write the failing tests:** `credential_get_github_prints_token`, `credential_other_host_prints_nothing`, `credential_http_scheme_prints_nothing`, `credential_store_and_erase_are_silent`, `cache_reused_until_five_minutes_left`, `cache_with_wrong_mode_or_garbage_is_replaced`, `cache_file_created_0600`, `token_without_grant_exits_5_with_guidance`, `setup_github_writes_helper_and_wrapper` (temp `HOME`, fake `gh` on `PATH`), `setup_github_refuses_foreign_wrapper`; e2e `e2e_request_github_then_git_credential` against `TestBroker` with the fake upstream.
- [ ] **Step 2: Run** `cargo test -p warden-broker-cli --all-features github` — expect FAIL.
- [ ] **Step 3: Implement.** Parse git's `key=value` lines strictly (unknown keys ignored, a line without `=` ends input with nothing printed). Never print the token anywhere but stdout of `get` / `github token`.
- [ ] **Step 4: Run** the tests and the full workspace suite — expect PASS.
- [ ] **Step 5: Commit** "Use warden's GitHub tokens from git and gh".

### Task 7: Documentation, threat model, changelog

**Files:**
- Modify: `README.md` (the "what agents never see" table: hour-long GitHub App tokens are the stated exception), `docs/threat-model.md` (the token is visible to agents, scope is the App installation, revocation cannot recall a minted token, RSA key held and signed with aws-lc-rs), `docs/security-assessment.md` (risk moved; update its date), `docs/assurance-case.md`, `docs/configuration.md` (`WARDEN_GITHUB_TOKEN_MAX_WINDOW`), `docs/1password-items.md` (the `warden:github-app` item), `docs/agent-usage.md` (`warden request github`, `warden setup github`, what to do on denial), `docs/agent-protocol.md`, `docs/interfaces.md`, `site/index.html` if it lists what agents never see, `CHANGELOG.md` (`## [Unreleased]`)
- Create: `docs/github-app.md`: creating the agent App (permissions exactly as in Global Constraints, no webhook, installed only on chosen repositories), downloading its key into the 1Password item, the three per-repository levels (no access / pull requests only with a ruleset requiring the owner's review / full) and that repositories whose content runs as the owner are at most "pull requests only", and that workflow-changing PRs are left to the owner

- [ ] **Step 1:** Write the docs; check every command and variable name against the code.
- [ ] **Step 2: Run** the whole "Before you push" list from `AGENTS.md` — expect all PASS.
- [ ] **Step 3: Commit** "Document GitHub App tokens for agents".

After Task 7: open one PR for #185 with the template filled in, the screenshots from Task 4 attached (see the PR screenshots memory), and a "Verified" section that separates local runs from CI. An end-to-end check against real GitHub needs the App created and its item in 1Password; say in the PR whether it was done.
