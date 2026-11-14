# Audit entry limits Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound the rate of every audit entry an enrolled agent or an unauthenticated peer can cause, and stop admin commands from stalling the running server's appends.

**Architecture:** One generic in-memory limiter for refusals (`audit_throttle`), registered in one list that the expiry loop flushes. Daily per-grant budgets in SQLite for real uses (proxied calls, relay sessions), copied from the commit signing budget. A two-phase, streaming open of the audit log.

**Tech Stack:** Rust (edition 2024, toolchain pinned), tokio, sqlx/SQLite, axum, russh, async-trait.

**Spec:** `docs/superpowers/specs/2026-11-13-audit-entry-limits-design.md`. Read it first: it holds the reasons, the bounds table and the disclosure rules.

**Tags:** **[call]** marks a decision made while planning that the spec left open; the owner may override it.

## Global Constraints

- Follow `AGENTS.md`: every CI command in "Before you push" passes; no `#[allow]`/`#[expect]` without a reason comment; no dead code; no `TODO`.
- Five pull requests, one branch and one GitHub issue each, in the order of the parts below. Part E is independent and may run in parallel. Each branch starts from `main` after the previous part merged.
- **Disclosure (owner's decision):** Part C's issue, branch name, commits, PR title and body and its docs describe only the bound, never the attack (for example "Bound relay audit entries"). The spec and this plan stay untracked until the release after Part C; Part F commits them.
- No source file passes about 800 lines. `src/api.rs` (830) and `src/audit.rs` (1146) are already over: new code goes in modules beside them, and the tasks below move code out.
- Defaults: `WARDEN_PROXY_MAX_CALLS_PER_DAY` 10000, `WARDEN_RELAY_MAX_SESSIONS_PER_DAY` 1000, each 1 to 1000000, parsed with `bounded_u32` like `WARDEN_COMMIT_SIGNING_MAX_PER_DAY`.
- Allowances per minute: agent-keyed refusals 30 (existing `REFUSALS_PER_MINUTE`); proxied-call refusals 30 per agent; relay session refusals 30 per grant; refused relay logins 5 per address, 10 overall, 1024 addresses held; local backend errors 10.
- The day is the UTC day `now.div_euclid(86_400)`. A held count is written at most once a minute per key (or per limiter, for an aggregate).
- Every user-visible change: a line under `## [Unreleased]` in `CHANGELOG.md`; docs that `AGENTS.md` lists stay consistent in the same PR.
- Public repository: test and doc names are generic (`bot`, `home-api`, `switch-01`).
- Agents: `rg` and line ranges, `--quiet` builds, output through `| tail -50`.

## Review Focus

1. **A flood from many addresses** (IPv6 makes them free): at most 10 `relay_login_refused` and one `relay_logins_refused_held` a minute in total. Pinned in Task 7.
2. **Concurrent calls at the edge of a budget:** exactly the limit pass, never one more. Pinned in Tasks 4 and 6.
3. **The audit log failing while a held count is flushed:** the count is kept for the next flush, never lost or doubled. Pinned in Task 2.
4. **Shutdown:** every registered limiter's counts (relay and local backend included) are flushed by the shutdown path. Pinned in Task 3.
5. **An admin command opening a large log while the server appends:** appends during the unlocked phase are verified, not lost, and a changed prefix is refused. Pinned in Task 9.

---

## Part A: the shared limiter (PR 1, no change in what is recorded)

### Task 1: Move `AuditEvent` out of `audit.rs`

**Files:**
- Create: `crates/broker/src/audit/event.rs` (the enum at `src/audit.rs:37-532` with its doc comments and derives)
- Modify: `crates/broker/src/audit.rs` (declare `mod event; pub use self::event::AuditEvent;`)

**Interfaces:**
- Produces: `crate::audit::AuditEvent`, unchanged path and variants.

- [ ] **Step 1:** Move the enum and any items only it uses. Nothing else changes.
- [ ] **Step 2:** Run `cargo test -p warden-broker --all-features --locked 2>&1 | tail -30`. Expected: all pass. Run `tokei crates/broker/src/audit.rs`: under 800 lines of code.
- [ ] **Step 3:** Commit `Move AuditEvent into its own module`.

### Task 2: The generic limiter

**Files:**
- Create: `crates/broker/src/audit_throttle.rs`, `crates/broker/src/audit_throttle/tests.rs`
- Modify: `crates/broker/src/lib.rs` (`pub mod audit_throttle;`)

**Interfaces:**
- Produces (all `pub`, documented, because `main.rs` uses them):
  - `pub trait Tally: Copy + Default + Send + Sync + 'static { fn add(&mut self, other: Self); }`, with `impl Tally for u64` (saturating).
  - `pub struct Allowance { pub per_key: u32, pub overall: Option<u32> }`
  - `pub enum Summary<K, V> { PerKey(fn(K, V) -> AuditEvent), Aggregate { max_keys: usize, event: fn(u64, V) -> AuditEvent } }`. `PerKey` is only for keys that come from enrolled agents or stored grants, so it holds no key cap. `Aggregate` writes one entry per minute for all keys, where the `u64` is the number of distinct keys counted; a key not yet held once `max_keys` are held is counted once, as one more key, and not added. **[call]**
  - `pub struct Throttle<K, V>`, with:
    - `pub fn new(what: &'static str, allowance: Allowance, summary: Summary<K, V>) -> Arc<Self>`
    - `pub async fn record(&self, audit: &AuditLog, key: &K, now: i64, tally: V, event: AuditEvent)`: writes `event` if both the key's and the overall allowance for the minute have room, otherwise adds `tally` to the held count. A failed write is logged with `what`.
    - private `fn note(&self, key: &K, now: i64, tally: V) -> bool` for the tests.
  - `#[async_trait] pub trait FlushHeld: Send + Sync { async fn flush(&self, audit: &AuditLog, now: i64, all: bool); }`, implemented by `Throttle`. It writes a key's held count when that key's minute is over, or every held count when `all`. A count whose write fails is put back. Keys whose minute is over and that hold nothing are dropped.
  - `#[derive(Default)] pub struct AuditThrottles`, with `pub fn register(&self, throttle: Arc<dyn FlushHeld>)` and `pub async fn flush(&self, audit: &AuditLog, now: i64, all: bool)`.
- Keep from `requests/refusal_throttle.rs`: a poisoned mutex is recovered, and a clock set back starts a new minute.

- [ ] **Step 1: Write the failing tests** in `audit_throttle/tests.rs`. Each uses an `AuditLog` in a temp dir and reads the entries back:
  - `per_key_allowance_writes_then_counts`: 30 records for `bot` at t=1000 write 30 entries; the 31st and 32nd write nothing; `flush(.., 1030, false)` writes nothing (minute not over); `flush(.., 1060, false)` writes one summary with count 2; a second flush writes nothing.
  - `another_key_has_its_own_allowance`
  - `overall_allowance_binds_across_keys`: `Allowance { per_key: 5, overall: Some(10) }`; 5 records each for 3 keys write 10 entries in total.
  - `aggregate_writes_one_summary_for_all_keys`: `max_keys: 4`, 1 per key and 2 overall. Records from 100 distinct keys write 2 entries. One flush after the minute writes exactly one summary, with keys = 5 (4 held plus one for overflow) and the summed tally.
  - `a_failed_flush_keeps_the_count`: make the log unwritable (as `tests/audit_stall.rs` does, or with a failing `AuditLog` the crate already offers for tests), flush, restore, flush again: one summary with the full count.
  - `flush_all_writes_counts_before_their_minute_is_over`
  - `a_clock_set_back_starts_a_new_minute`
  - `registry_flushes_every_registered_throttle`
- [ ] **Step 2:** Run `cargo test -p warden-broker --lib audit_throttle 2>&1 | tail -30`. Expected: FAIL, the module does not exist.
- [ ] **Step 3:** Implement `audit_throttle.rs` with the interfaces above.
- [ ] **Step 4:** Run the same command. Expected: PASS. Then run `cargo clippy -p warden-broker --all-targets --all-features -- -D warnings 2>&1 | tail -20`: clean.
- [ ] **Step 5:** Commit `Add a generic limiter for audit entries`.

### Task 3: Move the three existing users onto it

**Files:**
- Delete: `crates/broker/src/requests/refusal_throttle.rs`
- Modify: `crates/broker/src/requests.rs:51,66,465-470` and its `new`; `requests/commit_signing.rs`, `requests/github_token.rs:165-195`, `requests/release_steps.rs:320-340`, `requests/limits.rs:339-347`
- Test: `crates/broker/tests/commit_signing_logs.rs`, `tests/github_token_logs.rs`, `tests/github_release_logs.rs` (existing tests, adjusted only for flush timing)

**Interfaces:**
- Consumes: Task 2.
- Produces:
  - A `Requests` field `throttles: Arc<AuditThrottles>`, and `pub fn audit_throttles(&self) -> &Arc<AuditThrottles>`.
  - The three fields become `Arc<Throttle<AgentName, u64>>`, built with `Allowance { per_key: 30, overall: None }` and `Summary::PerKey`, with the existing `*RefusalsHeld` constructors, and registered in `Requests::new`.
  - `flush_refusals(all)` calls `self.throttles.flush(&self.audit, self.clock.now(), all)` in place of the three `flush_*_refusals` methods, which are deleted.

- [ ] **Step 1: Write the failing test** `a_held_refusal_count_is_written_once_a_minute` in `tests/commit_signing_logs.rs`, using the existing refusal helpers. 31 refusals at t, then `flush_refusals(false)` at t+15 writes no `commit_signing_refusals_held`, and at t+60 writes exactly one with count 1.
- [ ] **Step 2: Write the failing test** `shutdown_flushes_every_registered_throttle` in `tests/audit.rs`. Register an extra `Throttle` through `requests.audit_throttles()`, hold a count in it, then stop the sweep loop through its shutdown channel. Its summary is in the log.
- [ ] **Step 3:** Run both. Expected: FAIL.
- [ ] **Step 4:** Make the changes listed above.
- [ ] **Step 5:** Run `cargo test --workspace --all-features --locked 2>&1 | tail -30`. Expected: all pass, the existing refusal tests included.
- [ ] **Step 6:** Under `Changed` in `CHANGELOG.md`, add: counts of refusals beyond the per-minute allowance are written at most once a minute per agent.
- [ ] **Step 7:** Run the full CI list from `AGENTS.md` (zizmor not needed). Commit `Share one limiter for audited refusals`, open PR 1, and fill in the template.

## Part B: proxied calls (PR 2)

### Task 4: The daily use budget, and `WARDEN_PROXY_MAX_CALLS_PER_DAY`

**Files:**
- Create: `crates/broker/migrations/0012_daily_use.sql`, `crates/broker/src/requests/daily_use.rs`
- Modify: `crates/broker/src/requests.rs` (field `proxy_calls_per_day: u32`, `mod daily_use;`, re-export `CALLS_PER_DAY`), `src/audit/event.rs`, `src/config.rs` (beside `commit_signing_limits`, field `proxy_max_calls_per_day`), `src/config/tests.rs`, `src/main.rs:616`, `docs/configuration.md:52`
- Test: `crates/broker/src/requests/tests.rs` or a new `requests/daily_use/tests.rs`

**Interfaces:**
- Produces:
  - Migration: `ALTER TABLE grants ADD COLUMN use_day INTEGER; ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0; ADD COLUMN use_limit_noticed_day INTEGER;`. Generic, because a grant has one kind. **[call]**
  - `pub const CALLS_PER_DAY: u32 = 10_000;`
  - `pub(crate) enum DailyUse { ProxyCall { secret: SecretName } }`. Part C adds `RelaySession`. Use whatever secret-name type `ApiGrant.secret` already has.
  - `Requests::with_proxy_calls_per_day(self, limit: u32) -> Self`
  - `pub(crate) async fn take_daily_use(&self, grant: &Id, kind: &DailyUse) -> Result<bool, RequestError>`: one `UPDATE … WHERE id = ?2 AND (use_day IS NOT ?1 OR use_count < ?3)`, as in `take_signature` (`requests/commit_signing.rs:55-72`).
  - `pub(crate) async fn daily_limit_reached(&self, agent: &AgentName, grant: &Id, kind: &DailyUse)`: claims `use_limit_noticed_day` once a day, writes the reached entry, and notifies on a spawned task, then writes the notified or `error` entry. It mirrors `signature_limit_reached` and `notify_signature_limit`.
  - Audit variants: `ProxyCallLimitReached { grant_id, agent, limit: u32 }`, `ProxyCallLimitNotified { grant_id, channel: String }` and `ProxyCallsRefusedHeld { agent, count: u64 }`. The last is used in Task 5.
  - Notice title `warden: {agent} reached its API call limit`. Message: `It made {limit} calls with {secret} today, so its calls fail until 00:00 UTC. If you do not expect this many, revoke its grant.` URL: `<public_url>/grants`.

- [ ] **Step 1: Write the failing tests:**
  - `take_daily_use_stops_at_the_limit_and_resets_the_next_day`
  - `take_daily_use_holds_for_concurrent_takes`: 5 joined takes at limit 3 give exactly 3 `true`.
  - `take_daily_use_counts_per_grant`
  - `the_daily_call_limit_has_a_default_and_a_range` in `config/tests.rs`: unset gives 10000; `0` and `1000001` are refused; `1` and `1000000` are accepted.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement as above, and wire `main.rs` with `.with_proxy_calls_per_day(config.proxy_max_calls_per_day)`. Add the `docs/configuration.md` row in the style of line 52.
- [ ] **Step 4:** Run `cargo test -p warden-broker --all-features --locked 2>&1 | tail -30`. Expected: PASS.
- [ ] **Step 5:** Commit `Count each grant's daily uses`.

### Task 5: Budget and limiter on proxied calls

**Files:**
- Create: `crates/broker/src/api/proxy_call.rs` (move `proxy_call`, `audited_call`, `call` and their helpers out of `api.rs:408-700`)
- Modify: `crates/broker/src/api.rs`, `crates/broker/src/requests.rs` (field `proxy_refusals: Arc<Throttle<AgentName, u64>>`, registered)
- Test: `crates/broker/tests/proxy/limits.rs`, `tests/proxy/audit_log.rs`; extend the proxy test `Setup` with a per-day limit, following `TestBroker::with_commit_signing_per_day`
- Docs: `docs/threat-model.md` (the proxy section and "A log that cannot be written stops what gives access", around line 274), `docs/security-assessment.md` (a new ranked risk "The audit log's disk fills or its lock stalls, and access stops for every agent", which risk 13 points to, plus the date), `docs/agent-protocol.md`, `docs/agent-usage.md`, `docs/design.md`, `docs/assurance-case.md`, `CHANGELOG.md` (noting migration `0012`)

**Interfaces:**
- Consumes: Task 4 (`take_daily_use`, `daily_limit_reached`, `DailyUse::ProxyCall`, `ProxyCallsRefusedHeld`) and Task 3.
- Produces: `Requests::record_proxy_refusal(&self, agent: &AgentName, event: AuditEvent)` (through `proxy_refusals`), in `requests/daily_use.rs` or a small `requests/proxy_refusals.rs`.
- The rule, from the spec:
  - `call` takes the budget after `proxy::check` passes and immediately before writing `proxy_call_started`. If none is left, it calls `daily_limit_reached` and returns `Failure::Client(StatusCode::TOO_MANY_REQUESTS, …)` with the message `this grant made {limit} calls today, its limit; calls fail until 00:00 UTC, and the owner was told`.
  - `audited_call` tracks whether `proxy_call_started` was written. If not, it writes the result through `record_proxy_refusal` and returns the result whatever happens to the entry. If it was, it writes the result directly, as today.

- [ ] **Step 1: Write the failing tests:**
  - `tests/proxy/limits.rs::a_grant_stops_at_its_daily_call_limit_and_the_owner_hears_once`, modelled on `tests/commit_signing/windows.rs:119-162`. At limit 2: two calls reach the upstream, and the third gets 429 with "calls fail until 00:00 UTC", with no upstream request. One `proxy_call_limit_reached` with `limit` 2; the bell title is `warden: bot reached its API call limit`; another grant's calls go on; `clock.advance(86_400)` starts again.
  - `concurrent_calls_at_the_daily_limit_pass_exactly_the_limit`
  - `refused_calls_do_not_use_the_budget`: calls refused by `proxy::check` leave the budget whole.
  - `tests/proxy/audit_log.rs::refused_calls_beyond_the_allowance_are_counted`: 35 calls refused by `proxy::check` write 30 `proxy_call` entries, and after `flush_refusals(true)` one `proxy_calls_refused_held` with count 5.
  - `a_call_refused_after_its_start_still_has_its_result`: revoke the grant while `proxy_call_started` is being written (use the existing stall hook in `tests/audit_stall.rs` or `tests/proxy_ended_calls.rs`). Both `proxy_call_started` and `proxy_call` are present, and no upstream request was made.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Move the code into `api/proxy_call.rs`, then implement the rule.
- [ ] **Step 4:** Run `cargo test --workspace --all-features --locked 2>&1 | tail -30` and `tokei crates/broker/src/api.rs`. Expected: PASS, and under 800 lines of code. Check what the CLI prints for this 429. If the message misleads (for example "retry"), fix it in `crates/cli` and add a test there.
- [ ] **Step 5:** Update the docs listed above. The threat model gets the spec's bounds table, with the entry size measured from a real `proxy_call` line in the test log.
- [ ] **Step 6:** Run the full CI list. Commit, open PR 2 with the template, and say what was and was not verified.

## Part C: relay (PR 3, neutral wording throughout)

### Task 6: Relay session budget and refusal limiter

**Files:**
- Modify: `crates/broker/src/requests/daily_use.rs` (`DailyUse::RelaySession { target: TargetName }`, `SESSIONS_PER_DAY: u32 = 1_000`, `with_relay_sessions_per_day`), `src/audit/event.rs`, `src/config.rs`, `src/config/tests.rs`, `src/main.rs`, `src/relay/server.rs:186-196,244-256` (a `session_refusals: Arc<Throttle<Id, u64>>` on `Shared`, registered through `requests.audit_throttles()`), `src/relay/server/start.rs:25-56,170-190`, `docs/configuration.md`
- Test: `crates/broker/tests/relay/start.rs`, `tests/relay/limits.rs`

**Interfaces:**
- Consumes: Tasks 2 to 4.
- Produces:
  - Audit variants `RelaySessionLimitReached { grant_id, agent, limit: u32 }`, `RelaySessionLimitNotified { grant_id, channel }` and `RelaySessionsRefusedHeld { grant_id: Id, count: u64 }`.
  - `refuse_session` writes through `shared.session_refusals` keyed by grant id, 30 a minute.
  - In `start.rs`, the budget is taken immediately before `RelaySessionStarted` is written. When none is left: `daily_limit_reached` with the agent from `RelayGrantRecord.agent`, then `refuse_session` with the reason `daily_limit` and the agent message `this grant reached its daily limit of sessions; new sessions fail until 00:00 UTC`.
  - Notice title `warden: {agent} reached its relay session limit`. Message: `It opened {limit} sessions to {target} today, so new sessions fail until 00:00 UTC. If you do not expect this many, revoke its grant.`

- [ ] **Step 1: Write the failing tests:**
  - `a_relay_grant_stops_at_its_daily_session_limit_and_the_owner_hears_once` (limit 2, following the signing test)
  - `concurrent_sessions_at_the_daily_limit_pass_exactly_the_limit`
  - `refused_sessions_beyond_the_allowance_are_counted`: 35 refusals give 30 entries plus one `relay_sessions_refused_held` with count 5 after a full flush.
  - `the_daily_session_limit_has_a_default_and_a_range` (config)
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test --workspace --all-features --locked 2>&1 | tail -30`. Expected: PASS.
- [ ] **Step 5:** Commit `Limit relay sessions per grant per day`.

### Task 7: Refused relay logins

**Files:**
- Modify: `crates/broker/src/relay/server.rs` (a `login_refusals: Arc<Throttle<IpAddr, LoginTally>>` on `Shared`, registered), `src/relay/server/conn.rs:208-229`, `src/audit/event.rs`
- Test: `crates/broker/tests/relay/limits.rs`
- Docs (neutral, the bound only): `docs/threat-model.md`, the new risk row in `docs/security-assessment.md`, `docs/design.md`, `docs/assurance-case.md`, `CHANGELOG.md`

**Interfaces:**
- Consumes: Task 2.
- Produces:
  - `pub struct LoginTally { pub connections: u64, pub attempts: u64 }` implementing `Tally`, in `relay/server/conn.rs` or beside it.
  - Audit variant `RelayLoginsRefusedHeld { peers: u64, connections: u64, attempts: u64 }`.
  - `Allowance { per_key: 5, overall: Some(10) }` and `Summary::Aggregate { max_keys: 1024, … }`.
  - `record_refused_login` passes `LoginTally { connections: 1, attempts }` and the existing `RelayLoginRefused` event to `record`.

- [ ] **Step 1: Write the failing tests:**
  - `refused_logins_from_one_address_are_counted_beyond_five_a_minute`
  - `refused_logins_from_many_addresses_write_one_summary_a_minute`. Drive `record_refused_login` (or the throttle as the relay builds it) with 2000 distinct addresses inside one minute. Expect exactly 10 `relay_login_refused` and, after the minute, exactly one `relay_logins_refused_held` with `peers` 1025 and the summed connections and attempts. If driving real connections is too slow, exercise the throttle exactly as the relay builds it, through a `pub(crate)` constructor shared with `RelayServer::new`. **[call]**
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test --workspace --all-features --locked 2>&1 | tail -30`. Expected: PASS.
- [ ] **Step 5:** Update the docs in neutral terms. Run the full CI list. Commit, then open PR 3 under a neutral title, with a neutral issue.

## Part D: local backend (PR 4)

### Task 8: Local backend errors through a limiter

**Files:**
- Modify: `crates/broker/src/policy/local.rs:595-631` and `LocalBackend::open`, `src/audit/event.rs`, `src/main.rs:540-560` (the backend builder also returns the throttle, and the server registers it on `requests.audit_throttles()` once `Requests` exists)
- Test: `crates/broker/tests/local_backend.rs`
- Docs: `docs/local-backend.md` if it describes the error entries; `docs/threat-model.md`; `CHANGELOG.md`

**Interfaces:**
- Consumes: Task 2.
- Produces:
  - `LocalBackend` holds `Arc<Throttle<(), u64>>`, with `Allowance { per_key: 10, overall: None }` and `Summary::PerKey(|(), count| AuditEvent::LocalBackendErrorsHeld { count })`.
  - `pub fn audit_throttle(&self) -> Arc<dyn FlushHeld>`.
  - Audit variant `LocalBackendErrorsHeld { count: u64 }`.
  - `record` and the problems `open` records at startup both go through it.

- [ ] **Step 1: Write the failing test** `errors_beyond_ten_a_minute_are_counted`. With the policy file in a broken state, 15 `GET /v1/offers` (three reads each) write 10 `error` entries with the backend's context, then one `local_backend_errors_held` with count 35 after a full flush.
- [ ] **Step 2:** Run it. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `cargo test --workspace --all-features --locked 2>&1 | tail -30`. Expected: PASS.
- [ ] **Step 5:** Update the docs. Run the full CI list. Commit, then open PR 4.

## Part E: opening the log (PR 5, independent)

### Task 9: Verify without the lock, streaming

**Files:**
- Create: `crates/broker/src/audit/open.rs` (move `verify`, `open_blocking`, `load_locked`, `split_tail`, `verify_bytes`, `repair_tail`, `FileLock` and `Head` out of `audit.rs:680-920` as needed)
- Modify: `crates/broker/src/audit.rs`
- Test: `crates/broker/tests/audit.rs` or `src/audit/open/tests.rs`
- Docs: `docs/threat-model.md` (where it describes admin commands and the log lock, if it does), `CHANGELOG.md` (Fixed)

**Interfaces:**
- Produces: `pub fn verify(path: &Path) -> Result<u64, AuditError>`, unchanged signature, now streaming. `open_blocking` keeps its signature. A new `AuditError` variant, `PrefixChanged`, for a file shorter under the lock than the length already verified. **[call]**
- The algorithm is in spec section 6. Verification streams with a `BufReader`, one line at a time, so memory does not grow with the file.

- [ ] **Step 1: Write the failing tests:**
  - `the_lock_is_held_only_for_the_tail`: take the file lock in another handle, start the open on a blocking thread, and check that phase one finishes (expose a test hook, or a `pub(crate) fn verify_prefix(file) -> Result<Head, _>` that takes no lock). Then release the lock: the open completes.
  - `entries_appended_between_the_phases_are_verified`
  - `a_prefix_that_shrank_between_the_phases_is_refused`
  - `a_torn_tail_is_still_repaired`
  - `verify_streams_a_large_log`: a log of 100k entries verifies with its count. Assert the count only, not the memory.
- [ ] **Step 2:** Run them. Expected: FAIL.
- [ ] **Step 3:** Move the code, then implement.
- [ ] **Step 4:** Run `cargo test --workspace --all-features --locked 2>&1 | tail -30` and `tokei crates/broker/src/audit.rs`. Expected: PASS, and fewer lines than after Task 1.
- [ ] **Step 5:** Run the full CI list. Commit, then open PR 5.

## Part F: after the release that ships Part C

### Task 10: Disclose and commit the design

**Files:**
- Modify: `docs/security-assessment.md` (the full description of each finding)
- Add: `docs/superpowers/specs/2026-11-13-audit-entry-limits-design.md`, `docs/superpowers/plans/2026-11-13-audit-entry-limits.md`

- [ ] **Step 1:** Confirm that the release containing Part C is published (`warden release` steps done by the owner's approval, not by this task).
- [ ] **Step 2:** Add the findings' full descriptions, then commit the spec and plan in one docs PR.
