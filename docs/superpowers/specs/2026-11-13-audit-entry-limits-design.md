# Audit entry limits: design

Date: 2026-11-13. Status: for approval.

Tags: `(owner's decision)` is the owner's; **[call]** is the designer's decision, open to
override; **[guess]** is an assumption the builder confirms.

## Intent

The audit log is append-only, never rotated, and fails closed: when an entry cannot be
written, everything that gives access stops, for every agent. So anyone who can make the
broker write entries without limit can, given time, fill the log's disk and stop warden for
everyone. Commit signing, GitHub token mints and their refusals are already bounded. Four
paths are not, found in the review of `main` at `189a041`:

- **M1.** Proxied calls (`POST /v1/grants/{id}/http`) write `proxy_call` for every call,
  refusals by the grant's rules and 429s from the call slots included, and
  `proxy_call_started` for every call that is sent. Needs an enrolled agent with one live API
  grant.
- **M2.** The relay writes `relay_login_refused` for every connection that offers a key and
  fails to log in. It needs **no enrolled key**: any peer that reaches the relay port can
  do it, slowed only by `PreAuthLimiter` and russh's one second delay. An agent with a relay
  grant can also loop short sessions (`relay_session_started` and `relay_session_ended`)
  or refused ones (`relay_session_refused`).
- **L11.** While the local secret backend's files are unusable, every read that fails writes
  an `error` entry. `GET /v1/offers` makes three reads and is not limited.
- **L10.** Opening the log (`load_locked`) reads and verifies the whole file under the
  exclusive file lock. A `warden-server` admin command on a large log holds the lock past the
  running server's 5 second `LOCK_WAIT`, so its appends fail and so does everything that
  gives access, meanwhile. Memory use equals the file size. Not a count of entries, but the
  same failure: the log stops access.

Success: every path that writes an entry has a bound on its rate that does not depend on
the caller's good behaviour, the bounds are written down in the threat model, and the one
entry per real use of a secret stays.

## Goals

- A rate bound on every entry an agent or an unauthenticated peer can cause.
- The guarantee that each proxied call and each relay session is on record before it reaches
  the upstream stays whole (owner's decision: budgets, not summaries).
- One shared limiter for refusals, instead of one per path.
- Admin commands on a large log do not hold up the running server.
- `docs/security-assessment.md` risk 13 (and its date) and `docs/threat-model.md` say what is
  bounded, by how much, and what is not.

## Non-goals

- Rotating or compacting the audit log. The log stays append-only and whole.
- A cap on the log's total size. It would stop access just as a full disk does.
- Limits on calls that write no entry (`GET /v1/offers` is #254, separate).
- Changing what an entry contains.

## Anti-goals

- **Summarising real uses.** A proxied call or relay session that reaches the upstream with
  no entry of its own breaks the audit promise (owner's decision).
- **A limit that fails open.** When a counter cannot be read or updated, refuse the use.
- **A limiter an unauthenticated peer can grow.** Memory held per key must stay bounded
  whatever addresses or names a peer offers.
- **A limit a restart resets**, for the budgets. A restart may lose at most one minute of
  refusal counts, as today.

## Constraints

- Public repository: no private names in code, tests or docs.
- Migrations are append-only: a new file, never an edit to a released one.
- No new dependency is needed. **[guess]**
- Each child is one issue, one branch and one pull request, per `AGENTS.md`.
- No source file passes about 800 lines. `api.rs` (830) and `audit.rs` (1146) are already
  over: whatever a pull request adds to them goes in a new module beside them, and the pull
  request that touches `audit.rs` moves the open and verify code into its own file in the
  same change. **[call]**

## Approaches

For successful calls and sessions, three were weighed:

1. **A daily budget per grant, counted in the database**, refusing beyond it.
   Chosen (owner's decision). It keeps one entry per use. The cost is that a legitimate
   heavy user can hit the limit; the defaults are set far above normal use and are
   configurable.
2. Summarising successful uses beyond a rate into count entries. Rejected: it breaks the
   audit promise.
3. Bounding only refusals and unauthenticated traffic. Rejected: an enrolled agent with one
   read-only grant could still fill the disk.

For refusals there was one sensible way: generalise the existing `RefusalThrottle` (the
first N in a minute are written one by one, the rest counted and written as one entry
later), because it is already proven on three kinds and its entries are already in the
threat model. A once-per-state dedupe for L11 was considered and rejected **[call]**: a
refusal message that varies (it names an item, a line) defeats it, while a count always
holds.

## Design

### 1. The shared limiter (first pull request)

`requests/refusal_throttle.rs` becomes a crate-level module, for example
`crates/broker/src/audit_throttle.rs` (name left to the builder), generic over its key:

- `Throttle<K: Eq + Hash + Clone>` with a per-key allowance per minute, as today.
- **A cap on keys held** (`max_keys`). A key not yet held, once the cap is reached, is
  counted under one overflow key ("other") and never added. Entries whose minute is over
  and that hold no count are dropped at each flush, so the map does not keep a key for
  ever. **[call]**
- **An overall allowance per minute** across all keys, checked after the key's own
  allowance: an entry is written only if both have room; otherwise it is counted under its
  key (or the overflow key). **[call]**
- **Generic over what it sums** for a held entry: a count for most kinds, a pair
  (connections, attempts) for refused relay logins. **[call]**
- **Summaries are bounded too.** A key's held count is written at most once a minute, not at
  every 15 second sweep. A limiter can also be set to write **one aggregate summary** a
  minute for all its keys together, which the relay's refused logins use, so a peer that
  keeps changing address gets one summary a minute, not one per address. **[call]**
- `record(audit, key, now, event, what)` and `flush(audit, now, what, held)`. The `held`
  closure builds the summary entry. A failed write puts the count back, as today.
- **One flush point.** Every limiter is created at startup and registered in one list that
  the expiry loop flushes each sweep and once at shutdown, the relay's and the local
  backend's included. This replaces the three `flush_*_refusals` methods. **[call]**
- Behaviour on a poisoned mutex, a clock set back and a failed write is unchanged.

The three existing users (signing, mint and release step refusals) move onto it keyed by
`AgentName`, with their current allowance (30 a minute), no overall allowance beyond the
enrolled-agent count, and `max_keys` high enough never to bind for enrolled agents
**[call]**: their entries stay the same; the only change is that a held count is written at
most once a minute per agent instead of at each sweep.

### 2. Daily budgets (in the M1 and M2 pull requests)

Both copy `take_signature` and `signature_limit_reached` (`requests/commit_signing.rs`):

- **One SQL statement** takes one use for today (UTC day, `now.div_euclid(86_400)`) or says
  none is left, so concurrent calls cannot pass the limit and a restart does not reset it.
  A storage error refuses the use.
- **At the limit**: the use is refused, the refusal goes through the limiter like any
  refusal, and once per grant per day a `*_limit_reached` entry is written and the owner is
  notified, on its own task, so the refusal does not wait for the notification channels.
  The notice's outcome is recorded (`*_limit_notified` or an `error` entry), as for signing.
- One new migration (`0012_…`) adds the counters to `grants`: a day and a count for
  proxied calls, the same for relay sessions, and a noticed day for each. Whether these are
  two pairs of columns or one generic pair (a grant has one kind) is the builder's choice.
  **[call]** The M1 pull request adds the migration with both kinds' columns, so M2 does not
  need its own. **[call]**
- Configuration, in `docs/configuration.md` beside `WARDEN_COMMIT_SIGNING_MAX_PER_DAY`, with
  the same parsing and range (1 to 1000000):
  - `WARDEN_PROXY_MAX_CALLS_PER_DAY`, default **10000** per API grant. **[call]**
  - `WARDEN_RELAY_MAX_SESSIONS_PER_DAY`, default **1000** per relay grant. **[call]**

  Builder methods on `Requests` (`with_proxy_calls_per_day`,
  `with_relay_sessions_per_day`) let tests set them low.

### 3. Proxied calls (M1, pull request 2)

In `api.rs`, `audited_call` and `call`:

- The budget is taken after `proxy::check` passes and just before `proxy_call_started` is
  written. Refused calls do not use it up, and nothing goes out without both the budget and
  the entry.
- **The rule for the result entry: whether `proxy_call_started` was written.** **[call]**
  - **Not written** (refused by `proxy::check`, by a changed policy, by the call slots with
    429, or by the budget): the `proxy_call` entry goes through the limiter keyed by agent,
    30 a minute, with a new `proxy_calls_refused_held { agent, count }` summary entry. The
    agent gets its answer whether or not the entry is written, since nothing was sent.
  - **Written**: the `proxy_call` result entry is written directly, as today, so every start
    has its result. That includes a call refused after its start by `usable_api_grant`
    because the grant ended meanwhile: nothing went out, but it used one of the budget,
    which is right because it wrote two entries. A failure to write the result still costs
    the agent the response, as today.
- At the budget the agent gets 429 with a message that says how many calls the grant made
  today, that calls fail until 00:00 UTC, and that the owner was told. **[call]** The
  builder checks what the CLI does with that 429 and that `docs/agent-protocol.md` and
  `docs/agent-usage.md` say it.
- The notice: "warden: `<agent>` reached its API call limit on `<secret>`", linking the
  grants page.

### 4. Relay (M2, pull request 3)

In `relay/server/conn.rs`, `relay/server/start.rs`:

- **Refused logins** (`record_refused_login`) go through a limiter keyed by the source IP
  address, with the `attempts` count of the connection kept in the entry. Allowance: 5
  entries a minute per address, 10 a minute overall, `max_keys` 1024. **[call]** Past it,
  the connections and attempts are summed, and one aggregate
  `relay_logins_refused_held { peers, connections, attempts }` entry a minute records them,
  where `peers` is the number of distinct addresses counted (overflow counted once).
  **[call]** The limiter is held by the relay's `Shared` and registered in the one flush
  list (section 1).
- **Refused sessions** (`refuse_session`) go through a limiter keyed by grant id, 30 a
  minute, with a `relay_sessions_refused_held { grant_id, count }` entry. Grant ids come
  from the database, so the keys are bounded by grants. **[call]**
- **Started sessions** take one from the grant's budget before `relay_session_started` is
  written. At the limit, the session is refused (through the limiter above) with a message
  saying when it resets, and the limit entry and notice follow section 2.
- `relay_session_ended` is bounded by its start: one per started session, unchanged.

### 5. Local backend (L11, pull request 4)

`LocalBackend::record` writes its `error` entry through a limiter with a single key,
10 a minute, and a `local_backend_errors_held { count }` summary entry. **[call]**
`Requests` holds the backend only as `Arc<dyn SecretBackend>`, so the trait does not change:
startup creates the limiter, hands it to `LocalBackend::open` and registers it in the flush
list (section 1). The problems `LocalBackend::open` records at startup go through it too.
**[call]**

### 6. Opening the log (L10, pull request 5)

`load_locked` becomes:

1. **Without the lock**: stream the file line by line, verifying the chain, up to the last
   complete line. Remember the head (seq, hash and length). Memory stays flat whatever the
   file's size.
2. **With the lock**: read only from the remembered length to the end, verify that it
   continues the chain from the remembered head, repair the tail as today, and return.
3. If the file is shorter under the lock than the length verified, refuse with an error:
   only `repair_tail` ever shortens the file, and only beyond the last complete line, so a
   verified prefix that shrank was changed by something else. **[call]**

`verify(path)` (the read-only check) streams too. The open and verify code moves out of
`audit.rs` into its own module in this pull request (see Constraints). Tests: a concurrent
append between the two steps is verified; a prefix changed between the steps is refused; a
torn tail is repaired; the lock is held only for the tail (a test can hold the lock in
another handle and show step 1 completes).

### Bounds after the change

Worst case per day at the defaults, at one entry of about 400 bytes **[guess: the builder
measures a real entry and corrects the table in the threat model]**:

| Source | Bound | Worst case a day |
|---|---|---|
| Proxied calls sent, per API grant | 10000 calls, 2 entries each | about 8 MB |
| Proxied calls refused, per agent | 30 a minute, plus 1 summary | about 18 MB |
| Relay sessions, per relay grant | 1000 sessions, 2 entries each | about 0.8 MB |
| Relay sessions refused, per grant | 30 a minute, plus 1 summary | about 18 MB |
| Refused logins, all peers, unauthenticated | 10 a minute, plus 1 aggregate summary | about 6 MB |
| Local backend errors | 10 a minute, plus 1 summary | about 6 MB |

Each grant takes a phone approval, so the per-grant figures multiply only by grants the
owner approved. Revoking the agent stops every enrolled source.

## Docs and changelog

In the pull request that changes each behaviour:

- `docs/security-assessment.md` and its date: a new ranked risk, "The audit log's disk fills
  or its lock stalls, and access stops for every agent", covering all four, because M2 needs
  no enrolled key and L10 no agent, which risk 13 ("needs an enrolled key") does not fit.
  Risk 13 points to it. A finding entry for each, in the style of its findings list. **[call]**
- `docs/threat-model.md`: the bounds table above, the new entries, and "a log that cannot be
  written stops what gives access" updated with the bounds.
- `docs/configuration.md`: the two new settings.
- `docs/design.md` and `docs/assurance-case.md`, which name these entries.
- `docs/agent-protocol.md` and `docs/agent-usage.md`: the budget's 429 and the relay
  refusal.
- `CHANGELOG.md` under `## [Unreleased]`, noting the new migration.

## Order

1. Shared limiter, existing users moved onto it, no change in behaviour.
2. M1: migration, proxied-call budget, proxied-call refusals.
3. M2: relay budget, session refusals, refused logins.
4. L11: local backend.
5. L10: opening the log. Independent of 1 to 4; can go in parallel.

## Disclosure

M2 lets a peer with no key push the broker towards stopping. `SECURITY.md` and the
fuzzing rule in `AGENTS.md` keep such details out of public issues and commits until a
fix is released. So (owner's decision):

- M2 is fixed in a public pull request with a neutral title and description (for example
  "Bound relay audit entries"), and a release follows soon after it merges.
- Its public issue, pull request, commits and docs changes do not describe the attack before
  that release. The threat model and assessment entries for M2 land in the same pull request
  only in neutral terms (the bound), and the finding's full description follows the release.
- This document, and any plan that describes M2, are committed only after that release. Until
  then they stay untracked on the design branch.

## Left to the builder

- Module and type names, and whether the budget columns are per kind or generic.
- The exact entry names, following the existing `*_refusals_held` pattern.
- Measuring an entry's size and correcting the bounds table.
- What the CLI does with the budget's 429, and its message.
