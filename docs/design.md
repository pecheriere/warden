# warden — design

This document records the intent and design of warden. It describes the full
v1 design; the current release (0.4.0) implements the SSH certificate mode
(§8.1), the SSH relay mode (§8.2) and the HTTP proxy mode (§8.3). Where the
implementation deviates from this design, the
[threat model](threat-model.md) says how and why.

## 1. Intent

An AI coding agent running on an operator's workstation regularly needs
privileged access to diagnose or operate self-hosted infrastructure: SSH into
servers and appliances, and calls to the HTTP APIs of the services that run
there. Handing the agent standing credentials is unsafe, and approving each
access through a prompt on the workstation only works when the operator is
sitting at it. When the operator is away, the agent is stuck.

warden is a small, self-hosted **approval broker**. The agent asks for access
with a stated goal; the owner gets a notification on their phone that shows
*why* (the goal) and *exactly what* is being granted; the owner approves with a
passkey for a time window; the agent then gets the access **without ever
holding a long-lived secret in clear**.

It is an open-source project, so it must be clean, generic in its interfaces,
and secure by construction.

## 2. Goals

1. The agent can request, and the owner can approve remotely (phone, off-LAN
   over Tailscale), three kinds of access:
   - **SSH (certificate mode)** to hosts that trust warden's SSH CA.
   - **SSH (relay mode)** to hosts that cannot trust a CA (Dropbear,
     password-only, vendor-managed appliances such as switches, firewalls and
     access points); warden terminates the agent's SSH session and opens the
     onward session itself.
   - **HTTP API calls with an injected secret** (proxy mode).
2. One approval covers a **goal for a time window**, not each command.
3. The agent never receives a reusable secret: SSH uses ephemeral keys and
   short-lived certificates; relay and proxy credentials never leave the
   broker.
4. Every request, decision, grant and use is recorded in an audit log.
5. The approval is cryptographically bound to the exact request and window
   (passkey signature), and only the owner's devices can reach the approval
   page (Tailscale).

## 3. Non-goals (v1)

- Standing / "always allow" approvals. Every window starts with an owner tap.
- Multiple approvers, quorum, teams, RBAC.
- Keystroke/session recording for SSH (session start/end and bytes only).
- Revocation of already-issued certificates on target hosts (KRL
  distribution). Short windows are the mitigation; revoke stops new issuance
  and kills relay sessions.
- Secret managers other than 1Password, and notifiers other than Home
  Assistant Companion and ntfy. The interfaces must make adding them easy;
  implementations are not in v1.
- A generic MCP server. v1 ships a CLI; an MCP front-end can come later.
- Replacing the owner's existing break-glass access. Whatever local path the
  owner already uses at their workstation keeps working and remains the
  fallback when warden is down. warden adds a remote path; it does not remove
  the local one.
- Transparent interception (`HTTPS_PROXY` MITM with a custom root CA).

## 4. Anti-goals (failure even if it "works")

- The agent can obtain a secret value by any path the design permits
  (echoing, redirecting it to another host, or smuggling it into a URL,
  header or body).
- An approval can be forged, replayed, widened (longer window, other host,
  other secret) or applied to a different request than the one displayed.
- A notification channel (Home Assistant, ntfy, push providers) sees secret
  values or can approve anything.
- Private keys or secrets written to disk on the workstation.
- warden itself becomes the easiest way into the network: anything exposed
  beyond the tailnet, anything running as root, broad egress.
- Silent failure: the agent must always get an explicit denied / expired /
  error result.

## 5. Actors and trust

| Actor | Trust |
|---|---|
| Owner (phone, workstation) | Root of trust. Holds the passkey. Edits 1Password. |
| Agent (an automated agent on the workstation) | Semi-trusted: well-intentioned but may be prompt-injected. Bounded by goal, window, targets and destination rules. |
| warden server | Trusted; holds the SSH CA key (in memory) and a **read-only** 1Password Connect token. Compromise = compromise of everything it brokers; hardened accordingly. |
| 1Password Connect | Trusted secret backend; reachable only from warden. |
| Notifiers (Home Assistant Companion, ntfy) | Untrusted doorbells: receive goal text and a link only. |
| Tailscale | Transport and network-level identity; the tailnet policy is the outer access control. |

## 6. Architecture

```
workstation                           server (container)                           targets
───────────                           ──────────────────                           ───────
warden CLI ── HTTPS (tailnet) ───────▶ warden server ── Connect API ──▶ 1Password Connect
  │  ephemeral key in ssh-agent         │  approval web UI (passkey)
  │                                     │  notifier ──▶ Home Assistant Companion / ntfy ──▶ phone
  ├── ssh (cert mode) ───────────────────────────────────────────────────────▶ hosts that trust the CA
  └── ssh (relay mode) ──── tailnet ──▶ warden SSH relay ── ssh (key/password) ──▶ appliances
                                        warden HTTP proxy ── HTTPS ──▶ service APIs
phone ── HTTPS (tailnet) ─────────────▶ approval page
```

Components, all in one Rust workspace:

- **`warden-server`** (one binary, run as a container): request API, approval
  web UI, SSH CA, SSH relay, HTTP injecting proxy, notifier dispatch, audit
  log.
- **`warden` CLI** (workstation): submits requests, waits for the decision,
  manages the ephemeral SSH key and certificate in an ssh-agent, wraps `ssh`
  and proxied HTTP calls.
- Shared crates for the protocol types and policy model.

Backends/notifiers are traits (`SecretBackend`, `Notifier`) with the v1
implementations `OnePasswordConnect`, `HomeAssistantNotifier`, `NtfyNotifier`.

## 7. Request lifecycle

1. **Request.** The CLI sends `{goal, kind, target, principal/secret, requested_duration}`.
   The server validates it against policy (target exists, mode/user/secret
   allowed, duration ≤ target max) and rejects invalid requests immediately
   with a clear error.
2. **Pending.** Stored with a random request id and a single-use approval
   token. One pending request per (agent, target, kind) at a time; duplicates
   return the existing pending id. Pending requests expire after **10 min**.
3. **Notify.** Doorbell via Home Assistant Companion; if Home Assistant does
   not accept the push within a short timeout (≈5 s) or errors, the same
   doorbell goes through ntfy. Content: goal (truncated), target summary, link
   to `/approve/<token>`. Never secret values.
4. **Review.** The approval page (HTTPS on the tailnet name) shows goal, kind,
   target, user/secret, destination rules, requested duration, and a duration
   picker (15 m / 30 m / 1 h / 4 h, capped by the target's max).
5. **Approve / deny.** Approve = WebAuthn assertion whose challenge is the
   hash of the canonical request **plus the chosen duration**. The server
   verifies the assertion, the challenge binding, the token's single use and
   that the requester identity (see §9) is the owner. Deny needs no passkey.
   The requesting agent can instead **cancel** its own pending request
   (`POST /v1/requests/{id}/cancel`, `warden request cancel <id>`, or Ctrl-C
   in the waiting CLI): the request becomes `cancelled`, audited as
   `request_cancelled`, and its approval page says "Cancelled by the agent."
   and cannot be approved. Another agent's or an unknown request is a 404, a
   request that is no longer pending (decided, cancelled or past its expiry) a
   409.
6. **Grant.** A grant record with `not_before/not_after` is created. The CLI,
   which long-polls (or polls) the request, receives the outcome:
   - cert/relay: the signed SSH certificate for the CLI's ephemeral public key;
   - proxy: a grant id usable for proxied calls until expiry.
7. **Use.** Every use (SSH cert issuance, relay session start/end, proxied
   call: method, URL, status, bytes) is audited against the grant.
8. **End.** Expiry or revoke (button on the page; also listed on an index of
   active grants). Revoke kills relay sessions and invalidates proxy grants
   immediately; issued certificates stay valid until their (short) expiry.

The CLI always gets a terminal state: `approved`, `denied`, `expired`,
`cancelled`, or `error` with a message.

## 8. Access modes

### 8.1 SSH certificate mode

- The CLI generates an **ephemeral Ed25519 key in memory**, adds it to an
  ssh-agent with a lifetime equal to the window (`ssh-add -t` semantics), and
  never writes it to disk.
- warden signs the public key: principal = `warden:<target>:<user>`; targets
  map it via AuthorizedPrincipalsFile or a cert-authority principals= option
  (so an approval is valid only on the approved target), validity
  = approved window (+ small clock skew allowance), key id = grant id,
  critical options/extensions from policy (default: no agent forwarding, no
  port forwarding, no X11; pty allowed).
- Targets trust the CA either via `TrustedUserCAKeys` plus an
  `AuthorizedPrincipalsFile` listing `warden:<target>:<user>` for each allowed
  user, or via a `cert-authority,principals="warden:<target>:<user>"` line in
  `authorized_keys` (for hosts that only read `authorized_keys`, such as the
  Home Assistant SSH add-on; a host that accepts neither uses relay mode).
- The CLI provides `warden ssh <target> [cmd]` which uses the grant's agent
  and the target's address/user.
- **One certificate per grant** (decision): the ephemeral public key is part
  of the request and of the hashed approval challenge, so the passkey signs
  the exact key. The grant cannot mint further certificates; the grant id is
  not a bearer credential for issuance. The CLI keeps the key alive for the
  window in a dedicated per-grant ssh-agent process (lifetime = window,
  socket under a 0700 runtime dir), which later `warden ssh` calls reuse. If
  the key is lost, a new request is needed.

### 8.2 SSH relay mode

For targets that cannot trust a CA. The agent connects to warden's SSH relay
(a `russh` server); warden opens the onward session to the target itself, with
a credential that never leaves the broker. The request flow, approval and CLI
commands are those of §8.1: `warden request ssh <target>` and
`warden ssh <target>` hide the difference between the modes.

**Agent authentication.** No certificate is issued. The agent logs in with the
ephemeral Ed25519 key whose public half is part of the request and of the
fingerprint the owner approved, so the approval is bound to that exact key
(an equivalent binding to a relay certificate, without a second principal
namespace). The user name is the **target name**; the Unix account on the
target is the one that was approved. Only public-key login exists (no
password, no keyboard-interactive), with 3 attempts and 10 s to log in. A
login is accepted iff an active grant (not revoked, before its end) exists for
that target whose bound key equals the offered key; an unknown target, an
unapproved key and an inactive grant are refused identically. The lookup of
that grant is bounded to 1.5 s, like every grant query (below), not only by
the 10 s login: an attempt whose lookup does not answer in time is refused
the same way, and audited with the connection's other refused attempts
(`relay_login_refused`). A public key can
be bound to one live request or grant at a time, across all agents (a second
request with it is a 409), so another agent cannot use a key it merely
learned, and every relay session is attributed to the agent that was
approved.

**Onward connection.** warden reads the target item once when the session
starts (policy and credential in one read) and re-checks that the mode is
still `relay`, that the approved user is still allowed, and that the
destination is still the one the owner approved: the grant stores the digest
of the target's address, port and pinned host keys taken at approval, and a
session whose target no longer matches it is refused (audited as `target
policy changed`) before any onward connection is made. A rotated credential
alone does not change the destination. It connects with a 10 s
timeout per step and verifies the target's **pinned host key**: the item's
`host_keys` are required (no trust on first use) and key exchange negotiates
only the algorithms of the pinned keys, so an unpinned algorithm cannot be
offered. Ed25519, RSA and ECDSA host keys verify (appliances commonly have
RSA or ECDSA host keys); for RSA, `rsa-sha2-256/512` is negotiated and SHA-1
never is, though a holder of the pinned private key could still sign with
SHA-1. Any other key aborts with a fixed message. warden logs in as the
approved user with the item's credential: an Ed25519 private key or a password
(exactly one; see [1password-items.md](1password-items.md)). The credential is
read and validated whenever the target item is read (at request, at approval
and at session start) but used only at session start, where it is held
zeroized and dropped right after the onward login. It is never logged,
returned or audited. No forwarding of any kind is requested.

**Session policy.** One session channel per connection. Allowed: `pty-req`,
`env` (only `LANG`, `LC_*` and `TERM`, at most 16 variables, values of at most
256 bytes), `window-change`, `signal`, then `shell` or `exec`. Refused with a
message on the session's stderr: port forwarding (local and remote), agent
forwarding, X11 and subsystems (sftp included). Before the session starts, at
most 32 messages or 64 KiB of input are accepted; past that the connection is
hung up. A connection that starts no session within 30 s is hung up, as is
one whose session is over and that the agent does not leave (2 s). A refused
start reaches OpenSSH as a session that exited 255 with a message on stderr
(a failed request would make the client drop the message); the audit trail
holds the precise reason.

**Limits.** At most 4 concurrent sessions per grant and 16 overall
(`WARDEN_RELAY_MAX_SESSIONS`, 1 to 1024). Before login, at most 10 connections
overall and 5 per source address. Behind Tailscale Serve every peer arrives
from `127.0.0.1`, so the per-address limit acts as a global limit of 5
connections logging in at once.

**Flow control.** warden pulls data out of both SSH connections continuously
and holds it in byte-bounded queues (2 MiB towards the target, 8 MiB towards
the agent), so memory per session is bounded. The SSH library offers no
reader-driven back-pressure, so liveness is enforced by two watchdogs instead
of by blocking: a wedge watchdog ends a session whose two directions are both
held up with nothing delivered for 2 s (the two connections are waiting on
each other), and a stall watchdog ends a session in which one direction has
held data for 60 s without delivering any of it (its receiver does not read).
Both measure only while data is held, so an idle session is not affected. The
session ends with the audited reason `flow control: both directions held up`
(wedge), or `flow control: output to the agent not drained` or `flow control:
input to the target not drained` (stall).

The relay reads each agent's connection ahead of the SSH library, so that
an agent that disconnects is seen even while the library is held up by a
target that does not read its input. What is read ahead is bounded: the
bytes it counts are capped at 64 KiB before the agent has logged in and
4 MiB after (each chunk counts for at least 128 bytes, covering its
bookkeeping), so its heap use stays within a small constant factor of that,
plus a 16 KiB read buffer and at most one partly read 16 KiB chunk per
connection; memory is freed as the library reads it. 4 MiB is twice the
2 MiB window the agent is granted, so it holds the channel data an agent can
send once the library stops granting window, in normally sized packets, and
the agent's close is reached. An agent that sends many tiny packets while
the session is held up can fill the budget before its window; then, as
without the read-ahead, the 60 s stall watchdog ends the session (nothing
deadlocks). Once an agent has left and its input has been
held for 2 s with nothing delivered, the session ends with the reason
`client closed`, its slot freed; the input still held is dropped, as nobody
is left to see its effect. Messages outside the channel have no window: an
agent that keeps sending them (no client does) only fills the read-ahead,
and its session is ended by the stall watchdog, as before.

**Teardown.** A running session ends when its grant or agent is revoked, when
the grant's window ends, after 15 minutes with no bytes in either direction,
when a flow-control watchdog fires, or when the relay shuts down. A revocation
that goes through the broker reaches the session at once, and expiry is
enforced from memory on a check every second, so the session is told to end
within about 1 s; it then has at most 1 s to close before both connections
are cut hard. A revocation made by another process (the server CLI) is found
by the check of live grants every second, each query bounded to 1.5 s: with a
healthy database the session ends within about 5 to 6 s in the worst case.
When the database cannot be read, the relay fails closed (below), which ends
the session within about 10 to 11 s. Each started session records exactly one
`relay_session_ended` event. Its reason is `revoked` (or `expired`) whenever
the revocation (or the end of the window) reached the session before its
teardown completed, even if the session also ended otherwise at the same
time (the command exited, say); the bytes moved and the exit status are
recorded as they were.

**Fail closed.** The grant check is a database query bounded to 1.5 s. If no
query has succeeded for 10 s, every relayed session ends (reason `grant state
unavailable`) and no session starts until a query succeeds; a refused start is
audited as `relay_session_refused`. A target item that cannot be read at
session start refuses the session too. Session setup is bounded and never
holds up teardown: the grant lookup at session start is bounded to 1.5 s
(`grant lookup failed`) and the target item read to 10 s (`target lookup
failed`), and a stop, revocation or expiry during setup refuses the session
at once. A session is either refused (one `relay_session_refused`) or
started and ended (one `relay_session_started`, one
`relay_session_ended`).

**Audit.** `relay_session_started` (grant, target, user, and for `exec` the
command truncated to 200 characters) is written before any byte reaches the
target; if it cannot be written the session does not start.
`relay_session_ended` carries the reason, the bytes moved in each direction
and the exit status. `relay_session_refused` records a start refused after a
successful login (the grant or the policy changed), and `relay_login_refused`
a connection that tried to log in and was turned away. Neither holds key
material.

**Configuration.** `WARDEN_RELAY_PUBLIC_ADDR` (`host:port`, required for relay
targets; when unset, requests for relay targets are refused) is the address
agents connect to; `WARDEN_RELAY_LISTEN` (default `127.0.0.1:2222`) is the
local listener; `WARDEN_RELAY_HOST_KEY_PATH` (default
`/data/relay_host_ed25519`) is the relay's Ed25519 host key, generated on first
use. The file is created atomically with mode 0600 and never overwritten. An
existing file must be a regular file (not a symbolic link) owned by the broker
user, not accessible to group or others, and hold an unencrypted OpenSSH
Ed25519 key; anything else stops the server at startup. Its public half is
returned in every relay grant, and the CLI pins it (and only it) for the
relay. The relay address is public information.

### 8.3 HTTP proxy mode (secret injection)

The agent never receives the secret. It asks warden to make an HTTPS call
and warden returns the answer. `warden http <secret> <METHOD> <url> [-H …]
[-d …]` is the CLI form, and `POST /v1/grants/{id}/http` is the route behind
it. The body is `{method, url, headers, body_b64}`. The grant must belong to
the calling agent, be unrevoked and unexpired, and be of kind `api`.

**The scope of a request.** The item is the ceiling; a request can only
narrow it. `Access::Api` carries two optional fields, `methods` and
`path_prefix`. Without `methods`, the grant is **read-only**: the item's
methods intersected with `GET` and `HEAD`, and a request is refused if that is
empty (`secret <name> allows no read-only method; ask for methods
explicitly`). With `methods` (1 to 8 uppercase tokens, no duplicates, never
`CONNECT` or `TRACE`), every entry must be one the item allows, or the request
is refused (`secret <name> does not allow <METHOD>`); nothing is dropped
silently. A requested `path_prefix` follows the item field's syntax rules and
must lie under the item's prefix on a segment boundary, or the request is
refused (`secret <name>: path prefix must be under <item prefix>`); absent, it
is the item's. The broker resolves the scope when the request is created
(a refused request is never notified) and again at approval, and stores it in
the grant. On every call it checks the item's policy narrowed to the stored
grant, so all the rules below apply to that narrower scope; the agent never
supplies the scope at call time. The dedupe key of a request includes its
resolved scope, so a pending read-only request never absorbs a write request.
An agent may hold several grants for one secret, for example a long read-only
one and a short write one.

**The header comes from the policy.** There are no placeholders and the agent
places nothing: warden builds the header itself from the item's `header` name
and `format` (default `Authorization: Bearer {{secret}}`), and sets it after
the agent's headers. The secret is read from 1Password at call time, held in
wiped memory and never logged or audited.

**Checks before anything is sent.** The request must satisfy the policy as it
stands now (see "Changes during approval and use" below):

- *Origin:* scheme `https`, host and port equal to the item's website, exactly.
  Userinfo and fragments are refused. The URL must be printable ASCII with no
  spaces.
- *Path:* under `path_prefix` (the narrower of the item's and the grant's),
  matched on a segment boundary (`/api` covers `/api` and `/api/x`, not
  `/apiary`; a prefix ending in `/` covers what is below it). The path is
  inspected as sent, before URL normalisation, and refused if it has `.` or
  `..` segments, `//`, `;`, `\`, or the encodings `%2e`, `%2f`, `%5c`, `%3b`,
  `%25`, `%c0`, `%c1` and `%u` (any case). A path the URL parser would rewrite
  is refused too, so the path that was checked is the path that is sent. The
  query string is not restricted.
- *Method:* one of the item's `methods` (default `GET`) and, since 0.4, one
  of the methods of the grant. `CONNECT` and `TRACE` are always refused, even
  if listed.
- *Request headers:* the agent may not set hop-by-hop or framing headers
  (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Keep-Alive`,
  `TE`, `Trailer`, `Upgrade`, `Proxy-*`), the header that carries the secret,
  `Accept-Encoding`, `Range`, `If-Range` (they could make the answer carry the
  secret compressed or in fragments), the method and URL override headers
  (`X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`,
  `X-Original-URL`, `X-Rewrite-URL`) or the forwarding and host-override
  headers (`Forwarded`, `Via`, `X-Forwarded-Host`, `-For`, `-Proto`, `-Port`,
  `-Server`, `-Prefix`, `X-Real-IP`, `X-Host`, `X-Original-Host`). Names and
  values with CR, LF or NUL are refused.
- *Body:* at most 1 MiB once decoded (the route accepts 2 MiB of JSON).

A refusal is a 400 whose message names the rule, never the secret.

**The outbound call.** warden sends `Accept-Encoding: identity` and refuses a
response with any other `Content-Encoding` or a `Transfer-Encoding` other
than `chunked` or `identity` (502), because redaction cannot see inside compressed data.
Redirects are **not followed** (a redirect to another origin would carry the
header); the 3xx is returned to the agent. No outbound proxy is used and
nothing is retried. Limits: request body 1 MiB, response body 1 MiB
(`WARDEN_PROXY_MAX_RESPONSE_BYTES`, at most 64 MiB), 30 s for the whole call,
10 s to connect. At most 4 calls per agent and 16 overall may be in flight
at once (`WARDEN_PROXY_MAX_CALLS_PER_AGENT`, 1 to 64, and
`WARDEN_PROXY_MAX_CALLS`, 1 to 256, never below the per-agent limit; the
broker refuses to start otherwise). A call over either limit is refused with
a 429 (`too many concurrent calls`) before anything is sent upstream, and
audited as a `proxy_call` with no status. A call holds its slot until the upstream
call has finished, even if the agent hangs up, and always gives it back. Over the response limit the agent gets a 502 and nothing
partial. Upstream trouble is a 502 or 504 with a fixed message that never
quotes upstream text. A secret that cannot be written into a header, or an
HTTP client that cannot be built, is a 500.

**TLS.** Strict verification with hostname checking always on, and no leaf
pinning. By default the system roots are used. If the item has `ca_pem`,
**only** those CA certificates are trusted (they replace the default roots,
they are not added to them), for private-CA targets. A fresh client is built
for each call, so no trust decision is shared between secrets.

**Redaction.** In the response headers (values) and body, warden replaces
with `[REDACTED]` every occurrence of the secret and of the full injected
header value, in these forms: raw; base64 (standard and URL-safe, padded and
unpadded), including base64 inside a larger base64 blob at any of the three
byte alignments; and, per character, the percent-encoded form (either hex
case), `+` for a space, JSON `\/`, `\"`, `\\` and `\u00hh`, and HTML
`&amp;`, `&quot;`, `&lt;`, `&gt;`, `&apos;`, `&#NN;` and `&#xHH;`, mixed
freely within one occurrence. Overlapping matches merge into one marker. A
header whose name contains the secret is dropped (the name cannot be
redacted into a valid one) and counted; names are matched
ASCII-case-insensitively, because the HTTP stack lowercases them. Hop-by-hop response
headers and `Content-Length` are dropped. The number of redactions is
audited and returned. Boundary residual: for a secret embedded in a larger
base64 blob, the one base64 character on each side that mixes secret bits
with neighbouring bytes is not matched, so at most 4 bits of the secret per
side can survive; a base64 run shorter than 8 characters is not matched on
its own. Redaction is defence in depth against services that echo input. The
destination rules are the real control.

**Changes during approval and use.** The approval binds a digest of the
destination: origin, path prefix, header name, value format, pinned CA and the
set of methods. The digest is the item's, not the narrowed scope's, so it still
detects item edits: if the owner removes a method from the item after approval,
calls are refused as below. If the item changes between the request and the
approval, the approval is refused with a 409 and the owner reloads and reviews.
The approval page shows the value format with the secret as `…` (for example
`Bearer …`) and whether a CA is pinned. At call time warden re-reads the item
once and takes both the policy and the secret value from that single read, so
an item edited in between can never pair the old destination with a new
credential. If the digest no longer matches (including the format and the CA),
or the secret is gone or invalid, the call is a 409 (`policy changed; request
access again`) and the agent must request again. A grant that is revoked or
expires while a call is in flight yields a 409 (`grant revoked during the call`
or `grant expired during the call`) and the response is discarded. The window
and the secret value are not part of the digest.

**Audit.** `proxy_call_started` is written **before** the request is sent; if
it cannot be written, the call is refused and nothing is sent. `proxy_call` is
written after the call ends, whatever the outcome; if that write fails, the
agent gets a 500 and no response. It records: grant, method, origin and path (never the query
string, which may carry the agent's own data), status, response size,
redaction count and outcome. The secret never appears. The call runs on its
own task, so an agent that disconnects can neither stop it halfway nor keep
it out of the log.

- **Request/response HTTPS only in v1** (decision). WebSocket and streaming
  APIs are out of scope for v1; diagnostics that need them go through SSH.
- **Strict TLS verification, no leaf pinning** (decision): API targets are
  expected to present certificates whose names match, either publicly trusted
  or issued by a private CA pinned in the item. Hostname checking is never
  disabled.

## 9. Approval authentication

- The web UI is served by warden over HTTPS on its tailnet name (Tailscale
  Serve terminates TLS with the ts.net certificate). The WebAuthn RP ID is
  that name.
- **Passkey** (`webauthn-rs`): one-time enrollment via a code printed by
  `warden-server enroll` (CLI inside the container), valid 10 min, single use.
  Multiple passkeys may be enrolled (for example a phone and a synced
  passkey); listing and removal via the same server CLI.
- **Phone-only approval** (decision): the approval UI port is granted in the
  tailnet policy to the owner's phone only, never to the workstation the agent
  runs on. The agent may have browser tools there, and synced passkeys may
  exist there; a prompt-injected agent must not be able to put an approval
  prompt in front of the owner on the machine it controls. The tailnet policy
  should have tests asserting that the workstation is denied on that port.
- **Tailscale identity** as a second check: the approval endpoints accept only
  requests carrying the owner's `Tailscale-User-Login` (set by Serve).
- Approval tokens: ≥128-bit random, single use, tied to one request, expire
  with the request.

Request submission and proxy/relay use are restricted by the tailnet policy to
the workstation the agent runs on and authenticated by the Serve identity
header **and an agent key**:

- **Agent keys**: one per agent (e.g. `laptop`), created with
  `warden-server agent add <name>`, 256-bit random, shown once, stored
  server-side only as a hash. Sent by the CLI on every API call. The agent is
  allowed to know its key: it can only request access, never approve.
- The agent name is recorded on requests, grants and audit events, and shown
  on the approval page ("requested by `laptop`").
- Grants are bound to the requesting agent key; another agent's key cannot use
  them. A relay grant is bound to the agent that requested it, and the relay
  logs the grant id with every session.
- `warden-server agent list|revoke <name>`: revoke disables the key
  immediately, cancels its pending requests, ends its grants and kills its
  relay sessions.
- On macOS, the CLI reads the key from the Keychain (not a config file).

The approval page, the notification (Home Assistant and ntfy) and the
`request_created` audit summary say whether an API request can modify
anything. The page shows **Read-only**, or **Can modify:** followed by the
non-read-only methods (for example `Can modify: POST, PUT`), styled as a
warning, together with the methods and the path prefix of the narrowed scope.
The notification and the audit summary show `api github (read-only)` or `api
github (CAN MODIFY: POST, PUT)`.

## 10. Policy: 1Password as the source of truth

A dedicated vault (**`Warden`** by default) is the only vault the Connect
token can read (read-only). Item conventions (documented in
[1password-items.md](1password-items.md) and validated with clear errors):

- **SSH target item** (one per host): address (host:port), mode (`cert` |
  `relay`), allowed users, max window, pinned host key(s); for relay mode the
  onward credential (`private_key` or `password` field on the same item).
- **API secret item**: the secret field, website field = allowed origin
  (scheme+host+port, exact), allowed header and format (default
  `Authorization: Bearer {{secret}}`), allowed methods, optional path prefix,
  optional pinned CA, max window.
- **CA item**: the SSH CA private key. Loaded into memory, zeroized on drop.
  (CA rotation procedure: documented, not automated.)

warden reads policy from Connect on each request; an item without required
fields is unusable (fail closed). Only the owner, in 1Password, can change
where a secret may go.

Only the vault id is cached. When Connect answers 404 for a vault-scoped
request, warden resolves the vault by name again (concurrent callers share
one lookup) and, if the vault now has a different id, repeats the request
once with it. A 404 for a missing item in an unchanged vault, a vault that
no longer resolves, or a second 404 is reported as unavailable: no retry loop.

## 11. Audit log

- Append-only JSON lines, one event per request / decision / grant / use /
  revoke / error, each carrying the previous entry's hash (tamper-evident
  chain).
- Written to a dedicated volume, and suitable for shipping to a log pipeline
  the server cannot modify (never secret values; goals are owner-visible free
  text).
- The approval UI has a read-only history view.

## 12. State

SQLite for pending requests, grants, passkey credentials and enrollment codes.
It lives on the data volume, which should be backed up. Losing it loses only
in-flight requests and enrolled passkeys (re-enroll).

## 13. Deployment model

- warden runs as a container built from this repository (multi-arch,
  distroless base), as a non-root user with all capabilities dropped and a
  read-only root filesystem. The data volume (database and audit log) is the
  only writable path and is backed up.
- **Dedicated tailnet node** (decision): a Tailscale sidecar container shares
  its network namespace with warden only, so (a) the WebAuthn RP ID/origin is
  not shared with other services and (b) no other container can reach warden
  to forge `Tailscale-User-Login`. Both listeners stay on loopback inside that
  namespace. warden's outbound tailnet traffic also goes through this node,
  so tailnet grants are written for its tag.
- Exposure only via that node's Tailscale Serve, on **separate ports**: API
  (HTTPS), approval UI (HTTPS), SSH relay (TCP). The tailnet policy grants
  each port to its own set of devices (see §9): the approval UI to the owner's
  phone only, the API and relay to the workstation the agent runs on. Nothing
  is published on the LAN. The relay listener stays on loopback
  (`WARDEN_RELAY_LISTEN`) and is published as a Tailscale Serve **TCP**
  forward; `WARDEN_RELAY_PUBLIC_ADDR` is its tailnet address and port. Serve
  does not add identity to a raw TCP stream and every peer appears as
  `127.0.0.1`, so the relay authenticates the agent itself (by key) and the
  tailnet policy is the only network-level restriction on who reaches it.
- **Tailscale is a hard requirement in v1** (decision). Caller identity sits
  behind an internal trait so other identity sources (mTLS, OIDC) can be
  added later, but only the Tailscale implementation ships.
- 1Password Connect runs on an internal network reachable only from warden,
  with a read-only token scoped to the `Warden` vault.
- Egress is limited to what warden needs: Connect, the notifiers and
  Tailscale.
- Secrets for warden itself (Connect token, notifier URLs and tokens) are
  passed from a secret manager, never written into the image or a repository.

## 14. CLI and agent integration

- `warden request ssh <target> --user <u> --for 30m --goal "…"`,
  `warden request api <secret> [--methods GET,POST] [--path /prefix] --for
  30m --goal "…"`, `warden status`,
  `warden ssh …`, `warden http …`, `warden revoke <grant>`.
- `warden http <secret> <METHOD> <url> [-H 'Name: value']… [-d <body> |
  --data-file <path|->] [-i] [--fail]` calls an API through the `api` grant for
  the secret that covers the method and the path (the one that stays valid
  longest, if several do). The response body goes to stdout unchanged, and
  with `-i` the status line and headers go to stderr. The CLI records an `api` grant locally (secret name, origin, grant
  id, end time, methods and path prefix; never a secret; records from 0.3 read
  as `GET` and `/`) and exits 5 when no active grant covers the call, with a
  hint naming `warden request api --methods`. `--fail` exits 22 on an upstream
  status of 400 or more, as `curl --fail` does, and still writes the body. The
  CLI refuses non-https URLs and bodies over 1 MiB before sending.
- Relay targets need no different commands: `warden request ssh` and
  `warden ssh` work as for certificate targets. The grant tells the CLI to
  connect to the relay's address and log in as the target name, with the
  relay's host key pinned and the same per-grant `ssh-agent` holding the key
  (no certificate). The CLI records the route in the local `grant.json`;
  records without one are direct. A 0.2.x CLI does not know the relay grant
  kind: it cannot use such a grant and fails with an error instead of
  connecting anywhere (broker and CLI should both be 0.3.0).
- Requests block (with progress on stderr) until a terminal state; exit codes
  distinguish approved / denied / expired / cancelled / error; Ctrl-C cancels
  the pending request and exits 130.
- A short usage doc ([agent-usage.md](agent-usage.md)) tells the agent to
  request with a precise goal and the narrowest scope.
- CLI config: server URL and agent name only; no secrets in the config file.

## 15. Quality bar

- Rust stable, edition 2024, `#![forbid(unsafe_code)]` in all crates,
  `clippy::pedantic` + `-D warnings`, `rustfmt` check, `cargo-deny`
  (licenses, advisories via RustSec, bans, sources) in CI. Any `#[allow]`
  carries a justification comment.
- Tests: unit tests for policy matching (origin matching edge cases, header
  placement, redirect handling, redaction encodings), approval binding
  (tampered duration/request rejected, replayed token rejected), certificate
  contents; integration tests with a fake Connect, fake notifiers, and a real
  OpenSSH server for cert and relay modes.
- License: MIT OR Apache-2.0.
- Naming: repo `warden`; crates.io packages `warden-broker` (server),
  `warden-broker-cli` (CLI), internal crates prefixed `warden-broker-`
  (`warden` and `warden-cli` are taken). Binaries: `warden` (CLI),
  `warden-server` (server).

## 16. Left to the implementation

- Crate layout, HTTP framework (axum), async runtime (tokio), templating for
  the approval UI (server-rendered, minimal JS beyond WebAuthn).
- Exact 1Password field names and the CLI's ssh-agent strategy, within the
  constraints above.
- Polling vs. long-poll vs. SSE for the CLI wait.
