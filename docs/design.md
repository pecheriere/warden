# warden — design

This document records the intent and design of warden. It describes the full
v1 design; the current release (0.2.0) implements the SSH certificate mode
(§8.1) and the HTTP proxy mode (§8.3). SSH relay mode (§8.2) is designed here
but not implemented yet. Where the implementation deviates from this design, the
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
6. **Grant.** A grant record with `not_before/not_after` is created. The CLI,
   which long-polls (or polls) the request, receives the outcome:
   - cert/relay: the signed SSH certificate for the CLI's ephemeral public key;
   - proxy: a grant id usable for proxied calls until expiry.
7. **Use.** Every use (SSH cert issuance, relay session start/end, proxied
   call: method, URL, status, bytes) is audited against the grant.
8. **End.** Expiry or revoke (button on the page; also listed on an index of
   active grants). Revoke kills relay sessions and invalidates proxy grants
   immediately; issued certificates stay valid until their (short) expiry.

The CLI always gets a terminal state: `approved`, `denied`, `expired`, or
`error` with a message.

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

- The agent authenticates to warden's SSH relay (a `russh` server) with a
  certificate issued as in §8.1 but whose principal is
  `relay:<target>:<user>` and which is valid only for the relay.
- warden opens the onward session to the target (`russh` client) with the
  credential from the target's 1Password item (private key or password),
  verifies the target's **pinned host key** from that item, and relays pty,
  exec and channel data. No agent forwarding, no port forwarding in v1.
- warden tears down relay sessions at grant expiry or revoke.
- `warden ssh <target>` hides the difference between the modes.

### 8.3 HTTP proxy mode (secret injection)

The agent never receives the secret. It asks warden to make an HTTPS call
and warden returns the answer. `warden http <secret> <METHOD> <url> [-H …]
[-d …]` is the CLI form, and `POST /v1/grants/{id}/http` is the route behind
it. The body is `{method, url, headers, body_b64}`. The grant must belong to
the calling agent, be unrevoked and unexpired, and be of kind `api`.

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
- *Path:* under `path_prefix`, matched on a segment boundary (`/api` covers
  `/api` and `/api/x`, not `/apiary`; a prefix ending in `/` covers what is
  below it). The path is inspected as sent, before URL normalisation, and
  refused if it has `.` or `..` segments, `//`, `;`, `\`, or the encodings
  `%2e`, `%2f`, `%5c`, `%3b`, `%25`, `%c0`, `%c1` and `%u` (any case). A
  path the URL parser would rewrite is refused too, so the path that was
  checked is the path that is sent. The query string is not restricted.
- *Method:* one of the item's `methods` (default `GET`). `CONNECT` and
  `TRACE` are always refused, even if listed.
- *Request headers:* the agent may not set hop-by-hop or framing headers
  (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Keep-Alive`,
  `TE`, `Trailer`, `Upgrade`, `Proxy-*`), the header that carries the secret,
  `Accept-Encoding`, `Range`, `If-Range` (they could make the answer carry the
  secret compressed or in fragments), the method and URL override headers
  (`X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`,
  `X-Original-URL`, `X-Rewrite-URL`) or the forwarding headers (`Forwarded`,
  `X-Forwarded-Host`, `-For`, `-Proto`, `-Port`, `X-Real-IP`). Names and
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
10 s to connect. Over the response limit the agent gets a 502 and nothing
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
header whose name contains the secret is dropped, and hop-by-hop response
headers and `Content-Length` are dropped. The number of redactions is
audited and returned. Boundary residual: for a secret embedded in a larger
base64 blob, the one base64 character on each side that mixes secret bits
with neighbouring bytes is not matched, so at most 4 bits of the secret per
side can survive; a base64 run shorter than 8 characters is not matched on
its own. Redaction is defence in depth against services that echo input. The
destination rules are the real control.

**Changes during approval and use.** The approval binds a digest of the
destination: origin, path prefix, header name, value format, pinned CA and the
set of methods. If the item changes between the request and the approval, the
approval is refused with a 409 and the owner reloads and reviews. At call
time warden re-reads the policy; if the digest no longer matches (including
the format and the CA), or the secret is gone or invalid, the call is a 409
(`policy changed; request access again`) and the agent must request again. A
grant revoked while a call is in flight yields a 409 and the response is
discarded. The window and the secret value are not part of the digest.

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
  them. Relay certificates carry the agent name in the key id.
- `warden-server agent list|revoke <name>`: revoke disables the key
  immediately, cancels its pending requests, ends its grants and kills its
  relay sessions.
- On macOS, the CLI reads the key from the Keychain (not a config file).

## 10. Policy: 1Password as the source of truth

A dedicated vault (**`Warden`** by default) is the only vault the Connect
token can read (read-only). Item conventions (documented in
[1password-items.md](1password-items.md) and validated with clear errors):

- **SSH target item** (one per host): address (host:port), mode (`cert` |
  `relay`), allowed users, max window, pinned host key(s); for relay mode the
  onward credential (SSH key item or password field).
- **API secret item**: the secret field, website field = allowed origin
  (scheme+host+port, exact), allowed header and format (default
  `Authorization: Bearer {{secret}}`), allowed methods, optional path prefix,
  optional pinned CA, max window.
- **CA item**: the SSH CA private key. Loaded into memory, zeroized on drop.
  (CA rotation procedure: documented, not automated.)

warden reads policy from Connect on each request; an item without required
fields is unusable (fail closed). Only the owner, in 1Password, can change
where a secret may go.

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
  is published on the LAN.
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
  `warden request api <secret> --for 30m --goal "…"`, `warden status`,
  `warden ssh …`, `warden http …`, `warden revoke <grant>`.
- `warden http <secret> <METHOD> <url> [-H 'Name: value']… [-d <body> |
  --data-file <path|->] [-i] [--fail]` calls an API through the newest active
  `api` grant for the secret. The response body goes to stdout unchanged, and
  with `-i` the status line and headers go to stderr. The CLI records an `api`
  grant locally (secret name, origin, grant id and end time; never a secret)
  and exits 5 when there is no active one. `--fail` exits 22 on an upstream
  status of 400 or more, as `curl --fail` does, and still writes the body.
  The CLI refuses non-https URLs and bodies over 1 MiB before sending.
- Requests block (with progress on stderr) until a terminal state; exit codes
  distinguish approved / denied / expired / error.
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
