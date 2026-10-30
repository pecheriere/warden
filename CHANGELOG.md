# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The Active grants page shows what each grant is doing right now. A relay
  grant lists its open sessions (start time, bytes to and from the target), an
  API grant its proxied calls in flight (method, path, start time), each under
  a live indicator ("2 sessions open", "1 call in flight"); a certificate
  grant says that its logins are not visible to warden. The page renders this
  server-side, so it works without script, and `warden.js` refreshes it every
  5 s from the new owner-only `GET /grants/live` while the page is visible,
  never with two requests at once, and stops when the broker no longer
  recognizes the viewer as the owner (401/403). A grant that is revoked or
  expires drops off the page, and one approved meanwhile appears (the page
  reloads once). Revoking an API grant stops new calls, but a call already in
  flight runs to completion (at most the proxy timeout) and is no longer
  listed. Times show in the viewer's local time. A path is shown as the audit
  log records it: without query string or fragment, and `invalid` when it does
  not parse or is longer than 512 bytes with its origin. Headers, bodies and
  secrets are never shown.

### Changed

- Docs: Secretive (Secure Enclave keys on macOS) is no longer suggested for
  signed requests. Such keys, like those in the 1Password SSH agent, refuse
  to sign while the Mac is locked, which is exactly when an agent needs
  warden. The docs now require a signer that works unattended with the
  screen locked (TPM, YubiKey PIV) and point an unattended Mac at a bearer
  key in the login Keychain.

## [0.6.0] - 2026-10-29

### Added

- Signed agent requests (protocol `warden-request-v1`, specified in
  `docs/agent-protocol.md`): an agent holds no reusable secret and proves
  itself with an SSH key, ideally one in hardware behind an `ssh-agent`
  (Secretive on the Secure Enclave, `ssh-tpm-agent`, YubiKey PIV). A captured
  request cannot be replayed, altered or sent to another broker. Bearer-key
  agents keep working unchanged.
  - CLI: `warden login --server <url> --agent <name> --ssh-key <path to .pub>
    [--ssh-agent-socket <path>] [--audience <id>]` pins the broker's audience
    from `/v1/info` (refusing one other than `--audience`, or than the one
    pinned before for that URL), checks that the agent holds the key, makes
    one signed call to confirm the enrollment and records the server, agent,
    public key, socket (default: `$SSH_AUTH_SOCK` at each run) and audience in
    the configuration. Nothing secret is stored and no Keychain is needed, so
    it also works on Linux. Every call, each long poll and retry included, is
    signed anew (fresh timestamp and nonce) over the exact method, target and
    body bytes sent; the private key is never read by the CLI. The server URL
    must have no path. A refused signed call says when the broker's audience
    has changed. `docs/agent-usage.md` covers the key setups and migrating a
    bearer-key agent.
  - Enrollment: `warden-server agent add <name> --public-key '<line>'`
    creates a key-signed agent without a bearer key; `warden-server agent
    set-key <name> '<line>'` switches an existing agent (its bearer key stops
    working at once); `agent list` shows the kind of authentication and the
    key's `SHA256:` fingerprint. Each change is audited as `agent_key_set`.
    Accepted keys are `ssh-ed25519` and `ecdsa-sha2-nistp256`; security keys,
    RSA, other curves, certificates and the published test keys of the
    protocol document are refused, by the broker and by the CLI, which share
    one policy (`warden_broker_proto::signing::SigningPublicKey`). A key
    belongs to one agent, and a revoked agent keeps its key: it can never be
    enrolled again, so make a new key after a revocation.
  - Migrating: on macOS, `warden login --ssh-key` over a bearer-key
    configuration prints the `security delete-generic-password` command that
    deletes the old key from the Keychain (it deletes nothing itself).
  - Verification: a key-signed agent sends `Warden-Agent`, `Warden-Timestamp`,
    `Warden-Nonce` and `Warden-Signature` (an SSHSIG, namespace
    `warden-request-v1`, hash `sha512` or `sha256`) on every call, including
    long polls and proxied calls. The broker refuses with 401 a missing,
    repeated or malformed header, an oversized signature, any other
    (reserved) `Warden-*` header, a `Warden-*` header together with
    `Authorization`, an unknown, revoked or bearer-key agent, a timestamp more
    than 60 seconds off, a signature by any other key or over anything else,
    and a nonce already used. An oversized body is a 413 and a body not
    received in time a 408, both before the signature is checked; the time
    scales with the route's body limit (the larger of 10 seconds and the limit
    at 128 KiB/s: 10 s, or 16 s for the 2 MiB of a proxied call).
    Nonces are recorded only once the signature verified, kept 10 minutes and
    swept with expired requests.
  - `GET /v1/info` returns the accepted signing protocols and the broker's
    audience, a random id created on first start in `WARDEN_AUDIENCE_PATH`
    (default `/data/audience`, next to the relay host key; never
    overwritten). It needs neither an agent key nor the owner's Tailscale
    login.
  - The worked shell client of the protocol document is run by the tests,
    as published, against a broker with Ed25519 and P-256 keys in an
    `ssh-agent`.

### Changed

- Security: key-signed agents do not need the owner's `Tailscale-User-Login`
  (tagged devices have none), a deliberate exemption. For them the signature
  authenticates the agent, and the tailnet policy (Serve and the gateway
  capability) alone decides which devices may reach the API, so keep that
  grant as narrow as the agents that need it. Bearer-key agents and the
  approval UI still require the owner's login. See the threat model, which
  also notes that agent names are not secret (a peer can tell an enrolled
  key-signed agent's name by the 413 or 408 its oversized or slow body gets).
- Security: the agent API is for tailnet peers only. Every route of its
  listener, `/healthz` and `/v1/info` included, refuses with 401 a request
  that came through Tailscale Funnel (`Tailscale-Funnel-Request` header),
  whatever credentials it carries. Never publish the API through Funnel.
- Upgrade note: schema migration `0005` rebuilds `agents` (and, below it,
  `requests` and `grants`, with all rows preserved) for the key columns and
  adds the nonce table; it runs on first start and is one-way. A 0.5.0 broker
  cannot open a database that 0.6.0 has migrated, so back up `/data`
  (database and audit log) before upgrading if you may need to go back.
- The approval UI follows the Sky Guard design language
  (`docs/design-language.md`): every page (approve, the finished and error
  states, Active grants, History, Enroll a passkey) shares one stylesheet with
  light and dark themes, the mascot, cards and 44 px touch targets, and works
  on phones, foldables and desktops. Active grants and History are cards on
  a phone; History is a table from 720 px.

## [0.5.0] - 2026-10-29

### Changed

- Breaking: the notification variables `WARDEN_HA_WEBHOOK_URL`,
  `WARDEN_NTFY_URL` and `WARDEN_NTFY_TOKEN` are replaced by `WARDEN_NOTIFY`
  and the `WARDEN_NOTIFY_*` settings (see Added). Startup fails, naming the
  replacement, if an old variable is set; update the broker's environment
  before upgrading.
- Schema migrations `0003` (widens the status check of `requests`, rebuilding
  it and `grants` with all rows preserved) and `0004` (the passkey counter
  column) run on first start.
- Upgrade note: the migrations are one-way. A 0.4.0 broker cannot open a
  database that 0.5.0 has migrated (it does not know migrations `0003` and
  `0004`), so back up `/data` (database and audit log) before upgrading if
  you may need to go back.

### Added

- Pluggable notification channels: `WARDEN_NOTIFY` lists the enabled channels
  (`homeassistant`, `ntfy`) in priority order and the first that accepts wins,
  the rest are fallbacks. Any single channel works alone. Settings are
  `WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL`, `WARDEN_NOTIFY_NTFY_URL` and
  `WARDEN_NOTIFY_NTFY_TOKEN`. Startup refuses an empty list, unknown,
  upper-case or repeated names, missing settings, and settings for a channel
  not listed in `WARDEN_NOTIFY`. Logs, errors and the audit log call each
  channel by its `WARDEN_NOTIFY` name, and the `notified` audit entry names
  the channel that delivered the notification (it was always `fallback`).
  `docs/notifications.md` documents the built-ins and a checklist for adding
  a channel.
- An agent can cancel its own pending request: `warden request cancel <id>`
  (`POST /v1/requests/{id}/cancel`, 404 for another agent's or an unknown
  request, 409 once it is no longer pending), audited as `request_cancelled`.
  The approval page of a cancelled request says "Cancelled by the agent." and
  cannot be approved, and the history lists it as `cancelled`. Ctrl-C while
  `warden request` waits cancels the pending request (waiting at most about
  10 s) and exits 130, revoking the grant if the owner approved first; a
  second Ctrl-C, or one while the approved grant is being installed, exits
  130 at once and says what may be left behind. A request cancelled from
  another terminal ends the waiting command with exit 6. `warden request` now prints the request id, which
  `warden request cancel` takes.
- Proxied API calls in flight are limited per agent
  (`WARDEN_PROXY_MAX_CALLS_PER_AGENT`, default 4, 1 to 64) and overall
  (`WARDEN_PROXY_MAX_CALLS`, default 16, 1 to 256, at least the per-agent
  limit; the broker refuses to start otherwise). A call over a limit gets a
  429 `too many concurrent calls`, is audited as a refused `proxy_call`, and
  never reaches the upstream. A slot is released when the call ends,
  whatever the outcome, including an agent that disconnects.
- CI check (`scripts/check-no-reqwest-decompression.sh`) that fails if
  reqwest's gzip, brotli, zstd or deflate feature is enabled, which secret
  redaction relies on. Tests cover the proxy's call-time failures (item
  removed, backend down, connect timeout).

### Fixed

- `warden http` exits 4 (revoked) with a message telling to request access
  again when the broker says the grant was revoked, and removes the stale
  local record, instead of exiting 1 with the broker's raw refusal.
- Redaction drops a response header whose name carries the secret whatever
  its letter case (names arrive lowercased from the HTTP stack, so a secret
  with uppercase letters was not matched).
- A relay session whose target stopped reading its input ends about 2 s
  after the agent disconnects (reason `client closed`), instead of when the
  60 s flow-control stall watchdog fires: the relay reads the agent's
  connection ahead of the SSH library (bounded: 64 KiB counted before
  login, 4 MiB after, twice the agent's window), so the agent leaving is
  seen even while that library is held up. Input still held for the target
  when the agent leaves is dropped. The session still gets exactly one
  `relay_session_ended` entry, and a session the relay ends (shutdown,
  revocation, expiry, grant state unavailable) keeps that reason although
  the agent's side closes as a result.
- The relay's login-time grant lookup is bounded to 1.5 s, like the grant
  checks of live sessions, instead of only by the 10 s login timeout: an
  attempt whose lookup does not answer in time is refused and audited as
  `relay_login_refused`, like any other refused login.
- A relay session revoked (or expired) while it was also ending normally is
  recorded with the reason `revoked` (or `expired`) rather than `exited`, as
  long as the revocation reached it before its teardown completed. It still
  gets exactly one `relay_session_ended` entry.
- The relay no longer hangs up 2 s after a session ends on an agent still
  taking the end of its output: such an agent (on a slow link, or with a busy
  reader) lost the rest of its output and got exit code 255 instead of the
  session's exit status. An agent now has the stall timeout (60 s) to take it
  and leave, and its connection keeps its place in the session limits until
  it is gone.
- A passkey's signature counter is never stored lower than it was: it lives in
  its own column (migration `0004`, backfilled from the stored credential) and
  is raised with one conditional update, so two concurrent approvals cannot
  overwrite each other's newer value. An assertion whose counter does not
  increase (unless the authenticator always reports 0) is refused as a
  possible cloned authenticator with a fixed message, no grant is issued, and
  it is audited as `passkey_counter_regressed`. Approving a request that was
  already decided is refused as already decided before the passkey is checked,
  so a second approval finishing after the first is not taken for a clone.
- A 1Password vault that was deleted and recreated under the same name is
  picked up without restarting the broker: on a Connect 404 the vault id is
  resolved again (once, shared by concurrent callers) and the request retried
  once. A vault that is gone, or a missing item in an unchanged vault, still
  fails closed with the same error.
- The CLI's cleanup on every run also removes leftover grant-record temporary
  files (`.<name>.<id>.tmp`, from a run that crashed mid-write) once they are
  over ten minutes old, in the grants and api-grants directories; fresher ones
  and live grants are never touched. Its failures are reported in a single
  warning. A per-grant `ssh-agent` still lingers until the next `warden` run
  after its grant ends (the agent's lifetime limit covers its keys, not the
  process), but that run stops it.

## [0.4.0] - 2026-10-29

### Added

- Narrowed API requests. `warden request api <secret> [--methods GET,POST]
  [--path /prefix] --goal … --for …` asks for a scope inside the 1Password
  item's policy. The item is the ceiling: requested methods and path prefix
  can only narrow it, `CONNECT` and `TRACE` are never allowed, and anything
  outside the item is refused when the request is made.
- The broker stores the approved scope in the grant and enforces it on every
  call, in addition to the item's policy.
- The approval page shows **Read-only**, or **Can modify:** with the
  non-read-only methods, as a warning. The notification (Home Assistant and
  ntfy) and the `request_created` audit summary read `api <secret>
  (read-only)` or `api <secret> (CAN MODIFY: POST, PUT)`.
- An agent may hold several grants for one secret. `warden http` uses the
  covering active grant that stays valid longest, and otherwise exits 5
  with the `warden request api … --methods` command to run.

### Changed

- Behaviour change: a request without `--methods` is now read-only (the
  item's methods that are `GET` or `HEAD`; refused if there are none).
  Previously it received every method of the item. This also applies to
  0.3 CLIs, which send no scope: against a 0.4 broker they receive read-only
  grants and must be upgraded to ask for write access.
- Wire format: `Access::Api` has optional `methods` and `path_prefix`, and
  the API grant carries the approved methods and prefix. Requests without them
  keep their fingerprint. The CLI's local API grant record stores them;
  records from 0.3 read as `GET` and `/`, so they are never widened.
- Upgrade the broker before the CLIs. A 0.4 CLI refuses, and does not record,
  a grant from an older broker that is wider than it asked for (methods
  beyond `--methods`, or beyond `GET` and `HEAD` without it, or a path outside
  `--path`); the message says to upgrade the broker.
- Requests still pending when the broker is upgraded are approved read-only
  (they carry no scope), and may not be deduplicated with a new identical
  request, which is then a second pending request.
- A requested path prefix may be at most 512 bytes.
- The active-grants page shows **Read-only** or **Can modify:** for API grants.

## [0.3.0] - 2026-10-27

### Added

- SSH relay mode for targets that cannot trust a CA. `warden request ssh` and
  `warden ssh` work as before; the broker runs an SSH relay that
  authenticates the agent by the ephemeral public key the owner approved
  (user name = target name; a key can be bound to one live request or grant
  at a time) and logs in to the target with the item's Ed25519 private key or
  password. The target's host keys must be pinned; key exchange negotiates only
  their algorithms (Ed25519, RSA and ECDSA host keys verify, SHA-1 is never
  negotiated). Port, agent and X11 forwarding and subsystems are refused, the
  environment is filtered, and there are limits of 4 sessions per grant,
  `WARDEN_RELAY_MAX_SESSIONS` overall (default 16) and for connections not yet
  logged in.
- Sessions end at revocation, expiry, 15 minutes without traffic, a 30 s wait
  for an unstarted session, or a flow-control watchdog (2 s wedge, 60 s
  stall), and fail closed when grant state cannot be read for 10 s.
- Audit events `relay_session_started` (before any byte reaches the target),
  `relay_session_ended`, `relay_session_refused` and `relay_login_refused`.
- Configuration `WARDEN_RELAY_LISTEN`, `WARDEN_RELAY_PUBLIC_ADDR`,
  `WARDEN_RELAY_HOST_KEY_PATH` and `WARDEN_RELAY_MAX_SESSIONS`.
- Target items accept `private_key` (unencrypted Ed25519) or `password` for
  `mode=relay`.

### Changed

- Wire format: `GrantAccess` has a new `relay` kind (target, user, relay host
  and port, relay host key); the CLI's local `grant.json` records a `route`
  (`direct` or `relay`, default `direct`). Agents and brokers should both be
  0.3.0; a 0.2.x CLI cannot use a relay grant.
- A public key can be bound to one live request or grant at a time across all
  agents; reusing one is a 409.
- The SSH destination digest covers the target's mode.

## [0.2.0] - 2026-10-27

### Added

- HTTP proxy mode. An agent runs `warden request api <secret> --for <window>
  --goal "…"`, the owner approves with a passkey, and `warden http <secret>
  <METHOD> <url>` makes the call through the broker. The broker builds the
  secret header from the policy, sends the call only to the secret's origin
  under its path prefix with an allowed method, and returns the response with
  the secret redacted. No redirects, compressed responses refused, 1 MiB
  request and response limits (`WARDEN_PROXY_MAX_RESPONSE_BYTES`), 30 s total
  and 10 s connect timeouts, optional pinned CA per secret.
- 1Password API secret items (tag `warden:api-secret`).
- Audit events `proxy_call_started` (before sending) and `proxy_call`.
- `warden http --fail` exits 22 on an upstream status of 400 or more.

### Changed

- Breaking: the `GrantView` wire format replaces the `ssh` field with a
  tagged `access` field (`{"kind": "ssh" | "api", …}`). Agents and brokers
  must both be 0.2.0.
- Approval and call time check a digest of the secret's destination (origin,
  path prefix, header, format, pinned CA, methods); any change since approval
  is a 409.

## [0.1.0] - 2026-10-25

### Added

- SSH certificate mode: short-lived certificates for an ephemeral Ed25519 key
  held in a per-grant `ssh-agent`, policy in 1Password via Connect.
- Passkey (WebAuthn) approval over the tailnet, phone-only approval port,
  Home Assistant and ntfy notifications, tamper-evident audit log, SQLite
  state, agent keys, and the `warden` CLI (`login`, `request ssh`, `ssh`,
  `status`, `revoke`).
