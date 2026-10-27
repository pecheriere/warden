# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.5.0] - unreleased

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
  `relay_session_ended` entry.
- The relay's login-time grant lookup is bounded to 1.5 s, like the grant
  checks of live sessions, instead of only by the 10 s login timeout: an
  attempt whose lookup does not answer in time is refused and audited as
  `relay_login_refused`, like any other refused login.
- A relay session revoked (or expired) while it was also ending normally is
  recorded with the reason `revoked` (or `expired`) rather than `exited`, as
  long as the revocation reached it before its teardown completed. It still
  gets exactly one `relay_session_ended` entry.
- A passkey's signature counter is never stored lower than it was: it lives in
  its own column (migration `0004`, backfilled from the stored credential) and
  is raised with one conditional update, so two concurrent approvals cannot
  overwrite each other's newer value. An assertion whose counter does not
  increase (unless the authenticator always reports 0) is refused as a
  possible cloned authenticator with a fixed message, no grant is issued, and
  it is audited as `passkey_counter_regressed`.
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

## [0.4.0] - unreleased

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

## [0.3.0] - unreleased

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

## [0.2.0] - unreleased

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
