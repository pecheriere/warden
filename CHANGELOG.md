# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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

### Fixed

- Redaction drops a response header whose name carries the secret whatever
  its letter case (names arrive lowercased from the HTTP stack, so a secret
  with uppercase letters was not matched).

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
