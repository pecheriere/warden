# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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
