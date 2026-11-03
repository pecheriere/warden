# External interfaces

Everything warden accepts from, or sends to, the outside, and where each one is
specified. Interfaces with a reference of their own are linked, not repeated.

## What warden accepts

| Interface | Who uses it | Reference |
|---|---|---|
| Agent API (HTTPS, through Serve) | Agents | [Agent protocol](agent-protocol.md), a complete specification with test vectors |
| SSH relay (SSH, through a Serve TCP forward) | Agents | [Below](#ssh-relay), and [using a relay grant](agent-protocol.md#relay-grants-kindrelay) |
| Approval UI (HTTPS, through Serve) | The owner's browser | [Below](#approval-ui) |
| `warden-server` commands | The operator | [Server commands](configuration.md#server-commands) |
| `warden` commands | Agents and people on the agent's machine | [CLI commands](configuration.md#cli-commands), [exit codes](agent-usage.md#exit-codes) |
| Server settings | The operator | [Environment variables](configuration.md#server-environment-variables), [secrets in files](configuration.md#secrets-in-files) |
| CLI settings and files | The agent's machine | [CLI environment and files](configuration.md#cli-environment-and-files) |
| 1Password items | The owner, in the vault | [1Password items](1password-items.md) |
| Local policy and secret files, with `WARDEN_SECRET_BACKEND=local` | Whoever can write them on the host | [Local files](local-backend.md) |

## What warden calls

| Interface | Why | What it sends | Reference |
|---|---|---|---|
| 1Password Connect API | Policy, secrets and the CA key | `GET` requests, with the token as a bearer | [Deployment](deployment.md#3-1password) |
| Home Assistant webhook, ntfy | Notifications | The agent, the access, a stated session label, a shortened goal, a link | [Notifications](notifications.md) |
| API origins | Proxied calls | The agent's call, with the secret in the policy's header | [HTTP proxy mode](design.md#83-http-proxy-mode-secret-injection) |
| Relay targets | Relayed sessions | An SSH login with the item's credential | [SSH relay mode](design.md#82-ssh-relay-mode) |
| Certificate targets | Nothing: the agent's `ssh` connects, and warden never does | A certificate, presented by the agent | [SSH targets](ssh-targets.md) |
| OpenSSH tools on the agent's machine | The CLI runs `ssh` and `ssh-agent`, and talks to `ssh-agent` sockets | Keys, and data to sign | [One-time setup](agent-usage.md#one-time-setup) |

## What warden writes

| Output | Format | Reference |
|---|---|---|
| Audit log | One JSON object per line, in a hash chain: `{"seq","ts","prev","event","hash"}`. `event` has a `type`. The types are in [`audit.rs`](../crates/broker/src/audit.rs). | [Audit log](design.md#11-audit-log), `warden-server audit verify` |
| Standard output | Logs (`RUST_LOG`), and each audit entry again under the target `audit` | [Server data](configuration.md#server-data) |
| SQLite database | Internal; it may change between releases, with one-way migrations | [Backups and upgrades](deployment.md#9-backups-and-upgrades) |

## Approval UI

On the approval listener (`WARDEN_APPROVAL_LISTEN`). The caller must be the owner
(`Tailscale-User-Login` equal to `WARDEN_OWNER_LOGIN`) on every route, or the
answer is `403 {"error":"forbidden"}`. Each `POST` must also carry the exact
`Origin` of `WARDEN_PUBLIC_URL` (otherwise 403) and
`Content-Type: application/json` (otherwise 415), with a body of at most 64 KiB.
A request that came through Tailscale Funnel gets `401` before any of this.
Every response has a strict Content-Security-Policy, `Referrer-Policy: no-referrer`,
`Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

These routes serve warden's own pages. They are listed for review, and are not a
stable API for other clients. The code is in
[`approval/mod.rs`](../crates/broker/src/approval/mod.rs).

| Route | Body | What it does |
|---|---|---|
| `GET /approve/{token}` | | The approval page for a pending request. |
| `POST /approve/{token}/begin` | `{"window","target"}`: the chosen window, and the destination digest the page showed | Starts a passkey ceremony bound to the request and window. 409 if the destination changed. |
| `POST /approve/{token}/finish` | `{"ceremony","credential"}` | Verifies the assertion, and makes the grant. |
| `POST /approve/{token}/deny` | `{}` | Denies the request. Takes no passkey. |
| `GET /pending` | | The pending requests, each with Approve… and Deny buttons. |
| `GET /pending/live` | | The pending requests' ids and seconds left, as JSON, for the page to refresh. Changes nothing. |
| `POST /pending/{id}/open` | `{}` | Gives a pending request a new approval link, returned as `{"link"}`; the old link stops working. Approves nothing. 404 if the request is no longer pending. |
| `POST /pending/{id}/deny` | `{}` | Denies a pending request, as `POST /approve/{token}/deny` does. Takes no passkey. 404 if the request is no longer pending. |
| `GET /grants` | | Active grants, with a Revoke button and live activity. |
| `GET /grants/live` | | The live activity, as JSON, for the page to refresh. |
| `POST /grants/{id}/revoke` | `{}` | Revokes a grant. Takes no passkey. |
| `GET /history` | | The latest 100 requests. |
| `GET /enroll` | | The page for enrolling a passkey. |
| `POST /enroll/begin` | `{"code","label"}` | Spends an enrollment code and starts registration. |
| `POST /enroll/finish` | `{"ceremony","credential"}` | Stores the passkey. |
| `GET /static/warden.js`, `GET /static/warden.css` | | The only script and stylesheet. |
| Any other path | | A 404 page. |

A ceremony must be finished within 120 seconds and works once. A request keeps its 4
newest, and opening it from the pending page drops them all. Enrollment has room for
8 at a time, and approvals as a whole for 1024 (429 beyond those).

## SSH relay

On the relay listener (`WARDEN_RELAY_LISTEN`), when `WARDEN_RELAY_PUBLIC_ADDR` is
set. The code is in [`relay/`](../crates/broker/src/relay/mod.rs), and the
[design](design.md#82-ssh-relay-mode) has the reasoning.

| Part | What it accepts |
|---|---|
| Identification | Banner `SSH-2.0-warden`. Host key: Ed25519, announced in each relay grant and pinned by the client. |
| Login | User name: the **target name**. Public key only: the key bound into an approved request whose grant is active. At most 3 attempts and 10 s. Everything else is refused in the same way. |
| Channels | One session channel per connection. |
| Before the session starts | `pty-req`, `env` (`LANG`, `LC_*`, `TERM`; at most 16 variables, values up to 256 bytes), `window-change`, `signal`. At most 32 messages or 64 KiB, and 30 s from login to start. |
| Session | `shell`, or `exec`. |
| Refused, with a message on stderr | Port forwarding (both ways), agent forwarding, X11, subsystems such as `sftp`, a second session. |
| Failure | Exit status 255, with a message starting `warden relay:`. The audit log holds the reason. |
| Limits | 4 sessions per grant and 16 overall (`WARDEN_RELAY_MAX_SESSIONS`); 10 connections before login, 5 per address; 15 minutes without bytes; [flow control](design.md#82-ssh-relay-mode) on data no one reads. |
| End | The grant's end or revocation, the limits above, or a broker that cannot read grant state. |

## Stability

warden uses semantic versioning for the whole workspace. These are the public
interfaces: the agent protocol (which has its own name and version,
`warden-request-v1`), both command lines with their exit codes, the settings, the
1Password item conventions and the audit log's format. A breaking change to them
is recorded in the [changelog](../CHANGELOG.md). Before 1.0, it may come with a
minor version.
