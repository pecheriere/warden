# Configuration reference

This page lists every setting and command of `warden-server` (the broker)
and `warden` (the agent's CLI). For how to put them together, see
[Deployment](deployment.md) and [Agent usage](agent-usage.md).

## Server environment variables

`warden-server serve` reads its configuration from the environment and
refuses to start, naming the variable, when one is missing or invalid.
Values are never echoed in errors.

### Required

| Variable | Meaning |
|----------|---------|
| `WARDEN_DB_PATH` | The SQLite database, for example `/data/warden.db`. |
| `WARDEN_AUDIT_PATH` | The audit log, for example `/data/audit.jsonl`. |
| `WARDEN_PUBLIC_URL` | The approval UI's URL: `https`, a domain name (not an IP address), no path, query or credentials. Its host is the WebAuthn relying party: changing it invalidates every enrolled passkey. Notifications link to it. |
| `WARDEN_OWNER_LOGIN` | The owner's Tailscale login (as Tailscale Serve reports it in `Tailscale-User-Login`). Only this login may use the approval UI or a bearer agent key. |
| `WARDEN_OP_CONNECT_URL` | The 1Password Connect API, for example `http://172.31.251.11:8080`. |
| `WARDEN_OP_CONNECT_TOKEN` | The Connect token. Read-only, for the warden vault only. Secret. |
| `WARDEN_NOTIFY` | The notification channels in priority order, comma-separated, lowercase: `homeassistant`, `ntfy`. See [Notifications](notifications.md). |

### Optional

| Variable | Default | Meaning |
|----------|---------|---------|
| `WARDEN_API_LISTEN` | `127.0.0.1:8080` | The agent API listener (`ip:port`). |
| `WARDEN_APPROVAL_LISTEN` | `127.0.0.1:8081` | The approval UI listener (`ip:port`). |
| `WARDEN_AUDIENCE_PATH` | `/data/audience` | The file holding the broker's audience id, created on first start and never changed. Keep it on the data volume. |
| `WARDEN_OP_VAULT` | `Warden` | The 1Password vault to read. |
| `WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL` | | Required when `homeassistant` is listed. Secret. |
| `WARDEN_NOTIFY_NTFY_URL` | | Required when `ntfy` is listed: the topic URL. |
| `WARDEN_NOTIFY_NTFY_TOKEN` | | An ntfy access token, sent as `Authorization: Bearer`. Secret. |
| `WARDEN_PROXY_MAX_RESPONSE_BYTES` | `1048576` (1 MiB) | The largest response a proxied API call may return, 1 to `67108864` (64 MiB). |
| `WARDEN_PROXY_MAX_CALLS_PER_AGENT` | `4` | Proxied calls in flight per agent, 1 to 64. |
| `WARDEN_PROXY_MAX_CALLS` | `16` | Proxied calls in flight overall, 1 to 256, at least the per-agent limit. |
| `WARDEN_RELAY_PUBLIC_ADDR` | unset | Where agents reach the SSH relay, `host:port`. Unset turns the relay off: requests for relay targets are refused. |
| `WARDEN_RELAY_LISTEN` | `127.0.0.1:2222` | The SSH relay listener. Used only when `WARDEN_RELAY_PUBLIC_ADDR` is set. |
| `WARDEN_RELAY_HOST_KEY_PATH` | `/data/relay_host_ed25519` | The relay's Ed25519 host key, created on first use (mode 0600) and never overwritten. An existing file must be a regular file owned by the broker's user, with no group or other permissions (0600). Keep it on the data volume. |
| `WARDEN_RELAY_MAX_SESSIONS` | `16` | Relayed sessions open at once, 1 to 1024. Each grant may hold 4. |
| `RUST_LOG` | `info` | Log filter, in [`tracing` `EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) syntax. |

Pass the secrets from a secret manager or an environment file readable only
by root, never on a command line or in a repository.

The variables of the fixed notifier wiring before 0.5.0
(`WARDEN_HA_WEBHOOK_URL`, `WARDEN_NTFY_URL`, `WARDEN_NTFY_TOKEN`) are
refused at startup, with the name of the replacement.

## Server commands

Run them in the container, for example
`docker compose exec warden /warden-server <command>`. They use the same
environment as the server. The image's default command is `serve`.

| Command | What it does | Needs |
|---------|--------------|-------|
| `serve` | Runs the agent API, the approval UI and, when configured, the SSH relay. | All of the above. |
| `enroll` | Prints a one-time code (single use, valid 10 minutes) and the URL of the enrollment page, where the owner creates a passkey. | `WARDEN_DB_PATH`, `WARDEN_AUDIT_PATH`, `WARDEN_PUBLIC_URL` |
| `passkey list` | Lists enrolled passkeys: id, label, creation time. | `WARDEN_DB_PATH` |
| `passkey remove <id>` | Removes a passkey. | `WARDEN_DB_PATH`, `WARDEN_AUDIT_PATH` |
| `agent add <name>` | Creates a bearer-key agent and prints its key once. | `WARDEN_DB_PATH`, `WARDEN_AUDIT_PATH` |
| `agent add <name> --public-key '<line>'` | Creates a key-signed agent, with the public key line of its signing key (`ssh-ed25519` or `ecdsa-sha2-nistp256`). No bearer key is made. | same |
| `agent set-key <name> '<line>'` | Switches an agent to key-signed requests. Its bearer key stops working at once. | same |
| `agent list` | Lists agents: name, creation time, `active` or `revoked@<time>`, `bearer` or `ssh-key`, and the key's `SHA256:` fingerprint (`-` for a bearer key). | `WARDEN_DB_PATH` |
| `agent revoke <name>` | Disables the agent, ends its pending requests and grants, and ends its relay sessions. A running server notices within about 30 seconds for waiting clients and within seconds for relay sessions. | `WARDEN_DB_PATH`, `WARDEN_AUDIT_PATH` |
| `audit verify` | Checks the audit log's hash chain and prints the number of entries. | `WARDEN_AUDIT_PATH` |
| `healthcheck` | Requests `/healthz` on `WARDEN_API_LISTEN` (loopback when it is `0.0.0.0`); exits 0 when healthy, 1 otherwise. For container health checks. | `WARDEN_API_LISTEN` (optional) |

Agent names match `^[a-z0-9][a-z0-9-]{0,31}$`. A key belongs to one agent,
and a revoked agent keeps its key: make a new key after a revocation.

## Server data

| Path (default) | Holds |
|----------------|-------|
| `WARDEN_DB_PATH` (with `-wal` and `-shm` files) | Requests, grants, agents, passkeys, enrollment codes, nonces. SQLite in WAL mode. |
| `WARDEN_AUDIT_PATH` | The audit log: one JSON object per line, each with the hash of the previous one. Every entry is also logged on stdout. |
| `/data/audience` | The audience id. |
| `/data/relay_host_ed25519` | The relay's host key. |

See [Backups and upgrades](deployment.md#9-backups-and-upgrades).

## Server endpoints

| Listener | Path | Who |
|----------|------|-----|
| Agent API | `GET /healthz` | Anyone who can reach it (static `ok`). |
| Agent API | `GET /v1/info` | Anyone who can reach it (protocols and audience). |
| Agent API | `/v1/requests…`, `/v1/grants…` | Agents. See [the agent protocol](agent-protocol.md#6-endpoints). |
| Approval UI | `/approve/<token>`, `/grants`, `/history`, `/enroll` and their actions | The owner (`WARDEN_OWNER_LOGIN`). |

Every request to the agent API that came through Tailscale Funnel is
refused with `401`.

## CLI commands

`warden` is the agent's client. Install it with Rust 1.94 or later; it needs
the OpenSSH client tools (`ssh`, `ssh-agent`, `ssh-add`):

```sh
cargo install --locked --git https://github.com/pecheriere/warden --tag v0.7.0 warden-broker-cli
```

| Command | What it does |
|---------|--------------|
| `warden login --server <url> --agent <name> --ssh-key <path.pub> [--ssh-agent-socket <path>] [--audience <id>]` | Sets up a key-signed agent: pins the broker's audience, checks that the `ssh-agent` holds the key and that the broker accepts a signed call. Stores nothing secret. |
| `warden login --server <url> --agent <name>` | Sets up a bearer-key agent: reads the key from stdin and stores it in the macOS Keychain. macOS only. |
| `warden request ssh <target> --user <user> --for <window> --goal "<goal>"` | Asks for SSH access and waits for the decision. |
| `warden request api <secret> [--methods <M,…>] [--path <prefix>] --for <window> --goal "<goal>"` | Asks for brokered API calls and waits. Read-only (`GET`, `HEAD`) without `--methods`. |
| `warden request cancel <id>` | Withdraws one of this agent's pending requests. |
| `warden ssh <target> [-- <command>…]` | Runs `ssh` through the active grant for the target that stays valid longest. |
| `warden http <secret> <METHOD> <url> [-H 'Name: value']… [-d <body> \| --data-file <path\|->] [-i] [--fail]` | Makes one HTTPS call through an `api` grant. |
| `warden status` | Lists the grants on this machine and the broker's view of this agent's grants. |
| `warden revoke <grant>` | Revokes a grant on the broker and stops its local `ssh-agent`. |

A window is `15m`, `30m`, `1h` or `4h`. Exit codes are in
[Agent usage](agent-usage.md#exit-codes).

### CLI environment and files

| Name | Meaning |
|------|---------|
| `~/.config/warden/config.toml` (or `$XDG_CONFIG_HOME/warden/config.toml`) | The server URL, the agent name and, for a key-signed agent, the public key, the `ssh-agent` socket and the pinned audience. Mode 0600; nothing secret. |
| `WARDEN_AGENT_KEY` | A bearer key. Takes precedence over the Keychain. The only way to give a bearer key on Linux. |
| `SSH_AUTH_SOCK` | The `ssh-agent` holding the signing key, unless `--ssh-agent-socket` was given at login. |
| `$XDG_STATE_HOME/warden` (Linux default `~/.local/state/warden`, macOS `~/Library/Application Support/warden`) | Grant records and the `known_hosts` files of grants. Mode 0700. |
| `$TMPDIR/warden-<uid>/` | The sockets of the per-grant `ssh-agent`s (a short path, as Unix socket paths are limited). Mode 0700. |

On Linux, `warden login` cannot store a bearer key (there is no Keychain).
Write the configuration file yourself, mode 0600:

```toml
server = "https://warden-api.example.ts.net/"
agent = "build-agent"
```

and set `WARDEN_AGENT_KEY` from a secret manager when you run `warden`.
A signing key is the better choice on Linux: see
[Agent usage](agent-usage.md#one-time-setup).
