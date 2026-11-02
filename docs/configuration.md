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
| `WARDEN_OP_CONNECT_URL` | The 1Password Connect API, for example `http://172.31.251.11:8080`. Plain `http` exposes the token and all it reads to that network, so it is accepted [only to a local or private host](#plain-http): use it only on the [private network](deployment.md#3-1password) that Connect shares with warden. Not with `WARDEN_SECRET_BACKEND=local`. |
| `WARDEN_OP_CONNECT_TOKEN` | The Connect token. Read-only, for the warden vault only. Secret; can be [read from a file](#secrets-in-files). Not with `WARDEN_SECRET_BACKEND=local`. |
| `WARDEN_NOTIFY` | The notification channels in priority order, comma-separated, lowercase: `homeassistant`, `ntfy`. See [Notifications](notifications.md). |

### Optional

| Variable | Default | Meaning |
|----------|---------|---------|
| `WARDEN_API_LISTEN` | `127.0.0.1:8080` | The agent API listener (`ip:port`). |
| `WARDEN_APPROVAL_LISTEN` | `127.0.0.1:8081` | The approval UI listener (`ip:port`). |
| `WARDEN_AUDIENCE_PATH` | `/data/audience` | The file holding the broker's audience id, created on first start and never changed. Keep it on the data volume. |
| `WARDEN_OP_VAULT` | `Warden` | The 1Password vault to read. Refused with `WARDEN_SECRET_BACKEND=local`. |
| `WARDEN_SECRET_BACKEND` | `1password` | Where targets, API secrets and the SSH CA key come from: `1password`, recommended, or `local`, [files on this host](local-backend.md), where a compromised host gets every secret. |
| `WARDEN_LOCAL_POLICY_FILE` | | Required with `WARDEN_SECRET_BACKEND=local`, and refused without it: the [policy file](local-backend.md#the-policy-file), an absolute path. |
| `WARDEN_LOCAL_SECRETS_DIR` | | Required with `WARDEN_SECRET_BACKEND=local`, and refused without it: the [only directory secrets are read from](local-backend.md#the-secret-files), an absolute path. |
| `WARDEN_ALLOW_PLAIN_HTTP` | | The URL settings that may use [plain `http`](#plain-http) to a host that is not clearly local or private, comma-separated. |
| `WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL` | | Required when `homeassistant` is listed. Secret. |
| `WARDEN_NOTIFY_NTFY_URL` | | Required when `ntfy` is listed: the topic URL. |
| `WARDEN_NOTIFY_NTFY_TOKEN` | | An ntfy access token, sent as `Authorization: Bearer`. Secret. |
| `WARDEN_PROXY_MAX_RESPONSE_BYTES` | `1048576` (1 MiB) | The largest response a proxied API call may return, 1 to `67108864` (64 MiB). |
| `WARDEN_PROXY_MAX_CALLS_PER_AGENT` | `4` | Proxied calls in flight per agent, 1 to 64. |
| `WARDEN_PROXY_MAX_CALLS` | `16` | Proxied calls in flight overall, 1 to 256, at least the per-agent limit. |
| `WARDEN_REQUEST_MAX_PENDING_PER_AGENT` | `5` | Requests of one agent that may wait for the owner at once, 1 to 256, at most the limit on new requests. See [Request limits](#request-limits). |
| `WARDEN_REQUEST_MAX_NEW_PER_AGENT` | `10` | New requests one agent may make per window, 1 to 1024. See [Request limits](#request-limits). |
| `WARDEN_REQUEST_LIMIT_WINDOW_SECS` | `600` (10 minutes) | Length of that sliding window, 60 to 3600 seconds. |
| `WARDEN_RELAY_PUBLIC_ADDR` | unset | Where agents reach the SSH relay, `host:port`. Unset turns the relay off: requests for relay targets are refused. |
| `WARDEN_RELAY_LISTEN` | `127.0.0.1:2222` | The SSH relay listener. Used only when `WARDEN_RELAY_PUBLIC_ADDR` is set. |
| `WARDEN_RELAY_HOST_KEY_PATH` | `/data/relay_host_ed25519` | The relay's Ed25519 host key, created on first use (mode 0600) and never overwritten. An existing file must be a regular file owned by the broker's user, with no group or other permissions (0600). Keep it on the data volume. |
| `WARDEN_RELAY_MAX_SESSIONS` | `16` | Relayed sessions open at once, 1 to 1024. Each grant may hold 4. |
| `RUST_LOG` | `info` | Log filter, in [`tracing` `EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) syntax. Above `info`, dependencies log too, and warden does not control what they say: keep the default in production. |

Pass the secrets from a secret manager, an environment file readable only by
root, or a file as below, never on a command line or in a repository.

### Request limits

Each agent has its own allowance, so that it cannot flood the owner with
notifications or grow the database. With the defaults, one agent can have 5
requests waiting and make 10 new ones every 10 minutes. Every request stored
counts towards the 10, whatever became of it, including cancelled ones. A
duplicate of a request already pending is answered with that request and does
not count, and neither does a request that the policy refuses.

An agent over a limit gets `429` with a `Retry-After` header and a message
saying how long to wait. A request held back by the limit on new requests waits
for the window at most, so 10 minutes by default and an hour at the highest
setting. One held back by the pending limit waits 10 minutes at most, when a
pending request expires, and less if the owner decides one or the agent cancels
one. An agent's refusals do not use up another agent's allowance or stop the
owner from deciding. They are not free, though: each refused request is first
checked against the policy, which reads 1Password Connect, shared with everyone
else.

The first refusal is recorded in the audit log as `request_limited`. Further
ones are counted and written at most once a minute. The owner gets one
notification per agent per hour at most, linking to the request history and
recorded as `limit_notified`. It names the agent and nothing the agent wrote.

### Secrets in files

These variables can be read from a file instead, by setting the name with
`_FILE` added to the path of that file. Then the process environment holds only
the path. [The systemd service](deployment-systemd.md) uses this.

| Variable | Read from a file with |
|----------|-----------------------|
| `WARDEN_OP_CONNECT_TOKEN` | `WARDEN_OP_CONNECT_TOKEN_FILE` |
| `WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL` | `WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL_FILE` |
| `WARDEN_NOTIFY_NTFY_URL` | `WARDEN_NOTIFY_NTFY_URL_FILE` |
| `WARDEN_NOTIFY_NTFY_TOKEN` | `WARDEN_NOTIFY_NTFY_TOKEN_FILE` |

`warden-server serve` reads each file once, at startup, and `warden-server
doctor` when it runs; neither prints its content. `serve` refuses to start, and
doctor fails its `config` check, naming the `_FILE` variable, when:

- both forms of one secret are set;
- the file is missing or unreadable, or is not a regular file;
- other users have any access to it (mode bits `0o007`; group access is allowed);
- it is empty, not valid UTF-8, larger than 32 KiB or more than one line. A
  line ending at the end of the file is removed.

The variables of the fixed notifier wiring before 0.5.0
(`WARDEN_HA_WEBHOOK_URL`, `WARDEN_NTFY_URL`, `WARDEN_NTFY_TOKEN`) are
refused at startup, with the name of the replacement.

## Server commands

Run them in the container, for example
`docker compose exec warden /warden-server <command>`. They use the same
environment as the server. The image's default command is `serve`. For the
systemd service, see [Server commands](deployment-systemd.md#7-server-commands)
there.

| Command | What it does | Needs |
|---------|--------------|-------|
| `serve` | Runs the agent API, the approval UI and, when configured, the SSH relay. | All of the above. |
| `doctor [--send-test-notification] [--strict]` | Checks the configuration and says what to fix. See [Checking a setup](#checking-a-setup). | The same environment as `serve`. |
| `enroll` | Prints a one-time code (single use, valid 10 minutes) and the URL of the enrollment page, where the owner creates a passkey. | `WARDEN_DB_PATH`, `WARDEN_AUDIT_PATH`, `WARDEN_PUBLIC_URL` |
| `passkey list` | Lists enrolled passkeys: id, label, creation time. | `WARDEN_DB_PATH` |
| `passkey remove <id>` | Removes a passkey. | `WARDEN_DB_PATH`, `WARDEN_AUDIT_PATH` |
| `agent add <name>` | Creates a bearer-key agent and prints its key once, alone on stdout. On stderr, what to run on the agent's machine; `--server <url>` gives the agent API's URL to use there. | `WARDEN_DB_PATH`, `WARDEN_AUDIT_PATH` |
| `agent add <name> --public-key '<line>'` | Creates a key-signed agent, with the public key line of its signing key (`ssh-ed25519` or `ecdsa-sha2-nistp256`). No bearer key is made. On stderr, the `warden login` command for the agent's machine, with `--server <url>` as above (`https`, or `http` on loopback; the root of the origin) and the audience from `WARDEN_AUDIENCE_PATH` once the server has created it. | same, and `WARDEN_AUDIENCE_PATH` (optional) |
| `agent set-key <name> '<line>'` | Switches an agent to key-signed requests, or replaces its signing key. Its bearer key or previous key stops working at once. | same as `agent add <name>` |
| `agent list` | Lists agents: name, creation time, `active` or `revoked@<time>`, `bearer` or `ssh-key`, and the key's `SHA256:` fingerprint (`-` for a bearer key). | `WARDEN_DB_PATH` |
| `agent revoke <name>` | Disables the agent, ends its pending requests and grants, and ends its relay sessions. A running server notices within about 30 seconds for waiting clients and within seconds for relay sessions. It revokes even if the audit log cannot be used, then prints the entries that could not be written and exits with an error; a running server writes them once the log works. | `WARDEN_DB_PATH`, `WARDEN_AUDIT_PATH` |
| `audit verify` | Checks the audit log's hash chain and prints the number of entries. | `WARDEN_AUDIT_PATH` |
| `healthcheck` | Requests `/healthz` on `WARDEN_API_LISTEN` (loopback when it is `0.0.0.0`); exits 0 when healthy, 1 otherwise. For container health checks. | `WARDEN_API_LISTEN` (optional) |

Agent names match `^[a-z0-9][a-z0-9-]{0,31}$`. A key belongs to one agent,
and a revoked agent keeps its key: make a new key after a revocation.

### Checking a setup

`warden-server doctor` reports each check as `pass`, `FAIL` or
`COULD NOT CHECK`, says what to do about anything that did not pass, and ends
by saying what the run did. Run it in the server's container, as the broker's
user, so that it sees the same network and files:

```sh
docker compose exec warden /warden-server doctor
```

For the systemd service, see
[Server commands](deployment-systemd.md#7-server-commands) there.

| Exit code | Meaning |
|-----------|---------|
| 0 | No check failed. Some may not have run: the report lists them. |
| 1 | At least one check failed. |
| 2 | Wrong arguments. This is `warden-server`: `warden` on an agent machine exits 2 for a denied request and [64 for wrong arguments](agent-usage.md#exit-codes). |
| 7 | With `--strict` only: no check failed, but at least one could not be checked. |

warden cannot see everything, so **exit 0 does not mean everything was
checked**. A check that could not run never counts as passed: it is labelled
`COULD NOT CHECK`, and the summary lists each one with what to do by hand. Do
those. Because some of them can never run from inside the container, a working
deployment exits 7 with `--strict`.

| Check | Passes when | Reports `COULD NOT CHECK` when |
|-------|-------------|--------------------------------|
| `config` | The settings are present and valid. A failure names the first bad setting and links this page; there may be more. | Never. When it fails, everything below except `tailscale.*` is not checked. |
| `plain-http` | Every service URL is `https`, or goes to a host that is clearly local or private; the detail names those that use plain `http`. | A variable in `WARDEN_ALLOW_PLAIN_HTTP` sends plain `http` to any other host: warden cannot see whether that path is safe. |
| `connect.reachable` | Connect answers. | The vault name is unusable. |
| `connect.token` | Connect accepts the token. | Connect gave no useful answer. |
| `connect.vault` | The token can see `WARDEN_OP_VAULT`. | Connect gave no useful answer, or refused the token. |
| `connect.token-read-only` | Never. | Always: Connect does not report a token's permissions, and doctor will not attempt a write. Check how the token was created. |
| `ssh-ca` | The CA key loads, or there is no CA item and no certificate target needs one. | Connect or the vault is not usable, or a target item cannot be read. |
| `local.policy`, `local.entries`, `local.host-boundary` | Instead of `connect.*`, with `WARDEN_SECRET_BACKEND=local`. See [Checking it](local-backend.md#checking-it). | |
| `notify` | Never. | Without `--send-test-notification`: nothing was sent. |
| `notify.<channel>` | With the flag: the channel accepts the message. | Never. |
| `notify.delivery` | Never. | With the flag: warden sees that a channel accepted the message, not that it reached the phone. Confirm that it did. |
| `passkey` | At least one passkey is enrolled. | The database exists but cannot be read. |
| `audit.waiting` | No audit log entries are waiting in the database. They wait there when the log could not take them; a running server writes them once it can. | The database exists but cannot be read. |
| `listener.api`, `listener.approval`, `listener.relay` | A process accepts TCP connections on the address, and the address is not `0.0.0.0` or `::`. This does not prove the process is warden. The relay is checked only when it is on. | The connection neither succeeds nor is refused. |
| `data.directory` | The database's directory belongs to doctor's user, with no group or other permissions (0700). | The path cannot be read. |
| `data.database`, `data.audit-log`, `data.audience` | Each is a regular file (not a symbolic link) of doctor's user, not writable by group or others. | The path cannot be read. |
| `data.relay-host-key` | The same, with no group or other permissions (0600). Only when the relay is on. | The path cannot be read. |
| `tailscale.funnel-off`, `tailscale.serve` | Never. | Always: from inside its container warden cannot see Tailscale's configuration. The output says what to run on the host. |

What doctor does and does not do:

- **It is read-only by default.** It creates and migrates nothing, and opens
  the database read-only. The one exception is outside warden's control: on a
  database in WAL mode, SQLite may create the `-shm` file that readers share.
  Its reads of the vault, the CA item included, appear in 1Password's usage
  reports like any other. With the local backend, it reads the same files by
  the same rules as the server, and audits no refusal.
- **`--send-test-notification` reaches the owner's phone.** It sends one message
  through every channel in `WARDEN_NOTIFY`, not only the first, so that a broken
  fallback shows up. The message says it is a test.
- **It writes nothing to the audit log, even with the flag.** The commands that
  change an agent or a passkey (`agent add`, `agent set-key`, `agent revoke`,
  `passkey remove`) are audited, as are enrolling a passkey and `enroll`, which makes
  a code. Those that only read (`agent list`, `passkey list`,
  `audit verify`) are not. Doctor is one of those: a test message changes no
  state and decides no access, and doctor has to work when the audit log is
  what is broken.
- **It never prints a secret.** It quotes no response body, removes the
  configured secrets from everything it prints in case an upstream echoed one
  into an error, and replaces control characters.

## Plain http

`WARDEN_OP_CONNECT_URL`, `WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL` and
`WARDEN_NOTIFY_NTFY_URL` carry tokens and secrets, so each must be `https`, or
plain `http` to a host that the URL shows to be local or private:

| Kind of host | Accepted for plain `http` |
|---|---|
| IPv4 address | Loopback, private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local, and `100.64.0.0/10`. That is the tailnet range and also carrier NAT, so it is accepted as an address warden cannot check belongs to your tailnet |
| IPv6 address | `::1`, unique local `fc00::/7`, which holds tailnet addresses, link-local `fe80::/10`, and the IPv4 addresses above written as IPv6 |
| Name | One without a dot, such as a Docker service name, and `localhost` and names ending in `.localhost`, `.local`, `.home.arpa`, `.internal` or `.lan`. Not `.ts.net`: it is publicly delegated, so use `https` with those names, or the opt-in below |

Anything else stops the server at startup, and `warden-server doctor` reports
it, naming the variable and never the URL. Prefer `https`. If the path to that
host is safe in a way the URL cannot show, list the variable in
`WARDEN_ALLOW_PLAIN_HTTP`, for example
`WARDEN_ALLOW_PLAIN_HTTP=WARDEN_NOTIFY_NTFY_URL`. The server then logs a warning
at each start, and doctor reports `plain-http` as not checked. An entry that
names another variable, an unset one, or one that does not need it is refused,
so that a forgotten entry cannot later let a mistyped URL through.

This judges the URL as written and resolves no name: a name that looks local
but resolves to a public address is not caught. Nor can warden see who else is
on a private network. Any other scheme is refused.

## Server data

| Path (default) | Holds |
|----------------|-------|
| `WARDEN_DB_PATH` (with `-wal` and `-shm` files) | Requests, grants, agents, passkeys, enrollment codes, nonces. SQLite in WAL mode. |
| `WARDEN_AUDIT_PATH` | The audit log: one JSON object per line, each with the hash of the previous one. Every entry is also logged on stdout. |
| `/data/audience` | The audience id. |
| `/data/relay_host_ed25519` | The relay's host key. |

See [Backups and upgrades](deployment.md#9-backups-and-upgrades). To replace a
key or token, see [Replacing credentials](assurance-case.md#7-replacing-credentials).

## Server endpoints

| Listener | Path | Who |
|----------|------|-----|
| Agent API | `GET /healthz` | Anyone who can reach it (static `ok`). |
| Agent API | `GET /v1/info` | Anyone who can reach it (protocols and audience). |
| Agent API | `/v1/requests…`, `/v1/grants…` | Agents. See [the agent protocol](agent-protocol.md#6-endpoints). |
| Approval UI | `/approve/<token>`, `/grants`, `/history`, `/enroll` and their actions; [full list](interfaces.md#approval-ui) | The owner (`WARDEN_OWNER_LOGIN`). |

Every request to either listener that came through Tailscale Funnel is
refused with `401`.

## CLI commands

`warden` is the agent's client. It needs the OpenSSH client tools (`ssh`,
`ssh-agent`, `ssh-add`). Releases after v0.8.1 attach attested binaries:
[Agent usage](agent-usage.md#one-time-setup) has the commands to download and
verify one. For v0.8.1 and earlier, or on another platform, build it with Rust
1.99 or later:

```sh
cargo install --locked --git https://github.com/pecheriere/warden --tag v0.8.1 warden-broker-cli
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
| `warden doctor [--strict]` | Checks this machine's setup and says what to fix. See [Checking an agent machine](#checking-an-agent-machine). |
| `warden status` | Lists the grants on this machine and the broker's view of this agent's grants. |
| `warden revoke <grant>` | Revokes a grant on the broker and stops its local `ssh-agent`. |

A window is `15m`, `30m`, `1h` or `4h`. Exit codes are in
[Agent usage](agent-usage.md#exit-codes).

### Checking an agent machine

`warden doctor` reports each check as `pass`, `FAIL` or `COULD NOT CHECK`, and
the summary lists what could not be checked with what to do by hand. It exits 1
when a check failed, 64 for wrong arguments, and otherwise 0. With `--strict` it
exits 7 when nothing failed but a check could not run.

| Check | Passes when | Reports `COULD NOT CHECK` when |
|-------|-------------|--------------------------------|
| `config` | The configuration file is usable. | Never. |
| `server.reachable` | The broker answers `GET /v1/info`. | There is no usable configuration. |
| `audience` | The broker reports the audience pinned at login. Another one is a failure. | The broker did not answer, or the agent uses a bearer key, which pins no audience. |
| `protocol` | The broker accepts signed requests. Only for a key-signed agent, when the broker answered. | Never. |
| `ssh-agent.key` or `bearer-key` | The `ssh-agent` holds the signing key, or the bearer key is available. | There is no usable configuration. |
| `broker.accepts-agent` | The broker accepts one authenticated `GET /v1/grants`. A 4xx answer is a failure. | The credential is not available, or the broker is unreachable or answers 5xx. |
| `version` | Never. | Always: the broker does not publish its version. Doctor prints the CLI's, to compare with `warden-server --version`. |

Because of `version`, a working machine exits 0, and 7 with `--strict`.

It changes nothing on the machine: unlike every other command, it does not even
clean up ended grants first. The broker handles its `GET /v1/grants` like any
other authenticated call, which for a signed call means recording the nonce.

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
