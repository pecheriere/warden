# warden

warden is a self-hosted approval broker. An AI coding agent (or any script)
asks for temporary access to a resource and says why. The owner gets a
notification on their phone, reviews the goal and exactly what would be
granted, and approves with a passkey. warden then issues a credential that
expires on its own. The agent never holds a long-lived secret.

Three kinds of access are supported:

- **SSH, certificate mode.** The broker signs a short-lived SSH certificate
  for an ephemeral Ed25519 key that exists only in memory on the requesting
  machine, and only for the approved window.
- **SSH, relay mode.** For hosts that cannot trust a CA (appliances, Dropbear,
  password-only logins), the agent connects to the broker's SSH relay with the
  approved ephemeral key, and the broker logs in to the target with a key or
  password that never leaves it. The agent's commands are the same as in
  certificate mode.
- **HTTP API secrets.** The agent never sees the secret. For the approved
  window the broker makes HTTPS calls for the agent, adds the secret to the
  header the policy names, sends them only to the one origin and path prefix
  the policy allows, and returns the response with the secret redacted.

Status: early development. This release (0.5.0) implements SSH certificate
mode, SSH relay mode and HTTP proxy mode.

## Why

Agents regularly need privileged access to diagnose or operate infrastructure,
but handing them standing credentials is unsafe, and approving each access
through a desktop prompt only works when you are at that desktop. warden lets
you approve remotely, from a phone, with a hardware-backed passkey, for a
bounded window and a stated goal.

## Architecture

```
workstation                           server (container)                      targets
-----------                           ------------------                      -------
warden CLI --- HTTPS (tailnet) -----> warden-server --- Connect API --> 1Password Connect
  |  ephemeral key in a per-grant       |  approval web UI (passkey)               |
  |  ssh-agent, never on disk           |  SSH CA (key held in memory)             v
  |                                     |  notifier --> Home Assistant / ntfy   1Password vault
  |                                     |                       |               (policy and CA key)
  |                                     |                       v
  |                                     |                     phone
  +--- ssh with the signed certificate ---------------------------------------> hosts that trust the CA
  |
  +--- ssh (approved key) --> relay (tailnet TCP) --- ssh (key/password) -----> appliances

phone --- HTTPS (tailnet) ------------> approval page (WebAuthn passkey)
```

## Components

- `warden-server` (crate `warden-broker`): the agent API, the approval web UI,
  the SSH CA, the SSH relay, the HTTP proxy, notifier dispatch, the
  hash-chained audit log and SQLite state.
  It runs as a container.
- `warden` (crate `warden-broker-cli`): the command-line client. It requests
  access, waits for the decision, keeps the ephemeral key in a per-grant
  `ssh-agent`, wraps `ssh` and makes brokered API calls (`warden http`).
- `warden-broker-proto`: the wire types shared by both.

Policy lives in a 1Password vault read through 1Password Connect. See
[docs/1password-items.md](docs/1password-items.md). Notifications go to the
channels you choose (Home Assistant, ntfy) in the order you choose; see
[docs/notifications.md](docs/notifications.md).

## Quickstart

1. **Create the 1Password items** (the SSH CA key and one item per target) and
   a read-only Connect token for that vault, as described in
   [docs/1password-items.md](docs/1password-items.md). Set up each target to
   trust the CA for that target only (below).

   Certificates carry a single principal, `warden:<target>:<user>`, so a host
   must map that exact string to the account. In `sshd_config`:

   ```
   TrustedUserCAKeys /etc/ssh/warden_ca.pub
   AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
   ```

   and in `/etc/ssh/auth_principals/<user>` one line per allowed user of this
   host, for example `warden:pi:deploy`. A host that only reads
   `authorized_keys` (for example the Home Assistant SSH add-on) uses one line
   instead:

   ```
   cert-authority,principals="warden:<target>:<user>" ssh-ed25519 AAAA…
   ```

   With this setup an approval for one target cannot be used on any other host
   that trusts the same CA. `TrustedUserCAKeys` without
   `AuthorizedPrincipalsFile` would not accept the certificate at all.

   A host that cannot trust a CA is a **relay target** instead: set its item's
   `mode` to `relay`, pin its `host_keys`, and put the account's Ed25519
   private key or password in the item (see
   [docs/1password-items.md](docs/1password-items.md)). Nothing is installed
   on the target except an ordinary login for that account. Set
   `WARDEN_RELAY_PUBLIC_ADDR` (below) so agents know where the relay is.

2. **Build and run the server.** The image is built from this repository; no
   image is published.

   ```sh
   docker buildx build -t warden:dev --load .
   docker run -d --name warden --read-only --cap-drop ALL \
     --network container:warden-tailscale \
     -v warden-data:/data \
     -e WARDEN_DB_PATH=/data/warden.db \
     -e WARDEN_AUDIT_PATH=/data/audit.jsonl \
     -e WARDEN_PUBLIC_URL=https://warden.example.ts.net \
     -e WARDEN_OWNER_LOGIN=you@example.com \
     -e WARDEN_OP_CONNECT_URL=http://connect-api:8080 \
     -e WARDEN_OP_CONNECT_TOKEN \
     -e WARDEN_NOTIFY=homeassistant,ntfy \
     -e WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL \
     -e WARDEN_NOTIFY_NTFY_URL \
     warden:dev
   ```

   Pass the secrets (`WARDEN_OP_CONNECT_TOKEN`, the webhook and ntfy settings)
   from your secret manager rather than writing them on the command line. The
   container runs as uid 65532 with no shell; `/data` is the only writable
   path.

   `warden-tailscale` is the dedicated Tailscale sidecar container (see
   "Deployment notes"). `--network container:warden-tailscale` puts warden in
   the sidecar's network namespace, so the listeners stay on their loopback
   defaults (`127.0.0.1:8080` and `127.0.0.1:8081`) and only the sidecar's
   Tailscale Serve can reach them. Do not bind them to `0.0.0.0` and do not
   run warden on a shared bridge network: warden trusts the
   `Tailscale-User-Login` header, and any process or container that can reach
   a listener directly can forge it. The sidecar must also be attached to the
   internal network where Connect runs, since warden uses its network.

   The image has no `HEALTHCHECK` because it has no shell. Configure your
   orchestrator to run `/warden-server healthcheck`, which requests `/healthz`
   on `WARDEN_API_LISTEN` and exits 0 when healthy and 1 otherwise.

   Relay mode adds three variables. `WARDEN_RELAY_PUBLIC_ADDR` (`host:port`)
   is the address agents connect to; it is required for relay targets, and
   without it requests for them are refused. `WARDEN_RELAY_LISTEN` (default
   `127.0.0.1:2222`) is the local listener, which the sidecar publishes as a
   Tailscale Serve TCP forward (granted to the workstation only, like the API
   port). `WARDEN_RELAY_HOST_KEY_PATH` (default `/data/relay_host_ed25519`) is
   the relay's Ed25519 host key: it is generated on first use with mode 0600
   and must stay on the data volume so the key does not change between
   restarts. `WARDEN_RELAY_MAX_SESSIONS` (default 16, at most 1024) limits
   relayed sessions open at once; each grant may hold 4.

   All variables: `WARDEN_DB_PATH`, `WARDEN_AUDIT_PATH`, `WARDEN_API_LISTEN`
   (default `127.0.0.1:8080`), `WARDEN_APPROVAL_LISTEN` (default
   `127.0.0.1:8081`), `WARDEN_PUBLIC_URL` (https), `WARDEN_OWNER_LOGIN`,
   `WARDEN_OP_CONNECT_URL`, `WARDEN_OP_CONNECT_TOKEN`, `WARDEN_OP_VAULT`
   (default `Warden`), `WARDEN_NOTIFY` (channels in priority
   order, required), `WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL`,
   `WARDEN_NOTIFY_NTFY_URL`, `WARDEN_NOTIFY_NTFY_TOKEN`,
   `WARDEN_PROXY_MAX_RESPONSE_BYTES` (largest response a proxied API call may
   return, default `1048576`, at most `67108864`),
   `WARDEN_PROXY_MAX_CALLS_PER_AGENT` (proxied calls in flight per agent,
   default `4`, 1 to 64), `WARDEN_PROXY_MAX_CALLS` (in flight overall,
   default `16`, 1 to 256, at least the per-agent limit),
   `WARDEN_RELAY_LISTEN`, `WARDEN_RELAY_PUBLIC_ADDR`,
   `WARDEN_RELAY_HOST_KEY_PATH` and `WARDEN_RELAY_MAX_SESSIONS`. See
   [docs/notifications.md](docs/notifications.md) for the channel settings.

3. **Enroll your phone's passkey.**

   ```sh
   docker exec warden /warden-server enroll
   ```

   Open the printed URL on your phone and enter the code. It works once, for
   10 minutes. List or remove passkeys with `warden-server passkey list|remove`.

4. **Create an agent key.**

   ```sh
   docker exec warden /warden-server agent add laptop
   ```

   The key is printed once. Store it in 1Password. `agent list` and `agent
   revoke <name>` manage agents.

5. **Log in from the workstation** (macOS; the key goes into the Keychain):

   ```sh
   op read "op://Private/warden agent laptop/key" \
     | warden login --server https://warden.example.ts.net --agent laptop
   ```

6. **Request access and use it.**

   ```sh
   warden request ssh pi --user deploy --for 30m --goal "restart the backup job"
   warden ssh pi
   ```

   `warden request` blocks until the owner approves, denies, or the request
   expires, and prints a fingerprint the approval page also shows. A relay
   target is requested and used with the same two commands; the session is
   relayed by the broker, and forwarding and sftp are refused. See
   [docs/agent-usage.md](docs/agent-usage.md) for how an agent should use it.

   To call an API with a stored secret, add an API secret item to the vault
   (see [docs/1password-items.md](docs/1password-items.md)), then:

   ```sh
   warden request api github --for 30m --goal "list my repos to find the stale fork"
   warden http github GET https://api.github.com/user
   ```

   Without `--methods` the grant is read-only (`GET` and `HEAD`). To change
   something, ask for it by name, and optionally under a narrower path:

   ```sh
   warden request api github --methods POST --path /repos/alice/ --for 15m \
     --goal "open an issue on alice/widgets about the stale fork"
   ```

   The approval page and the notification say **Read-only** or **Can modify:
   POST**. A request can only narrow what the item allows.

   The secret is added by the broker and never reaches the workstation. It goes
   only to the item's origin, under its path prefix, with the methods the owner
   approved. `warden http` writes the response body to stdout; `-i` shows the
   status and headers on stderr and `--fail` exits 22 on a status of 400 or
   more.

## Deployment notes

warden expects to run behind a dedicated Tailscale node (a sidecar container)
whose network namespace it shares (`--network container:<sidecar>`), with both
listeners on loopback. The sidecar publishes the agent API and the approval UI
as two Tailscale Serve ports (proxying to `127.0.0.1:8080` and
`127.0.0.1:8081`) with separate tailnet grants. Serve sets the
`Tailscale-User-Login` header that warden checks; nothing else can reach the
listeners to forge it. Grant the approval port to the owner's phone only, and
the API and relay ports to the machine the agent runs on (the relay is a raw
TCP forward, so the tailnet policy is its only network-level restriction). Keep
the Connect server on an internal network that only warden can reach, run
warden with all capabilities dropped and a read-only root filesystem, and back
up the `/data` volume. Details and the reasons are in the threat model.

## Security model

An agent can only request; a passkey approval from the owner's enrolled device,
reachable only over the tailnet, is required for every grant; certificates are
valid for at most four hours for one ephemeral key; relayed sessions end at
revocation or expiry and the target's credential never leaves the broker; API
secrets never leave the broker except toward their approved origin; secrets
never reach notifiers; and every step is written to a tamper-evident audit log.
The actors, anti-goals, accepted residual risks and deployment assumptions are
in [docs/threat-model.md](docs/threat-model.md).

## Development

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo deny check
```

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option.
