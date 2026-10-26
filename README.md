# warden

warden is a self-hosted approval broker. An AI coding agent (or any script)
asks for temporary access to a resource and says why. The owner gets a
notification on their phone, reviews the goal and exactly what would be
granted, and approves with a passkey. warden then issues a credential that
expires on its own. The agent never holds a long-lived secret.

Two kinds of access are supported:

- **SSH.** The broker signs a short-lived SSH certificate for an ephemeral
  Ed25519 key that exists only in memory on the requesting machine, and only
  for the approved window.
- **HTTP API secrets.** The agent never sees the secret. For the approved
  window the broker makes HTTPS calls for the agent, adds the secret to the
  header the policy names, sends them only to the one origin and path prefix
  the policy allows, and returns the response with the secret redacted.

Status: early development. This release (0.2.0) implements SSH certificate
mode and HTTP proxy mode.

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

phone --- HTTPS (tailnet) ------------> approval page (WebAuthn passkey)
```

## Components

- `warden-server` (crate `warden-broker`): the agent API, the approval web UI,
  the SSH CA, the HTTP proxy, notifier dispatch, the hash-chained audit log and SQLite state.
  It runs as a container.
- `warden` (crate `warden-broker-cli`): the command-line client. It requests
  access, waits for the decision, keeps the ephemeral key in a per-grant
  `ssh-agent`, wraps `ssh` and makes brokered API calls (`warden http`).
- `warden-broker-proto`: the wire types shared by both.

Policy lives in a 1Password vault read through 1Password Connect. See
[docs/1password-items.md](docs/1password-items.md). Notifications go to Home
Assistant first and fall back to ntfy; see
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
     -e WARDEN_HA_WEBHOOK_URL \
     -e WARDEN_NTFY_URL \
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

   All variables: `WARDEN_DB_PATH`, `WARDEN_AUDIT_PATH`, `WARDEN_API_LISTEN`
   (default `127.0.0.1:8080`), `WARDEN_APPROVAL_LISTEN` (default
   `127.0.0.1:8081`), `WARDEN_PUBLIC_URL` (https), `WARDEN_OWNER_LOGIN`,
   `WARDEN_OP_CONNECT_URL`, `WARDEN_OP_CONNECT_TOKEN`, `WARDEN_OP_VAULT`
   (default `Warden`), `WARDEN_HA_WEBHOOK_URL`, `WARDEN_NTFY_URL`,
   `WARDEN_NTFY_TOKEN` and `WARDEN_PROXY_MAX_RESPONSE_BYTES` (largest response
   a proxied API call may return, default `1048576`, at most `67108864`). At
   least one notifier is required.

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
   expires, and prints a fingerprint the approval page also shows. See
   [docs/agent-usage.md](docs/agent-usage.md) for how an agent should use it.

   To call an API with a stored secret, add an API secret item to the vault
   (see [docs/1password-items.md](docs/1password-items.md)), then:

   ```sh
   warden request api github --for 30m --goal "list my repos to find the stale fork"
   warden http github GET https://api.github.com/user
   ```

   The secret is added by the broker and never reaches the workstation. It
   goes only to the item's origin, under its path prefix, with its allowed
   methods. `warden http` writes the response body to stdout; `-i` shows the
   status and headers on stderr and `--fail` exits 22 on a status of 400 or
   more.

## Deployment notes

warden expects to run behind a dedicated Tailscale node (a sidecar container)
whose network namespace it shares (`--network container:<sidecar>`), with both
listeners on loopback. The sidecar publishes the agent API and the approval UI
as two Tailscale Serve ports (proxying to `127.0.0.1:8080` and
`127.0.0.1:8081`) with separate tailnet grants. Serve sets the
`Tailscale-User-Login` header that warden checks; nothing else can reach the
listeners to forge it. Grant the approval
port to the owner's phone only, and the API port to the machine the agent runs
on. Keep the Connect server on an internal network that only warden can
reach, run warden with all capabilities dropped and a read-only root
filesystem, and back up the `/data` volume. Details and the reasons are in the
threat model.

## Security model

An agent can only request; a passkey approval from the owner's enrolled device,
reachable only over the tailnet, is required for every grant; certificates are
valid for at most four hours for one ephemeral key; API secrets never leave
the broker except toward their approved origin; secrets never reach
notifiers; and every step is written to a tamper-evident audit log. The actors,
anti-goals, accepted residual risks and deployment assumptions are in
[docs/threat-model.md](docs/threat-model.md).

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
