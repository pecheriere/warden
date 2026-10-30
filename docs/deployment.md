# Deploying warden

This guide is the recommended way to run warden: what to set up, in which
order, and why each step matters for safety.

Requirements:

- **A Linux host dedicated to warden** (see
  [who can reach the listeners](#who-can-reach-the-listeners)), with
  Tailscale installed, and MagicDNS and HTTPS certificates enabled for the
  tailnet.
- **Docker Engine 28 or later and Docker Compose 2.33 or later.** This is a
  security requirement, not only a feature one. Before Engine 28, another
  machine on the LAN that adds a route to a container network through the
  host can reach a container's ports even when they are not published. That
  would let it reach warden's listeners and forge the owner's identity
  header. Engine 28 blocks such direct access, and the Compose file below
  also uses `gw_priority`, which needs Engine 28 and Compose 2.33. Check
  with `docker version` and `docker compose version`.
- A 1Password account that can create Connect servers.
- A phone that can hold a passkey, on the tailnet.

warden's guarantees depend on its surroundings as much as on its code. The
[threat model](threat-model.md#deployment-assumptions) lists the assumptions;
this guide is how to meet them.

Contents:

1. [The recommended layout](#1-the-recommended-layout)
2. [Tailscale](#2-tailscale)
3. [1Password](#3-1password)
4. [1Password Connect, hardened](#4-1password-connect-hardened)
5. [Run warden](#5-run-warden)
6. [Network rules](#6-network-rules)
7. [Notifications](#7-notifications)
8. [First start](#8-first-start)
9. [Backups and upgrades](#9-backups-and-upgrades)
10. [The sidecar layout, for relay targets](#10-the-sidecar-layout-for-relay-targets)
11. [Checklist](#11-checklist)

The examples use these placeholder names. Replace them with your own.

| Placeholder | Meaning |
|-------------|---------|
| `example.ts.net` | Your tailnet's DNS name. |
| `tag:warden-host` | The tag of the host that runs warden. |
| `svc:warden`, `svc:warden-api` | The Tailscale Services for the approval UI and the agent API. |
| `owner@example.com` | The owner's Tailscale login. |
| `owner-phone` | The owner's phone, as a tailnet device. |
| `agent-machine` | The machine an agent runs on. |
| `build-agent` | An agent's name in warden. |
| `web-01`, `switch-01` | SSH targets (certificate and relay). |
| `home-api` | An API secret. |
| `<account>.1password.com` | Your 1Password account's sign-in address. |

## 1. The recommended layout

```
owner-phone ──── tailnet ───▶ svc:warden      (443) ─┐
                                                      │  Tailscale Serve
agent-machine ── tailnet ───▶ svc:warden-api  (443) ─┤  on tag:warden-host
                                                      ▼
                              ┌─ network "front" ──────────────────┐
                              │  warden  :8081 approval UI         │
                              │          :8080 agent API           │
                              └──────────────────┬─────────────────┘
                                                 │ network "connect"
                              ┌──────────────────┴─────────────────┐
                              │  connect-api ◀─▶ connect-sync      │──▶ 1Password
                              └────────────────────────────────────┘
```

- **Tailscale Services** publish warden on the tailnet, one name per
  endpoint, on port 443. Nothing is published on the LAN or the internet.
- **The approval UI is reachable from the owner's phone only.** The agent
  API is reachable from the agent machines only.
- **warden and Connect each run hardened**: non-root, no capabilities, a
  read-only root filesystem, and no published ports.
- **Connect sits on its own network.** It can reach 1Password, and warden
  can reach it, but it can never reach warden's listeners.

Why the last point matters: warden trusts the `Tailscale-User-Login` header
that Tailscale Serve adds. Anything that can open a connection to a warden
listener directly can forge that header. So the only things that may reach
the listeners are Tailscale Serve and, if you use one, a reverse proxy that
Serve targets.

This layout does not support SSH relay targets yet: they need
[the sidecar layout](#10-the-sidecar-layout-for-relay-targets).

### Who can reach the listeners

In this layout the host's Tailscale Serve connects to warden's address on
the `front` network. **Every other process on the host can connect to that
address too, and so can every container with host networking.** Any of them
can send a forged `Tailscale-User-Login` with the owner's login. A forged
login cannot approve anything (that needs the passkey), but it can read
`/grants` and `/history` (every goal, agent and target), revoke grants,
deny requests whose link it learns, and use a stolen bearer agent key.

So in this layout **the whole host is inside the trust boundary**, not only
its root. Contain it:

- **Dedicate the host to warden** (and its Connect), with no untrusted local
  users and no other services that run untrusted code.
- **Run no container with host networking** (`network_mode: host`) on it.
- **Bind the listeners to warden's address on a network no other service
  shares** (`front` below holds warden alone), never to `0.0.0.0`, and
  publish no port.
- **Put a gateway in front of warden** if you want a second check: a
  reverse proxy on `front` that Serve targets instead of warden, which
  requires a Tailscale app capability per endpoint (see
  [app capabilities](#publish-the-services)). A local process can forge a
  capability header to the gateway as easily as a login to warden, so
  this helps only together with the next point.
- **Optionally, refuse local connections that do not come from
  tailscaled.** tailscaled runs as root, so a rule like the following
  rejects every other user's connections to the listeners (add the
  gateway's ports if you run one). It does not stop root, which is the root
  of trust anyway:

  ```sh
  iptables -I OUTPUT -d 172.31.250.0/24 -p tcp -m multiport --dports 8080,8081 \
    -m owner ! --uid-owner 0 -j REJECT
  ```

The [sidecar layout](#10-the-sidecar-layout-for-relay-targets) avoids this:
there, warden shares a network namespace with its own Tailscale node only,
and nothing on the host reaches its loopback listeners.

## 2. Tailscale

### Why Tailscale

- **Tailnet only.** warden is never exposed to the internet. No ports are
  opened on your router or firewall.
- **Identity.** Tailscale Serve authenticates every peer and tells warden
  who it is (`Tailscale-User-Login`). The approval UI accepts only the
  owner's login.
- **Per-device access.** The tailnet policy decides which device can reach
  which endpoint. That is how the approval UI is kept off the agent's
  machine.

Tailscale is a hard requirement: warden has no other way to identify the
owner.

### Recommended: Tailscale Services

A [Tailscale Service][svc] (`svc:<name>`) is a name on your tailnet with its
own MagicDNS name (`<name>.example.ts.net`), its own virtual IP and a
Tailscale certificate on port 443. warden uses two:

| Service | Serves | Reachable from |
|---------|--------|----------------|
| `svc:warden` | The approval UI (`WARDEN_PUBLIC_URL`) | The owner's phone only |
| `svc:warden-api` | The agent API | The agent machines only |

Each endpoint gets its own name, so the WebAuthn relying party (the approval
Service's name) belongs to warden alone. The following was tested on
Tailscale 1.104.

[svc]: https://tailscale.com/kb/1552/tailscale-services

#### The tailnet policy

Only a device with a **tag** identity can host Services. Tag the host that
runs warden (`tag:warden-host`), and keep the phone and the agent machines
as they are. Tagging a device removes it from its user: give it the access
it needs through grants.

The policy needs four pieces, plus tests. In HuJSON:

```jsonc
{
  // Name the devices by their tailnet IP, as shown in the admin console.
  "hosts": {
    "owner-phone":   "<tailnet IP of the owner's phone>",
    "agent-machine": "<tailnet IP of the agent machine>",
  },

  // 1. Who may apply the host's tag.
  "tagOwners": {
    "tag:warden-host": ["autogroup:admin"],
  },

  // 2. Let the tagged host serve the two Services without a manual
  //    approval in the admin console.
  "autoApprovers": {
    "services": {
      "svc:warden":     ["tag:warden-host"],
      "svc:warden-api": ["tag:warden-host"],
    },
  },

  "grants": [
    // 3. Network access: the approval UI to the owner's phone only...
    {
      "src": ["owner-phone"],
      "dst": ["svc:warden"],
      "ip":  ["tcp:443"],
    },
    // ...and the agent API to the agent machines only.
    {
      "src": ["agent-machine"],
      "dst": ["svc:warden-api"],
      "ip":  ["tcp:443"],
    },
  ],

  // 4. Tests: the policy is refused if one fails.
  "tests": [
    {
      "src":    "owner-phone",
      "accept": ["svc:warden:443"],
      "deny":   ["svc:warden-api:443"],
    },
    {
      "src":    "agent-machine",
      "accept": ["svc:warden-api:443"],
      "deny":   ["svc:warden:443"],
    },
  ],
}
```

Merge these into your existing policy. **Remove or narrow the default
allow-all grant** (`"src": ["*"], "dst": ["*"], "ip": ["*"]`): with it, the
agent machine can reach `svc:warden` and the deny tests fail. The tests are
the important part: they make sure no later edit lets the agent machine
reach the approval UI.

**Never grant the approval UI to an agent machine.** An agent can be
prompt-injected. If it could open the approval page, it could put an
approval prompt in front of the owner on a machine it controls (or use a
passkey synced to that machine). warden checks that the caller is the owner;
only the tailnet policy can check that the caller is the owner's *phone*.

A device without a grant to a Service cannot even resolve its name, so the
agent machine does not see `warden.example.ts.net` at all.

#### Publish the Services

Define each Service once in the admin console (**Services**), then publish
it on the host. The targets are warden's listeners on the `front` network
(see [Run warden](#5-run-warden)):

```sh
tailscale serve --service=svc:warden     --https=443 --bg http://172.31.250.10:8081
tailscale serve --service=svc:warden-api --https=443 --bg http://172.31.250.10:8080
```

Then set `WARDEN_PUBLIC_URL=https://warden.example.ts.net` on warden, and
give agents `https://warden-api.example.ts.net` as the server URL.

Behaviour to know:

- **Headers.** Serve forwards `Tailscale-User-Login` to warden for user
  devices (a tagged device has no user login, so none is sent). Serve
  removes any `Tailscale-*` identity header that a client sends itself.
- **App capabilities.** warden does not read app capabilities, so the
  commands above do not pass any. If you put a reverse proxy in front of
  warden that checks a capability (for example one that refuses requests
  without `example.com/cap/warden-approve`), add
  `--accept-app-caps=example.com/cap/warden-approve` to the `serve`
  command, and grant the capability **to the host, not to the Service**:

  ```jsonc
  {
    "src": ["owner-phone"],
    "dst": ["tag:warden-host"],
    "app": {"example.com/cap/warden-approve": [{}]},
  },
  ```

  A capability granted with `dst: svc:<name>` is never forwarded. Serve
  strips any `Tailscale-App-Capabilities` header a client sends.
- **`tailscale serve get-config`** omits `AcceptAppCaps`
  (`tailscale serve status --json` shows it). Set up a Service that needs
  capabilities with the commands above, not with `set-config`.
- **The relying party is the Service name.** Moving an existing deployment
  to other names changes it: enroll the passkeys again, and have agents run
  `warden login` again with the new API URL (a bearer key can be reused).

#### Never use Funnel

Never publish either Service with Tailscale Funnel. Funnel puts a name on
the public internet. warden refuses every agent API request that came
through Funnel (`401`), and the approval UI needs the owner's login, which a
Funnel request never carries. Do not rely on those refusals: keep Funnel off.

- In the tailnet policy, give no `nodeAttrs` entry with the `funnel`
  attribute to `tag:warden-host` (or to `tag:warden` in the sidecar layout).
  Without it, the node cannot enable Funnel at all.
- On the host, `tailscale funnel status` must list nothing.

### Alternative: a dedicated sidecar node

A Tailscale container can instead be a dedicated tailnet node for warden.
warden shares its network namespace, so its listeners stay on loopback and
nothing but that node's Serve can reach them, not even other processes on
the host. It is also, for now, the only layout that supports SSH relay
targets. [Section 10](#10-the-sidecar-layout-for-relay-targets) is the full
recipe.

### The SSH relay endpoint

Relay targets (see [SSH targets](ssh-targets.md#relay-targets)) need a third
endpoint: warden's SSH relay, a raw TCP listener (`WARDEN_RELAY_LISTEN`,
default `127.0.0.1:2222`). Serve adds no identity to a TCP stream, and every
peer appears to come from the same address, so the relay authenticates the
agent by its approved key, and the tailnet policy is the only network-level
control. Grant the relay port to the agent machines only.

**Publishing the relay through Tailscale Services has not been tested.** Use
[the sidecar layout](#10-the-sidecar-layout-for-relay-targets), which
publishes it as a Serve TCP forward, if you have relay targets.

## 3. 1Password

warden reads its policy (targets, API secrets, the SSH CA key) from a
1Password vault through a [1Password Connect][connect] server. Nothing is
cached: an edit in 1Password takes effect on the next request.

[connect]: https://developer.1password.com/docs/connect/

1. **Create a dedicated vault**, named `Warden` (or set `WARDEN_OP_VAULT`).
   Put nothing in it but warden's items. Everything in this vault is
   something warden may hand out on approval.

   ```sh
   op vault create Warden
   ```

2. **Create a Connect server with access to that vault only.** The command
   writes `1password-credentials.json` to the current directory: run it in
   a private directory (or a RAM disk), move the file to the host, and
   delete the local copy.

   ```sh
   op connect server create warden-connect --vaults Warden
   ```

3. **Issue a read-only token for that vault.** `,r` makes it read-only.
   warden never writes to 1Password.

   ```sh
   op connect token create warden-read --server warden-connect --vault Warden,r \
     | ssh root@<warden host> \
         'umask 077; sed "s/^/WARDEN_OP_CONNECT_TOKEN=/" >> /srv/warden/warden.env'
   ```

   The token is printed once. The command above writes it straight into
   warden's environment file on the host (mode 0600, in the directory
   prepared in [section 4](#4-1password-connect-hardened); create that
   first), so it is never on a command line or in your terminal's
   scrollback. Use any account on the host that can write the file without
   a password prompt (a prompt would read the token). Otherwise run the
   command alone, paste the token into the file with an editor, and clear
   the terminal.
   **Never reuse a token or a Connect server that serves other vaults or
   other applications**: a token that can read more than the `Warden`
   vault turns a warden compromise into a compromise of those secrets too.

4. **Create the SSH CA key.** It must be an unencrypted Ed25519 key in an
   SSH Key item tagged `warden:ssh-ca` (exactly one such item):

   ```sh
   op item create --vault Warden --category "SSH Key" \
     --title warden-ssh-ca --tags warden:ssh-ca --ssh-generate-key ed25519
   ```

   Its public key goes on every certificate target
   ([SSH targets](ssh-targets.md)). Get it from the item's `public key`
   field:

   ```sh
   op read "op://Warden/warden-ssh-ca/public key" > warden_ca.pub
   ssh-keygen -lf warden_ca.pub   # note the fingerprint
   ```

5. **Add one item per target and per API secret.** The tags, titles and
   field labels are exact; [1Password item conventions](1password-items.md)
   is the reference.

## 4. 1Password Connect, hardened

Connect runs as two containers, `connect-api` (which warden calls) and
`connect-sync` (which talks to 1Password). The defaults of the official
images run as root with a writable root filesystem. The settings below
remove that. Each was tested with the Connect 1.8 images.

- **Run as a dedicated, unused uid** (not the image's default, which may
  collide with a uid on the host).
- **Give that uid a passwd entry.** Connect refuses to use a data directory
  when its uid has no entry in `/etc/passwd` ("can't safely access … because
  it's not owned by the current user"), even when the directory is owned by
  that uid. Mount a small `passwd` and `group` file read-only over the
  image's.
- **Point `OP_SESSION` and `XDG_DATA_HOME` at explicit paths.** `OP_SESSION`
  is the credentials file; Connect keeps its data in
  `$XDG_DATA_HOME/.op/data`. With a read-only root filesystem the defaults
  are not writable.
- **Read-only root filesystem**, with a `tmpfs` on `/tmp`.
- **Drop all capabilities** and set `no-new-privileges`.
- **Set the bus explicitly.** `connect-api` and `connect-sync` find each
  other by broadcast, which needs `NET_BROADCAST`. With all capabilities
  dropped, that discovery fails, so set `OP_BUS_PORT` (the container's own
  bus port) and `OP_BUS_PEERS` (the other container's address and bus port)
  on both, with fixed addresses.
- **Its own network.** Connect's network holds Connect and warden, and
  nothing else. warden's listeners are not on it (see
  [Run warden](#5-run-warden)), so Connect can never reach them.
- **No published ports.** Only warden talks to `connect-api`.

Prepare the files on the host (`64001` is an example of an unused uid):

```sh
install -d -m 0750 /srv/warden
cd /srv/warden
install -d -o 64001 -g 64001 -m 0700 connect-data
install -o 64001 -g 64001 -m 0400 /path/to/1password-credentials.json .
printf '%s\n' 'root:x:0:0:root:/root:/sbin/nologin' \
  'op-connect:x:64001:64001:1Password Connect:/nonexistent:/sbin/nologin' > connect-passwd
printf '%s\n' 'root:x:0:' 'op-connect:x:64001:' > connect-group
chmod 0644 connect-passwd connect-group
```

The Compose services (part of the file in [Run warden](#5-run-warden)):

```yaml
  connect-api:
    image: 1password/connect-api:<version>@sha256:<digest>
    user: "64001:64001"
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    environment:
      OP_SESSION: /op-creds/1password-credentials.json
      XDG_DATA_HOME: /op-data
      OP_BUS_PORT: "11220"
      OP_BUS_PEERS: "172.31.251.12:11221"
    volumes:
      - ./connect-passwd:/etc/passwd:ro
      - ./connect-group:/etc/group:ro
      - ./1password-credentials.json:/op-creds/1password-credentials.json:ro
      - ./connect-data:/op-data
    networks:
      connect:
        ipv4_address: 172.31.251.11

  connect-sync:
    image: 1password/connect-sync:<version>@sha256:<digest>
    user: "64001:64001"
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    environment:
      OP_SESSION: /op-creds/1password-credentials.json
      XDG_DATA_HOME: /op-data
      OP_BUS_PORT: "11221"
      OP_BUS_PEERS: "172.31.251.11:11220"
    volumes:
      - ./connect-passwd:/etc/passwd:ro
      - ./connect-group:/etc/group:ro
      - ./1password-credentials.json:/op-creds/1password-credentials.json:ro
      - ./connect-data:/op-data
    networks:
      connect:
        ipv4_address: 172.31.251.12
```

Pin both images by digest, and upgrade them together. After the first start,
`docker compose logs connect-api connect-sync` should show the two finding
each other over the bus and the first sync completing.

**Lock Connect's egress to 1Password.** Connect only needs HTTPS to your
account's 1Password servers. The hosts observed so far are
`<account>.1password.com` and `b5n.1password.com`; **observe and verify
yours** before you rely on that list. An IP firewall cannot pin a name, so
use an egress proxy that checks the TLS server name (SNI), or a DNS
allowlist. When you observe the traffic through a proxy or relay, note that
many log a connection only when it closes: also list the connections that
are open (`ss -tnp`, `conntrack -L`) before you trust an observed list.

## 5. Run warden

The image is published for `linux/amd64` and `linux/arm64` as
`ghcr.io/pecheriere/warden:<version>`, with a build provenance attestation.
Verify it, and pin the digest you verified:

```sh
gh attestation verify oci://ghcr.io/pecheriere/warden:0.7.0 --owner pecheriere
docker buildx imagetools inspect ghcr.io/pecheriere/warden:0.7.0   # the digest
```

You can also build it from this repository:
`docker buildx build -t warden:dev --load .`.

The image runs as uid 65532, has no shell, and writes only to `/data`.

### Networks

warden joins two networks:

- **`front`**: warden alone (and a reverse proxy, if you use one). Its
  listeners bind to warden's fixed address on this network, and the host's
  Tailscale Serve proxies to that address. No port is published.
- **`connect`**: warden and Connect. warden reaches `connect-api` here.
  warden's listeners are not bound on this network.

Docker does not route between two bridge networks, so Connect cannot reach
`front`. (A container that can add routes or craft packets could still
send to warden's `front` address through warden's `connect` interface;
dropping `NET_ADMIN` and `NET_RAW`, as `cap_drop: [ALL]` does, prevents
that.)

### The Compose file

`/srv/warden/compose.yaml`, with the two Connect services from the previous
section:

```yaml
name: warden

services:
  warden:
    image: ghcr.io/pecheriere/warden:0.7.0@sha256:<digest>
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    # warden lets in-flight requests finish for up to 10 s on shutdown.
    stop_grace_period: 15s
    environment:
      WARDEN_DB_PATH: /data/warden.db
      WARDEN_AUDIT_PATH: /data/audit.jsonl
      WARDEN_AUDIENCE_PATH: /data/audience
      WARDEN_API_LISTEN: 172.31.250.10:8080
      WARDEN_APPROVAL_LISTEN: 172.31.250.10:8081
      WARDEN_PUBLIC_URL: https://warden.example.ts.net
      WARDEN_OWNER_LOGIN: owner@example.com
      WARDEN_OP_CONNECT_URL: http://172.31.251.11:8080
      WARDEN_OP_VAULT: Warden
      WARDEN_NOTIFY: homeassistant,ntfy
    # WARDEN_OP_CONNECT_TOKEN and the WARDEN_NOTIFY_* settings (mode 0600).
    env_file: ./warden.env
    volumes:
      - ./data:/data
    networks:
      front:
        ipv4_address: 172.31.250.10
        gw_priority: 100   # leave by "front" (Engine 28, Compose 2.33 or later)
      connect:
        ipv4_address: 172.31.251.10
    healthcheck:
      test: ["CMD", "/warden-server", "healthcheck"]
      interval: 30s
      timeout: 5s
      retries: 3

  # connect-api and connect-sync: see section 4.

networks:
  front:
    driver_opts:
      com.docker.network.bridge.name: br-warden
    ipam:
      config: [{subnet: 172.31.250.0/24}]
  connect:
    driver_opts:
      com.docker.network.bridge.name: br-warden-op
    ipam:
      config: [{subnet: 172.31.251.0/24}]
```

The addresses are examples: pick subnets that are free on your host.

**1. Prepare the data directory:**

```sh
cd /srv/warden
install -d -o 65532 -g 65532 -m 0700 data
```

**2. Complete `warden.env`**, which holds the secrets. It already has the
Connect token from [section 3](#3-1password); add the notification settings
from your secret manager, and keep the file mode 0600, owned by root:

```sh
WARDEN_OP_CONNECT_TOKEN=<written there in section 3>
WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL=https://ha.example.com/api/webhook/<id>
WARDEN_NOTIFY_NTFY_URL=https://ntfy.example.com/warden-<random>
```

Every variable is described in [Configuration](configuration.md).

About secrets on disk: Connect needs its credentials file on disk anyway,
so a root-only environment file next to it adds no new kind of exposure.
But anyone in the `docker` group can read the container's environment
(`docker inspect`), including the Connect token and the webhook URL: treat
`docker` group membership on this host as root.

**3. Start the stack:**

```sh
cd /srv/warden
docker compose config -q && docker compose up -d
```

The image has no `HEALTHCHECK` of its own (it has no shell): the Compose
file runs `/warden-server healthcheck`, which requests `/healthz` on
`WARDEN_API_LISTEN` and exits 0 when healthy.

### Relay targets

This layout leaves `WARDEN_RELAY_PUBLIC_ADDR` unset, so requests for relay
targets are refused. For relay targets, use
[the sidecar layout](#10-the-sidecar-layout-for-relay-targets).

## 6. Network rules

| Component | Inbound | Outbound |
|-----------|---------|----------|
| warden | Only from Tailscale Serve (or the reverse proxy Serve targets), to the listeners on `front`. | `connect-api`; the notification endpoints (Home Assistant, ntfy); the origins of your API secrets; the addresses of your relay targets. Nothing else. |
| connect-api | From warden, on `connect`; from `connect-sync` on its bus port. | `connect-sync` (the bus); your 1Password servers on 443. |
| connect-sync | From `connect-api` on its bus port. | `connect-api` (the bus); your 1Password servers on 443. |

- **No published ports**, on any of the three containers (`docker port
  <container>` prints nothing).
- **No listener on `0.0.0.0`.** Bind warden's listeners to its `front`
  address (or to loopback in the sidecar layout).
- **No other host-local access.** Nothing else on the host may connect to
  the listeners (see
  [who can reach the listeners](#who-can-reach-the-listeners)).
- **Certificate targets need no warden egress.** The agent connects to
  them directly with its certificate.

### Lock warden's egress

`front` is an ordinary bridge with the default route, so out of the box
warden can reach anything. Limit it with rules in Docker's `DOCKER-USER`
chain for the `br-warden` bridge, which sees every connection warden opens
to the outside (its traffic to Connect stays on `br-warden-op` and is not
affected). warden calls its upstreams directly and does not use an HTTP
proxy, so filter by address:

```sh
iptables -N WARDEN-EGRESS
iptables -A WARDEN-EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -A WARDEN-EGRESS -p tcp -d <home assistant address> --dport 443 -j RETURN
iptables -A WARDEN-EGRESS -p tcp -d <ntfy server address> --dport 443 -j RETURN
iptables -A WARDEN-EGRESS -p tcp -d <API secret origin address> --dport 443 -j RETURN
iptables -A WARDEN-EGRESS -p tcp -d <relay target address> --dport 22 -j RETURN
iptables -A WARDEN-EGRESS -j REJECT
iptables -I DOCKER-USER -i br-warden -j WARDEN-EGRESS
```

- One line per notification endpoint, API secret origin and relay target,
  with the port it uses. Name resolution needs no rule: Docker's embedded
  DNS resolver answers inside the container and queries upstream from the
  host.
- An address rule pins an IP, not a name. If an origin's addresses change
  (a CDN, for example), allow its published ranges, or reach it through a
  fixed address.
- The Compose networks are IPv4 only. If you enable IPv6 on them, add the
  same rules with `ip6tables`.
- Docker does not flush `DOCKER-USER`, but the rules are lost at reboot:
  load them from your firewall configuration or a systemd unit ordered
  after `docker.service`.
- Lock Connect's egress as described in
  [section 4](#4-1password-connect-hardened).

### Check the rules

From throwaway containers in the same network namespaces (warden's image
has no shell or HTTP client):

```sh
# warden's listeners are not reachable from Connect's network (must fail):
docker run --rm --network warden_connect curlimages/curl:<version> \
  -sS -m 5 http://172.31.250.10:8080/healthz
# warden cannot reach an address you did not allow (must fail):
docker run --rm --network container:warden-warden-1 curlimages/curl:<version> \
  -sS -m 5 -o /dev/null https://www.example.org/
```

And from **another machine on the LAN**, with a route to the container
network through the warden host (this must fail; it succeeds on Docker
Engine versions before 28):

```sh
sudo ip route add 172.31.250.0/24 via <warden host LAN address>
curl -sS -m 5 http://172.31.250.10:8080/healthz
sudo ip route del 172.31.250.0/24
```

## 7. Notifications

warden notifies the owner of each request through the channels listed in
`WARDEN_NOTIFY`, in order, falling back to the next on failure. A common
setup is a Home Assistant webhook automation with ntfy as the fallback.

If warden reaches Home Assistant over the tailnet, do **not** use
`local_only: true` on the webhook trigger: Home Assistant does not count a
tailnet address as local and refuses the call. The webhook id is then the
secret, so make it long and random. Details and the automation are in
[Notifications](notifications.md).

## 8. First start

Run these on the warden host, in `/srv/warden`.

1. **Enroll the owner's passkey**, on the phone:

   ```sh
   cd /srv/warden
   docker compose exec warden /warden-server enroll
   ```

   It prints a one-time code (valid for 10 minutes, single use) and the URL
   of the enrollment page, `https://warden.example.ts.net/enroll`. Open it on
   the phone, enter the code and create the passkey. You can enroll more
   than one; list and remove them with `warden-server passkey list` and
   `warden-server passkey remove <id>`.

2. **Set up each SSH target**, as described in [SSH targets](ssh-targets.md).

3. **Enroll each agent**, as described in [Agent usage](agent-usage.md):

   ```sh
   # A key-signed agent: paste the public key line (the content of its .pub
   # file) that the agent machine's user sent you:
   docker compose exec warden /warden-server agent add build-agent \
     --public-key 'ssh-ed25519 AAAA… build-agent'
   # Or a bearer-key agent; the key is printed once:
   docker compose exec warden /warden-server agent add build-agent
   ```

4. **Make a test request** from the agent machine, approve it on the phone,
   and check the audit log:

   ```sh
   docker compose exec warden /warden-server audit verify
   ```

## 9. Backups and upgrades

### What to back up

Everything warden keeps is in `/data` (`./data` on the host):

| File | Holds | If lost |
|------|-------|---------|
| `warden.db` (and `warden.db-wal`, `warden.db-shm`) | Requests, grants, agents, enrolled passkeys | Re-enroll every passkey and every agent. |
| `audit.jsonl` | The hash-chained audit log | The history is gone. |
| `audience` | The broker's audience id | Key-signed agents must log in again with the new one. |
| `relay_host_ed25519` | The relay's SSH host key | Agents see a new relay host key (they get it with each grant). |

The database runs in WAL mode, so copy it only while warden is stopped:

```sh
docker compose stop warden
rsync -a ./data/ /backup/warden-data/
docker compose start warden
```

warden stops within a few seconds (it lets requests in flight finish for up
to 10 s). Also ship the audit log somewhere the warden host cannot modify:
the hash chain detects edits, but whoever can rewrite the whole file can
rewrite the chain too.

The Connect data directory (`connect-data`) is a cache that Connect
rebuilds; the credentials file can be reissued with
`op connect server create`. Back up neither with warden's data.

### Upgrades

Schema migrations run at the first start of a new version and are
**one-way**: an older warden cannot open a database that a newer one has
migrated. So for every upgrade:

1. Read the [changelog](../CHANGELOG.md) for breaking changes and upgrade
   notes.
2. Verify the new image's attestation and note its digest:

   ```sh
   gh attestation verify oci://ghcr.io/pecheriere/warden:<version> --owner pecheriere
   ```

3. Stop warden and back up `/data` (above).
4. Pin the new digest in `compose.yaml` and run `docker compose up -d`.
5. To roll back, restore the backup of `/data` together with the previous
   image. Never start the previous image on a migrated database.

Do not let an automatic image updater upgrade warden: it would migrate the
database without a backup.

Upgrade the broker before the agents' `warden` CLIs when a release says so.

## 10. The sidecar layout, for relay targets

In this layout a Tailscale container is a dedicated tailnet node for warden
(here named `warden`, tagged `tag:warden`). warden runs in that container's
network namespace, so its listeners stay on loopback: only that node's
Serve can reach them, not other processes on the host. It publishes the
approval UI, the agent API and the SSH relay as three ports of the node.
Everything else in this guide (1Password, Connect, backups) is the same.

The Tailscale container settings below (`TS_*`) follow Tailscale's
documentation for its container image. This Compose file has not been run
end to end in exactly this form: check `tailscale serve status` and a test
request after the first start.

### The tailnet policy

```jsonc
{
  "hosts": {
    "owner-phone":   "<tailnet IP of the owner's phone>",
    "agent-machine": "<tailnet IP of the agent machine>",
  },
  "tagOwners": {
    "tag:warden": ["autogroup:admin"],
  },
  "grants": [
    // The approval UI (443) to the owner's phone only.
    {"src": ["owner-phone"],   "dst": ["tag:warden"], "ip": ["tcp:443"]},
    // The agent API (8443) and the SSH relay (2222) to the agent machines.
    {"src": ["agent-machine"], "dst": ["tag:warden"], "ip": ["tcp:8443", "tcp:2222"]},
  ],
  "tests": [
    {"src": "owner-phone",   "accept": ["tag:warden:443"],
                             "deny":   ["tag:warden:8443", "tag:warden:2222"]},
    {"src": "agent-machine", "accept": ["tag:warden:8443", "tag:warden:2222"],
                             "deny":   ["tag:warden:443"]},
  ],
}
```

As with Services: remove or narrow the default allow-all grant, and give
`tag:warden` no `funnel` node attribute. MagicDNS and HTTPS certificates
must be enabled for the tailnet.

### The auth key

In the admin console, generate an auth key that is **tagged** `tag:warden`,
**pre-approved**, **not reusable** and **not ephemeral** (the node keeps its
identity in its state directory). Write it to `/srv/warden/ts-authkey`, mode
0600. After the first successful start the node no longer needs it: delete
the file and remove the `secrets` entry.

### Serve configuration

`/srv/warden/serve.json`, applied by the container at every start, so the
configuration survives restarts. `${TS_CERT_DOMAIN}` is replaced with the
node's name (`warden.example.ts.net`):

```json
{
  "TCP": {
    "443":  {"HTTPS": true},
    "8443": {"HTTPS": true},
    "2222": {"TCPForward": "127.0.0.1:2222"}
  },
  "Web": {
    "${TS_CERT_DOMAIN}:443":  {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8081"}}},
    "${TS_CERT_DOMAIN}:8443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8080"}}}
  }
}
```

### The Compose file

The Connect services of [section 4](#4-1password-connect-hardened) stay as
they are. warden and the sidecar become:

```yaml
name: warden

services:
  tailscale:
    image: tailscale/tailscale:<version>@sha256:<digest>
    hostname: warden
    environment:
      TS_AUTHKEY: file:/run/secrets/ts-authkey
      TS_EXTRA_ARGS: --advertise-tags=tag:warden
      TS_STATE_DIR: /var/lib/tailscale
      TS_SERVE_CONFIG: /config/serve.json
      TS_USERSPACE: "true"
    secrets: [ts-authkey]
    volumes:
      - ./tailscale-state:/var/lib/tailscale
      - ./serve.json:/config/serve.json:ro
    networks:
      front:
        ipv4_address: 172.31.250.10
        gw_priority: 100
      connect:
        ipv4_address: 172.31.251.10

  warden:
    image: ghcr.io/pecheriere/warden:0.7.0@sha256:<digest>
    # warden's network is the sidecar's: no networks of its own, and the
    # listeners stay on their loopback defaults (127.0.0.1:8080, :8081,
    # and the relay on :2222).
    network_mode: service:tailscale
    depends_on: [tailscale]
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    stop_grace_period: 15s
    environment:
      WARDEN_DB_PATH: /data/warden.db
      WARDEN_AUDIT_PATH: /data/audit.jsonl
      WARDEN_AUDIENCE_PATH: /data/audience
      WARDEN_PUBLIC_URL: https://warden.example.ts.net
      WARDEN_OWNER_LOGIN: owner@example.com
      WARDEN_OP_CONNECT_URL: http://172.31.251.11:8080
      WARDEN_OP_VAULT: Warden
      WARDEN_NOTIFY: homeassistant,ntfy
      WARDEN_RELAY_PUBLIC_ADDR: warden.example.ts.net:2222
      WARDEN_RELAY_HOST_KEY_PATH: /data/relay_host_ed25519
    env_file: ./warden.env
    volumes:
      - ./data:/data
    healthcheck:
      test: ["CMD", "/warden-server", "healthcheck"]
      interval: 30s
      timeout: 5s
      retries: 3

  # connect-api and connect-sync: see section 4.

secrets:
  ts-authkey:
    file: ./ts-authkey

networks:
  front:
    driver_opts:
      com.docker.network.bridge.name: br-warden
    ipam:
      config: [{subnet: 172.31.250.0/24}]
  connect:
    driver_opts:
      com.docker.network.bridge.name: br-warden-op
    ipam:
      config: [{subnet: 172.31.251.0/24}]
```

Prepare and start:

```sh
cd /srv/warden
install -d -m 0700 tailscale-state
install -d -o 65532 -g 65532 -m 0700 data
docker compose config -q && docker compose up -d
docker compose exec tailscale tailscale serve status   # the three ports
```

Then:

- `WARDEN_PUBLIC_URL` is `https://warden.example.ts.net` (the approval UI
  on 443), agents log in with `https://warden.example.ts.net:8443`, and the
  relay is at `warden.example.ts.net:2222`, which every relay grant tells
  the agent.
- The relay's host key is created on first use at
  `/data/relay_host_ed25519` and must stay on the data volume, so that it
  does not change between restarts. Agents receive it pinned in each grant.
- Each relay target needs its item in the vault (`mode` `relay`, its pinned
  `host_keys` and one credential): see
  [SSH targets](ssh-targets.md#relay-targets).
- In userspace mode (`TS_USERSPACE: "true"`, which needs no capabilities
  or `/dev/net/tun`), warden's own connections leave through `front`, not
  through the tailnet. If warden must reach a notifier, an API origin or a
  relay target **over the tailnet**, run the sidecar in kernel mode
  instead (`TS_USERSPACE: "false"`, with `cap_add: [NET_ADMIN]` and
  `devices: [/dev/net/tun]`).
- The egress rules of [section 6](#lock-wardens-egress) apply to
  `br-warden` here too, but that bridge now also carries the sidecar's own
  Tailscale traffic (to Tailscale's coordination and relay servers, and to
  peers directly over UDP). Allow that traffic, or the node goes offline;
  the rules can no longer tell warden's connections from tailscaled's.
- Further hardening of the Tailscale container (a read-only root
  filesystem, dropped capabilities) has not been tested with this setup.

## 11. Checklist

- [ ] Docker Engine is 28 or later and Compose 2.33 or later.
- [ ] The host is tagged `tag:warden-host` (or the sidecar `tag:warden`);
      the tailnet policy has the grants and the tests above, the default
      allow-all grant is removed or narrowed, and the tests pass.
- [ ] The approval UI is granted to the owner's phone only, never to an
      agent machine.
- [ ] Funnel is off: no `funnel` node attribute for warden's tag, and
      `tailscale funnel status` lists nothing.
- [ ] The host runs nothing untrusted and no container with host networking
      (Services layout).
- [ ] The `Warden` vault holds only warden's items; the Connect server and
      its token cover that vault only, and the token is read-only.
- [ ] Connect runs as a dedicated uid with a passwd entry, a read-only root
      filesystem, no capabilities, and an explicit bus.
- [ ] Connect is on its own network and cannot reach warden's listeners.
- [ ] Connect's egress is limited to your 1Password servers; warden's to
      Connect, the notifiers, the API origins and the relay targets.
- [ ] No container publishes a port; no listener binds to `0.0.0.0`; a LAN
      machine with a route to the container network cannot reach warden.
- [ ] The image is pinned by a digest whose attestation you verified.
- [ ] `/data` is backed up with warden stopped, and before every upgrade.
- [ ] The audit log is shipped somewhere the host cannot modify.
