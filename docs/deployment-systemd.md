# Running warden without Docker

[The Docker deployment](deployment.md) stays the recommended setup. This page
runs `warden-server` as a hardened systemd service instead, for hosts where you
would rather not run warden in a container. It is less isolated than the
container in several ways, which
[the first section](#1-what-holds-what-is-replaced-what-is-lost) lists one by
one. Read that section before you choose it.

Status:

- **It has not been tested on a clean host.** The unit
  ([`deploy/systemd/warden.service`](../deploy/systemd/warden.service)) has only
  been started in a privileged container on arm64: see
  [What has been tested](#10-what-has-been-tested).
- **It needs a release later than 0.8.1.** The unit passes secrets through the
  `*_FILE` variables, which 0.8.1 does not have. On 0.8.1 the service refuses to
  start, because the Connect token is missing.
- **It does not support SSH relay targets.** They need
  [the sidecar layout](deployment.md#10-the-sidecar-layout-for-relay-targets),
  which is a Docker layout.
- **Published server binaries are planned, not available.** For now you build
  from source at a release tag. This also means there is no build attestation to
  verify yet.

Everything about the tailnet and 1Password that is not repeated here applies
unchanged: the tailnet policy and its tests, keeping Funnel off and the vault
setup, in sections [2](deployment.md#2-tailscale) and
[3](deployment.md#3-1password) of the deployment guide.

The placeholder names are those of the deployment guide.

Contents:

1. [What holds, what is replaced, what is lost](#1-what-holds-what-is-replaced-what-is-lost)
2. [1Password Connect is still a container](#2-1password-connect-is-still-a-container)
3. [Install](#3-install)
4. [Keep the listeners private](#4-keep-the-listeners-private)
5. [Limit warden's egress](#5-limit-wardens-egress)
6. [Who can read the Connect token](#6-who-can-read-the-connect-token)
7. [Server commands](#7-server-commands)
8. [Backups](#8-backups)
9. [Upgrades and rollback](#9-upgrades-and-rollback)
10. [What has been tested](#10-what-has-been-tested)
11. [Checklist](#11-checklist)

## 1. What holds, what is replaced, what is lost

| Guarantee of the Docker setup | Here |
|-------------------------------|------|
| Non-root process | **Holds.** A dedicated `warden` user. |
| No capabilities, no new privileges | **Holds.** Empty `CapabilityBoundingSet`, `NoNewPrivileges`, and a private user namespace. |
| Read-only root filesystem, one writable data path | **Holds.** `ProtectSystem=strict`, and only `/var/lib/warden` is writable. |
| No published ports, nothing on `0.0.0.0` | **Replaced.** The listeners stay on loopback, warden's defaults. |
| Other LAN machines cannot route to the listeners (the reason for Docker Engine 28) | **Replaced.** The kernel drops packets for loopback addresses that arrive on another interface, as long as `route_localnet` stays 0. See [section 4](#4-keep-the-listeners-private). |
| Connect cannot reach warden's listeners | **Holds.** Connect runs in a container or on another host, and neither can reach this host's loopback. See [section 2](#2-1password-connect-is-still-a-container). |
| Egress limited to what warden needs | **Replaced, and differs.** `IPAddressDeny` and `IPAddressAllow` filter by address only, not by port, but they also cover tailnet addresses, which the `DOCKER-USER` rules do not. See [section 5](#5-limit-wardens-egress). |
| The Connect token readable only by root and the `docker` group | **Improved.** Root and the `warden` user. It is no longer in the process environment. See [section 6](#6-who-can-read-the-connect-token). |
| Docker's default seccomp and AppArmor profiles | **Partly replaced.** `SystemCallFilter` takes the place of the seccomp profile. No AppArmor or SELinux profile ships with warden. |
| Restart on failure | **Holds.** `Restart=on-failure`. |
| Graceful stop | **Holds.** `TimeoutStopSec=15s`, as `stop_grace_period` in Compose. |
| Image with no shell or other programs | **Partly lost.** See below. |
| Own filesystem | **Lost.** See below. |
| Own network namespace | **Lost.** See below. |
| Only warden can use the listeners' address | **Lost.** See below. |
| Image pinned by digest, with a verified build attestation | **Lost for now.** See below. |
| Runtime libraries fixed by the image | **Lost.** See below. |
| Health status (`docker ps`) | **Lost.** `warden-server healthcheck` still works; run it from your monitoring. |
| The sidecar layout, and with it relay targets | **Lost.** Use Docker for relay targets. |

What each loss means:

- **warden can see the host.** The image holds warden and nothing else. Here,
  code running in warden can read every world-readable file on the host, such as
  `/etc`. `NoExecPaths=/` keeps it from running a shell or other programs (only
  `/usr/local/lib/warden` and the library directories stay executable, because the
  dynamic loader needs them), but `/usr/lib` still holds some programs. Keep
  secrets of other services off this host, and in files that only they can read.
- **warden shares the host's network stack.** It has no address of its own and
  can connect to anything else listening on the host's loopback, because
  `IPAddressAllow=localhost` is what lets Tailscale Serve reach it. It has no
  access to Unix sockets, such as tailscaled's. Run nothing else on this host that
  trusts local connections.
- **Any local user can take a listener's port while warden is down.** A container's
  address can only be bound inside that container. Ports 8080 and 8081 on loopback
  can be bound by any process when warden is stopped, and Tailscale Serve would then
  send the owner's requests to that process. It would not get an approval (the
  passkey is bound to the request on the real server), but it could show a false
  page. Moving to low ports would stop this at the cost of a capability, which this
  unit does not give. So a dedicated host is a requirement here, as
  [below](#4-keep-the-listeners-private).
- **There is no provenance to verify yet.** You trust the tag, your toolchain and
  the machine that builds. Record the commit you built. Published binaries with
  attestations are planned.
- **The host supplies glibc.** The rest is linked statically: Rust crates and, with
  the feature below, OpenSSL. Host updates patch glibc, so restart warden after them,
  and only a new warden release patches the rest. The binary must not be built
  against a newer glibc than the host's.

The result is a smaller attack surface on the host (no container runtime, if Connect
runs elsewhere), and a larger one if warden itself is compromised. That is why Docker
stays the recommendation.

## 2. 1Password Connect is still a container

With 1Password, the recommended backend, warden reads its policy through Connect,
which 1Password ships only as container images. There are no binaries, so **with
1Password, no setup of warden is free of containers**. "Without Docker" here means
that warden does not run in one, and you choose where Connect does. The other way is
[local files](local-backend.md#with-systemd), with no Connect and no container, at
the price that a compromised host gets every secret.

- **On another host (the only way to have no container runtime on the warden host).**
  Run Connect there, hardened as in
  [section 4 of the deployment guide](deployment.md#4-1password-connect-hardened).
  warden's token travels over the network, so it must not cross it in clear: use the
  tailnet. Publish `connect-api` on that host as its own Service, with
  `tailscale serve --service=svc:warden-connect --https=443 --bg http://<connect-api address>:8080`,
  grant that Service to `tag:warden-host` only, and set
  `WARDEN_OP_CONNECT_URL=https://warden-connect.example.ts.net`. The cost is a second
  machine to keep as locked down as this one, since it holds the credentials
  file. warden is then unavailable when that machine or the path to it is down. This
  layout has not been tested.
- **On the same host, in Docker.** Use the two Connect services and the `connect`
  network of [the deployment guide](deployment.md#4-1password-connect-hardened), with
  no `warden` service and no `front` network, and set
  `WARDEN_OP_CONNECT_URL=http://172.31.251.11:8080`. The host reaches that address
  directly, with no published port. The cost: Docker is still on the host, so Engine
  28 is still required to keep other LAN machines from routing to the container, and
  `docker` group membership still equals root. Leave Docker's `userland-proxy` at its
  default, because turning it off sets `route_localnet` on Docker's bridges (see
  [section 4](#4-keep-the-listeners-private)). You do gain something over the
  full Docker setup: the `docker` group can no longer read warden's token with
  `docker inspect`. Another container runtime, such as Podman, has not been tested.

Either way, Connect cannot reach warden's listeners. They are on the loopback interface
of the warden host, which neither another machine nor a container on its own network
can reach. Limit Connect's egress as the deployment guide describes.

## 3. Install

You need systemd 249 or later with cgroup v2, a tagged host on the tailnet as in
[the deployment guide](deployment.md#2-tailscale), and the `ca-certificates` package
(warden verifies TLS with the system's roots). Check `systemctl --version` for
`+BPF_FRAMEWORK`: without it, as on Debian 12, `SocketBindAllow` and `SocketBindDeny`
have no effect. `IPAddressDeny` needs only cgroup v2.

### Build from source

Build at a release tag, on a machine with the same architecture and the same or an
older glibc than the host, so that the host needs no compiler. The repository's
`rust-toolchain.toml` selects the toolchain if you have
[rustup](https://rustup.rs/). The build also needs a C compiler, `make` and `perl`,
because `vendored-openssl` compiles OpenSSL and links it statically, as the image does.

```sh
git clone --depth 1 --branch <version tag> https://github.com/pecheriere/warden
cd warden
git rev-parse HEAD   # record the commit you built
cargo build --release --locked -p warden-broker --features vendored-openssl
```

The binary is `target/release/warden-server`.

### Prepare the host

Install each version under its own name and point a symlink at it, so that a rollback
only moves the link. The unit allows execution in `/usr/local/lib/warden` and nowhere
else in `/usr/local`, so the binary must be there.

```sh
sudo useradd --system --user-group --home-dir /var/lib/warden --no-create-home \
  --shell /usr/sbin/nologin warden
sudo install -d -m 0755 /usr/local/lib/warden
sudo install -m 0755 warden-server /usr/local/lib/warden/warden-server-<version>
sudo ln -sfn /usr/local/lib/warden/warden-server-<version> /usr/local/bin/warden-server
sudo install -m 0644 deploy/systemd/warden.service /etc/systemd/system/warden.service
sudo install -d -m 0755 /etc/warden /etc/systemd/system/warden.service.d
sudo install -d -m 0700 /etc/warden/credentials
```

`/etc/warden/warden.conf` holds the settings that are not secret. It can be
world-readable, so **no secret goes in it**. The commands of
[section 7](#7-server-commands) load it as a shell file, so keep each line a plain
`NAME=value`:

```sh
WARDEN_PUBLIC_URL=https://warden.example.ts.net
WARDEN_OWNER_LOGIN=owner@example.com
WARDEN_OP_CONNECT_URL=https://warden-connect.example.ts.net
WARDEN_OP_VAULT=Warden
WARDEN_NOTIFY=homeassistant,ntfy
```

Do not set `WARDEN_API_LISTEN` or `WARDEN_APPROVAL_LISTEN`: their defaults are
loopback. [Every other setting](configuration.md) that is not secret can go in this
file too. The unit itself sets the paths of the data files, because warden's default
for the audience is under `/data`, which does not exist here.

### Secrets

Each secret is a root-only file in `/etc/warden/credentials`. systemd copies it at
start to a directory in memory that only the `warden` user can read, and warden
receives only the path, through a variable ending in `_FILE`
([Configuration](configuration.md#secrets-in-files)). So the secret is not in an
environment file, the process environment or the output of `systemctl show`.

Write the Connect token as you issue it (see
[section 3 of the deployment guide](deployment.md#3-1password) for the vault and
the server):

```sh
op connect token create warden-read --server warden-connect --vault Warden,r \
  | ssh root@<warden host> 'umask 077; cat > /etc/warden/credentials/op-connect-token'
```

Write the notifier secrets the same way, then add them in a drop-in,
`/etc/systemd/system/warden.service.d/site.conf`, which is also where
[the egress rules](#5-limit-wardens-egress) go. A `LoadCredential` whose file is
missing stops the service from starting (status `243/CREDENTIALS`), so list only those
you use:

```ini
[Service]
LoadCredential=ha-webhook-url:/etc/warden/credentials/ha-webhook-url
Environment=WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL_FILE=%d/ha-webhook-url
LoadCredential=ntfy-url:/etc/warden/credentials/ntfy-url
Environment=WARDEN_NOTIFY_NTFY_URL_FILE=%d/ntfy-url

IPAddressAllow=192.0.2.53
IPAddressAllow=192.0.2.10
```

The source files are in clear on disk, as `warden.env` is in the Docker setup. With
`systemd-creds encrypt` and `LoadCredentialEncrypted=` they would be useless on a
stolen disk or backup, tied to the host's TPM or credential key. It needs
systemd 250 or later, and does not stop root on the running host.

### Start

```sh
sudo systemd-analyze verify /etc/systemd/system/warden.service
sudo systemctl daemon-reload
sudo systemctl enable --now warden.service
systemctl status warden.service
sudo systemd-analyze security warden.service   # the hardening as systemd sees it
```

warden logs to the journal. That includes every audit entry (goals, agents, targets,
no secrets), so anyone in the `adm` or `systemd-journal` group can read them, where
in the Docker setup it took the `docker` group. Keep those groups as narrow.

Then publish the Services, and continue with the
[first start](deployment.md#8-first-start), using the commands of
[section 7](#7-server-commands):

```sh
sudo tailscale serve --service=svc:warden     --https=443 --bg http://127.0.0.1:8081
sudo tailscale serve --service=svc:warden-api --https=443 --bg http://127.0.0.1:8080
```

If you are moving from the Docker setup, stop the `warden` container and copy its
data before the first start, with its owner changed:
`sudo rsync -a --chown=warden:warden /srv/warden/data/ /var/lib/warden/`. Keep
`WARDEN_PUBLIC_URL` the same, or every passkey must be enrolled again.

## 4. Keep the listeners private

warden trusts the `Tailscale-User-Login` header, so anything that can connect to a
listener directly can forge it (see
[who can reach the listeners](deployment.md#who-can-reach-the-listeners)).

**From other machines.** Docker Engine 28 is a requirement of the Docker setup because
older versions let another LAN machine route to a container's address. Loopback has
its own protection, from the kernel: it drops packets for `127.0.0.0/8` that arrive on
any other interface. That needs `route_localnet` to stay 0. Some software turns it on,
such as Docker with `userland-proxy` off (on its bridges) and kube-proxy, so check all
of them. Then check that warden is on loopback only:

```sh
sysctl -a 2>/dev/null | grep route_localnet    # every line must end in 0
sudo ss -tlnp | grep warden-server             # only 127.0.0.1:8080 and 127.0.0.1:8081
```

The unit's `IPAddressDeny` also drops traffic from addresses it does not allow, so
a listener bound to `0.0.0.0` by mistake would not be open to the whole LAN. Do not
rely on that: an allowed address could still connect.

**From this host.** As in the Docker layout with Tailscale Services, **every process
on the host can connect to the listeners and forge the owner's login**, so the whole
host is inside the trust boundary, not only its root. A forged login cannot approve
anything, but it can read `/pending`, `/grants` and `/history`, revoke grants, deny
any pending request, replace approval links so that the one in a notification stops
working, and use a stolen bearer agent key. So the same rules apply:

- Dedicate the host to warden and its Connect, with no untrusted local users and
  no other services that run untrusted code.
- Run nothing else as the `warden` user.
- If Docker is on the host, run no container with host networking.
- Optionally, refuse local connections that do not come from tailscaled, which runs
  as root. Load the rule at boot, as
  [the deployment guide](deployment.md#lock-wardens-egress) does for its rules, and
  note that it also blocks `warden-server healthcheck` unless you run that as root:

  ```sh
  iptables -I OUTPUT -o lo -p tcp -m multiport --dports 8080,8081 \
    -m owner ! --uid-owner 0 -j REJECT
  ```

  This rule does not stop root, or a process that takes over the port (see
  [section 1](#1-what-holds-what-is-replaced-what-is-lost)).

The sidecar layout, where nothing on the host can reach the listeners, has no
equivalent here. If you need that property, use it.

## 5. Limit warden's egress

The unit starts from `IPAddressDeny=any` and `IPAddressAllow=localhost`, so until you
add addresses warden can reach nothing but loopback. **Requests and notifications fail
until the drop-in allows what they need:**

- Connect's address;
- the DNS resolvers in `/etc/resolv.conf`, if they are not on loopback. A blocked
  resolver looks like every upstream failing, with `error sending request` in the
  log. With MagicDNS, that resolver is `100.100.100.100`;
- every address of each notifier and API origin. A name with several addresses needs
  them all.

This differs from the Docker rules in three ways:

- **No ports.** An allowed address is allowed on every port. To limit ports too, add
  host firewall rules that match the user:
  `iptables -A OUTPUT -m owner --uid-owner warden ...`.
- **Tailnet addresses are covered**, because the filter applies to the service, not to
  an interface. In the Docker setup they can bypass `DOCKER-USER`. The tailnet policy
  remains the control over what the host may reach.
- **It does not fail closed if the kernel cannot do it.** Without cgroup v2 the
  service starts unfiltered. So check that it works on your host. This must fail:

  ```sh
  sudo systemd-run --pipe --wait --collect -p IPAddressDeny=any -p IPAddressAllow=localhost \
    curl -sS -m 5 -o /dev/null https://www.example.org/
  ```

An address rule pins an IP, not a name, so the note about CDNs in
[the deployment guide](deployment.md#lock-wardens-egress) applies here too.

## 6. Who can read the Connect token

| | Docker | systemd |
|---|--------|---------|
| At rest | `warden.env`, root-only | `/etc/warden/credentials/op-connect-token`, root-only |
| While running | The process environment | A file in `/run/credentials/warden.service`, in memory and not swapped, mode 0400 |
| Root | Yes | Yes |
| `docker` group | Yes, with `docker inspect` | No, unless Connect's credentials are on the same host, where that group still means root |
| warden's user | Yes | Yes: **anything running as `warden` can read it**, including [the commands below](#7-server-commands) |
| Other local users | No | No |
| `systemctl show` | Not applicable | Shows only the path |
| Core dumps and swap | Depends on the host | `LimitCORE=0` and `MemorySwapMax=0` keep warden's memory out of both |

In both setups the token is in warden's memory while it runs, and root on the host can
read it from there. The host remains the root of trust. warden reads the token at
start, so restart it after you replace the file.

## 7. Server commands

Run the commands of [Configuration](configuration.md#server-commands) as the `warden`
user, with its settings. Add this function to the shell of whoever administers the
host:

```sh
warden_admin() {
  sudo -u warden sh -c 'umask 077; set -a; . /etc/warden/warden.conf
    WARDEN_DB_PATH=/var/lib/warden/warden.db
    WARDEN_AUDIT_PATH=/var/lib/warden/audit.jsonl
    WARDEN_AUDIENCE_PATH=/var/lib/warden/audience
    exec /usr/local/bin/warden-server "$@"' warden-admin "$@"
}
```

Where other pages say `docker compose exec warden /warden-server <command>`, run
`warden_admin <command>`, for example `warden_admin enroll`, `warden_admin audit verify`
or `warden_admin agent add build-agent --public-key '<line>' --server <url>`. These
commands do not read the Connect token. **`doctor` is the exception**, below.

### Doctor

[`warden-server doctor`](configuration.md#checking-a-setup) needs the same secrets as the
server, and those are in the unit's credentials. systemd keeps them in
`/run/credentials/warden.service` while the service runs, and the `warden` user can read
them there. So point doctor at those files, with one line per `LoadCredential` of your
unit and drop-in. Remove the lines of the secrets you do not use:

```sh
warden_doctor() {
  sudo -u warden sh -c 'umask 077; set -a; . /etc/warden/warden.conf
    WARDEN_DB_PATH=/var/lib/warden/warden.db
    WARDEN_AUDIT_PATH=/var/lib/warden/audit.jsonl
    WARDEN_AUDIENCE_PATH=/var/lib/warden/audience
    WARDEN_OP_CONNECT_TOKEN_FILE=/run/credentials/warden.service/op-connect-token
    WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL_FILE=/run/credentials/warden.service/ha-webhook-url
    WARDEN_NOTIFY_NTFY_URL_FILE=/run/credentials/warden.service/ntfy-url
    exec /usr/local/bin/warden-server doctor "$@"' warden-doctor "$@"
}
```

Run `warden_doctor`, or `warden_doctor --send-test-notification`. What differs from the
Docker setup:

- **The service must be running.** When it is stopped, so that the files are gone, `config`
  fails with `cannot read the file named by WARDEN_<...>_FILE: entity not found`, and
  everything else is not checked. This means a service that fails to start cannot be
  checked this way: read `journalctl -u warden.service`, which names the bad setting.
- **Doctor runs outside the unit's sandbox.** Its `connect.*`, `ssh-ca` and `notify.*`
  checks do not go through `IPAddressAllow`, so a pass does not show that the service can
  reach the same address. A request that fails in the journal with `error sending request`
  points at the allow list ([section 5](#5-limit-wardens-egress)). A test request, as in
  [the first start](deployment.md#8-first-start), is what exercises the real path.
- **Some of its advice mentions a container.** Where it says to run inside the container
  or the `front` network, this means running `warden_doctor` on the host, with the
  listeners on loopback.
- **This cannot be made simpler with `systemd-run`.** A transient unit gets only the
  credentials and settings you repeat on its command line, and none from your drop-in, so
  it would be longer and would still not be the same sandbox.

## 8. Backups

Everything warden keeps is in `/var/lib/warden`, with the same files as
[in the Docker setup](deployment.md#what-to-back-up). The database runs in WAL mode, so
copy it only while warden is stopped:

```sh
sudo systemctl stop warden.service
sudo install -d -m 0700 /var/backups/warden
sudo rsync -a /var/lib/warden/ /var/backups/warden/current/
sudo systemctl start warden.service
```

Copy backups off the host, and ship the audit log somewhere the host cannot modify.
The credentials in `/etc/warden/credentials` can be issued again, and are better kept
out of data backups. On a new host, the `warden` user can have another uid: restore
with `rsync -a --chown=warden:warden`, because warden refuses a relay key it does not
own.

## 9. Upgrades and rollback

Schema migrations run at the first start of a new version and are **one-way**: an older
warden cannot open a database that a newer one has migrated. So a rollback needs
**both the old binary and the data backed up before the upgrade**. No package manager or
updater should replace the binary, as it would migrate without a backup.

1. Read the [changelog](../CHANGELOG.md) for breaking changes and upgrade notes.
2. Build the new tag ([above](#build-from-source)) and install it next to the old
   binary. Do not delete the old one:

   ```sh
   sudo install -m 0755 warden-server /usr/local/lib/warden/warden-server-<new version>
   ```

3. Stop warden and back up its data under the old version's name:

   ```sh
   sudo systemctl stop warden.service
   sudo install -d -m 0700 /var/backups/warden
   sudo rsync -a /var/lib/warden/ /var/backups/warden/before-<new version>/
   ```

4. Move the link, take any changes to the unit from the new tag, and start:

   ```sh
   sudo ln -sfn /usr/local/lib/warden/warden-server-<new version> /usr/local/bin/warden-server
   sudo install -m 0644 deploy/systemd/warden.service /etc/systemd/system/warden.service
   sudo systemctl daemon-reload
   sudo systemctl start warden.service
   ```

To roll back, restore that backup together with the old binary. **Never start the old
binary on a migrated database.** Everything since the upgrade is lost: requests, grants,
new agents and passkeys, and audit entries, so ship the audit log first if you can.

```sh
sudo systemctl stop warden.service
sudo rsync -a --delete /var/backups/warden/before-<new version>/ /var/lib/warden/
sudo ln -sfn /usr/local/lib/warden/warden-server-<old version> /usr/local/bin/warden-server
sudo systemctl start warden.service
```

Delete the old binary and its backup once you no longer need to go back. Upgrade the
broker before the agents' `warden` CLIs when a release says so.

## 10. What has been tested

The unit was run under systemd 252 (Debian 12) and 257 (Debian 13), inside a privileged
container on arm64, with a binary built by the repository's Dockerfile. There:

- `systemd-analyze verify` printed nothing, and `systemd-analyze security` rated the
  unit at 1.0.
- warden started with every setting in the unit and read its secrets from credentials,
  which did not appear in `/proc/<pid>/environ` or `systemctl show`.
- On 257, `warden_doctor` read the running unit's credentials and passed `config`,
  `connect.*`, `ssh-ca`, `listener.*` and `data.*`, against a small fake Connect server on
  loopback, and its failure with no passkey enrolled was right. With the flag it sent one
  message to a fake ntfy server. It printed no secret, and with the service stopped it
  failed as described in [section 7](#doctor). `warden_admin agent add` printed the
  `warden login` command with the audience.
- On 257, the `warden_admin` function printed an enrollment code, listed agents and
  verified the audit log.
- On 257, the file steps of the upgrade and rollback worked, with the same binary under a
  second name, so no migration ran.
- On 252, DNS, TLS verification and an HTTPS call from inside the sandbox worked. Blocking the
  resolver or the destination with `IPAddressAllow` made them fail.
- `SocketBindDeny` refused a bind on 257, and had no effect on 252, which lacks
  `BPF_FRAMEWORK`. `NoExecPaths` stopped a shell from running.
- A missing credential stopped the service from starting.

**Not tested:** a clean host or amd64, a real Connect server (the sandboxed call went to
another HTTPS server), Tailscale Serve and Services, a passkey approval, a notification,
an upgrade or rollback across a real migration, and an attempt to reach the listeners from
another LAN machine. A container also differs from a host, so a failure on a real host
would not be a surprise yet; please report one.

## 11. Checklist

- [ ] You read [section 1](#1-what-holds-what-is-replaced-what-is-lost) and accept what
      is lost, compared with Docker.
- [ ] The tailnet policy, its tests and Funnel are set up as in
      [the deployment guide](deployment.md#2-tailscale).
- [ ] The host is dedicated to warden and its Connect, with no untrusted local users;
      nothing else runs as `warden`.
- [ ] `ss` shows the listeners on `127.0.0.1` only, and every `route_localnet` is 0.
- [ ] The secrets are in root-only files under `/etc/warden/credentials`, loaded with
      `LoadCredential`. None is in `warden.conf` or in `Environment=`.
- [ ] Connect's token is read-only and for the `Warden` vault only, and Connect's own
      egress is limited.
- [ ] The drop-in allows only the addresses warden needs, and the `IPAddressDeny` check
      fails as it should on this host.
- [ ] You recorded the commit you built, at a release tag.
- [ ] `/var/lib/warden` is backed up with warden stopped, before every upgrade, and the
      previous binary is kept until you no longer need to roll back.
- [ ] The audit log is shipped somewhere the host cannot modify.
