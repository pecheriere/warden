# Upgrading

**Only the latest release gets fixes, including security fixes.** warden does
not maintain older versions: the way to get a fix is to upgrade. See the
[security policy](../SECURITY.md).

warden uses [Semantic Versioning](https://semver.org/). Before 1.0, a release can
include breaking changes. To hear about new releases, watch the repository on
GitHub and choose **Custom**, then **Releases**.

## Upgrade the server

Schema migrations run at the first start of a new version, in order, so you can
move across several releases at once. They are **one-way**: an older warden
cannot open a database that a newer one has migrated. So before every upgrade:

1. Read the [changelog](../CHANGELOG.md) for every release you are moving across,
   for breaking changes and upgrade notes.
2. Back up warden's data, with warden stopped.

Then follow the steps for your setup, which include how to roll back:

- [Docker](deployment.md#upgrades)
- [systemd](deployment-systemd.md#9-upgrades-and-rollback)

Do not let an automatic updater upgrade warden, because it would migrate the
database without a backup.

## Fingerprints as words

From 0.10.0, the approval pages and `warden request` write a
fingerprint as five words, with the hex form beside them. They are the same 48
bits, so there is nothing to migrate, and you can upgrade the broker and the CLI in
either order:

| Broker | CLI | What you compare |
|---|---|---|
| New | New | The words, on both |
| New | 0.9.0 or older | The CLI prints hex: compare it with the hex under the words on the page |
| 0.9.0 or older | New | The page shows hex: compare it with the hex in brackets in the CLI's line |

Every pair agrees on the hex. The CLI's own check of what the broker answers
still compares hex, so no pair refuses a request because of this. The API, an agent
that computes a fingerprint itself, stored requests and the audit log are unchanged,
and requests made before the upgrade show their words too.

A script that reads the fingerprint from `warden request`'s stderr needs checking:
the line is now `fingerprint <words> (<hex>)`. Prefer the API's `fingerprint` field.

## Private files

From 0.9.0, warden keeps its files private to its user, and corrects
their permissions when it starts. Most setups need do nothing, but check these:

- **A tool reading warden's data as another non-root user**, such as a backup job
  using group permissions, loses access. Run it as warden's user or as root. The
  `rsync -a` commands in the deployment guides run as root and keep the modes, so
  their copies stay private too.
- **A symbolic link in place of the database, the audit log or the audience** is
  refused. Point the setting at the file itself.
- **A file warden cannot correct**, because another user owns it or it is on a
  read-only mount, stops it at start with a message naming the file. Change it as
  its owner or as root.
- **A data directory others can write to** stops warden at start if warden cannot
  correct it. See [which directories it corrects](configuration.md#the-data-directory).

`warden-server doctor` reports these, and it changes nothing. Older versions have
no `doctor`, so run it on the new version. For Docker, stop warden, as the documented
Compose file gives it a fixed address that a second container cannot share, then
change the image pin in your Compose file to the new version and run
`docker compose run --rm warden doctor`, which pulls it. Read the result
with care, as warden is not running and has not started on the new version yet:

- The listener checks fail because nothing is listening. That is expected here.
- A loose mode also fails, even on a file the server would correct at start. Only
  the cases above stop the server.

Run it again with `docker compose exec` once warden is up.

## Plain http URLs

From 0.9.0, warden refuses to start when `WARDEN_OP_CONNECT_URL`,
`WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL` or `WARDEN_NOTIFY_NTFY_URL` is plain
`http` to a host that is not clearly local or private. The error names the
variable.

Nothing changes for `https` URLs, for private and tailnet addresses such as
`http://172.31.251.11:8080`, or for names such as `http://connect:8080` and
`http://homeassistant.local:8123`. A plain `http` URL with a `.ts.net` name is
refused: use `https`, as the documented setups do, or a tailnet address. See the
[full list](configuration.md#plain-http). `warden-server doctor` shows what a
setup uses, in its `plain-http` check, so run it on the new version before
switching over.

If yours is refused, change the URL to `https`, or to a tailnet address. If that
path really is safe, keep the URL and list the variable in
`WARDEN_ALLOW_PLAIN_HTTP`. warden then warns about it at every start.

## Upgrade the CLI

Install the new version as in [Agent usage](agent-usage.md#one-time-setup).
Upgrade the server before the agents' CLIs when a release says so.
