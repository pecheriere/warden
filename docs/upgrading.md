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

## Private files

From the next release, warden keeps its files private to its user, and corrects
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

`warden-server doctor` reports all of these. Run it on the new version before
switching over, as older versions have no `doctor`: for Docker, pull the new image
and run `docker compose run --rm warden doctor`. It changes nothing.

## Plain http URLs

From the next release, warden refuses to start when `WARDEN_OP_CONNECT_URL`,
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
