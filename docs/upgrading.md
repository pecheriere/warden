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

## Upgrade the CLI

Install the new version as in [Agent usage](agent-usage.md#one-time-setup).
Upgrade the server before the agents' CLIs when a release says so.
