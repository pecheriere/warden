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

## GitHub tokens and the repository

After upgrading the CLI past 0.12.0, run `warden setup github` again on every machine
where an agent uses it. It sets `credential.https://github.com.useHttpPath` and
rewrites the `gh` wrapper to pass `gh`'s arguments to warden. Until then `warden
doctor` fails its `github.token` check, git sends warden no repository, and an old
wrapper does not pass `-R` to warden. A `gh` run outside a checkout needs `-R
owner/name`.

## The permission is actions_variables, not variables (0.18.1)

0.18.0 named the sensitive permission for a repository's Actions variables `variables`. GitHub's
key is `actions_variables`, which an installation never reported as `variables`, so every request
for it was refused. 0.18.1 renames it, with no alias: it stays sensitive (extras only, named by
the agent, `15m`, `30m` or `1h`), and `variables` is an unknown name.

Upgrade in this order:

1. Let any active or pending `variables` grant or request end, or revoke it: the broker reads a
   stored grant strictly, and after the upgrade one that names `variables` makes that agent's
   GitHub token lookups and the grants page fail until it expires (at most `1h`). None could
   mint a token under 0.18.0, so revoking one loses nothing.
2. Remove `variables` from `extra_permissions` on the `warden:github-app` item, **before**
   upgrading the broker: 0.18.1 does not know the name, and an unknown name there turns off every
   GitHub token.
3. Upgrade the broker.
4. Add `actions_variables:read` or `actions_variables:write` to `extra_permissions`. The GitHub App
   must also hold the Variables permission: see [Permissions](github-app.md#permissions).

## The sensitive permission variables (0.18.0)

`variables` (a repository's Actions variables) was a sensitive GitHub permission from this
release, but GitHub's name for it is `actions_variables`: see
[the rename in 0.18.1](#the-permission-is-actions_variables-not-variables-0181). Otherwise it
was allowed in `extra_permissions` only, named by the agent, and granted for `15m`, `30m` or
`1h`. Upgrade the broker before adding it to `extra_permissions` on the `warden:github-app`
item: an older broker does not know the name, and an unknown name there turns off every GitHub
token. The GitHub App must also hold the Variables permission: see
[Permissions](github-app.md#permissions).

## Extra GitHub permissions only when named (0.17.0, breaking)

**A GitHub token now carries an extra permission only when the request names it.** Until
now, a mint that named no permissions got the grant's whole set, extras included. After
upgrading the broker, it gets the owner's current `default_permissions`, limited to what the
grant holds, and GitHub refuses whatever needs an extra. An agent that relied on its grant's
extras by default names them on the command that needs them:

```sh
WARDEN_GITHUB_PERMISSIONS=contents:write,workflows:write git push    # a workflow change
GH_TOKEN=$(warden github token --repo owner/name --permissions actions:write) gh run rerun …
```

The broker mints from the least privileged grant that holds what is named. A CLI older
than this release can still name permissions with `warden github token --permissions`,
but its `git-credential` cannot, so a push that changes a workflow needs this release's
CLI. A default the owner narrowed since a grant was approved now narrows that grant's plain
tokens; a widened default never widens them. Nothing is migrated.

Approving a GitHub grant now ends only the agent's grants on the same repositories with the
same extras; the others stay live and the approval page lists them under "Also live". Upgrade
the broker first. The CLI's token cache is now version 4 (`github-token.json`): an older
file is ignored and replaced. A plain token cached before the broker's upgrade, by an older
CLI or by this one against the older broker, may still carry the grant's extras until it
expires, within the hour. A GitHub request that was pending at the upgrade is not matched by
an identical one made after it, which waits beside it until the first is decided or
expires; approving both is harmless, as the second replaces the first.

## Extra GitHub permissions (0.16.0)

`warden request github --extra-permissions` and `warden github token --permissions` send
fields that a 0.15.0 or older broker refuses, so upgrade the broker first if agents will use
them. Requests and tokens without them work with either version. The owner allows extras with
`extra_permissions` on the `warden:github-app` item, and the GitHub App must hold each
permission itself: see [Permissions](github-app.md#permissions).

## GitHub token permissions

GitHub token grants now hold a set of permissions that the owner configures
(`default_permissions` on the `warden:github-app` item, see [Permissions](github-app.md#permissions)),
instead of a constant. With no field set, nothing changes: the set is `contents`, `issues` and
`pull_requests` write and `metadata` read.

- A new migration, `0013_github_permissions`, applies at startup. As with every migration,
  rolling back means restoring the backup together with the old version.
- **Grants that exist keep the four permissions** they were approved with. A renewal takes
  the default of that moment, and the owner sees it on the approval page.
- The approval page for a GitHub request now reads the App's installation once for each view,
  begin and finish: one more App key read and one more GitHub call each. A GitHub approval page
  opened before the upgrade must be reloaded.
- The `approved` audit entry has a new optional field, `permissions`, so an older
  `warden-server audit verify` refuses a log that holds one.
- The `permissions` of a `github_token_minted` entry is now what GitHub granted, in canonical
  order (sorted by name). It was the fixed four in a fixed order.
- A bad `default_permissions` or `extra_permissions` makes GitHub tokens unusable, and `doctor`
  names the field. A sensitive permission (`workflows`, `administration` and the like) is
  allowed in `extra_permissions` and refused in `default_permissions`.

## Repository-scoped GitHub grants

GitHub token grants now cover named repositories, and a token is minted for one repository.
**Upgrade the broker before the CLI.** A new CLI refuses a broker that does not report
`scoped_github_tokens` in `/v1/info`, and an old CLI is refused by a new broker (its mint
body is `{}`). At upgrade, every GitHub grant and pending GitHub request that names no
repository ends, each recorded as `github_unscoped_ended`: the agents ask again with
`warden request github <owner/name>...`, or let the first `git` or `gh` call ask. The
owner approves each again, with the repositories shown on the page. Run `warden setup
github` again on each agent machine, as [above](#github-tokens-and-the-repository) says
after upgrading the CLI past 0.12.0. The CLI's token cache is
now per repository (`github-token.json`, version 2): an older file is ignored and replaced.
An agent may now hold several GitHub grants, and approving one ends the agent's grants that
share a repository with it (now only those with the same extras: see
[above](#extra-github-permissions-only-when-named-0170-breaking)).

## GitHub token permissions and extras

`/v1/info` has a new flag, `github_token_permissions`, which a broker sets when a request may
name `extra_permissions` and a mint may name `permissions`. **Upgrade the broker before the
CLI**: a new CLI refuses `--extra-permissions` against a broker that does not report it. Grants
and requests that exist are unchanged. An agent with a request waiting for a repository now gets
a `409` when it asks for the same repositories with other extras; it cancels the first or waits.
`warden github token --permissions` needs the flag too. The CLI's token cache is now per
repository and permission set (`github-token.json`, version 3): a version 1 or 2 file is
ignored and replaced, and the next token is minted anew.

## The Claude Code plugin

Nothing changes for a Claude Code session until `warden setup claude` is run on its
machine, from this release's CLI or later: it installs the warden plugin, pinned to the
tag of that CLI's version, which runs `warden hook session-start` and `warden hook check`
([The Claude Code plugin](agent-usage.md#the-claude-code-plugin)). A `SessionStart` hook you
wrote yourself to run `warden prime --brief` can go once the plugin is installed, since the
plugin prints the same brief. The broker needs no change.

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

## Proxies and HTTP/2

From 0.14.0, the broker's clients for 1Password Connect, the
notifiers and the health probe ignore `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and
`NO_PROXY`. A deployment that reached Connect or a notifier only through a proxy
needs a direct route before it upgrades. The listeners also serve HTTP/1.1 only:
Tailscale Serve and the CLI use it, but anything else that spoke HTTP/2 to them
directly (h2c) must change.

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

On a machine with the Claude Code plugin, run `warden setup claude` again after the
upgrade. It points the marketplace at the new version's tag and updates the plugin, so the
plugin stays at the CLI's version. If `claude` is not on the `PATH`, the command only prints
the `/plugin` commands to type in a session, which repoint the marketplace but do not update
an installed plugin: run `claude plugin update warden@warden --scope user` once `claude` is
available.
