# Secrets and policy in local files

**1Password stays the recommended backend.** This one keeps targets, API secrets
and the SSH CA key in files on warden's own host, so that warden can run with no
1Password account and no Connect containers. It is weaker in a way no setting can
repair.

## What you give up

| | 1Password | Local files |
|---|---|---|
| Where the secrets rest | A vault, away from the host. warden holds a token and reads them when needed. | On the host's disk. |
| A compromised host | Gets the token, what warden has in memory, and whatever it can read from the vault through that token until you revoke the token. The vault's other copies, its history and your other vaults stay out of reach. | **Gets every secret, and keeps them.** Rotate every credential warden holds; there is no token to revoke. |
| A stolen backup or disk of the host | Holds no secret from the vault beyond the Connect token. | Holds every secret, unless the secrets are encrypted at rest some other way. |
| A read-only boundary | warden's token cannot change the policy. | **None of warden's own making.** Whoever can write the files decides what warden hands out and where secrets go. Keep the policy file owned by root and the mounts read-only (below): that stops a compromised warden process, not a compromised host. |
| Who edited what | 1Password's item history and usage reports. | Nothing, unless you add it. warden does not know who changed a file. |

Everything else is unchanged: every grant still needs your passkey, is bounded in
time and scope, and is audited, and the agent still never receives a secret. The
[threat model](threat-model.md#the-local-secret-backend) has the details.

Use this to try warden for real without a 1Password account, or on a host you are
already prepared to treat as holding every credential it can reach. warden's
[deployment guide](deployment.md) applies otherwise unchanged, except for its
1Password sections.

## Turning it on

The backend is chosen by `WARDEN_SECRET_BACKEND`. Unset means 1Password, so
existing deployments do not change, and nothing ever falls through to this weaker
one: it has to be asked for by name.

```sh
WARDEN_SECRET_BACKEND=local
WARDEN_LOCAL_POLICY_FILE=/etc/warden/policy.toml
WARDEN_LOCAL_SECRETS_DIR=/var/lib/warden/secrets
```

Both paths must be absolute. warden refuses to start when:

- the local settings are set without `WARDEN_SECRET_BACKEND=local`;
- any 1Password setting (`WARDEN_OP_*`) is set with `WARDEN_SECRET_BACKEND=local`.

Either could mean you believe your secrets are somewhere they are not. Setting a
variable to an empty value counts as not setting it.

## The policy file

TOML. Nothing in it is secret, and no secret may go in it: an unknown setting such
as `credential = "..."` stops the file from loading. The rules are those of
[1Password items](1password-items.md), and the same validators check them. The
differences are spelled out below.

```toml
[ca]
private_key_file = "ssh-ca"

[targets.web-01]
address = "web-01.example.com"
mode = "cert"
users = ["build-agent"]
max_window = "1h"
host_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... root@web-01"]

[targets.switch-01]
address = "switch-01.example.com:2222"
mode = "relay"
users = ["admin"]
max_window = "1h"
host_keys = ["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... root@switch-01"]
password_file = "switch-01-password"

[api_secrets.home-api]
website = "https://home.example.com"
credential_file = "home-api"
max_window = "30m"
methods = ["GET", "POST"]
path_prefix = "/api/"

[end_of_policy]
sha256 = "9f2c...the digest seal-policy writes..."
```

### The end of the file: `[end_of_policy]` and its digest

The last two lines of the file must be `[end_of_policy]`, then
`sha256 = "<digest>"`: the SHA-256, in lower-case hex, of every byte before that
last line. warden checks it on the bytes it read, at every read, and refuses
anything else.

A file cut short at any point, by a full disk or an interrupted write, has lost
those lines. A write in place that does not truncate can show the start of one
version with the end of another, and the digest no longer matches. Without these
checks, either could still be valid and **wider** than any version you wrote: cut
before `path_prefix`, the entry above would allow every path, and a mix could put
one version's methods on the other's path.

The digest catches accidents, not an attacker. Anyone who can write the file can
compute a new digest, so it adds nothing to the [ownership rules](#what-is-refused).

### Editing the file

`warden-server seal-policy` writes the digest and replaces the file in one atomic
rename. It needs none of warden's settings. Edit a copy, keeping `[end_of_policy]`
at the end (the old digest line after it does not matter, and is replaced), then
install it:

```sh
cp /etc/warden/policy.toml /etc/warden/policy.draft
$EDITOR /etc/warden/policy.draft
warden-server seal-policy --from /etc/warden/policy.draft /etc/warden/policy.toml
warden-server doctor
```

Requests are served from the old file until the rename, and from the new one after
it. The command keeps the replaced file's owner and mode, makes a new file `0644`, and
prints what each entry allows. It refuses a draft that does not parse, or that has
lost its `[end_of_policy]` line, because that may mean the draft was cut short, and
it then leaves the policy file as it was. A draft is held to the rules of the policy
file below, because it turns into access: keep it beside the policy file, not in a
home directory. The command does not read your secrets, which is what `doctor` is
for.

Editing the policy file itself also works, with one more step. From your save on,
warden refuses every request and audits why, and says what to run:

> the policy file does not match the digest on its last line: it was changed without
> sealing, or read while being overwritten; to change it, check a draft and run
> warden-server seal-policy --from \<draft> \<file>; to see what this file allows, run
> warden-server seal-policy \<file>

warden cannot tell your edit from a mix of two versions left by a write in place, and
a sealed mix is a valid policy, so `warden-server seal-policy
/etc/warden/policy.toml` does not seal such a file. It exits non-zero and lists the
destination, methods, path prefix and secret file of every entry. Read them. If they
are what you meant, run it again with `--accept-unverified`. If not, restore the file
from a draft. A file with no digest yet, or one that matches, is sealed without this
step.

The list shows settings whole and as written, so a value pasted into one, such as
`header` or `path_prefix`, shows too. The exceptions: a website is shown only as its
origin, a format and a CA only as present, and a setting naming a secret file only if
its value is a valid file name. No secret file is read. Host keys are shown as a count.

**Sealing is your decision, and this check only stops it being made by accident.**
Deleting the digest line and sealing the file as new skips the check, and so does
copying the file and sealing the copy with `--from`, which carries any mix with it.
The digest detects a torn write, not tampering. Seal only a file nobody is still
writing, and only a draft you have read.

With Docker, run it on the host if you have the binary. Otherwise use the image, with
the directory mounted writable, as the user that owns the file (`--user 0` for a file
root owns, `--user 65532` for the image's user). warden trusts only root and its own
user, and this command holds files to the same rule, so root is refused on a file
owned by anyone else, even though it could write it:

```sh
docker run --rm --user 0 -v /etc/warden/policy:/policy --entrypoint /warden-server \
  ghcr.io/pecheriere/warden:<version> \
  seal-policy --from /policy/policy.draft /policy/policy.toml
```

Any other tool can write the file too, given the format above, as long as it
replaces the file by a rename.

### `[targets.<name>]`

The name follows `^[a-z0-9][a-z0-9-]{0,31}$`. Required: `address`, `mode`, `users`,
`max_window` and `host_keys`, with the meanings in
[SSH target](1password-items.md#ssh-target). `users` and `host_keys` are lists.

A relay target names exactly one of `private_key_file` (an unencrypted Ed25519
key, OpenSSH or PKCS#8) and `password_file`. A certificate target names neither.

### `[api_secrets.<name>]`

The name follows the same pattern. Required: `website`, `credential_file` and
`max_window`. Optional: `header`, `format`, `methods` (a list), `path_prefix` and
`ca_pem`. See [API secret](1password-items.md#api-secret).

An optional setting you leave out takes its default. **One you set blank is
refused**, unlike a blank field of a 1Password item, so that `path_prefix = ""`
cannot quietly mean the widest prefix.

### `[ca]`

`private_key_file` names an unencrypted Ed25519 key. You can leave the section out
only if no target is in certificate mode.

warden does not create this key: it never writes to the secrets directory. Make it
yourself, on the host and as warden's user, in one step:

```sh
ssh-keygen -t ed25519 -N '' -C warden-ssh-ca -f /var/lib/warden/secrets/ssh-ca
```

Publish the `.pub` file it also writes to your targets, as in
[SSH targets](ssh-targets.md). warden reads only the files the policy names, so
that file can stay or go.

## The secret files

Each secret is a file of its own in `WARDEN_LOCAL_SECRETS_DIR`, named in the policy
by its plain file name: up to 64 letters, digits, `.`, `_` or `-`, starting with a
letter or digit. No paths, so an edit of the policy can never point a credential at
another file on the host.

```sh
install -d -m 0700 -o warden /var/lib/warden/secrets
install -m 0600 -o warden /dev/stdin /var/lib/warden/secrets/home-api
```

A password is taken as one line, without its line ending, and any spaces are kept.
A credential ignores surrounding whitespace.

## What is refused

warden reads through the path one component at a time, without following links, and
decides on the file it actually opened, so nothing can be swapped in between the
check and the read.

| What | Rule |
|---|---|
| Every directory on either path, from `/` | Owned by root or warden's user. Not writable by group or others, unless sticky (as `/tmp` is). Not a symbolic link, so give real paths. Readable by warden's user. |
| The policy file | A regular file, not a link, with exactly one name, and not a mount of that file alone. Owned by root or warden's user. Not writable by group or others. At most 1 MiB. It ends with `[end_of_policy]` and a digest that matches. |
| The secrets directory | Owned by warden's user, with no access for group or others (`0700` or `0500`). |
| Each secret file | A regular file, not a link, with one name (no hard links), and not a mount of that file alone. Owned by warden's user, with no access for group or others (`0600` or `0400`). Not blank, valid UTF-8, at most 32 KiB. |

**At startup**, `warden-server serve` reads the whole policy and every secret it
names. If anything is invalid, unreadable or too open, or a certificate target has
no CA, it writes each problem to the audit log and refuses to start.

**On every request**, everything is read again and nothing is cached:

- A policy edit applies at once, with no restart. A grant whose destination changed
  stops working (409), as when a 1Password item is edited.
- Removing an entry or a secret file stops it at once.
- If a file has become invalid or too open, or the policy no longer matches its
  digest, the request or call is refused and the
  refusal is written to the audit log as an `error` event from
  `local secret backend`. Only the entry concerned is affected, unless the policy
  file itself cannot be used, which refuses everything.

Errors and audit entries name the entry and the setting. They never quote a value,
a file's content or a line of the policy, and a secret value is held in memory that
is wiped after use.

### Rotating a secret

The policy and a secret are two reads, not the single read of a 1Password item. A
secret always comes from the file the policy being checked names, but a change that
needs both files is two steps, and a call can fall between them. So when a
credential moves to another destination, do not rewrite its file: write the new
credential under **a new file name**, then point the policy at it in one atomic
step, with [`warden-server seal-policy`](#editing-the-file).

Always replace the policy file that way. A write in place can be read part way
through. warden refuses what such a read returns, whether cut short or mixed with
the old file, so it cannot widen anything, but every request in that moment fails.

## Where the files go

### With Docker

Mount both directories read-only, so that a compromised warden process cannot change
them:

```yaml
    volumes:
      - warden-data:/data
      - /etc/warden/policy:/policy:ro
      - /etc/warden/secrets:/secrets:ro
    environment:
      WARDEN_SECRET_BACKEND: local
      WARDEN_LOCAL_POLICY_FILE: /policy/policy.toml
      WARDEN_LOCAL_SECRETS_DIR: /secrets
```

**Mount the directory, never the single file.** A mount of one file stays on the old
file after a rename over it, so an edit or a revocation on the host would not reach
the container. warden refuses a policy file or a secret file that is a mount of its
own, at startup and at every read, so this fails at once rather than after your first
edit. The check needs Linux 5.8 or later, with the `statx` system call allowed. Where
the kernel or a sandbox cannot answer, warden cannot tell, so it refuses every policy
and secret file: **the local backend does not work there at all**. The same goes for a single-file `BindReadOnlyPaths=` under
systemd.

On the host, `/etc/warden/secrets` and its files belong to the image's user (uid
65532), mode `0700` and `0600`. Compose's own `secrets:` do not fit, because the
directory they appear in belongs to root.

### With systemd

Use a drop-in on [the systemd service](deployment-systemd.md), which also clears the
Connect token the unit asks for:

```ini
# /etc/systemd/system/warden.service.d/local-backend.conf
[Service]
LoadCredential=
Environment=WARDEN_OP_CONNECT_TOKEN_FILE=
Environment=WARDEN_SECRET_BACKEND=local
Environment=WARDEN_LOCAL_POLICY_FILE=/etc/warden/policy.toml
Environment=WARDEN_LOCAL_SECRETS_DIR=/var/lib/warden/secrets
```

Keep `/etc/warden/policy.toml` owned by root, mode `0644` or `0640` with warden's
group: then warden cannot change it, and the unit's `ProtectSystem=strict` makes that
hold twice. `/var/lib/warden` is the one path warden can write, so a compromised
warden process could change files in the secrets directory there.

Systemd credentials avoid that, and keep the secrets out of the process's writable
paths and in memory that does not swap:

```ini
LoadCredential=home-api:/etc/warden/credentials/home-api
Environment=WARDEN_LOCAL_SECRETS_DIR=%d
```

The file name in the policy is then the credential's name. **systemd copies the
source file when the service starts, so rotating or removing such a secret takes a
restart.** Revoking by removing the source file does not apply until then; removing
the entry from the policy file still applies at once.

## Checking it

`warden-server doctor` reads the same files by the same rules, writes nothing, and
reports:

| Check | Passes when | Otherwise |
|---|---|---|
| `local.policy` | The policy file is safe to read, matches its digest and parses. | Fails, and the next two are not checked. |
| `local.entries` | Every entry is valid and its secret files are safe to read. | Fails, listing each problem. |
| `ssh-ca` | The CA key loads, or no target needs one. | Fails, or could not check if the system refused the read. |
| `local.host-boundary` | Never. | Always reported as could not check: warden cannot tell whether the host is kept as locked down as this backend needs. |

Run it as warden's user, with the same environment, or the ownership checks fail. A
`connect.*` check does not appear with this backend. On a systemd service using
credentials, run it inside the unit's context, because `%d` exists only there.

## What has been tested

Unit tests through the backend's interface and an integration test of the whole
flow (request, approval, a certificate signed by the local CA, a proxied call with
redaction, refusals) run in CI on Linux, with reads torn by a real overwrite part
way through and a real bind mount of a single file. Neither the Docker Compose
example nor the systemd drop-ins and credentials above have been run on a real host yet. The code
was written for what systemd documents about the credentials directory (a private
directory of regular files, mode `0400`, owned by the service's user), and has not
been run against it. `warden-server doctor` tells you straight away if a host
differs.
