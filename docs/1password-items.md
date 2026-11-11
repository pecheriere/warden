# 1Password item conventions

warden reads its policy from a 1Password vault through a
[1Password Connect](https://developer.1password.com/docs/connect/) server.
Nothing is cached: every request reads the items afresh, so an edit in
1Password takes effect on the next request.

- The vault is named by `WARDEN_OP_VAULT` (default `Warden`). Keep it for
  warden's items only.
- Items are matched by **tag**.
- Fields are matched by **label** (case-sensitive).
- The Connect token needs read access to this vault only, and nothing more.

How to create the vault, the Connect server and its token is in
[Deployment](deployment.md#3-1password). 1Password is the recommended backend;
[local files](local-backend.md) are a weaker alternative with the same rules.

A missing or malformed field makes the request fail with an error naming the
item and the field. A required field never falls back to a default.

## SSH target

Tag: `warden:ssh-target`. The item title is the target name and must match
`^[a-z0-9][a-z0-9-]{0,31}$`. Two tagged items with the same title are an
error.

| Field label  | Value |
|--------------|-------|
| `address`    | `host` or `host:port`; the port defaults to 22. Write IPv6 as `[addr]` or `[addr]:port`. |
| `mode`       | `cert` or `relay`. |
| `users`      | Comma-separated Unix accounts that may be requested, each matching `^[a-z_][a-z0-9_-]{0,31}$`. |
| `max_window` | Longest window that may be granted: `15m`, `30m`, `1h` or `4h`. |
| `host_keys`  | One or more OpenSSH public key lines (`ssh-ed25519 AAAA...`), newline-separated. Any key algorithm is accepted: these are the target's host keys. warden does not check an RSA key's length, so pin one of at least 2048 bits. They are pinned: there is no trust on first use. Required for both modes; for relay targets the onward connection negotiates only the algorithms of these keys. |
| `private_key` | Relay targets only: the private key warden logs in to the target with. See below. |
| `password`    | Relay targets only: the password warden logs in to the target with. See below. |

### Relay targets

A target with mode `relay` is reached through warden: the agent connects to
warden, and warden logs in to the target with a credential that never leaves
it. The item holds that credential in **exactly one** of two fields:

- `private_key`: an **unencrypted Ed25519** private key (the only key type
  warden handles privately; it holds no RSA or NIST-curve private key), in
  OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`) or PKCS#8
  (`-----BEGIN PRIVATE KEY-----`) PEM format. RSA and ECDSA keys are
  refused (warden performs no RSA or NIST-curve private-key operation): use
  a password for a target that cannot accept an Ed25519 key.
  Passphrase-protected keys are refused too.
- `password`: the account's password, at least one character, used verbatim
  (surrounding spaces included). The Server category's built-in `password`
  field can hold it.

A field that is absent or empty counts as not set. A relay item with neither
field, or with both, is unusable; so is a `cert` item with either field set,
so that a credential is never left on an item that does not use it. Errors
name the item and the field but never quote the value.

Every read of the item (at request, at approval and at session start)
reads and validates the credential, so a bad one fails the request up front,
but only a session start uses it: the session takes it from the same read as
the rest of the item, holds it zeroized, drops it right after logging in to
the target, and never logs it, returns it to the agent or writes it to the
audit log.

Example (category Server, tag `warden:ssh-target`, title `switch-01`):

```
address     switch-01.example.com:2222
mode        relay
users       admin
max_window  1h
host_keys   ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... root@switch-01
password    ••••••••••••
```

Example (category Server, tag `warden:ssh-target`, title `web-01`):

```
address     web-01.example.com
mode        cert
users       build-agent
max_window  1h
host_keys   ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... root@web-01
```

How to set up the target host itself is in [SSH targets](ssh-targets.md).

## API secret

Tag: `warden:api-secret`. The item title is the secret name and must match
`^[a-z0-9][a-z0-9-]{0,31}$`. Two tagged items with the same title are an
error. Use the 1Password **API Credential** category: its built-in
`credential` field holds the secret; add the other fields as custom fields.

The secret is only ever sent to **one origin: the item's website**. warden
uses the item's primary website (or its first one, if none is marked
primary). It must be exactly `https://host` or `https://host:port`, with no
path, query, fragment, user name or password. There is no default: an item
without a website is unusable. Only someone who can edit the item in
1Password can change where the secret may go.

| Field label   | Required | Value |
|---------------|----------|-------|
| `credential`  | yes      | The secret, at least 12 printable ASCII characters. Leading and trailing whitespace is ignored. |
| `max_window`  | yes      | Longest window that may be granted: `15m`, `30m`, `1h` or `4h`. |
| `header`      | no       | Header that carries the secret. Default `Authorization`. Connection and framing headers (`Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade`, `Proxy-*`) are refused. |
| `format`      | no       | Header value, with `{{secret}}` exactly once where the secret goes. Default `Bearer {{secret}}`. The rest must be printable ASCII. |
| `methods`     | no       | Comma-separated HTTP methods, uppercase (`GET, POST`). Default `GET`. The most any request can be granted. |
| `path_prefix` | no       | Only paths under this prefix may be called. The widest any request can be granted. Must start with `/`; no `?`, `#`, `\`, spaces, `//`, `.` or `..` segments. Default `/`. |
| `ca_pem`      | no       | One or more PEM CA certificates (`-----BEGIN CERTIFICATE-----`). When set, the server certificate must chain to one of them and the system roots are not used. |

An optional field that is absent or blank takes its default. A required
field that is absent, blank or malformed makes the item unusable, with an
error naming the item and the field; the error never quotes the value.

The secret value is read from 1Password only when a call is made, held in
memory that is wiped after use, and never logged, returned to the agent or
written to the audit log.

Example (category API Credential, tag `warden:api-secret`, title
`home-api`):

```
website      https://home.example.com
credential   ••••••••••••••••
max_window   30m
methods      GET, POST
path_prefix  /api/
```

This lets an approved agent call `GET` and `POST` on
`https://home.example.com/api/…`, with the header
`Authorization: Bearer <credential>` added by warden.

The item is the **ceiling**: an agent's request can only narrow it. A request
without `--methods` gets the item's methods that are `GET` or `HEAD` (here
`GET`, so read-only), and is refused if there are none. To write, the agent
names the methods (`--methods POST`), which must be in the item's list, and
may name a narrower `--path` under the item's prefix. List a method in the
item only if some task needs it; the owner still sees on the approval page
whether each request can modify.

## Commit signing key

Tag: `warden:commit-signing`. Optional: with no such item, commit signing is off. More
than one is an error. An SSH Key item holding an unencrypted `ssh-ed25519` key in the
field with id `private_key`, used for nothing else: warden refuses the SSH CA key here.
warden reads it for each signature and approval page, and never gives it out. Replacing it ends every grant made
for the old key: see [rotating the key](threat-model.md#rotating-the-commit-signing-key).

## GitHub App

Tag: `warden:github-app`. Optional: with no such item, GitHub tokens are off. More than one
is an error, and the local backend cannot hold one. An item with three fields, matched by label like the other items (case-sensitive, each label
once):
`app_id` (the App's id), `installation_id` (a positive number) and `private_key` (the
App's RSA private key as PEM, PKCS#1 or PKCS#8, unencrypted, at least 2048 bits). Add them in
1Password as custom fields, text for the two ids and concealed for the key; the item's category
does not matter. warden
reads the item for each approval page and token, and never gives the key out. Changing
the App or installation ends every grant made for the old one; replacing only the key
does not.

## Release signing key

Tag: `warden:release-signing`. Optional: with no such item, there are no release keys. One
item per repository; the local backend cannot hold one. warden loads and checks these items
for the release process to come, and does not use them for anything else yet. Fields are
matched by label (case-sensitive, each label once); add them in 1Password as custom fields,
concealed for the key, text for the rest. The item's category does not matter.

| Field | Rule |
|---|---|
| `private_key` | Required. An unencrypted `ssh-ed25519` key, as OpenSSH or PKCS#8 PEM. It must be a key of its own: warden refuses one that is also the commit signing key, the SSH CA key or another repository's release key. |
| `repository` | Required. `owner/name`: the owner is letters, digits and dashes (at most 39 characters, starting with a letter or digit), the name is letters, digits, dots, underscores and dashes (at most 100, not `.` or `..`). Compared ignoring case. Two items for the same repository are an error. |
| `tagger_name` | Required. The name on the tags this key signs: 1 to 100 characters on one line, without `<` or `>`, control characters, or leading or trailing whitespace. |
| `tagger_email` | Required. The email on those tags: an address that contains an `@`, with no whitespace, `<`, `>` or control characters, no leading or trailing whitespace, and at most 254 characters. |
| `manifest` | Optional. The file name of the signed checksums file the repository publishes, with `{version}` exactly once, such as `example-repo-{version}-SHA256SUMS`: letters, digits, dots, underscores, plus signs and dashes around it, no path separator, at most 200 characters. |
| `manifest_namespace` | Required with `manifest`, and an error without it: the `ssh-keygen -Y` namespace the manifest is signed in, `^[a-z0-9][a-z0-9-]{0,63}$`. |
| `publish` | Optional: `true` or `false` (the default). Whether warden may publish the draft release itself. |

Example (tag `warden:release-signing`, title `release-example-repo`):

```
private_key          -----BEGIN OPENSSH PRIVATE KEY-----
                     ...
                     -----END OPENSSH PRIVATE KEY-----
repository           example-owner/example-repo
tagger_name          Example Release Bot
tagger_email         releases@example.com
manifest             example-repo-{version}-SHA256SUMS
manifest_namespace   example-repo-release
publish              false
```

One unusable item fails every release key, because which repository it was meant for cannot be
trusted. The same goes for a commit signing key or SSH CA key that exists but cannot be read,
since nothing then says the release keys are different keys; with no release item at all
there is nothing to compare, so neither is checked here (the `commit-signing` and `ssh-ca`
doctor checks cover them). warden never gives the private
key out. `warden-server doctor` shows the result in its `release-signing` check.

## Release GitHub App

Tag: `warden:github-release-app`. Optional: with no such item, there is no release App. More
than one is an error, and the local backend cannot hold one. A second GitHub App, apart from
the one in [GitHub App](#github-app), for the release process to come. warden loads and
checks the item and does not use it for anything else yet. It has no installation: the
installation is found when the App is used. Two fields, matched by label like the others:

| Field | Rule |
|---|---|
| `app_id` | Required. The App's id: 1 to 64 letters, digits, dots, underscores and dashes. |
| `private_key` | Required. The App's RSA private key as PEM, PKCS#1 or PKCS#8, unencrypted, at least 2048 bits. |

Example (tag `warden:github-release-app`, title `release-app`):

```
app_id        123456
private_key   -----BEGIN PRIVATE KEY-----
              ...
              -----END PRIVATE KEY-----
```

warden never gives the key out. `warden-server doctor` shows the result in its `release-app`
check.

## SSH CA

Tag: `warden:ssh-ca`. Exactly one item in the vault carries this tag; zero or
more than one is an error.

The item is a 1Password **SSH Key** item. warden reads the private key from
the field whose id is `private_key`, in OpenSSH or PKCS#8 PEM format. The key
must be an **unencrypted Ed25519** key. RSA, ECDSA and passphrase-protected
keys are rejected.

Example (category SSH Key, tag `warden:ssh-ca`, title `warden-ssh-ca`):

```
private key   -----BEGIN OPENSSH PRIVATE KEY-----
              ...
              -----END OPENSSH PRIVATE KEY-----
```

Publish the matching public key to the certificate targets (the item's
`public key` field, or `ssh-keygen -y`). Each target must accept the CA only
for its own principal, `warden:<target>:<user>`, where `<target>` is the
target item's title; [SSH targets](ssh-targets.md) shows how. Without that
mapping an approval for one target would be usable on every host that
trusts the CA.

To create the item with the 1Password CLI, see
[Deployment](deployment.md#3-1password).
