# 1Password item conventions

warden reads its policy from a 1Password vault through a
[1Password Connect](https://developer.1password.com/docs/connect/) server.
Nothing is cached: every request reads the items afresh, so an edit in
1Password takes effect on the next request.

- The vault is named by `WARDEN_OP_VAULT` (default `Warden`).
- Items are matched by **tag**.
- Fields are matched by **label** (case-sensitive).
- The Connect token needs read access to this vault only.

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
| `host_keys`  | One or more OpenSSH public key lines (`ssh-ed25519 AAAA...`), newline-separated. Any key algorithm is accepted: these are the target's host keys. |

Example (category Server, tag `warden:ssh-target`, title `pi`):

```
address     192.0.2.10
mode        cert
users       alice, admin
max_window  1h
host_keys   ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... root@pi
```

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
| `methods`     | no       | Comma-separated HTTP methods, uppercase (`GET, POST`). Default `GET`. |
| `path_prefix` | no       | Only paths under this prefix may be called. Must start with `/`; no `?`, `#`, `\`, spaces, `//`, `.` or `..` segments. Default `/`. |
| `ca_pem`      | no       | One or more PEM CA certificates (`-----BEGIN CERTIFICATE-----`). When set, the server certificate must chain to one of them and the system roots are not used. |

An optional field that is absent or blank takes its default. A required
field that is absent, blank or malformed makes the item unusable, with an
error naming the item and the field; the error never quotes the value.

The secret value is read from 1Password only when a call is made, held in
memory that is wiped after use, and never logged, returned to the agent or
written to the audit log.

Example (category API Credential, tag `warden:api-secret`, title `github`):

```
website      https://api.example.com
credential   ••••••••••••••••
max_window   30m
methods      GET, POST
path_prefix  /repos/alice/
```

This lets an approved agent call `GET` and `POST` on
`https://api.example.com/repos/alice/…`, with the header
`Authorization: Bearer <credential>` added by warden.

## SSH CA

Tag: `warden:ssh-ca`. Exactly one item in the vault carries this tag; zero or
more than one is an error.

The item is a 1Password **SSH Key** item. warden reads the private key from the
field whose id is `private_key`, in OpenSSH or PKCS#8 PEM format. The key must
be an **unencrypted Ed25519** key. RSA, ECDSA and passphrase-protected keys are
rejected.

Example (category SSH Key, tag `warden:ssh-ca`, title `warden-ssh-ca`):

```
private key   -----BEGIN OPENSSH PRIVATE KEY-----
              ...
              -----END OPENSSH PRIVATE KEY-----
```

Publish the matching public key to targets (the `public key` field of the
item, or `ssh-keygen -y`). Certificates carry a single principal,
`warden:<target>:<user>`, where `<target>` is the target item's title, so each
host must accept the CA only for its own target name:

```
# sshd_config
TrustedUserCAKeys /etc/ssh/warden_ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u
```

`/etc/ssh/auth_principals/<user>` holds one line per allowed user, for example
`warden:pi:alice` on the host of target `pi`. A host that only reads
`authorized_keys` (for example the Home Assistant SSH add-on) uses:

```
cert-authority,principals="warden:<target>:<user>" ssh-ed25519 AAAA…
```

Without this mapping an approval for one target would be usable on every host
that trusts the CA.
