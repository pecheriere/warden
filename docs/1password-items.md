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
item and the field. It never falls back to a default.

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
