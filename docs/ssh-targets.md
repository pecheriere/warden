# SSH targets

An SSH target is a host that agents may log in to after the owner approves.
Each target is a 1Password item (see
[1Password item conventions](1password-items.md#ssh-target)) and is one of
two kinds:

- **A certificate target** (`mode` `cert`) trusts warden's SSH CA. The agent
  logs in directly, with a short-lived certificate for a key that exists
  only in its memory. Prefer this kind.
- **A relay target** (`mode` `relay`) cannot trust a CA (an appliance, a
  Dropbear server, a password-only login). The agent logs in to warden's SSH
  relay, and warden logs in to the target with a key or password that never
  leaves it.

The agent's commands are the same for both: `warden request ssh` and
`warden ssh`.

## Certificate targets

### How a certificate is bound to one target

A certificate carries a single principal, `warden:<target>:<user>`, where
`<target>` is the target item's title and `<user>` the approved account. Its
key id is `warden:<agent>:<grant id>`, so the target's logs name the agent
and the grant. It is valid for the approved window (backdated 60 s for
clock skew), for one ephemeral key, and allows a pty and nothing else: no
agent, port or X11 forwarding.

A host must accept the CA **only for its own principal**. If it accepted any
principal from the CA, an approval for one target would work on every host
that trusts the CA.

### The recommended setup: one user per agent

Give each agent its own account on the target, reachable **only** with a
warden certificate. Then every login is an approved one, and the account's
permissions bound what an approved agent can do.

On `web-01`, for the agent `build-agent`:

1. **Create the account**, with only the permissions the agent's tasks need
   (for example, membership of one group, or a narrow `sudoers` rule):

   ```sh
   sudo useradd --create-home --shell /bin/bash build-agent
   ```

2. **Install the CA's public key** (from the CA item, see
   [Deployment](deployment.md#3-1password)):

   ```sh
   sudo install -m 0644 warden_ca.pub /etc/ssh/warden_ca.pub
   ```

3. **Map the principal to the account.** One file per account, one line per
   principal it accepts:

   ```sh
   sudo install -d -m 0755 /etc/ssh/auth_principals
   echo 'warden:web-01:build-agent' | sudo tee /etc/ssh/auth_principals/build-agent
   ```

4. **Configure sshd**, for example in
   `/etc/ssh/sshd_config.d/50-warden.conf`:

   ```
   TrustedUserCAKeys /etc/ssh/warden_ca.pub
   AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u

   # build-agent logs in with a warden certificate only.
   Match User build-agent
       AuthorizedKeysFile none
       PasswordAuthentication no
       KbdInteractiveAuthentication no
   ```

   `AuthorizedKeysFile none` means no plain key can log in to the account;
   no `authorized_keys` file is read for it. `TrustedUserCAKeys` without
   `AuthorizedPrincipalsFile` would not accept the certificate at all,
   because its principal is not the user name.

5. **Check and reload sshd:**

   ```sh
   sudo sshd -t && sudo systemctl reload ssh   # or sshd, by distribution
   ```

   sshd uses the **first** value it reads for each of these keywords. If
   the host already sets `TrustedUserCAKeys`, `AuthorizedPrincipalsFile` or
   `AuthorizedKeysFile` earlier (in `sshd_config` before its `Include`, or
   in a drop-in that sorts first), the file above is silently ignored. Check
   the effective values for the account:

   ```sh
   sudo sshd -T -C user=build-agent,host=localhost,addr=127.0.0.1 \
     | grep -iE 'trustedusercakeys|authorizedprincipalsfile|authorizedkeysfile'
   ```

   It must print `/etc/ssh/warden_ca.pub`,
   `/etc/ssh/auth_principals/%u` and `none`. If the host already trusts
   another CA, list both keys in one `TrustedUserCAKeys` file instead.

6. **Create the target item** in the `Warden` vault: title `web-01`, tag
   `warden:ssh-target`, `mode` `cert`, `users` `build-agent`, the host's
   `address` and pinned `host_keys`, and a `max_window`. The host keys are
   in `/etc/ssh/ssh_host_*_key.pub` on the target; copy them over a channel
   you trust, not from `ssh-keyscan` on an untrusted network.

To let a second agent in, create a second account (with its own principal
file) and add it to the item's `users`.

warden itself does not tie an account to an agent: any enrolled agent may
request any account that the item's `users` lists. The certificate's key id
and the audit log name the agent, and the approval page shows both the
agent and the account, so check that they belong together before you
approve.

### Hosts that read only `authorized_keys`

A host whose SSH server reads only `authorized_keys` (for example the Home
Assistant SSH add-on) uses one line instead, which restricts the CA to the
principal:

```
cert-authority,principals="warden:<target>:<user>" ssh-ed25519 AAAA…
```

### Login alerts

If you alert on logins with unknown keys, exclude warden's certificates by
the **CA's fingerprint**, not by user or key: each certificate is for a new
key. OpenSSH logs a certificate login like this:

```
Accepted publickey for build-agent from … ssh2: ED25519-CERT SHA256:<key> ID warden:build-agent:<grant id> (serial <random>) CA ED25519 SHA256:<CA fingerprint>
```

Match `CA ED25519 SHA256:<CA fingerprint>` exactly, with the fingerprint
from `ssh-keygen -lf /etc/ssh/warden_ca.pub`. Keep alerting on every other
login to the agent accounts.

### Revocation and certificates

Revoking a grant stops warden from issuing anything more for it, but a
certificate already issued stays valid on the target until it expires: sshd
checks it offline (see [issue #35][i35]). Short windows are the defence.
To cut an approved agent off at once, lock its account on the target or
remove its principal line.

[i35]: https://github.com/pecheriere/warden/issues/35

## Relay targets

A relay target needs nothing from warden installed on it: only an ordinary
login for the account, with an Ed25519 key or a password. Set up the item
(title, tag `warden:ssh-target`, `mode` `relay`, `users`, `address`,
`max_window`) with:

- **`host_keys`**: required. There is no trust on first use, and key
  exchange negotiates only the algorithms of the pinned keys.
- **Exactly one credential**: `private_key` (an unencrypted Ed25519 key) or
  `password`. Give it a credential that works only on this target and for
  this account.

warden must be able to reach the target's address (allow it in
[warden's egress rules](deployment.md#lock-wardens-egress)), and the relay
endpoint must be published with `WARDEN_RELAY_PUBLIC_ADDR` set. Relay
targets currently need
[the sidecar layout](deployment.md#10-the-sidecar-layout-for-relay-targets):
publishing the relay through Tailscale Services has not been tested.

Through the relay, port, agent and X11 forwarding and subsystems (`sftp`,
and so `scp` in its default mode) are refused, and the environment is
filtered. The audit log records each session's start, end, bytes and, for a
single command, its first 200 characters; it does not record interactive
input. Revoking a grant ends its relay sessions within seconds.

The full rules are in [the design](design.md#82-ssh-relay-mode) and the
fields in [1Password item conventions](1password-items.md#relay-targets).
