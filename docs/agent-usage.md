# Using warden as an agent

`warden` is how an agent (or a person at a terminal) asks the owner for
short-lived SSH access and then uses it. The owner approves on their phone
with a passkey. The CLI makes an Ed25519 key in memory. That key goes only
to a dedicated `ssh-agent` and is never written to disk.

## One-time setup (done by the owner)

```sh
op read "op://Private/warden agent laptop/key" \
  | warden login --server https://warden.example.ts.net --agent laptop
```

`warden login` reads the agent key from stdin. Typed keys are not echoed;
a piped key is read as one line. The key goes into the macOS Keychain
(service `warden-broker`, account `<server>|<agent>`). The server URL and
agent name go into `~/.config/warden/config.toml` (or
`$XDG_CONFIG_HOME/warden/config.toml`), mode 0600.

The server URL must be `https://` (Tailscale Serve), or plain `http://` to a
loopback address. The CLI never sets the `Tailscale-User-Login` header.
Tailscale Serve adds it after authenticating the machine.

`WARDEN_AGENT_KEY`, when set, takes precedence over the Keychain. Use it for
CI and tests, and on platforms without a Keychain. Fill it from a secret
manager, never from a file in a repository.

## When to request access

Request access only when the task actually needs a shell on the target, and
only right before you use it. Do not request access "in case it is needed".
Do not keep a grant open while you do unrelated work.

```sh
warden request ssh pi --user alice --for 15m \
  --goal "restart the web container after the config change in PR #42"
```

- **Precise goal.** The owner sees the goal on their phone and decides on it
  alone. Say what you will do and why, and name the change, issue or error.
  "maintenance" or "debugging" is not a goal. The goal is one line of at
  most 500 characters, and the notification shows the first 200.
- **Narrowest user.** Ask for the least privileged account that can do the
  job. Do not ask for `admin` when your own user is enough.
- **Shortest window.** Pick the smallest of `15m`, `30m`, `1h` and `4h` that
  covers the work. The owner may approve a shorter window than you asked
  for. The target's policy caps every window.

## The fingerprint check

`warden request` prints this to stderr:

```
fingerprint b65b-9812-eb72 — waiting for approval…
```

The approval page shows the same fingerprint. If you are talking with the
owner, give them the fingerprint so they can compare it before approving. A
mismatch means the request they see is not yours, and they should deny it.

Only one request per agent and target can be pending at a time. If another
one is already waiting, `warden request` stops and prints that request's
fingerprint. It does not wait on a request it did not make.

The CLI waits for a decision for up to 11 minutes. Pending requests expire
after 10. If the broker is briefly unreachable or fails with a 5xx while
the CLI waits, it retries. The pause starts at 1 s and doubles up to 15 s,
with one note on stderr per failure. A refusal (4xx) ends the wait at once.
When the CLI gives up, it says so: the request may still be pending, and it
expires on its own. Do not make a new request while the old one is
pending. When the request is approved, it prints this to stdout:

```
approved: grant 0f3a…e1 until 2026-10-25 21:15:00 CET
```

## Using a grant

```sh
warden ssh pi                       # interactive shell
warden ssh pi -- systemctl status x # run one command
```

`warden ssh` uses the newest active grant for the target. It runs OpenSSH
with your `~/.ssh/config` ignored, with only the grant's agent, and with only
the host keys the broker pinned (`StrictHostKeyChecking=yes`). Passwords and
keyboard-interactive login are disabled. Put everything after `--`. It is
the remote command, never ssh options.

`warden status` lists the grants on this machine and the broker's view of
your live grants.

When the work is done, revoke the grant. Do not let it run out on its own:

```sh
warden revoke <grant-id>
```

This revokes the grant on the broker and stops its local `ssh-agent`.
Certificates that were already issued are not revoked on the target. Short
windows limit that risk, so revoke as soon as you finish. Every `warden` run
also cleans up expired grants and stops their agents.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success: the request was approved, the command ran, or the grant was revoked. `warden ssh` exits with ssh's own code. |
| 1 | Error. The message on stderr comes from the broker or the CLI. |
| 2 | The request was denied. Do not retry the same request. Ask the owner what to change. |
| 3 | The request expired without a decision. The owner may be away. Retry later, not in a loop. |
| 4 | The grant was revoked. |
| 5 | `warden ssh` found no active grant for the target. Run `warden request ssh …` first. |

## When the broker is unreachable

If `warden` cannot reach the broker (Tailscale down, broker down), do not
keep retrying. Tell the owner. The owner's own break-glass access (for
example credentials in a password manager unlocked at their workstation) is
outside warden and is meant for a person who is physically present. An agent
must never try to get around warden by any other route.
