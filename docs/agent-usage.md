# Agent usage

`warden` is how an agent (or a person at a terminal) asks the owner for
short-lived access, an SSH shell or calls to an HTTP API that needs a
secret, and then uses it. The owner approves on their phone with a passkey.

For SSH, the CLI makes a new Ed25519 key in memory for each request. That
key goes only to a dedicated `ssh-agent` for the grant and is never written
to disk. For APIs, the agent never sees the secret: warden makes the calls.

Contents:

- [One-time setup](#one-time-setup)
- [Rules for requesting access](#rules-for-requesting-access)
- [Requesting access](#requesting-access)
- [Using a grant](#using-a-grant)
- [Ending a grant](#ending-a-grant)
- [Exit codes](#exit-codes)
- [When the broker is unreachable](#when-the-broker-is-unreachable)
- [Known limits](#known-limits)
- [Instructions to give an agent](#instructions-to-give-an-agent)

## One-time setup

Install the CLI on the agent's machine (Rust 1.94 or later, and the OpenSSH
client tools):

```sh
cargo install --locked --git https://github.com/pecheriere/warden --tag v0.7.0 warden-broker-cli
```

The machine must be on the tailnet, and the tailnet policy must let it reach
the agent API (and the relay, if you have relay targets), but **never the
approval UI**. See [Deployment](deployment.md#2-tailscale).

### Choose how the agent authenticates

Every call to the broker is authenticated in one of two ways:

| | Signing key | Bearer key |
|-|-------------|------------|
| What the machine holds | An SSH key (Ed25519 or ECDSA P-256) behind an `ssh-agent`. Nothing secret is stored by warden. | A `wdn_…` key: in the macOS login Keychain, or in `WARDEN_AGENT_KEY`. |
| If it is copied | A hardware key cannot be copied. A key file can. | Whoever copies it can use it until the agent is revoked. |
| Replay | A captured request cannot be replayed or sent to another broker. | The key is sent with every call. |
| Tailscale identity | Not needed: works from a tagged machine. | The call must come from a device of the owner's Tailscale login. |
| Platforms | Any, with an `ssh-agent`. | `warden login` stores it on macOS; elsewhere, set `WARDEN_AGENT_KEY`. |

Prefer a signing key held in hardware. But the key must sign **unattended,
including while the screen is locked**: that is exactly when an agent needs
warden. Check your options against that:

- **Linux with a TPM** ([ssh-tpm-agent](https://github.com/Foxboron/ssh-tpm-agent)):
  signs unattended. The best choice on Linux.
- **YubiKey PIV**, with PIN policy `never` (or `once`) and touch policy
  `never`: signs unattended while plugged in.
- **macOS: Secure Enclave keys** (for example with Secretive) **and the
  1Password SSH agent refuse to sign while the Mac is locked.** They do not
  suit an agent that runs unattended.
- **macOS, unattended: a bearer key in the login Keychain.** The login
  Keychain still serves it while the Mac is locked.
- **A plain key file**: signs unattended, but anyone who copies the file can
  sign. Still better than a bearer key: nothing reusable crosses the
  network.
- **FIDO security keys** (`sk-ssh-ed25519@openssh.com`,
  `sk-ecdsa-sha2-nistp256@openssh.com`) need a touch for every signature and
  are refused.

Whatever you pick, lock the screen once and check that signing still works
(`ssh-keygen -Y sign` through the agent) before relying on it.

### With a signing key

1. **Make a key** the agent can sign with unattended (no touch, PIN or
   biometric prompt per signature: every call is signed, including a long
   poll every 30 seconds while a request waits).

   - **TPM:** create a P-256 key sealed to the TPM with `ssh-tpm-keygen`
     (no PIN, or one the agent unlocks unattended), run `ssh-tpm-agent`, and
     use its socket. The key file it writes is usable only with that TPM.
   - **YubiKey PIV:** generate an ECC P-256 key in a slot and give the slot
     a certificate (the PKCS#11 module exposes a slot's key only when it
     holds one; a self-signed one does):

     ```sh
     ykman piv keys generate --algorithm ECCP256 --pin-policy NEVER \
       --touch-policy NEVER 9a build-agent.pem
     ykman piv certificates generate --subject "CN=build-agent" 9a build-agent.pem
     ssh-add -s <path to libykcs11>
     ssh-add -L > ~/.ssh/build-agent.pub   # keep only the slot's line
     ```

   - **A key file:** `ssh-keygen -t ed25519 -f ~/.ssh/build-agent`, used for
     nothing else, loaded with `ssh-add ~/.ssh/build-agent`.

2. **Have the owner enroll the public key**, on the broker:

   ```sh
   warden-server agent add build-agent --public-key "$(cat ~/.ssh/build-agent.pub)"
   ```

   `warden-server agent list` shows the key's `SHA256:` fingerprint; compare
   it with `ssh-keygen -lf ~/.ssh/build-agent.pub`.

   A key is enrolled for one agent only, and stays with it after the agent
   is revoked: a revoked agent's key can never be enrolled again. If the
   agent is revoked (for example because its machine was compromised), make
   a new key and enroll it under a new name.

3. **Log in** with the public key file (the CLI never reads a private key):

   ```sh
   warden login --server https://warden-api.example.ts.net --agent build-agent \
     --ssh-key ~/.ssh/build-agent.pub
   ```

   `warden login` fetches the broker's audience from `GET /v1/info` and
   pins it, checks that the `ssh-agent` holds the key, makes one signed
   call to confirm the enrollment, and writes the configuration (see
   [Configuration](configuration.md#cli-environment-and-files)). Add
   `--ssh-agent-socket <path>` to use an agent other than the one at
   `$SSH_AUTH_SOCK`.

   The server URL is the agent API's URL, the root of its origin, with no
   path: the path is part of what is signed.

**The audience** identifies the broker: a signature for one broker is
refused by every other. To check it at login, ask the owner for it (it is
in the broker's startup log, `audience loaded`, and in its `/data/audience`
file) and pass `--audience <id>`; the login fails if the broker reports
another. Once an audience is pinned, logging in again to the same URL fails
if the broker reports a different one: you are talking to another broker,
or its data was reset. Ask the owner, then log in with `--audience <new
id>`. If a call is refused and the broker's audience has changed, `warden`
says so.

Each request carries a timestamp, so the machine's clock must be within 60
seconds of the broker's (use NTP). If a request cannot be signed (for
example while the `ssh-agent` restarts), the command stops, also while
waiting for a decision: rerun it once the agent is back. If the broker then
says a request is already pending, cancel the old one or let it expire.

Clients other than `warden` follow [the agent protocol](agent-protocol.md).

**Migrating from a bearer key:** make the key, have the owner run
`warden-server agent set-key build-agent "$(cat ~/.ssh/build-agent.pub)"`
(the bearer key stops working at once), then run `warden login --ssh-key …`
as above. On macOS, that login prints the command that deletes the old key
from the Keychain (`security delete-generic-password -s warden-broker -a
'<server>|<agent>'`); it deletes nothing itself. Run it, and delete the key
from your password manager too.

### With a bearer key

The owner creates the agent and gets its key once:

```sh
warden-server agent add build-agent
```

Store the key in a password manager. On macOS, log in with it:

```sh
op read "op://Private/warden build-agent/key" \
  | warden login --server https://warden-api.example.ts.net --agent build-agent
```

`warden login` reads the key from stdin (a typed key is not echoed) and
stores it in the login Keychain (service `warden-broker`, account
`<server>|<agent>`). The server URL and agent name go into the
configuration file.

`WARDEN_AGENT_KEY`, when set, takes precedence over the Keychain. Fill it
from a secret manager, never from a file in a repository. On Linux there is
no Keychain: write the configuration file yourself and set
`WARDEN_AGENT_KEY` (see
[Configuration](configuration.md#cli-environment-and-files)).

A bearer key is accepted only together with the owner's Tailscale login, so
the agent must run on one of the owner's (untagged) devices.

### Either way

The server URL must be `https://`, or plain `http://` to a loopback address.
The CLI never sets the `Tailscale-User-Login` header: Tailscale Serve adds it
after authenticating the machine.

## Rules for requesting access

These rules keep the owner's approval meaningful and the audit trail true.

- **One grant per task.** Request access for the task in front of you, right
  before you need it, and revoke the grant when the task is done. Do not
  request access "in case it is needed", and do not reuse a grant that was
  approved for another task (see [Known limits](#known-limits)).
- **An honest, precise goal.** The owner decides on the goal alone. Say what
  you will do and why, and name the change, issue or error. "maintenance" or
  "debugging" is not a goal. The goal is one line of at most 500 characters;
  the notification shows the first 200.
- **The narrowest scope.** The least privileged account; for an API, no
  `--methods` (read-only) unless you will change something, and then only
  the methods you will use, under the narrowest `--path`.
- **The shortest window** of `15m`, `30m`, `1h` and `4h` that covers the
  work. The owner may approve a shorter one, and the target's policy caps it.
- **Give the owner the fingerprint** when you can talk to them, so they can
  compare it with the approval page.
- **Never work around warden.** If access is denied, ask what to change. If
  the broker is unreachable, stop and tell the owner.

## Requesting access

### SSH

```sh
warden request ssh web-01 --user build-agent --for 15m \
  --goal "restart the web container after the config change in PR #42"
```

Some targets are reached through the broker's SSH relay instead of with a
certificate. You do not need to know which: the commands are the same. The
target's login credential stays on the broker. Through the relay, port
forwarding (`-L`, `-R`, `-D`), agent forwarding, X11 and subsystems such as
`sftp` (and so `scp` in its default mode) are refused: move files with a
command that reads or writes stdin and stdout instead.

### An HTTP API

Ask for the secret by name. You never see the secret: the broker adds it to
your calls.

```sh
warden request api home-api --for 15m \
  --goal "read the thermostat state to find why automation 12 did not fire"
```

A request without `--methods` is **read-only**: `GET` and `HEAD`. Ask for
write access only when the task needs it, and name just the methods you will
use, optionally under a narrower path:

```sh
warden request api home-api --methods POST --path /api/services/climate/ --for 15m \
  --goal "set the thermostat back to 19 °C after the automation 12 fix"
```

The owner sees **Can modify: POST** for that request, so the goal must say
what you will change. You can only narrow what the secret's item allows; a
method or path outside it is refused at once, and `CONNECT` and `TRACE`
never are. A good pattern is a read-only grant for looking around and a
short write grant for the one change; you may hold both.

The approval page shows the one origin, path prefix and methods the grant
allows, the header and value format the secret is sent in, and whether a CA
is pinned.

### The fingerprint

`warden request` prints this to stderr:

```
request 0b8f4c1e…, fingerprint b65b-9812-eb72 — waiting for approval…
```

The approval page shows the same fingerprint. A mismatch means the request
the owner sees is not yours, and they should deny it.

Only one request per agent and target (or secret and scope) can be pending
at a time. If another one is already waiting, `warden request` stops and
prints that request's fingerprint. It does not wait on a request it did not
make.

### Waiting for the decision

The CLI waits for up to 11 minutes; pending requests expire after 10. If the
broker is briefly unreachable or fails with a 5xx, the CLI retries, pausing
1 s and doubling up to 15 s, with one note on stderr per failure. A refusal
(4xx) ends the wait at once. When the CLI gives up, it says so: the request
may still be pending, and it expires on its own. Do not make a new request
while the old one is pending.

When the owner approves, it prints this to stdout:

```
approved: grant 0f3a…e1 until 2026-10-25 21:15:00 CET
```

### Cancelling a request

If you no longer need access, withdraw the request so the owner's
notification stops being actionable:

- Press Ctrl-C while `warden request` waits. It cancels the pending request
  (waiting at most 5 s for the broker), says so on stderr and exits 130. If
  the broker cannot be reached in time, it says that too: check
  `warden status` and revoke any grant it shows. A second Ctrl-C stops
  waiting for the broker at once.
- Or run `warden request cancel <id>` with the id printed on the
  `request …` line, for example from another terminal. The waiting
  `warden request` then exits 6.

If the owner approves in the instant before the cancel arrives,
`warden request` revokes the grant that approval produced and says so.
Ctrl-C after approval, while the CLI installs the grant, exits 130 at once
and names the grant: run `warden revoke <grant>` if you do not want it.

The approval link of a cancelled request shows "Cancelled by the agent." and
cannot be approved.

## Using a grant

### SSH

```sh
warden ssh web-01                        # interactive shell
warden ssh web-01 -- systemctl status x  # one command
```

`warden ssh` uses the active grant for the target that stays valid longest.
It runs OpenSSH with your `~/.ssh/config` ignored, with only the grant's
`ssh-agent`, and with only the host keys the broker pinned
(`StrictHostKeyChecking=yes`). Passwords and keyboard-interactive login are
disabled. Everything after `--` is the remote command, never ssh options.

A relayed session can end with ssh's exit status 255 and a message starting
`warden relay:` on stderr: the access is no longer valid (revoked or
expired), the broker cannot read the target's policy or the state of grants
right now, the session could not be recorded, forwarding or a subsystem was
asked for, or the broker is shutting down. A session also ends after 15
minutes without traffic, when the target stops reading and the broker gives
up (`flow control`), or when the window ends. Do not retry in a loop: check
`warden status`, and request again if the grant is gone. A refused start and
a target that refuses its login look alike to ssh (255); the owner can tell
them apart in the audit log.

### An HTTP API

```sh
warden http home-api GET https://home.example.com/api/states/climate.living_room
warden http home-api POST https://home.example.com/api/services/climate/set_temperature \
  -H 'Content-Type: application/json' \
  -d '{"entity_id":"climate.living_room","temperature":19}'
warden http home-api POST https://home.example.com/api/services/climate/set_temperature \
  --data-file body.json -i --fail
```

`warden http <secret> <METHOD> <url>` uses the `api` grant for the secret
whose methods and path prefix cover the call; if several do, the one that
stays valid longest. The response body goes to stdout, unchanged. With
`-i`, the status line and response headers go to stderr. `-H 'Name: value'`
adds a request header (repeatable). `-d` gives the body inline, and
`--data-file <path>` reads it from a file (`-` for standard input). A body
is at most 1 MiB.

The broker refuses, with a message that names the rule (exit 1):

- a URL that is not on the secret's origin, not `https`, or whose path is
  outside the allowed prefix or has dot segments, `//`, `;`, `\` or encoded
  separators;
- a method or path the policy, narrowed to the grant, does not allow;
- headers you may not set: `Host`, `Content-Length`, `Connection` and other
  hop-by-hop headers, the secret's own header, `Accept-Encoding`, `Range`,
  `If-Range`, method or URL override headers, and forwarding or
  host-override headers (`Forwarded`, `Via`, `X-Forwarded-*`, `X-Real-IP`,
  `X-Host`, `X-Original-Host`).

Redirects are not followed; a 3xx comes back to you as is. Responses over
the broker's size limit (1 MiB by default) or compressed are an error, and
the secret is replaced by `[REDACTED]` wherever it shows up in a response. A
call takes at most 30 seconds. If the owner changes the secret's policy
after you were approved, or revokes the grant, or the grant expires, the
broker answers 409 (also while a call is out: the response is withheld) and
you request again.

`warden status` lists the grants on this machine and the broker's view of
your live grants.

## Ending a grant

When the work is done, revoke the grant. Do not let it run out on its own:

```sh
warden revoke <grant-id>
```

This revokes the grant on the broker, stops its local `ssh-agent` and
removes the local record of an `api` grant. Relay sessions on the grant end
within seconds.

- **Certificates already issued stay valid on the target** until they
  expire: the target checks them offline. Short windows limit that, so
  revoke as soon as you finish.
- **A proxied API call already in flight runs to completion** (at most
  30 s); only new calls are refused.

Every `warden` run also cleans up expired grants and stops their agents, and
removes temporary files abandoned for over ten minutes by an interrupted
write; live grants and recent files are left alone. A problem during cleanup
is reported once on stderr and never stops the command.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success: the request was approved, the command ran, or the grant was revoked. `warden ssh` exits with ssh's own code. |
| 1 | Error. The message on stderr comes from the broker or the CLI. |
| 2 | The request was denied. Do not retry the same request. Ask the owner what to change. |
| 3 | The request expired without a decision. The owner may be away. Retry later, not in a loop. |
| 4 | The grant was revoked: reported by `warden request`, or by `warden http` when the broker says the grant it used was revoked. `warden http` then removes the stale local record; request access again. |
| 5 | `warden ssh` or `warden http` found no active grant (for `warden http`, none that covers the method and path; the message gives the `warden request api <secret> --methods <METHOD> …` command to run). |
| 6 | The request was cancelled while `warden request` waited for it (`warden request cancel` from another terminal). |
| 22 | `warden http --fail` got an upstream status of 400 or more. The body is still written to stdout. |
| 130 | Interrupted with Ctrl-C while `warden request` waited; the pending request was cancelled (or, if the broker did not answer in time or Ctrl-C was pressed again, left to expire). Also Ctrl-C while an approved grant was being installed; the message names the grant to revoke. |

`warden http` exits 0 for any upstream status unless `--fail` is given. A
refusal or failure by the broker (policy violation, 409, timeout, size
limit) is exit 1 with the broker's message on stderr.

## When the broker is unreachable

If `warden` cannot reach the broker (Tailscale down, broker down), do not
keep retrying. Tell the owner. The owner's own break-glass access (for
example credentials in a password manager unlocked at their workstation) is
outside warden and is meant for a person who is present. An agent must
never try to get around warden by any other route.

## Known limits

- **Grants are shared by everything that runs as the same OS user.**
  `warden ssh` and `warden http` pick any active grant of the agent for the
  target or secret, so two sessions of one agent (or one session across
  tasks) can use each other's grants, under a goal the owner approved for
  something else. Until this is fixed ([issue #49][i49]), revoke each grant
  as soon as its task ends, and run agents that must not share grants as
  different OS users with different agent keys.
- **Revoking does not stop a proxied call in flight** ([issue #44][i44]).
- **Revoking does not invalidate an issued certificate** on the target
  ([issue #35][i35]).

[i49]: https://github.com/pecheriere/warden/issues/49
[i44]: https://github.com/pecheriere/warden/issues/44
[i35]: https://github.com/pecheriere/warden/issues/35

## Instructions to give an agent

A block to paste into an agent's instructions (for example a `CLAUDE.md`):

```markdown
## Privileged access: warden

- Get SSH or API access only through `warden`. Never use other credentials,
  and never try to get around a denial or an unreachable broker: stop and
  tell me.
- Request access right before a task needs it, one request per task:
  `warden request ssh <target> --user <user> --for 15m --goal "<goal>"` or
  `warden request api <secret> [--methods POST --path /prefix/] --for 15m --goal "<goal>"`.
- The goal says exactly what you will do and why, naming the issue, change or
  error. Ask for the least privileged user, read-only API access unless you
  must change something, and the shortest window.
- Tell me the fingerprint `warden request` prints, and wait for the decision.
- Use the grant only for that task: `warden ssh <target> -- <command>` or
  `warden http <secret> <METHOD> <url>`.
- When the task is done, run `warden revoke <grant-id>`.
- Exit 2 (denied): do not retry; ask me what to change. Exit 3 (expired):
  retry later, not in a loop.
```
