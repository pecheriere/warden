# Using warden as an agent

`warden` is how an agent (or a person at a terminal) asks the owner for
short-lived access (an SSH shell, or calls to an HTTP API that needs a
secret) and then uses it. The owner approves on their phone
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

Request access only when the task actually needs a shell on the target (or
a call to the API), and
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
  job. Do not ask for `admin` when your own user is enough. (SSH only.)
- **Shortest window.** Pick the smallest of `15m`, `30m`, `1h` and `4h` that
  covers the work. The owner may approve a shorter window than you asked
  for. The target's policy caps every window.

To call an HTTP API that needs a secret, ask for the secret by name. You
never see the secret: the broker adds it to your calls.

```sh
warden request api github --for 15m \
  --goal "list open PRs on alice/widgets to triage issue #42"
```

The same rules apply: a precise goal, the shortest window, and no request
until you need it. The owner sees the secret's name, and the approval page
shows the one origin, path prefix and methods the grant allows, the header
and value format it is sent in, and whether a CA is pinned.

A request without `--methods` is **read-only**: `GET` and `HEAD`. Ask for
write access only when the task needs it, and name just the methods you will
use, optionally under a narrower path:

```sh
warden request api github --methods POST --path /repos/alice/widgets/ --for 15m \
  --goal "open an issue about the stale fork on alice/widgets"
```

The owner sees **Can modify: POST** for that request, so the goal must say
what you will change. You can only narrow what the secret's item allows; a
method or path outside it is refused at once, and `CONNECT` and `TRACE` never
are. Keep write windows short. A good pattern is a long read-only grant for
looking around and a short write grant for the one change; you may hold both
for the same secret. A 0.3 broker or CLI knows nothing of this: against 0.4,
a request from a 0.3 CLI is read-only. Upgrade the broker before the CLIs: a
0.4 CLI refuses (and does not record) a grant from an older broker that is wider
than it asked for, and says so.

Some targets are reached through the broker's SSH relay instead of with a
certificate. You do not need to know which: `warden request ssh` and
`warden ssh` work the same way. The target's login credential stays on the
broker, and you never see it. Through the relay, port forwarding (`-L`, `-R`,
`-D`), agent forwarding, X11 and subsystems such as `sftp` are refused
(this includes `scp` in its sftp mode), so move files with a command that
reads or writes stdin and stdout instead.

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

`warden ssh` uses the active grant for the target that stays valid longest.
It runs OpenSSH with your `~/.ssh/config` ignored, with only the grant's agent,
and with only the host keys the broker pinned (`StrictHostKeyChecking=yes`). Passwords and
keyboard-interactive login are disabled. Put everything after `--`. It is
the remote command, never ssh options.

### Calling an API

```sh
warden http github GET https://api.github.com/user
warden http github POST https://api.github.com/repos/alice/widgets/issues \
  -H 'Content-Type: application/json' -d '{"title":"stale fork"}'
warden http github PUT https://api.github.com/repos/alice/widgets/x \
  --data-file body.json -i --fail
```

`warden http <secret> <METHOD> <url>` uses the `api` grant for the secret whose
methods and path prefix cover the call; if several do, the one that stays valid
longest. The response body goes to stdout, unchanged. With `-i`, the status line and response headers go to
stderr. `-H 'Name: value'` adds a request header (repeatable). `-d` gives the
body inline, and `--data-file <path>` reads it from a file (`-` for standard
input). A body is at most 1 MiB.

The broker refuses, with a message that names the rule (exit 1):

- a URL that is not on the secret's origin, not `https`, or whose path is
  outside the allowed prefix or has dot segments, `//`, `;`, `\` or encoded
  separators;
- a method or path the policy, narrowed to the grant, does not allow
  (`CONNECT` and `TRACE` never are);
- headers you may not set: `Host`, `Content-Length`, `Connection` and other
  hop-by-hop headers, the secret's own header, `Accept-Encoding`, `Range`,
  `If-Range`, method or URL override headers, and forwarding or host-override
  headers (`Forwarded`, `Via`, `X-Forwarded-Host`, `-For`, `-Proto`, `-Port`,
  `-Server`, `-Prefix`, `X-Real-IP`, `X-Host`, `X-Original-Host`).

Redirects are not followed; a 3xx comes back to you as is. Responses over the
broker's size limit (1 MiB by default) or compressed are an error, and the
secret is replaced by `[REDACTED]` wherever it shows up in a response. A call
takes at most 30 seconds. If the owner changes the secret's policy after you
were approved, or revokes the grant, or the grant expires, the broker answers
409 (also when this happens while a call is out: the response is withheld)
and you request again.

A relayed session can end with ssh's exit status 255 and a message
beginning `warden relay:` on stderr. This happens when the access is no longer
valid (revoked or expired), the broker cannot read the target's policy or the
state of grants right now, the session could not be recorded, forwarding or a
subsystem was asked for, or the broker is shutting down. A session also ends
when it carries no data for 15 minutes, when the target stops reading and the
broker gives up (`flow control`), or when the window ends. Do not retry in a
loop: check `warden status`, and request again if the grant is gone. A refused
start and a target that refuses its login look alike to ssh (255), and
the owner can tell them apart in the audit log.

`warden status` lists the grants on this machine and the broker's view of
your live grants.

When the work is done, revoke the grant. Do not let it run out on its own:

```sh
warden revoke <grant-id>
```

This revokes the grant on the broker, stops its local `ssh-agent` and removes
the local record of an `api` grant.
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
| 5 | `warden ssh` or `warden http` found no active grant. Run `warden request ssh …` or `warden request api …` first. For `warden http`, also when no active grant covers the method and path; the message gives the `warden request api <secret> --methods <METHOD> …` command to run. |
| 22 | `warden http --fail` got an upstream status of 400 or more. The body is still written to stdout. |

`warden http` exits 0 for any upstream status unless `--fail` is given. A
refusal or failure by the broker (policy violation, 409, timeout, size limit)
is exit 1 with the broker's message on stderr.

## When the broker is unreachable

If `warden` cannot reach the broker (Tailscale down, broker down), do not
keep retrying. Tell the owner. The owner's own break-glass access (for
example credentials in a password manager unlocked at their workstation) is
outside warden and is meant for a person who is physically present. An agent
must never try to get around warden by any other route.
