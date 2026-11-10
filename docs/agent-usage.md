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

[Examples](agent-examples.md) walks through an SSH deployment and an API call,
end to end.

## One-time setup

In short:

1. Pick the key for the machine:

   | Machine | Use |
   |---------|-----|
   | Linux with a TPM | A signing key in the TPM. |
   | Linux without one | A signing key from a YubiKey or a key file. A bearer key only if neither is possible, through `WARDEN_AGENT_KEY`, as `warden login` cannot store one there. |
   | macOS, unattended | A bearer key in the login Keychain: the macOS key agents refuse to sign while the Mac is locked. |
   | macOS, someone present | A signing key, for example in the 1Password SSH agent. |

2. The owner runs `warden-server agent add`, which prints the exact
   `warden login` command for the agent's machine.
3. Install the CLI there and run that command. `warden doctor` then checks
   the setup ([what it checks](configuration.md#checking-an-agent-machine)).
4. Paste [the instructions](agent-instructions.md) into the agent's `AGENTS.md`
   or `CLAUDE.md`.

The rest of this section gives the details.

Install the CLI on the agent's machine. It needs the OpenSSH client tools.

With [Homebrew](https://brew.sh), on macOS (Apple silicon) or Linux (x86-64 or arm64):

```sh
brew install pecheriere/tap/warden
```

This installs the latest release's binary from the
[pecheriere/homebrew-tap](https://github.com/pecheriere/homebrew-tap) formula, and
`brew upgrade` updates it after that. Homebrew checks each download against the
checksum in the formula, and the tap's CI refuses a formula whose checksums are not
the ones in the release's signed manifest. To check the binary as well, run
[the release checks](verifying-releases.md#homebrew) on the archive Homebrew
downloaded.

Without Homebrew, releases after v0.8.1 attach binaries for macOS arm64, Linux amd64 and Linux
arm64 (fully static, with no dependency on the distribution's libc). Pick a
release that lists `warden-<version>-<platform>.tar.gz` files on the
[releases page](https://github.com/pecheriere/warden/releases). Checking the
attestation needs a logged-in [`gh`](https://cli.github.com/).
[Verifying a release](verifying-releases.md) adds the check of the maintainer's
signature. That also holds if GitHub is compromised later, but only if you got the
maintainer's public key before then; there is no source for it off GitHub yet:

```sh
version=x.y.z         # the release you picked
platform=linux-amd64  # or linux-arm64, macos-arm64
file="warden-$version-$platform.tar.gz"
curl -fLO "https://github.com/pecheriere/warden/releases/download/v$version/$file"
gh attestation verify "$file" --repo pecheriere/warden \
  --signer-workflow pecheriere/warden/.github/workflows/release.yml \
  --source-ref "refs/tags/v$version"
tar -xzf "$file"
mkdir -p ~/.local/bin
install -m 0755 "warden-$version-$platform/warden" ~/.local/bin/warden
```

`~/.local/bin` must be on your `PATH`. On macOS, download with `curl` as above
rather than a browser: the binary is not notarized, and macOS may block one
that a browser downloaded.

On Debian, Ubuntu, Fedora or RHEL, releases after v0.9.0 also attach `.deb` and `.rpm`
packages of the same binary, which bring in what it needs. Download one, check it the
same way, and install it. Nothing updates it for you, because there is no package
repository, so install the next release's package yourself:

```sh
version=x.y.z
file="warden_${version}_amd64.deb"      # or arm64
# file="warden-$version-1.x86_64.rpm"   # or aarch64
curl -fLO "https://github.com/pecheriere/warden/releases/download/v$version/$file"
gh attestation verify "$file" --repo pecheriere/warden \
  --signer-workflow pecheriere/warden/.github/workflows/release.yml \
  --source-ref "refs/tags/v$version"
sudo apt install "./$file"              # or: sudo dnf install "./$file"
```

The packages hold only the CLI. They are not signed with a package key, so
`dnf install` of a local file relies on the check above.

On another platform, build it instead, with Rust 1.99 or later. For an older
release, which has no binaries, use its tag in the same command:

```sh
cargo install --locked --git https://github.com/pecheriere/warden --tag v0.10.0 warden-broker-cli
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
  are refused, as are RSA keys, ECDSA keys on curves other than P-256, and
  certificates.

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

2. **Have the owner enroll the public key.** Send the owner the one line of
   `~/.ssh/build-agent.pub` (it is not secret). The owner runs, on the
   warden host (in `/srv/warden` with the Compose file of
   [Deployment](deployment.md#5-run-warden)):

   ```sh
   docker compose exec warden /warden-server agent add build-agent \
     --server https://warden-api.example.ts.net \
     --public-key 'ecdsa-sha2-nistp256 AAAA… build-agent'
   ```

   It prints the command for step 3, with the broker's audience pinned.
   `--server` is the agent API's URL: the server does not know the name agents
   reach it by. Without it, the command says `<agent-api-url>`. The audience is
   left out, with a note, if warden has not started yet. Nothing in the command
   is secret.

   `docker compose exec warden /warden-server agent list` shows the key's
   `SHA256:` fingerprint; compare it with
   `ssh-keygen -lf ~/.ssh/build-agent.pub` on the agent machine.

   A key is enrolled for one agent only, and stays with it after the agent
   is revoked: a revoked agent's key can never be enrolled again. If the
   agent is revoked (for example because its machine was compromised), make
   a new key and enroll it under a new name.

3. **Log in** with the public key file (the CLI never reads a private key),
   using the command `agent add` printed:

   ```sh
   warden login --server https://warden-api.example.ts.net --agent build-agent \
     --ssh-key ~/.ssh/build-agent.pub --audience 0123456789abcdef0123456789abcdef
   ```

   The printed `--ssh-key` path uses the agent's name; change it if the file
   is elsewhere.

   `warden login` fetches the broker's audience from `GET /v1/info` and
   pins it, checks that the `ssh-agent` holds the key, makes one signed
   call to confirm the enrollment, and writes the configuration (see
   [Configuration](configuration.md#cli-environment-and-files)). Add
   `--ssh-agent-socket <path>` to use an agent other than the one at
   `$SSH_AUTH_SOCK`.

   The server URL is the agent API's URL, the root of its origin, with no
   path: the path is part of what is signed.

**The audience** identifies the broker: a signature for one broker is
refused by every other. To check it at login, pass `--audience <id>` as the
command from `agent add` does (it is also in the broker's startup log,
`audience loaded`, and in its `/data/audience` file); the login fails if the
broker reports another. Once an audience is pinned, logging in again to the same URL fails
if the broker reports a different one: you are talking to another broker,
or its data was reset. Ask the owner, then log in with `--audience <new
id>`. If a call is refused and the broker's audience has changed, `warden`
says so.

Each request carries a timestamp, so the machine's clock must be within 60
seconds of the broker's (use NTP). If a request cannot be signed (for
example while the `ssh-agent` restarts), the command stops, also while
waiting for a decision: rerun it once the agent is back. If `warden request`
then says a request is pending, cancel the old one or let it expire.

Clients other than `warden` follow [the agent protocol](agent-protocol.md).

**Migrating from a bearer key:** make the key and send its `.pub` line to
the owner, who runs, on the warden host:

```sh
docker compose exec warden /warden-server agent set-key build-agent '<the line>'
```

The bearer key stops working at once. Then run `warden login --ssh-key …`
as above. On macOS, that login prints the command that deletes the old key
from the Keychain (`security delete-generic-password -s warden-broker -a
'<server>|<agent>'`); it deletes nothing itself. Run it, and delete the key
from your password manager too.

### With a bearer key

The owner creates the agent on the warden host and gets its key once:

```sh
docker compose exec warden /warden-server agent add build-agent \
  --server https://warden-api.example.ts.net
```

Only the key goes to stdout, so it can be piped into a password manager. The
next steps go to stderr and never contain the key: the `warden login` command
for macOS, which takes the key from a prompt or stdin, and the configuration
to write on Linux.

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

`warden doctor` checks this machine's setup and says what to fix: see
[Checking an agent machine](configuration.md#checking-an-agent-machine).

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
request 0b8f4c1e…, fingerprint dozed-crawfish-kayak-ascend-answer (b65b-9812-eb72) — waiting for approval…
```

The approval page shows the same fingerprint. A mismatch means the request
the owner sees is not yours, and they should deny it.

The words and the hex in brackets are the same 48 bits written two ways, not two
checks: the words are for people, to compare at a glance or read aloud, and the hex
is what the API and the audit log carry. The page shows both, so an agent or an older
`warden` that shows only hex can still be compared with it.

Only one request per agent and target (or secret and scope) can be pending
at a time. If one is pending, `warden request` waits on it only when the
fingerprints match:

- `warden request ssh` always stops, even when you rerun the same command,
  because each run generates a new key and the key is part of the fingerprint.
- `warden request api` waits on a pending request written the same way, with the
  same goal, window, methods and path. Otherwise it stops, even if the two ask
  for the same access: leaving out `--methods` and listing the read-only methods
  yourself give different fingerprints.

A [session label or link](#telling-sessions-apart) is part of the fingerprint too.

When it stops, it prints the pending request's ID and fingerprint in both forms,
says that it
expires within 10 minutes of being made, and gives the command to withdraw it:
`warden request cancel <id>`.

### Waiting for the decision

The CLI waits for up to 11 minutes; pending requests expire after 10. If the
broker is briefly unreachable or fails with a 5xx, the CLI retries, pausing
1 s and doubling up to 15 s, with one note on stderr per failure. A refusal
(4xx) ends the wait at once. When the CLI gives up, it says so: the request
may still be pending, and it expires on its own. Do not make a new request
while the old one is pending: you would get the same request back, and the owner
no new notification. If the owner missed the notification, they do not need one:
the request waits on the **Pending** page of their approval UI, so tell them to
look there.

When the owner approves, it prints this to stdout:

```
approved: grant 0f3a…e1 until 2026-10-25 21:15:00 CET
```

`warden request` blocks, and its progress, including the request ID and the
fingerprint to tell the owner, goes to stderr. Do not run it through a command
that holds its output until the end, such as `warden request … 2>&1 | tail -20`:
you see nothing while the owner decides, and if the command is killed you never
see the ID. Run it in the background with its output in a file if your tools
cannot wait 11 minutes. If you have lost the output, `warden status` lists what
is pending.

### If the `warden request` is gone

A request does not depend on the command that made it. If that command is killed
or its output is lost, the request stays pending on the broker, the owner can still
approve or deny it, and it expires 10 minutes after it was made like any other. The
broker cannot tell that the command is gone, and an API client is free to poll now
and then, so nothing ends a request early except the owner, a cancel or the expiry.

`warden status` shows your pending requests, under `pending requests:`, with the ID,
the access, the window, the fingerprint, the goal, any session label and link, and
when each was made and expires. Looking is safe: it does not notify the owner, is not written to the audit log, and
does not count against your request limits. It never shows the approval link, which goes
only to the owner.

What you can do next depends on the kind of request:

| | While it is pending | After it is approved |
|---|---|---|
| `warden request api` | Run the same command again, with the same goal, window, methods, path, session label and link, to wait on the same request. The owner gets no second notification. | `warden status` lists the grant under `broker grants:` as not on this machine. Run `warden request collect <grant-id>`, and `warden http` can use it. |
| `warden request signing` | Run the same command again, with the same goal, window, session label and link, to wait on the same request. | Nothing to do: the broker signs under the grant, which needs nothing on this machine, so `git commit` works once git is [set up](#signing-commits). `warden request collect` says so and exits 1. |
| `warden request ssh` | **It cannot be completed, even if the owner approves it.** Withdraw it with `warden request cancel <id>`, then make a new request. | **The grant cannot be used.** Run `warden revoke <grant-id>`, then make a new request if the task still needs the access. |

An SSH request cannot be recovered because `warden request ssh` makes a new key for
each run and keeps it only in memory, so that no private key is written to disk. The
broker certifies the public key the request named, or binds a relay grant to it, and
with the run gone nothing holds the private half. The grant gives nobody access, but
it stays on the owner's lists until you revoke it or it expires, so end it. `warden
request collect` refuses it and says so (exit 5). A client that uses the
[API](agent-protocol.md#what-happens-when-a-client-dies) and keeps its own key can
complete such a request.

If the command is still running, leave its request alone: `warden status` cannot
tell whether it is. Do not cancel a request another terminal is waiting on.

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

You can cancel only your own requests, and only while they are pending. The
approval link of a cancelled request shows "Cancelled by the agent." and
cannot be approved; the request appears as `cancelled` in the owner's
history and the audit log.

### Commit signing

```sh
warden request signing --goal "Sign build-agent's commits on the warden repo"
```

This is one of two grants that last long: 30 days by default, with `--for 1d`, `7d`, `30d` or
`90d` up to what the server allows, because a rebase can need many signatures and none of
them should need a prompt. Ask once, not per commit. See [Signing commits](#signing-commits).

### Requesting GitHub tokens

```sh
warden request github --goal "Push branches and open PRs for build-agent's fixes"
```

The other long grant: 30 days by default, with `--for 1d`, `7d` or `30d` up to what the
server allows. Ask once, not per push. You do not have to ask ahead: with none, the first
`git` or `gh` call to GitHub asks by itself and waits. See [GitHub tokens](#github-tokens).
Unlike every other grant, this one hands you a credential: revoking the grant stops new
tokens, and does not recall one already minted. Do not copy the token anywhere.

### Telling sessions apart

When several sessions of a coding agent run under one enrolled agent, the owner
cannot tell from the agent's name which one is asking. A request can say:

```sh
warden request ssh web-01 --user build-agent --for 15m \
  --session release-work \
  --goal "restart the web container after the config change in PR #42"
```

- **`--session <label>`**, or `WARDEN_SESSION` for every request made from that
  environment; the option wins, and a blank variable counts as unset. One line of
  at most 64 characters, with the rules of a goal, and no line or paragraph
  separators. An invalid one stops the command (exit 64), including one from the
  variable, so a setup that fills it in must keep it short.
- **`--link <url>`**: a page about this work, such as a pull request. It works
  only with hosts the owner has listed in
  [`WARDEN_REQUEST_LINK_HOSTS`](configuration.md#links-in-requests), which is empty
  by default. A link to any other host refuses the request, and nothing reaches
  the owner: make it again without the link. There is no variable for it, so that
  a setup cannot break every request on a broker without the list.

  A link must be `https://<host>/<path>`, at most 256 bytes: no user or password,
  no port, no query or fragment, no IP address, only printable ASCII (an
  international host as `xn--…`). Do not put anything secret in the path: the
  owner sees it, and the broker stores it.

The owner sees both on the approval page, Pending, Active grants and History, as
what the agent stated. The label is also in the notification and the audit log.
The link is in neither. Both are in the [fingerprint](#the-fingerprint), so the
two are bound to what the owner approves.

**A label is a claim, not an identity.** Sessions under one agent run as the same
OS user with the same key, so any of them can state any label, and it does not stop
one session from using another's grant ([issue #49][i49]). Separating sessions
takes separate OS users and agent keys.

**Only one request per agent and target can be pending, whatever the label.** A
second session asking for the same thing gets the first one's request back. Its
fingerprint differs, so `warden request` stops and says so.

**An older broker ignores both.** `warden request` still waits, since the access
is the same, and warns that the owner does not see them.

#### Where a name comes from in Claude Code

From Claude Code's [documentation](https://code.claude.com/docs/en/env-vars.md),
which may change; warden depends on none of it:

| What | Available to commands the agent runs? |
|---|---|
| Session ID | Yes, `CLAUDE_CODE_SESSION_ID`, an opaque ID. |
| Session title | No. A [`SessionStart` hook](https://code.claude.com/docs/en/hooks.md) gets `session_title`, but only for a custom title (`--name`, `/rename`). The [status line](https://code.claude.com/docs/en/statusline.md) gets `session_name`. |
| Session page URL | Not as a URL. `CLAUDE_CODE_REMOTE_SESSION_ID` is set in cloud sessions and `CLAUDE_CODE_BRIDGE_SESSION_ID` during Remote Control, to build one from. A local session without Remote Control has no page. |

So a session does not reliably know its title, and has to be told it or use a short
ID. A `SessionStart` hook can set the variable for the session's later commands, by
appending to the file that `CLAUDE_ENV_FILE` names:

```sh
#!/bin/bash
# The hook's input is JSON on stdin; session_title is there only for a custom title.
# An invalid WARDEN_SESSION stops every request, so keep only printable ASCII, which
# can pass any label check, and cut by bytes, which cannot split a character then.
input="$(cat)"
clean() { LC_ALL=C tr -cd ' -~' | head -c 64; }
label="$(printf '%s' "$input" | jq -r '.session_title // empty' 2>/dev/null | clean)"
if [ -z "${label// /}" ]; then
  label="$(printf '%s' "$input" | jq -r '.session_id // empty' 2>/dev/null | clean | head -c 8)"
fi
# With no usable name, set nothing: the request simply has no label.
if [ -n "${label// /}" ] && [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  printf 'export WARDEN_SESSION=%q\n' "$label" >> "$CLAUDE_ENV_FILE"
fi
```

A title in another script or with emoji loses those characters, and falls back to the
ID if nothing is left. This was run with sample input against `warden`'s validation,
not in a real session.

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

### Tools that run ssh themselves

Some tools need to run `ssh` themselves, with options of their own
(`BatchMode`, `ControlMaster`, `ControlPath`, `ControlPersist`, `-G`), so they
cannot go through `warden ssh`. `warden ssh-config` gives them the same grant
as an `ssh_config` `Host` block:

```sh
warden ssh-config web-01 --output "$dir/ssh_config" --min-remaining 10m
ssh -F "$dir/ssh_config" -o BatchMode=yes web-01 -- systemctl status x
```

It picks the grant `warden ssh` would use, and the block carries exactly the
options `warden ssh` passes on its command line:

```
# warden grant <id> for web-01, not_after=1800000000 (2027-01-15T08:00:00Z)
Host web-01
  HostName 192.0.2.10
  Port 22
  User deploy
  IdentityAgent "/tmp/warden-501/0123456789ab.sock"
  IdentityFile none
  IdentitiesOnly no
  UserKnownHostsFile "/home/agent/.local/state/warden/grants/<id>/known_hosts"
  StrictHostKeyChecking yes
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  ForwardAgent no
```

- The `Host` name is the target name, so `ssh -F <file> <target>` stays the
  same from one grant to the next. For a relay grant, `HostName` and `Port`
  are the relay's and `User` is the target name, as with `warden ssh`.
- Paths are quoted, with `%` doubled. A path that quoting cannot carry (a
  `"`, a `\` or a control character in it) is refused, with exit 1.
- Without `--output`, the block goes to stdout. `--output <file>` writes it
  0600 and atomically: a temporary file in the same directory, renamed over
  the old one. If `<file>` exists and is not a regular file, such as a symlink
  or a directory, it is refused, with exit 1; a symlink is never followed.
- `--json` prints one JSON object on stdout, also with `--output`: `target`,
  `grant` (its id), `host`, `port`, `user` (the block's `User`), `not_after`
  (Unix seconds), `socket` and `known_hosts` (plain paths, not quoted) and
  `config` (the block).
- `--min-remaining <duration>`, such as `10m`, `1h30m` or `90s`, exits 5 when
  the grant ends sooner, so the tool does not start work the grant would cut
  short. The message gives how long the grant has left and the
  `warden request ssh …` command.
- With no active grant for the target, or if its agent socket is gone, it
  exits 5 with the `warden request ssh …` command, as `warden ssh` does.

The block names this grant's agent socket, which changes with every grant.
Make it again right before each connection rather than keeping it: one
command, and it always reflects the live grant. A block from an ended grant
points at a socket that is gone, so its connections fail.

The block points at the grant's agent and its pinned `known_hosts`; no key or
certificate is written. Expiry and revocation work as for `warden ssh`: the
agent drops the key at `not_after`, and revoking removes the socket. A
connection that has already logged in, including a `ControlMaster` master the
tool keeps open with `ControlPersist`, lives until it closes, as a
`warden ssh` session does. End it when the work is done.

Keep the grant's socket inside this block:

- Do not put the socket in `SSH_AUTH_SOCK`. Every ssh, git and other program
  that reads it would then offer the grant's key, to any host.
- Do not add the block, or `IdentityAgent` with the socket, to a normal
  `~/.ssh/config`. Use it only with `ssh -F <file>`, which reads no other
  config file.
- Keep `ForwardAgent no`. Forwarding the agent lets the remote host use the
  key for as long as the connection is open.

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
- more than 100 headers;
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
broker answers 409 (also while a call is out: the call stops, and nothing of the
response comes back) and
you request again.

`warden status` lists the grants on this machine, and the broker's view of
your live grants and pending requests.

### Signing commits

Once, on each machine, with a grant: `warden setup git`. It makes this program git's `gpg.ssh.program`,
sets `user.signingkey` to the broker's public key and turns on `commit.gpgsign`, so that
`git commit`, `git rebase` and the rest work as usual. The key stays on the broker, which
returns only the signature. Verifying goes to the real `ssh-keygen`.

A signature means warden signed the commit for this agent, not that anyone reviewed the
change. A commit does not say which repository or branch it is for, so warden does not ask.

With this set up, a commit needs a signature. It fails, with the reason on stderr, when:

| What git shows | What to do |
|---|---|
| The agent has no active commit signing grant (it never had one, or it ended or was revoked). | `warden request signing --goal "..."`, then commit again. If the owner revoked it, ask them why before asking again. |
| The grant has reached its limit of signatures for today, 5000 by default. | warden tries to notify the owner, so tell them too. It starts again at 00:00 UTC. If you did not mean to make this many, stop and find out why. |
| The broker cannot be reached. | As in [When the broker is unreachable](#when-the-broker-is-unreachable): tell the owner and commit again once it answers. |
| The broker signs with another key than `user.signingkey`, or says the key changed. | The owner replaced the key: run `warden setup git`, and ask for a new grant. |

Do not turn signing off to get past this. If the task needs a commit and signing is not
available, stop and tell the owner.

Tags are not signed: a tag object is refused, whatever the grant. `warden doctor` checks all
of this, and the owner sees every signature in the audit log.

### GitHub tokens

Once, on each machine, and needing no grant: `warden setup github`. It points git's global
`credential.https://github.com.helper` at warden alone, first an empty value, which drops the
helpers configured before it, then `!<warden> git-credential`. It writes `~/.local/bin/gh`, a
script that sets `GH_TOKEN` from `warden github token` and runs the real `gh`. It refuses to
replace a `gh` there that it did not write, and warns on stderr when `~/.local/bin` is not
before the real `gh` on `PATH`, as plain `gh` would then run without a token. With no `gh` on
`PATH` it sets git up and writes no wrapper. It prints each change. Run it again after
an upgrade that moves the warden binary, as Homebrew's can.

After that `git push`, `git fetch` and `gh` work against GitHub as usual, with a token from
warden. The token covers **every repository the owner's GitHub App is installed on**, with
`contents`, `pull_requests` and `issues` write, and lasts an hour. It can also open issues and
comment on public repositories outside the installation, which takes only read access. warden keeps it in
`github-token.json` in its state directory, mode 0600, and gets a new one when less than 5
minutes of it remain. Use it only through `git` and `gh`: do not print it, write it into a
file, put it in a URL or hand it to another program.

**With no active grant**, the first call asks the owner itself: a request for 30 days, or the
broker's maximum if that is shorter, with a
fixed goal that says which program asked, followed by `, in <current directory>`. It says on
stderr that it is asking and waits, as `warden request` does, for up to 11 minutes. To word the
goal yourself or choose the window, run `warden request github` first.

When no token can be had, `git` or `gh` fails, with the reason on stderr:

| What you see | What to do |
|---|---|
| The request was denied, expired, cancelled or revoked, or the owner did not answer in time (exit 5, "do not retry … ask the owner"). | Stop. Do not retry in a loop and do not look for another way to reach GitHub: tell the owner what you need and why. |
| The broker refused the call while the request was waiting, for example because the agent was revoked (exit 5 as well). | The same: tell the owner. |
| "no active GitHub token grant" although the owner approved one (exit 5). | The grant was revoked since. Ask the owner why before asking again. |
| "the GitHub App changed; request a new grant" (exit 5). | The owner changed the App or its installation. `warden request github --goal "…"`. |
| The grant ended while the token was being minted (exit 5). | If the owner has just approved a new grant, run the command once more. Otherwise tell the owner. |
| "GitHub tokens are not configured on this broker" (exit 1). | Tell the owner. |
| "this agent has reached its limit of GitHub tokens for this hour" (exit 1). | Something on this machine asks for far more tokens than `git` and `gh` need (the CLI keeps one for its hour). Stop it rather than retrying, and tell the owner if you cannot find it. |
| The broker refused the request when it was made, for example because the agent is over its [request limits](configuration.md#request-limits) (exit 1, with the wait in the message). | Wait that long, or reuse the request already pending. Do not retry sooner. |
| GitHub or the broker is unavailable, or the broker cannot be reached (exit 1). | As in [When the broker is unreachable](#when-the-broker-is-unreachable): tell the owner and try again once it answers. `warden doctor` checks the connection. |

Do not turn the helper off, give git another credential or ask for a token another way to get
past this. `warden doctor` checks the setup (the `github.token` check), and the owner sees
every token minted in the audit log.

**Revoking and tokens.** A grant that is revoked or ends stops new tokens at once, but a
token already minted works until GitHub ends it, at most an hour later. The cached one is
served for the rest of its hour even after the owner revokes in the approval UI. `warden
revoke <grant>` on this machine deletes it. There is no **Renew** button and no notice before
a GitHub token grant ends: the next call after it ends asks the owner again, and approving a
new grant ends the old one.

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
  revoke as soon as you finish. A login already open continues even after the
  certificate expires, so end your sessions and what they started.
- **A proxied API call already in flight stops**, with none of its response, even if
  a response had started to arrive (`warden http` exits 4 for a revoke and 5 for
  expiry). The outcome upstream is unknown: the API may have acted on the call, so
  find out before you repeat one that changes something.

Every `warden` run also cleans up expired grants and stops their agents, and
removes temporary files abandoned for over ten minutes by an interrupted
write; live grants and recent files are left alone. A problem during cleanup
is reported once on stderr and never stops the command.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success: the request was approved, the command ran, the block was written, or the grant was revoked. `warden ssh` exits with ssh's own code. |
| 1 | Error. The message on stderr comes from the broker or the CLI. |
| 2 | The request was denied. Do not retry the same request. Ask the owner what to change. |
| 3 | The request expired without a decision. The owner may be away. Retry later, not in a loop. |
| 4 | The grant was revoked: reported by `warden request`, or by `warden http` when the broker says the grant it used was revoked. `warden http` then removes the stale local record; request access again. |
| 5 | Called by git to sign a commit, with no active commit signing grant. `warden github token` or git's credential helper could not get a GitHub token without going around the owner: the request they filed ended without a grant, the grant ended or was revoked, or the App changed. `warden ssh`, `warden ssh-config` or `warden http` found no active grant (for `warden http`, none that covers the method and path; for `warden ssh-config --min-remaining`, none that stays valid that long), or the broker said the grant `warden http` used has expired, whose local record is then removed. The message gives the `warden request …` command to run if the task needs it. `warden request collect` exits 5 too, when the grant is not live or is an SSH grant whose key is lost. |
| 6 | The request was cancelled while `warden request` waited for it (`warden request cancel` from another terminal). |
| 7 | `warden doctor --strict` found no failure, but could not check everything: see [Checking an agent machine](configuration.md#checking-an-agent-machine). Without `--strict` it exits 0 and lists those items. It exits 1 when a check failed. |
| 8 | The broker stopped a `warden http` call that was out, because it could not read the grant's state. No response came back, and the API may have acted on the call: find out before repeating one that changes something. The grant stays; if this repeats, tell the owner. |
| 22 | `warden http --fail` got an upstream status of 400 or more. The body is still written to stdout. |
| 64 | Wrong arguments: nothing ran. The message on stderr shows the usage. Fix the command and run it again. |
| 130 | Interrupted with Ctrl-C while `warden request` waited; the pending request was cancelled (or, if the broker did not answer in time or Ctrl-C was pressed again, left to expire). Also Ctrl-C while an approved grant was being installed; the message names the grant to revoke. |

A broker error includes being over the [request limits](configuration.md#request-limits):
an agent can have 5 requests pending and make 10 new ones per 10 minutes by
default. The message says how long to wait. Do not retry sooner: reuse a grant
or a pending request where you can.

`warden http` exits 0 for any upstream status unless `--fail` is given. A
refusal or failure by the broker (policy violation, other 409s, timeout, size
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
- **Revoking a proxied call in flight cannot undo it.** The call stops, but the API
  may already have acted on it.
- **Revoking commit signing does not undo a signature.** It stops new ones.
- **Revoking a GitHub token grant does not recall a token already minted.** It stops new
  ones. A token already out works for up to an hour, and covers every repository the App is
  installed on, plus issues and comments on public repositories.
- **Revoking does not invalidate an issued certificate** on the target
  ([issue #35][i35]).

[i49]: https://github.com/pecheriere/warden/issues/49
[i35]: https://github.com/pecheriere/warden/issues/35

## Instructions to give an agent

[Instructions for an agent](agent-instructions.md) is a block to paste into an
agent's `AGENTS.md` or `CLAUDE.md`: how to ask, how to write a goal, how to
choose a window, when to revoke and what to do when denied.
