# Instructions for an agent

Paste the block below into the agent's `AGENTS.md` or `CLAUDE.md`, once the
agent's machine is set up (see [Agent usage](agent-usage.md#one-time-setup)).
The agent needs nothing else to ask for access. The reasoning behind these
rules is in [Agent usage](agent-usage.md#rules-for-requesting-access), and
[Examples](agent-examples.md) walks through an SSH deployment and an API call.

Add the targets and secrets this agent may use where the block says so: it
cannot list them, and it should not guess. If several sessions of this agent run
on one machine, also see [Telling sessions apart](agent-usage.md#telling-sessions-apart).

````markdown
## Privileged access: warden

Reach SSH hosts and HTTP APIs that need a secret only through `warden`. A
person decides each request on their phone. Never use other credentials,
and never look for another way in.

Available here: <the targets and users, and the secrets, this agent may ask for>

### Asking for access

Ask right before a task needs it, once per task, for only what that task needs.

SSH, as the least privileged user that can do the work:

```sh
warden request ssh <target> --user <user> --for 15m --goal "<what and why>"
```

An API, read-only unless you must change something:

```sh
warden request api <secret> --for 15m --goal "<what and why>"
```

To change something, name only the methods you will use, under the narrowest
path:

```sh
warden request api <secret> --methods POST --path <prefix> --for 15m --goal "<what and why>"
```

`warden request` blocks until the person decides, for up to 11 minutes. Run it
so it can wait that long, in the background if your tools time out sooner, and
do not start a second one meanwhile: it would not notify them again. If they
missed the notification, the request is on the Pending page of their approval UI.
It prints a fingerprint on stderr, as five words and as hex: tell the person the
words, so they can compare them with the approval page. If you no longer need
the access, withdraw the request with Ctrl-C, or:

```sh
warden request cancel <request-id>
```

### Writing the goal

The person decides on the goal alone, often on a phone, and the notification
shows only the first 200 characters. Say what you will do and why, and name
the issue, change or error. One line, at most 500 characters, nothing secret.

- Good: `restart the web container to load the config from PR #42`
- Good: `read thermostat state to find why automation 12 did not fire`
- Bad: `maintenance`, `debugging`, `need access to the server`

The goal must be true. Do not write one that makes the request look smaller
than it is, and do not use a grant for anything else.

### Naming your session

If your session has a name, say it, so the person can tell which session is
asking. Add `--session "<name>"` to the request, unless `WARDEN_SESSION` is
already set: one line, at most 64 characters. If `warden` or the broker is too old
for that (`warden` rejects the option, or says the owner does not see the label),
start the goal with the name instead: `[release-work] restart the web container
to load the config from PR #42`.

This is a claim, not an identity. Nothing checks it, and you share your key with
every other session of this agent. Use your session's real name, and do not use a
name to make a request look like it comes from someone else.

If the person has asked for a link back to your work, add `--link <url>`: `https`,
no query or fragment. The request is refused if the broker's owner has not listed
that host; make it again without the link, and do not look for another way to
pass it.

### The window

Use the shortest of `15m`, `30m`, `1h` or `4h` that covers the work, and start
with `15m` when unsure. If the work runs longer, make a new request that says
what is left. Never ask for a long window to avoid asking twice. A window
above the target's limit is refused: ask for a shorter one.

### Using a grant

On approval, `warden request` prints `approved: grant <id> until <time>`. The
person may approve a shorter window than you asked for, so read the time.

```sh
warden ssh <target> -- <command>
warden http <secret> <METHOD> <url> --fail
```

`warden http` exits 0 for any upstream status unless you pass `--fail`. The
secret never reaches you, so do not try to read it. `warden status` lists
your grants.

### When you are finished

Revoke the grant as soon as the task is done, also when it failed. Do not let
it run out:

```sh
warden revoke <grant-id>
```

### When it does not work

Read the message on stderr, then act on the exit code:

| Exit | Meaning | What to do |
|------|---------|------------|
| 2 | Denied. | Do not send the same request again. Stop, and ask the person what to change. Change the request only as they say. |
| 3 | No decision in time. | Tell the person you need the access. Try again later, not in a loop. |
| 4 | The grant was revoked. | It may have been on purpose. Check with the person before asking again. If the message says the call was already out, it may have taken effect: find out before repeating it. |
| 5 | No active grant covers this. It was never requested, or it expired or was revoked. | If the message says the call was already out, it may have taken effect: find out before repeating it. If the task still needs it, make a new request with an honest goal. Do not widen it beyond what the task needs. |
| 6 | The request was cancelled. | Someone withdrew it. Ask again only if the task still needs it. |
| 8 | The broker stopped your `warden http` call while it was out. | It may have taken effect: find out before repeating it. If this repeats, tell the person. |
| 64 | Your command is wrong. The message shows the usage. | Fix the command and run it again. |
| 1 | Another error. The message says which. | If the broker cannot be reached or refuses your login, stop and tell the person what `warden doctor` reports. Otherwise fix what the message names, and do not retry blindly. |

Checking the setup changes nothing, and is safe at any time:

```sh
warden doctor
```

A denial is an answer. Never get around it or an unreachable broker: no other
credentials, no other route, no splitting a denied request into smaller ones,
and no rewording the goal to get a different answer. Stop and tell the person.
````

## What this has and has not been tested on

The tests check that every `warden` command in this page and in
[Examples](agent-examples.md) parses with the current CLI. These instructions
have not yet been tried by real agents against a real broker.
