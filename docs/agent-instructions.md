# Instructions for an agent

`warden prime` prints the instructions below for an agent, from the copy built
into the installed CLI. In place of the `warden:offers` marker it puts what the
broker offers this agent, as `warden list` prints it. It leaves out the
sections for what the broker does not offer, and in a git checkout of a GitHub
repository it adds what the broker offers for that repository. Once the agent's
machine is set up (see [Agent usage](agent-usage.md#one-time-setup)), the agent
needs nothing else to ask for access. The reasoning behind these rules is in
[Agent usage](agent-usage.md#rules-for-requesting-access), and
[Examples](agent-examples.md) walks through an SSH deployment and an API call.

## Giving them to an agent

- **A session-start hook**, for an agent whose key signs without a prompt (a
  dedicated agent socket, as `warden login` sets up). The hook runs:

  ```sh
  warden prime --brief
  ```

  It prints [the short form](#the-short-form), about ten lines naming what
  warden covers here, and asks the broker one question.
- **One rule**, for an agent with no hooks, or with a key that prompts for every
  signature. Put this line in the agent's `AGENTS.md` or `CLAUDE.md`:

  ```markdown
  Run `warden prime` before a task that needs an SSH host, an API secret, GitHub, commit signing or a release.
  ```

- **Pasting the block**, the fallback for an agent with no shell access at
  session start: paste the block below into its `AGENTS.md` or `CLAUDE.md`.

`warden list` shows the agent what it may ask for, so it does not have to
guess. If several sessions of this agent run on one machine, also see
[Telling sessions apart](agent-usage.md#telling-sessions-apart).

The HTML comments in the block are for `warden prime`: `warden:section <name>`
and `warden:end` wrap a part it prints only when the broker offers that kind of
access, and `warden:offers` is where the offers go. They render to nothing in
the agent's file.

````markdown
## Privileged access: warden

Reach SSH hosts and HTTP APIs that need a secret only through `warden`. A
person decides each request on their phone. Never use other credentials,
and never look for another way in.

What you may ask for here (run `warden list` to see it):

<!-- warden:offers -->

### Asking for access

First run `warden status`, and do not ask again for what is already granted.
Use a live grant that:

- your own request printed, if its goal covers the work; or
- another session of this agent asked for, only if it is one you would let run
  out (see "When you are finished" below) and it is for the same
  target and user, or the same repository. Never use another session's grant that
  can do harm: ask for your own.

Otherwise ask right before the task needs it, for only what it needs.

<!-- warden:section ssh -->
SSH, as the least privileged user that can do the work:

```sh
warden request ssh <target> --user <user> --for 15m --goal "<what and why>"
```
<!-- warden:end -->

<!-- warden:section api -->
An API, read-only unless you must change something:

```sh
warden request api <secret> --for 15m --goal "<what and why>"
```

To change something, name only the methods you will use, under the narrowest
path:

```sh
warden request api <secret> --methods POST --path <prefix> --for 15m --goal "<what and why>"
```
<!-- warden:end -->

`warden request` blocks until the person decides, for up to 11 minutes. Run it
so it can wait that long, in the background if your tools time out sooner, and
do not start a second one meanwhile: it would not notify them again. If they
missed the notification, the request is on the Pending page of their approval UI.
It prints a fingerprint on stderr, as five words and as hex: tell the person the
words, so they can compare them with the approval page. Do not pipe it through a
command that holds output until the end, such as `tail`: you would not see the
fingerprint or the request ID. If you no longer need the access, withdraw the
request with Ctrl-C, or:

```sh
warden request cancel <request-id>
```

If the command was killed or you lost its output, `warden status` lists your pending
requests and live grants, and asks the person nothing. For an API, commit signing or GitHub
token request still pending, run the same command again to wait on it. A commit signing or
GitHub token grant then needs nothing more. For an API grant that status says is not on this
machine:

```sh
warden request collect <grant-id>
```

An SSH request cannot be picked up: its key was lost with the command. Cancel it if
it is pending, or revoke its grant if it was approved, then make a new request if
the task still needs the access.

### Writing the goal

The person decides on the goal alone, often on a phone, and the notification
shows only the first 200 characters. Say what you will do and why, and name
the issue, change or error. One line, at most 500 characters, nothing secret.

- Good: `restart the web container to load the config from PR #42`
- Good: `read thermostat state to find why automation 12 did not fire`
- Bad: `maintenance`, `debugging`, `need access to the server`

The goal must be true. Do not write one that makes the request look smaller
than it is, and do not use a grant for work its goal does not cover.

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

<!-- warden:section signing -->
### Commits, if this machine signs through warden

If `warden setup git` was run here, git commits are signed by the broker with no prompt,
and a commit fails without that. If it fails saying there is no active commit signing
grant, ask once, not per commit, then commit again. Setting up a new machine takes a grant
too, so ask first and then run `warden setup git`:

```sh
warden request signing --goal "<which agent, and what it commits to>"
```

If it fails because the broker cannot be reached, stop and tell the person. Do not turn
signing off, and do not commit another way, to get past this. A signature says warden signed
for you, not that anyone reviewed your change.
<!-- warden:end -->

<!-- warden:section github -->
### GitHub, if this machine uses warden for it

If `warden setup github` was run here, `git` and `gh` get a token for GitHub from warden
with no prompt. Use them as usual and never print the token, write it into a file or hand it
to anything else. With no grant, the first call asks the person itself and waits. If it ends
with "do not retry … ask the owner" (exit 5), stop and tell the person what you needed and
why: do not retry in a loop, and do not use another credential or turn the helper off. To ask
ahead, with a goal of your own:

```sh
warden request github <owner/name> --goal "<which agent, and what it pushes or opens>"
```

A grant has the owner's default permissions, enough to push, open pull requests and
comment. Ask for more only when the task needs it, such as reading CI results, with
`--extra-permissions name:level,…` (`warden list` shows which the owner allows), and say why
in the goal. A sensitive extra, such as `workflows` or `secrets`, is granted for 1 hour at
most, and its last token lives up to an hour more (the request defaults to `1h`, and a longer
`--for` is refused): make the goal say exactly why you need that permission. Do not ask for one
to get around a refusal. Ask once, with every extra the task needs: a request with other extras
is refused while one waits.
When a task needs less than the grant, such as a read-only check, mint a narrower token with
`warden github token --repo <owner/name> --permissions checks:read`, and add `--fresh` when a
token must be minted again (for example after the owner changed the App's permissions, or a
token was revoked).

A grant covers the repositories the person approves, and a token covers one of them. Name the
repository your task is about, and more than one only when the task needs them. A token for
one repository cannot push, open pull requests, comment or edit issues on another, but it can
still open a new issue on a public repository the App is installed on, and assume it can open issues and comment on any public repository, installed or not. Revoking does not
recall a token already minted, so keep to the repository your task is about, and post nowhere
else. If a call says more than one grant covers the repository, stop and tell the person: they
revoke one.
<!-- warden:end -->

<!-- warden:section release -->
### Releases, if the person asked you to make one

Ask for the one release you were told to make, with `<sha>` the full 40-character commit id,
on the default branch:

```sh
warden request release <owner/name> <tag> --commit <sha> --goal "<what this release is>"
```

Then take only the steps it prints, each once, one command per line:

```sh
warden release tag <owner/name> <tag>
warden release sign-manifest <owner/name> <tag> <manifest-file>
warden release publish <owner/name> <tag>
```

Run `sign-manifest` once the draft release exists. A refusal is final for that step: tell the
person what it said instead of trying another way, and never publish the draft
yourself with another credential.
<!-- warden:end -->

### When you are finished

Revoke right after use, also when the task failed, a grant that can do harm:

- SSH as root, or as a user that can run `sudo`
- an API grant with any method other than `GET` or `HEAD`
- a release grant you give up on before its last step (it ends by itself after
  the last one)
- a GitHub grant with a sensitive permission, such as `workflows` or `secrets`

```sh
warden revoke <grant-id>
```

Let the others run out on their own: SSH as a user that cannot run `sudo`,
read-only API grants, commit signing, and GitHub grants with no sensitive
permission. Revoking one of those only makes the person approve the same thing
again for the next task.

Revoke only a grant your own request printed. Grants belong to the agent, not to
your session: every session of this agent uses the same ones, and a revoke ends
the grant for all of them. The one exception: revoke at once any grant you used
by mistake or think someone else misused, whoever asked for it, and tell the
person.

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

## The short form

`warden prime --brief` prints this, for a session-start hook:

````markdown
<!-- warden:section brief -->
## Privileged access: warden

Privileged access here goes through `warden`: a person approves each request on
their phone. It covers:

<!-- warden:offers -->

Never use other credentials, and never look for another way in.
Run `warden prime` before your first request: it prints how to ask.
Run `warden status` before each request, and use a live grant that covers the work.
<!-- warden:end -->
````

## What this has and has not been tested on

The tests check that every `warden` command in this page and in
[Examples](agent-examples.md) parses with the current CLI. These instructions
have not yet been tried by real agents against a real broker.
