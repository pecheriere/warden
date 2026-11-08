# Agent access model: what is free, what needs the owner, and where secrets live

Date: 2026-11-08. Status: draft for the owner's review.

## Why

Coding agents on the owner's Mac currently act with the owner's own
credentials: the owner's `gh` token (scopes `repo`, `workflow`, `admin:org`,
`admin:public_key`, `admin:ssh_signing_key`, `gist`) in the login Keychain, and
an on-disk SSH signing key that is also a key listed in `docs/release-signers`.
Anything that runs as the owner, including any build script an agent runs, can
read both. Everything agents do on GitHub looks exactly like the owner. A
release needs the owner at the Mac (1Password prompts for the release key).
And an SSH remote made the owner answer a 1Password prompt for an ordinary
`git pull`.

The owner wants:

- never to be pinged for routine work: commits, signing, pushes, pull requests,
  merges, issues, comments;
- to be able to tell what agents did apart from what they did themselves;
- a phone prompt, and only a phone prompt, for anything elevated (creating
  repositories, changing settings, secrets), for releases, for SSH and for
  sensitive APIs;
- **never to run a command for an agent.** Every approval happens on the phone
  and the agent does the work;
- good secret hygiene that limits the damage if the Mac or an agent is
  compromised, without "fake security": no closed door next to five open
  windows, and no roadblock that does not buy real protection.

## Threats this addresses, and what it does not

**Addressed.**

1. *A compromised agent session* (a malicious dependency or build script, an
   injected instruction in a web page or issue). This is the most likely path,
   because agents run unreviewed code all day. It must not reach the owner's
   own account: browser sessions, Keychain, 1Password, shell configuration.
2. *Theft of anything agents hold.* What an agent can copy off the machine must
   be narrow, short-lived where possible, and revocable from the phone.
3. *A release nobody approved.* Nothing reaches users without a phone approval
   bound to one version and one commit.

**Not addressed, by decision.**

- Malware running as the owner's own macOS user (from outside the agents). It
  can ride the owner's browser and unlocked 1Password; that is ordinary Mac
  hygiene and outside warden.
- An attacker who steals the agent's warden identity can do what the routine
  tier allows until the owner revokes it, including merging into `main` once
  checks pass. That follows from letting agents merge freely; release approval
  is the gate before users.
- What `contents: write` allows. On GitHub it covers branches, tags and
  releases, so the routine App can also create, edit, publish and delete
  releases, replace draft assets, and delete branches and tags outside `v*`.
  Neither GitHub permissions nor rulesets can split that. Consequences: a
  compromised agent could publish a release draft early (releases are
  immutable, so that release could never gain its signed manifest, and the
  Homebrew tap would refuse it), or delete non-release branches. "Delete
  anything" in the elevated tier therefore means repositories, settings and
  `v*` tags, not branches. Release integrity rests on the signed manifest
  (see "Release"), not on who can press publish.
- Hiding the routine GitHub token from agents. An agent that may use a token
  without asking can already do everything the token allows; hiding it would
  only stop it being copied, and the token lives an hour. See "Decisions".

## The tiers

| Tier | What | Owner sees |
|---|---|---|
| Routine | commit, sign, push, open/merge PRs, issues, comments, on the repositories the agent App is installed on | one standing grant, approved once (up to 30 days), then nothing |
| Elevated | create a repository, change settings or rulesets, manage keys, deploy keys or Actions secrets, delete anything, change workflow files | a phone prompt per action |
| Release | signed tag, signed manifest, publish, for one agreed version and commit | one phone prompt per release |
| SSH and sensitive APIs | as today | a prompt per grant |
| Owner's account | run a command as the owner on the Mac | a phone prompt per command (default) or per short window |

## Identities

| Who | Credential | Held by |
|---|---|---|
| Agents, routine | GitHub App **agent**, installed on the repositories the owner chooses. Repository permissions: contents write, pull requests write, issues write, metadata read. No administration, no workflows, no secrets. | warden (App private key in 1Password, read by the broker) |
| Agents, release | GitHub App **release**: contents write. A new tag ruleset on each released repository restricts creating, updating and deleting `v*` tags to this App as the only bypass actor. (Today's `protect-release-tags` ruleset on warden blocks only update, deletion and non-fast-forward, with no bypass actors; the builder first confirms an App can be a bypass actor on a user-owned repository.) | warden |
| Agents, commit signing | A dedicated SSH signing key for agents, separate from the owner's | warden (existing commit signing) |
| Agents, release signing | A new release signing key listed in `docs/release-signers` for `warden-release` | warden |
| Agents, elevated | A fine-grained personal token with the administration and secrets permissions elevated actions need | warden, through the existing HTTP proxy |
| Agents, identity to warden | A bearer agent key in the agent user's login Keychain, which keeps working while the Mac is locked | the agent macOS user |
| Owner | The owner's own GitHub login, token and signing key | 1Password, behind the owner's prompts; never reachable by agents |

Hardware-bound agent keys (Secure Enclave, TPM) are rejected: they stop
signing while the Mac is locked, which defeats running agents unattended.

## How each tier works

### Routine

- The owner approves one standing grant per agent identity for the routine
  scope, with a window of up to 30 days (a new per-kind maximum, like
  `WARDEN_COMMIT_SIGNING_MAX_WINDOW`; other grants keep their 4-hour cap).
- With the grant active, the CLI asks the broker for a GitHub token. The
  broker mints an installation token from the agent App with the routine
  permissions (fixed by the broker, never chosen by the agent), lifetime 1
  hour, and audits the mint (agent, installation, permissions, expiry).
  *Designer's call:* the token covers every repository the App is installed
  on, not one repository per token. The installation is the scope the owner
  sets per repository; an agent that may mint for any installed repository
  gains nothing from per-repository tokens except a narrower hour if one is
  copied, and per-repository tokens would make plain `gh` fail across
  repositories. The CLI caches the token (0600, in the agent user's state
  directory) and mints again when it has less than 5 minutes left.
- GitHub Apps sign with RSA only. The broker signs the App's JWT (RS256) with
  `aws-lc-rs`, already in the dependency tree, never with the `rsa` crate,
  whose private-key operations are what RUSTSEC-2023-0071 covers; `deny.toml`'s
  "holds no RSA private key" justification is reworded to say exactly that.
- `warden setup github` installs, in the agent user's account:
  - a git credential helper for `https://github.com`, so plain `git fetch` and
    `git push` work over HTTPS;
  - a way for plain `gh` to get the token (a `gh` wrapper earlier on `PATH`
    that sets `GH_TOKEN`, or an equivalent the builder finds cleaner).
- Without an active grant, the helper requests one, says it is waiting for
  approval, and continues when approved. A denial is a clear error telling the
  agent not to retry around it.
- Commit signing uses the existing warden commit signing with the agent key.
- Commit identity (the owner's decision): agent commits keep the owner's name
  and email, so the DCO check and the sign-off rule in `AGENTS.md` are
  unchanged. The agent signing key is added to the owner's GitHub account as a
  signing key, so commits show "Verified". Agent work is told apart from the
  owner's by the signing key, by the App's bot doing the push and merge, and
  by warden's audit. The broker keeps one commit signing key; the owner's own
  signing stays in 1Password, outside warden, in this design.
- Attribution: pushes, PRs, merges and comments show on GitHub as the App's
  bot account; commits are signed by the agent key, which differs from the
  owner's; warden's audit records each token and signature.

### Elevated

- Calls go through the existing HTTP proxy (`warden http`) using the elevated
  token, one approval per call (or per very short window). The approval page
  shows method, path and repository.
- Changing workflow files counts as elevated because a workflow can read a
  repository's secrets. The routine App has no workflows permission, so:
  - pull requests that change workflows, including Dependabot's GitHub
    Actions bumps, are merged by the owner from the GitHub app (the owner's
    decision); agents leave them and say so;
  - when an agent itself needs to push a workflow change, it requests an
    elevated grant for that push. How that push is made (an installation
    token from the agent App with the workflows permission added, minted only
    under an elevated grant, is the likely shape) is left to the builder.

### Release

- The agent and the owner agree on a version and commit in conversation. The
  agent requests a release grant naming the repository, version and full
  commit SHA. The approval page shows all three and the changelog section.
- Under that grant only, the broker:
  - signs the annotated tag object for `vX.Y.Z` pointing at exactly that commit
    (the broker parses the tag object and refuses any other name or target);
  - signs `warden-X.Y.Z-SHA256SUMS` for that version (the broker checks the
    file name and format; the agent runs the attestation checks of
    `scripts/sign-release.sh` before asking);
  - mints one release-App token, limited to that repository, to push the tag
    and publish the draft.
- **Warden does not check build attestations** (the owner's decision: that
  would take warden beyond its scope). A compromised agent session during an
  approved release could therefore get a manifest of its own archives signed.
  That is caught where releases are consumed, by requiring both checks there:
  - the Homebrew tap verifies each warden archive's build provenance
    attestation against `pecheriere/warden` and the tag before rendering the
    formula, as it already does for landfall (its warden path appears to check
    only the manifest signature today; the builder confirms and adds the
    check in the tap);
  - `docs/verifying-releases.md` makes the attestation check a required step,
    not an optional one, and says why: the signature proves the maintainer
    approved the release, the attestation proves the workflow built it from
    the tag.
  Forging an attestation needs a change to the release workflow, which the
  agent App cannot push (no workflows permission).
- The grant ends when the release is published, or after a fixed time
  (builder's call, about a day, since the workflow takes a while).
- `scripts/sign-release.sh` gains a mode that signs through warden instead of
  a local key. The release steps in `AGENTS.md` change accordingly: the owner's
  phone approval replaces both the owner's confirmation of the tag and the
  owner's signing step.

### The agent macOS user

- Agents run as a separate standard (non-admin) macOS user. Their sessions,
  clones, tool installs (Rust, cargo tools, other per-user installs), Claude
  Code configuration and warden identity live in that user's home.
- The owner talks to sessions exactly as now; a Rex pane opens into the agent
  user. *Designer's call:* the pane starts the session with
  `sudo -u <agent> -i`, allowed without a password by a sudoers rule limited
  to that one target user. This works after a reboot with nobody logged in as
  the agent user, and needs no Remote Login for it. Because a `sudo` session
  has no unlocked login Keychain, the agent's credentials live in files only
  that user can read (mode 0600 in a 0700 home): the warden bearer key through
  `WARDEN_AGENT_KEY` or a key file, and Claude Code's login through a
  long-lived token (`claude setup-token`) if its Keychain storage does not
  work there. Against an attacker running as the agent user, a 0600 file and
  that user's Keychain protect the same; the boundary is the user, not the
  store. The builder verifies Claude Code, Rex and git work this way.
- Homes are locked down at setup: the owner's home is `drwxr-x--- staff`
  today and standard users are in `staff`, so it becomes `chmod 700` (and any
  directory the owner deliberately shares gets an explicit ACL), with an audit
  of what else on the machine is readable by other users. The agent user's
  home is 0700 too.
- The agent user has no 1Password, no access to the owner's Keychain, browser
  or home, and cannot use the owner's Homebrew to install. What it needs from
  Homebrew is installed by the owner once at setup, or per user.
- The agent's Claude Code configuration is built from the dotfiles repository
  (the agent user's own clone). Project memory moves to the agent user.

### The owner's account as an SSH target

- Remote Login is enabled for the owner's user only. A warden relay target
  (for example `owner@owner-mac`) with the Mac's host key pinned points at it.
- It is reachable only through Tailscale (the owner's requirement). On macOS,
  launchd owns sshd's socket on all addresses and ignores `ListenAddress`, and
  the Application Firewall cannot filter by port, so:
  - `pf` rules drop port 22 on every interface except the tailnet interface
    and loopback;
  - the tailnet policy allows only the broker's node to reach port 22 on the
    Mac;
  - sshd itself is the real boundary, because neither of the above stops a
    process on the Mac (the agent user) from connecting locally: public key
    only (password and keyboard-interactive off), `AllowUsers` the owner only,
    and the relay's key in the owner's `authorized_keys` restricted with
    `from=` to the broker's tailnet address and `no-port-forwarding,
    no-agent-forwarding,no-X11-forwarding`.
  This uses plain OpenSSH with warden's key, not Tailscale SSH, so access stays
  bound to warden's key and grants rather than to tailnet identity alone
  (builder to confirm Tailscale SSH is not enabled on the Mac).
- **New: command grants.** A request names the exact command. The approval
  page shows it in full (with a length cap; no truncation). The relay allows
  exactly one `exec` of exactly those bytes, no `shell` request, PTY,
  forwarding or subsystem, returns the exit status, and the grant is consumed by that run or
  expires after a few minutes. As with any SSH `exec`, sshd runs the bytes
  through the owner's login shell (zsh, which reads `.zshenv` first); the
  approval page says so rather than implying no shell is involved. The full
  command is audited. Commands must not
  carry secrets; the docs say so.
- Time-window grants stay available for interactive work, with short windows,
  and their approval page says plainly that the grant is full access to the
  owner's account for that window.
- Command grants are general relay features, not specific to this target.

### What agents may do, per repository

This is GitHub configuration, not warden code (the owner's decision). Each
repository gets one of three levels:

| Level | How |
|---|---|
| No access | the agent App is not installed on it |
| Pull requests only | App installed; a ruleset on the default branch requires the owner's approving review, so agents can push branches and open PRs but not merge; the owner approves and merges from the GitHub app, which shows the diff |
| Full routine | App installed, no review requirement: agents merge when checks pass |

Repositories whose content runs as the owner, such as dotfiles (the owner's
shell and Claude settings are symlinks into its clone), are at most "pull
requests only": anything merged there runs as the owner on the next pull, so
free merging would undo the separate user. The setup docs list each
repository's level.

## Changes to the owner's machine, done first

1. Retire the owner's on-disk signing key from release signing. It has been
   readable by every agent on the Mac, so it is treated as exposed (the
   owner's decision): list the new warden-held release key in
   `docs/release-signers` (namespaces `git,warden-release`, since
   `sign-release.sh` requires the tag and manifest to share a key), and once
   the first release signed through warden is out, remove the old key from
   that file. `docs/verifying-releases.md` then tells anyone verifying an
   older release to use `docs/release-signers` as it was at that release's
   tag. The agent tells the owner when this point is reached.
2. Replace agent use of the owner's `gh` token: agents use the routine App. The
   owner's own `gh` login moves behind 1Password (`op run`), or is removed if
   the owner does not use `gh` locally.
3. Remotes use HTTPS (done for warden on 2026-11-08).

## Decisions

- The routine GitHub token is visible to agents (an installation token, 1
  hour). This replaces #82's preferred option (keep the token in warden) and
  #80's SSH relay for git. `docs/threat-model.md` and the README's "what agents
  never see" table must state it. Rationale: a token usable without approval
  gives the agent its full power whether or not the agent can read it;
  visibility only adds copying an hour-long, repository-scoped token.
- Two GitHub Apps rather than one, because a ruleset bypass is granted per
  actor, so `v*` tags can only be reserved for a separate identity.
- Claude Code's sandbox mode is not part of this design. It covers shell
  commands only (not file tools, web fetches, MCP or hooks), reads stay open by
  default, and its network allowlist starts empty, which would restrict the
  internet access the owner wants open. The separate macOS user is the
  boundary instead.
- No Secure Enclave or TPM agent identity (see "Identities").

## Left to the builder

- Grant and table design, migrations, CLI command names.
- How `gh` gets its token, as long as plain `gh` works in a repository.
- Exact release grant lifetime and how the broker validates the manifest.
- How workflow-file pushes are made under an elevated grant.
- Split into issues and PRs (one per issue). *Designer's call on order*,
  because nothing protects much while agents still run as the owner and can
  read the owner's files:
  1. the routine App tier (agents need it to work as a separate user);
  2. the agent macOS user and the home lockdown; from here the owner's
     on-disk key and `gh` token are out of agents' reach;
  3. the release key in warden and the release grant, then retiring the old
     key;
  4. command grants and the owner's account as an SSH target.

## Documentation to update

README, `docs/threat-model.md`, `docs/assurance-case.md`,
`docs/security-assessment.md` (risk moves), `docs/configuration.md`,
`docs/agent-usage.md`, `docs/agent-protocol.md`, `docs/ssh-targets.md`,
`docs/interfaces.md`, `docs/verifying-releases.md`, `docs/release-signers`,
`AGENTS.md` (release steps), the Homebrew tap's warden checks, `CHANGELOG.md`, and the
approval pages (new grant kinds), following `docs/design-language.md`.

## Issues affected

#80 (replaced by the App tier), #81 (release signing part folds into the
release grant), #82 (decided: option 2 with an App), #101 (release signing
through warden).
