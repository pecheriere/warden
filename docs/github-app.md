# GitHub tokens for agents

warden can give an agent a token for GitHub, so that `git push` and `gh` work on the agent's
machine with no personal access token or deploy key stored there. The broker holds the
private key of a GitHub App that you create for your agents. With a grant from you, it
exchanges that key for an installation token and hands the agent the token, which GitHub ends
after an hour.

**This is the one access where the agent holds a usable credential.** For an API, SSH
certificate or relay target, the secret stays on the broker or in the agent's memory for
minutes. Here the agent has a token it can use on its own, from any machine, for up to an
hour, and warden cannot take it back. Read [what that means](#what-the-agent-holds) before you
set it up.

## What an agent gets

- A token for **every repository the App is installed on**, not one repository. warden cannot
  narrow it, and does not ask the agent for a repository. What the agent can push to and edit
  is what you installed the App on: see [the three levels](#the-three-levels-per-repository).
  Issues and comments reach further: see below.
- **Fixed permissions**: `contents` write, `pull_requests` write, `issues` write and
  `metadata` read. warden asks GitHub for these and nothing else, whatever the App itself may
  do. No `workflows`, no `administration`.
- **One hour.** The token lasts as long as GitHub lets it, and the CLI gets a new one when
  less than 5 minutes of the old one remain.
- **A grant of `1d`, `7d` or `30d`**, 30 days by default, up to
  [`WARDEN_GITHUB_TOKEN_MAX_WINDOW`](configuration.md#server-environment-variables). The grant
  decides whether warden mints more tokens, not how long a token lasts. Like commit signing,
  it is long because the agent is expected to use it on its own: a prompt for every hour would
  be a reflex tap.
- One grant at a time per agent. Approving a new one ends the one before it.
- **Issues and comments on public repositories, too.** Opening an issue or commenting on a
  public repository needs only read access, and GitHub documents that an App's token can read
  public repositories.
  So the agent can post as the App on public repositories you did not install it on: tested
  on one of the owner's own, and to be assumed for anyone's. Choosing repositories limits pushes, pull requests and edits, not that.
  What it posts shows as the App (`<app name>[bot]`), and GitHub's logs, not warden's, record it.

## What the agent holds

- **Revoking a grant does not recall a token already minted.** GitHub, not warden, ends it,
  within the hour. A token is a bearer secret: whoever has it can use it until then.
- **The CLI keeps the token** in `github-token.json` in its state directory, mode 0600, for
  that agent and broker. It serves that file for the rest of the hour even after you revoke
  the grant in the approval UI, because nothing tells the CLI. `warden revoke <grant>` on the
  agent's machine deletes it. To be sure, also remove the App's access on GitHub (below).
- **A compromised agent machine gets the token**, and the agent's key can mint more for as
  long as the grant lasts. Revoke the grant, then revoke the agent with
  `warden-server agent revoke` if the machine is lost, and suspend the App or remove its
  installation on GitHub if you must end a token at once.
- **Everything the token can do is allowed**, within the permissions above: push to any
  branch the repository's rules allow, open and edit pull requests and issues, and read and
  write file contents. warden does not see what the agent does with it; GitHub's own logs
  show it, as the App.

The audit log records each token minted (grant, agent, installation, permissions, expiry) and
each refusal, never the token. See [the threat model](threat-model.md#github-tokens).

## Create the App

Create one App per broker: the broker reads exactly one App, and treats more than one
`warden:github-app` item as an error. Agents that need another trust level need their own
broker. The App is yours, on your account or organization.

1. On GitHub, **Settings**, **Developer settings**, **GitHub Apps**, **New GitHub App**.
2. Give it a name that says what it is, such as `warden agents`, and any homepage URL.
3. **Webhook**: turn **Active** off. warden never receives events, and there is nothing for a
   webhook to reach.
4. **Repository permissions**: set exactly these, and no others.

   | Permission | Level |
   |---|---|
   | Contents | Read and write |
   | Issues | Read and write |
   | Pull requests | Read and write |
   | Metadata | Read-only (GitHub requires it) |

   Leave **Workflows** and **Administration** at no access, and leave account and
   organization permissions empty. warden never asks for them, but an App that cannot do
   them is what protects you if warden has a bug.
5. **Where can this GitHub App be installed?** Choose **Only on this account**.
6. **Create GitHub App**. Note the **App ID** on the App's page.
7. On the same page, **Generate a private key**. GitHub downloads a `.pem` file, which starts
   with `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1). warden also reads PKCS#8
   (`-----BEGIN PRIVATE KEY-----`). It refuses a key protected by a passphrase, and any key
   that is not RSA or is shorter than 2048 bits.
8. **Install App**, then **Only select repositories**, and choose the repositories the agents
   may reach. Never **All repositories**. The installation id is the number at the end of the
   installation's settings URL, `https://github.com/settings/installations/<installation id>`,
   or `https://github.com/organizations/<org>/settings/installations/<installation id>` for
   an organization.

## Put the App in 1Password

Add one item to warden's vault, tagged `warden:github-app`, with three custom fields
labelled `app_id`, `installation_id` and `private_key` (text for the ids, concealed for the key). The exact rules are in
[1Password items](1password-items.md#github-app). Paste the whole `.pem` file, header and
footer lines included, into `private_key`, and delete the downloaded file.

`warden-server doctor` has a `github-app` check that loads the item and says what is wrong
with it. It cannot tell whether GitHub still accepts the App: only a token tells you that.
GitHub tokens are off while there is no such item.

Changing the App id or the installation ends every grant made for the old one, and the agents
ask again. Replacing only the private key keeps the grants, so you can rotate it: add a new
key to the App on GitHub, put it in the item, and delete the old key on GitHub.

## The three levels, per repository

The App has the same permissions on every repository it is installed on. What differs is
what the repository itself allows an App to do, which is yours to set on GitHub. Choose one of
three levels for each repository, and install the App on a repository only when you have
chosen.

1. **No access.** The App is not installed there. Do this for repositories whose loss would
   hurt and that no agent needs, and for any repository you have not decided about.
2. **Pull requests only.** The agent can push branches and open pull requests, but nothing
   reaches the default branch without you. Install the App and add a
   [ruleset](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
   on the default branch that requires a pull request with an approving review from the code
   owners, with a `CODEOWNERS` file that names you, and leave the App out of its bypass list.
   The agent's token has pull request write, so it can post a review too: naming you as the
   owner is what makes the required review yours. Do the same for any other branch a release
   is built from.
3. **Full.** The agent can push to the default branch and merge. Use it only for
   repositories where a bad push costs little, such as a scratch repository.

**A repository whose content runs as you is at most "pull requests only".** That means
repositories that your machines pull and run (dotfiles, install scripts, infrastructure
code, a tool you run daily), and those with CI that deploys or holds secrets. A push or a merge
there is code execution as you. Reviewing the diff is the check, so make it a real one, and
do not approve a pull request that you did not read because an agent asked nicely.

**Workflow files are left to you.** Without the `workflows` permission, GitHub refuses a push
that creates or changes a file under `.github/workflows/`. An agent that needs a workflow
changed should say so in a pull request or an issue, and you make the change. Do not give the
App `workflows` to get around this: it would let an agent change what CI runs, with the
repository's secrets.

## Set up the agent's machine

**The broker needs outbound HTTPS to `api.github.com`.** If you limit its egress as
[the deployment guide](deployment.md#lock-wardens-egress) does, allow that name, or every mint
fails with "GitHub could not issue a token".

Once the App is in the vault (warden reads the item afresh, so the server needs no restart),
run this on each agent machine:

```sh
warden request github --goal "Push branches and open PRs for build-agent's fixes"
warden setup github
```

`warden request github` asks for 30 days (`--for 1d`, `7d` or `30d`) and waits for your
passkey. It is optional: with no grant, the first `git` or `gh` call to GitHub files the
request itself, and waits for you. See [Agent usage](agent-usage.md#github-tokens).

`warden setup github` makes git use warden for `https://github.com` and puts a `gh` wrapper
in `~/.local/bin`. It changes nothing on GitHub. See
[Agent usage](agent-usage.md#github-tokens) for what it writes and checks.

## Revoking

- **Revoke the grant** in the approval UI (or `warden revoke <grant>` on the agent machine).
  No new token is minted. A token already minted works until GitHub ends it, at most an hour
  later. The CLI's cached token is served until then too, unless you ran `warden revoke` on
  the agent's machine.
- **To end a token now**, suspend the App or remove its installation on GitHub. That ends
  every token of the App, including other agents'.
- **If the private key leaks**, delete it in the App's settings on GitHub, add a new one, and
  update the item. A leaked key lets its holder mint tokens for every installation of the App
  until you delete it, with no grant and no audit entry here.
