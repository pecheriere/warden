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

- A token for **one repository**, the one the agent names and you approved. A grant covers
  one to ten repositories, and the agent asks for a token per repository. GitHub is asked to
  scope the token to that repository's id, so a token for A cannot push, open a pull request,
  comment or edit issues on B, even though the App is installed on B. What the agent can do
  on the repository is what you installed the App on and the rules you set there: see
  [the three levels](#the-three-levels-per-repository). Issues on public repositories reach further: see below.
- **The permissions you configure**: by default `contents` write, `pull_requests` write,
  `issues` write and `metadata` read. You can set a different default (see
  [Permissions](#permissions)). warden asks GitHub for at most the grant's set, and nothing
  else, whatever the App itself may do: the permissions the request names, or your default
  limited to the grant. Keep `workflows` and `administration` out of it: see [Sensitive permissions](#sensitive-permissions).
- **One hour.** The token lasts as long as GitHub lets it, and the CLI gets a new one when
  less than 5 minutes of the old one remain.
- **A grant of `1d`, `7d` or `30d`**, 30 days by default, up to
  [`WARDEN_GITHUB_TOKEN_MAX_WINDOW`](configuration.md#server-environment-variables). The grant
  decides whether warden mints more tokens, not how long a token lasts. Like commit signing,
  it is long because the agent is expected to use it on its own: a prompt for every hour would
  be a reflex tap.
- **Several grants at a time per agent**, one for each set of repositories and extra permissions.
  Approving a grant ends the agent's other grants that share a repository with it, by
  GitHub's id or by name (ignoring case), and were approved with exactly the same extra permissions (the owner's default is not compared); the approval
  page lists them before you approve. A grant with other extras stays, and so does a
  request waiting for them, so a short grant with a sensitive permission never ends the
  agent's everyday one, and revoking it leaves that one working. A grant that names no
  repository (made before grants were scoped) ends at upgrade and is replaced by asking
  again.
- **Issues on public repositories, too.** Measured on real GitHub: a token scoped to
  repository A got 403 creating a branch, a pull request or a comment, and editing issues on
  B, and 404 reading a private B, but it could still open a new issue on a public repository
  B the App is installed on. Nothing else was possible on that B. That is the only case
  measured for a scoped token. Opening an issue (and, to be assumed, commenting) takes only
  read access, and an unscoped token did it on a public repository the App is not installed
  on (finding F22 in the [security assessment](security-assessment.md#findings-of-this-review)), so assume
  a scoped token can open issues and comment on public repositories the App is not installed
  on, anyone's. What it posts shows as the App (`<app name>[bot]`), and GitHub's logs, not
  warden's, record it.

## What the agent holds

- **Revoking a grant does not recall a token already minted.** GitHub, not warden, ends it,
  within the hour, for each repository the agent held a token for. A token is a bearer secret: whoever has it can use it until then.
- **The CLI keeps the token** in `github-token.json` in its state directory, mode 0600, for
  that agent and broker, with one entry per repository and asked permission set. It serves that file for the rest of the hour even after you revoke
  the grant in the approval UI, because nothing tells the CLI. `warden revoke <grant>` on the
  agent's machine deletes it. To be sure, also remove the App's access on GitHub (below).
- **A compromised agent machine gets the token**, and the agent's key can mint more for as
  long as the grant lasts, for the repositories it covers. Revoke the grant, then revoke the agent with
  `warden-server agent revoke` if the machine is lost, and suspend the App or remove its
  installation on GitHub if you must end a token at once.
- **Everything the token can do is allowed**, on its repository and within the permissions
  above: push to any
  branch the repository's rules allow, open and edit pull requests and issues, and read and
  write file contents. warden does not see what the agent does with it; GitHub's own logs
  show it, as the App.

The audit log records each token minted (grant, agent, installation, repository and its id,
the permissions GitHub granted, expiry) and each refusal, never the token. See [the threat model](threat-model.md#github-tokens).

## Permissions

A grant holds a set of permissions, fixed when the request is made. Each is `name:level`,
with `level` `read` or `write` (`write` includes `read`); `admin` is refused, and the set
always holds `metadata:read`. The owner sets what a request gets in two optional fields of
the `warden:github-app` item ([1Password items](1password-items.md#github-app)):

- `default_permissions`: the set every request gets. Missing means `contents:write`,
  `issues:write`, `metadata:read` and `pull_requests:write`, which is what warden granted
  before this setting existed.
- `extra_permissions`: the permissions an agent may ask for on top of the default, with
  `warden request github --extra-permissions <set>`. A request that names one outside this
  list, or at a higher level than listed, is refused before you are asked. The approval page
  marks each extra, read or write, and a sensitive one in red. `warden list` shows the agent
  the default set and the extras it may ask for.

A set is written as `name:level` pairs separated by commas, such as
`checks:read,contents:write,metadata:read`. The approval page lists the set, so you see it
before you approve.

### Sensitive permissions

These reach past a repository's code, or outlive the grant: `administration`, `workflows`,
`secrets`, `environments`, `dependabot_secrets`, `repository_hooks` and the `organization_*`
permissions GitHub documents for installation tokens (read from GitHub's REST documentation on
2026-11-15). Repository secrets, environments and workflow files let whoever holds a token
change what runs with the repository's own credentials. A webhook keeps sending the
repository's events to whoever created it after the token has expired and the grant is revoked,
so `repository_hooks` gives access that outlives the grant.

warden does not refuse them by itself: you decide. They are allowed in `extra_permissions` only,
so a sensitive permission reaches a grant only when an agent names it and you approve it. In
`default_permissions` one makes GitHub tokens unusable, because every grant, including the
30-day automatic ones of the git helper and `gh` wrapper, would hold it. Agents can ask for
extras. A grant that holds a sensitive permission lasts 15 minutes, 30 minutes or 1 hour at
most: the approval page offers only those windows, marks the permission with what it lets
the holder do at the level asked, and a longer window is refused. A token minted at the end
of such a grant lives up to an hour more, so the access can last about 2 hours. The request
defaults to `1h` when it names one, and its goal should say exactly why the agent needs it. A name that GitHub does not
document, such as an `organization_*` one missing from its page, stays unknown and is refused,
and so is a level GitHub does not document for a name: `workflows` has only `write`, and
`organization_copilot_requests`, `organization_events` and `organization_plan` have only
`read`. Such an entry in `extra_permissions` makes GitHub tokens unusable, and
`warden-server doctor` names the field.

A token carries an extra permission only when the request names it: the mint endpoint takes
a `permissions` field, which `warden github token --permissions <set>` and, for git,
`WARDEN_GITHUB_PERMISSIONS` send. A mint that names nothing, such as a plain `git push` or `gh`
call, gets your current default set, limited to what the grant holds, so narrowing the default
narrows the plain tokens of grants already approved. When an agent holds several grants on a
repository, the broker mints from the least privileged one holding what is named. Nothing can
mint more than the grant.

**The App must hold what you set.** The approval page reads the installation's permissions
each time it is shown, begun or finished, and refuses a request whose set the installation
does not hold, naming what is missing. Give the App those permissions on GitHub first
(step 4 below) and accept the change on the installation. A grant keeps the set it was
approved with, so its tokens never hold more than that set. Narrowing the default narrows
the plain tokens of grants that exist at once; widening it never widens them, and reaches a
grant only at the next request or renewal. If you remove a permission from the App after a grant was approved with
it, GitHub may refuse to mint the grant's tokens: the agent then gets `409` with the
repository-unreachable error, and you should check the App's permissions on GitHub against
the grant's set, which the grants page lists. Where GitHub instead grants a token less than
the grant holds, the token is served with what GitHub granted, and the response and the audit
entry list that.

A field that is repeated, present but empty, not a valid set, or a `default_permissions` that holds a sensitive permission, makes the
App unusable for GitHub tokens, the same as a bad `installation_id`: tokens are refused,
and `warden-server doctor`'s `github-app` check fails and names the field, never its value.
SSH, APIs, signing and releases keep working.

## Create the App

Create one App per broker: the broker reads exactly one App, and treats more than one
`warden:github-app` item as an error. Agents that need another trust level need their own
broker. The App is yours, on your account or organization.

1. On GitHub, **Settings**, **Developer settings**, **GitHub Apps**, **New GitHub App**.
2. Give it a name that says what it is, such as `warden agents`, and any homepage URL.
3. **Webhook**: turn **Active** off. warden never receives events, and there is nothing for a
   webhook to reach.
4. **Repository permissions**: set exactly these, and no others. (If you change
   `default_permissions`, add the permissions it names, at those levels.)

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
   may reach. Never **All repositories**: tokens are scoped to the repository an agent names,
   but the installation is the outer limit, and a bug in the scoping must not meet an
   installation that reaches everything. The installation id is the number at the end of the
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
warden request github example-owner/example-repo --goal "Push branches and open PRs for build-agent's fixes"
warden setup github
```

`warden request github <owner/name>...` takes the repositories (up to ten, and a notice says
when there is more than one) and asks for 30 days (`--for 1d`, `7d` or `30d`) and waits for your
passkey. It is optional: with no grant, the first `git` or `gh` call to GitHub files the
request itself, and waits for you. See [Agent usage](agent-usage.md#github-tokens).

`warden setup github` makes git use warden for `https://github.com` and puts a `gh` wrapper
in `~/.local/bin`. It changes nothing on GitHub. See
[Agent usage](agent-usage.md#github-tokens) for what it writes and checks.

## The release App

[Releases](agent-usage.md#releases) use a second GitHub App, apart from the one above. The
agent never holds its token: the broker mints it, creates the tag, attaches the manifest and
publishes the draft with it, and drops it. So this App has none of the risks of
[the agent's token](#what-the-agent-holds), but it can do more than that one, and the broker
is the only thing that holds its key.

- **Permissions**: `contents` write and `metadata` read, and no webhooks. warden asks GitHub for
  a token with exactly those two permissions, narrowed to the one repository of the release.
  No `workflows`, no `administration`, no `pull_requests`.
- **Install it on each repository you release from**, and on no other. The broker looks the
  installation up for the repository when it is needed, so the item holds only `app_id` and
  `private_key` ([1Password items](1password-items.md#release-github-app)). A repository
  without it is refused when the release is asked for.
- **Tag ruleset.** The tag step creates `refs/tags/<tag>` as the App. If you protect release
  tags with a [ruleset](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
  that restricts creating, updating and deleting `v*` tags (you should), the release App must be
  that ruleset's only bypass actor, in place of a repository administrator. Then the broker
  creates a release's tags, and so can an administrator only by changing the ruleset. GitHub
  lets an App be a bypass actor on a repository owned by a user as well as on one owned by an
  organization (confirmed on a user-owned repository). warden does not check your ruleset.
- **Egress.** The broker needs outbound HTTPS to `api.github.com` and to
  `uploads.github.com`, where it attaches the manifest to the draft release. If you limit its
  egress as [the deployment guide](deployment.md#lock-wardens-egress) does, allow both.
- **Rotation** works as for the agent's App: add a key on GitHub, put it in the item, delete
  the old key. Changing the App or the release key while a grant is open makes its remaining steps
  fail with `policy changed; request access again`: ask again.

What the broker will and will not do with it, and what stays open, is in
[the threat model](threat-model.md#phone-approved-releases). In short: it creates the tag you
approved at the commit you approved, and publishes the draft of that tag, and nothing else. It
cannot publish a draft early for the agent, but **the agent's own token can**, because it has
`contents` write (see [the accepted gap](threat-model.md#phone-approved-releases)). That costs a
version, not the integrity of a release.

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
