# Agent GitHub tokens scoped to the grant's repositories (#230)

Status: approved by the owner, 2026-11-11.

Statements are tagged: (owner's decision) the owner decided it; **[call]** the
designer's call, open to the owner's veto; **[guess]** an assumption about
how things work that the builder must check.

## Why

A GitHub token grant today names the agent App and its installation, but no
repository (`GithubTokenGrant` in `crates/proto/src/github_token.rs`). The
broker mints each installation token with a `permissions` body only
(`crates/broker/src/github_app.rs`, `mint`), so every token reaches every
repository the App is installed on. The only boundary is the installation's
repository selection on GitHub; when that is set to *All repositories*, one
approval of "GitHub for 30 days" hands an agent write access to every
repository of the account. This happened during the 0.12.0 release test: the
owner set both Apps to *All repositories*.

GitHub's [create an installation access token](https://docs.github.com/rest/apps/apps#create-an-installation-access-token-for-an-app)
accepts `repositories` or `repository_ids`; a token minted with them reaches
only those repositories, whatever the installation covers.

## What success looks like

An agent working in one repository cannot push to, open pull requests in, or
touch issues of any other repository through warden unless the owner approved
that repository on their phone. When an agent opens a checkout of another
repository and git asks for a credential, the owner gets a phone prompt naming
that repository; nothing works there until they approve. (owner's decision)

Caveat to verify **[guess]**: the threat model records that an installation
token opened an issue on a public repository the App was not installed on.
Whether a token minted with `repository_ids` still can is unknown. The first
pull request tests it with a real scoped token for `warden-app-test` against
another of the owner's public repositories the App is installed on (open an
issue, comment, then close/delete what it made), and the docs state only what
the test shows. No test against anyone else's repository.

## Goals

1. **A grant covers exactly one repository by default.** (owner's decision)
2. **Several repositories in one grant is possible but exceptional**, and
   unmistakable on the approval page. (owner's decision)
3. **An agent can hold several GitHub grants at once**, e.g. one for
   `owner/app` and one for `owner/homebrew-tap`. (owner's decision)
4. **Every minted token reaches only the repository it was asked for.**
5. **Existing (unscoped) grants end at upgrade.** (owner's decision)

## Non-goals

- Changing the permissions set (`PERMISSIONS`: contents, pull requests, issues
  write; metadata read). Unchanged.
- Changing windows (1d, 7d, 30d; default 30d). Unchanged. **[call]**
- Release grants (`warden request release`): already bound to one repository,
  minted from the release App. Untouched.
- Repository-level read access to repositories the agent has no grant for
  (e.g. `gh` browsing a public repo). Public data needs no token; private repos
  need a grant like any other.
- Per-repository permission levels. They stay GitHub configuration
  (`docs/github-app.md`, "the three levels").

## Anti-goals (a failure even if it works)

- A token, cached or fresh, ever served for a repository its grant does not
  name.
- An unscoped token minted after the upgrade, for any grant, by any path.
- The agent picking or widening its repository list silently: a multi-repository
  grant that looks like a single-repository one on the phone.
- Fail-open on ambiguity: when the CLI cannot tell which repository is meant,
  it refuses with a clear message; it never falls back to "any grant".

## Design

### Grant and request

- `GithubTokenGrant` gains `repositories`: a non-empty list of repositories,
  each a `RepoName` (`owner/name`, the type release grants already use) plus
  the numeric repository id the broker resolved at approval. **[call]**
  - Why the id: a repository deleted and recreated under the same name, or
    renamed and replaced, is a different repository. The broker mints with
    `repository_ids` and checks the ids GitHub returns, so a grant stays bound
    to the repository the owner approved. **[call]**
- The request carries the names. At creation the broker only checks them
  without GitHub: valid `RepoName`s, all under the installation's account,
  no duplicates, at most the cap. It does **not** read the App key at
  creation, so the threat model's "an agent with no grant cannot make the
  broker read the key" stays true (`requests/create.rs` says the same).
  **[call]**
- The broker resolves names to ids when the owner opens the approval page:
  it mints a throwaway token with `{"permissions":{"metadata":"read"},
  "repositories":[names]}` and discards it unused. GitHub answers 422 when any
  name is not accessible to the installation; otherwise its `repositories[]`
  give `id` and `full_name`. `GET /repos/{owner}/{name}` is **not** used: an
  installation token reads any public repository, so it would "resolve"
  repositories the installation does not cover. The result (ids and GitHub's
  names) is stored on the pending row on first render and reused; a 422
  shows "cannot be approved: the App is not installed on X" with no approve
  button. The resolution mint is audited. **[call]** The cost: a request that
  cannot work still reaches the owner's phone (a typo); accepted to keep the
  key property.
- Order and duplicates: names compare case-insensitively (GitHub's rule);
  duplicates are refused, not merged. Stored in the case GitHub returns.
  **[call]**
- Cap: at most 10 repositories per grant. **[call]** GitHub allows 500; a grant
  that needs more than a handful is not exceptional any more, it is a sign the
  agent should be split.
- The names and resolved ids are stored with the pending request, as
  `ReleaseFacts` is for releases, and both are inside the destination digest
  the passkey ceremony binds (`approval/mod.rs`), so a pending row changed
  between render and approve is refused. **[call]**
- Pending requests: today one pending request per agent and dedupe slot; a
  duplicate gets the existing pending request back (`created: false`). For
  GitHub the slot becomes the agent plus the exact repository set, so an agent
  can have a pending request for A and another for B at the same time; a
  duplicate keeps today's behaviour. **[call]**
- **Replacement, renewal, revocation.** Today `github_token` is a
  `OneAtATime` kind (`crates/broker/src/requests/renewal.rs`): approving a new
  one ends the agent's other one, so revoking on the owner's screen really
  stops that agent's access. With several grants per agent, the rule becomes:
  approving a GitHub grant ends the agent's active GitHub grants whose
  repository sets **overlap** it (recorded as "renewed"); grants for other
  repositories stay. So each repository is covered by at most one grant per
  agent, and revoking it really stops access to that repository.
  (owner's decision) Renewal from the grants page copies the stored names and
  ids (the mint check catches a repository that changed). The ending-soon
  notice is per grant and names its repositories. **[call]**

### CLI

- `warden request github <owner/name>... --goal … [--for 30d]`: the
  repositories are positional, at least one. Naming more than one prints a line
  saying the request covers N repositories and will be shown to the owner as
  such. **[call]** No flag besides the list itself is required for several:
  the page is where it must be unmistakable. **[call]**
- **Which repository a token is for** (`warden github token`, the `gh`
  wrapper, `warden git-credential`), in this order: **[call]**
  1. `warden github token --repo owner/name`, explicit.
  2. git credential helper: the `path` git sends (`owner/name.git` for
     github.com), which git sends only with `credential.useHttpPath=true`.
     `warden setup github` sets `credential.https://github.com.useHttpPath
     true` alongside the helper. Git sends `path` for push and fetch with
     this setting (security review, high confidence); gh's own git calls do
     not reach this helper (gh sets its own), they use the wrapper's token.
  3. `gh` wrapper: the wrapper passes gh's arguments to warden (a new
     `warden github token --gh-args -- "$@"` or similar; the wrapper script and
     `setup github` change, and wrappers already written are rewritten by the
     next `warden setup github`, which `docs/upgrading.md` says to run). The
     repository is `-R/--repo` from them, else `GH_REPO`, else the `origin`
     remote of the current directory's checkout when it is an
     `https://github.com/` or `git@github.com:` URL. **[call]**
  4. `warden github token` without `--repo`: `GH_REPO`, then `origin`, as above.
  5. Otherwise: `warden github token` refuses ("cannot tell which repository
     this token is for; pass --repo owner/name"), and so does the `gh`
     wrapper: it exits non-zero with "cannot tell which repository; pass
     -R owner/name" and never starts gh. (owner's decision) Running gh without a
     token was rejected: gh would fall back to its own stored login, which on
     the owner's Mac is the owner's full-access account (security review).
     `gh auth status`, `gh search` and the like need `-R` or a checkout.
     Never fall back to "any grant".
- **The `gh` wrapper is interim.** (owner's decision) It exists until warden covers
  what agents use gh for, and will then be removed. Keep it minimal: no
  parsing beyond `-R/--repo`, no features that would make removing it hard.
  The root cause of the refusal (gh falling back to the owner's login) goes
  away when agents run as their own macOS user (#186): then the refusal can
  relax, or the wrapper go. Running commands as the owner on the same Mac is
  tracked separately (#231). (owner's decision)
- A `gh` command spanning two repositories (a pull request from a fork to its
  upstream) gets a token for one of them and fails at GitHub. Accepted: agents
  push branches to the owner's repositories, not forks. **[call]**
- The helper ignores a `path` that is not exactly `owner/name` or
  `owner/name.git`, and answers nothing (git then fails asking for
  credentials), as it does today for other hosts. **[call]**
- Without a grant covering the repository, the CLI files a request for that one
  repository and waits, as `obtain` does today; the automatic goal text names
  the repository. Automatic requests always name exactly one repository.
  (owner's decision: multi is only on explicit request)
- **Token cache** (`github-token.json`): keyed by repository id and grant; a
  file holding several entries, each served only for its own repository, with
  the same 0600 / owner / size checks. A token for one repository is never
  served for another. Entries of grants that ended or were revoked are dropped
  (as `discard` does now). **[call]** The file's version bumps; an old-format
  file is discarded on read, not migrated. **[call]**
- `warden status` lists each GitHub grant with its repositories.
- `warden doctor` (client): the github token check reports whether the helper
  is configured with `useHttpPath`; missing it is a FAIL with the
  `warden setup github` fix. **[call]**

### Broker: minting

- The mint call names the repository: the CLI sends the repository it wants a
  token for; the broker picks the agent's active grant covering it, or refuses
  with `NO_ACTIVE_GRANT` (the CLI then requests one, as today).
- `mint` sends `{"permissions": …, "repository_ids": [<the one id>]}`: one
  repository per token, even when the grant covers several. **[call]**
- The broker refuses GitHub's answer, and audits the refusal, unless
  `repository_selection` is `"selected"` and the returned repositories are
  exactly the requested id. The token is then discarded unused. **[call]**
- The `GithubTokenMinted` audit entry records the repository.
- The hourly limit is per agent, across repositories and grants. Today it is
  counted on the grant row (`take_mint`, `mint_hour`/`mint_count` from
  migration 0009), which equalled per agent only while an agent held one grant;
  several grants would multiply it. A new migration adds a per-agent counter
  and the grant columns stop being used (a later migration may drop them).
  **[call]**
- A mint for a repository that GitHub no longer lets the installation reach
  (App uninstalled from it, repository deleted) fails at GitHub; the broker
  reports that, without retrying.

### Approval page

- Single repository: the repository name is the headline of the request
  (today the headline names the App id and installation,
  `approval/pages/github_token.rs`), with the window and goal as now; the App
  and installation move to the details.
- Several repositories: a highlighted notice above the details, "This request
  covers N repositories", and each repository listed on its own line. Follows
  `docs/design-language.md`; screenshots in the PR at the template's sizes,
  light and dark.
- The grants page shows each GitHub grant's repositories.

### Migration at upgrade

- At startup after the upgrade, the broker ends every active `github_token`
  grant that has no repositories, with an audit entry per grant saying it
  ended because grants are now scoped to repositories. (owner's decision: end them)
- It is done in Rust at startup, not in a SQL migration, so each end goes
  through the audit chain. **[call]** It is idempotent: a second start finds
  nothing to end.
- Old rows stay readable: the grants page, request status and history parse
  every stored row, and one unparseable active row would break the whole grants
  page (`requests/grants.rs`, `decide.rs`). So a grant or request without
  `repositories` parses as a **legacy** shape that is shown ("all repositories
  of the installation", ended at upgrade) and is **never minted from**, whether
  or not the startup step ran: fail closed by type, not by parse failure.
  Rows are not rewritten. **[call]**
- Clients: an old-format token cache is discarded (above). An agent's next
  push files a new request naming its repository.
- `CHANGELOG.md` and `docs/upgrading.md` say existing GitHub grants end at
  upgrade and agents ask again.

### Hardening (from the security review of this design)

All **[call]** unless marked.

- **Pending requests from before the upgrade:** the startup step also expires
  every pending `github_token` request without repositories, audited.
  Approval refuses a pending GitHub request without a non-empty resolved set
  (today approval builds the grant from live policy, `pending.rs`,
  `approval/grant.rs`). Renew and the ending-soon notifier skip legacy grants.
- **Wire:** `Access::GithubToken` requires `repositories` and gets
  `deny_unknown_fields`, so this skew class cannot recur.
- **Version skew, new CLI and old broker:** the broker's info response gains a
  capability flag for scoped GitHub grants; the CLI refuses to file a GitHub
  request (or mint) against a broker without it, *before* anything reaches the
  owner, and `warden doctor` shows it. This replaces the after-creation check
  in Constraints.
- **Overlap (owner rule above):** overlap is computed by repository id; legacy
  rows overlap everything. The approval page lists the grants approving will
  end, with their repositories, so the owner sees "this also ends agent X's
  grant for A, B". Those grants end with `by` = "replaced" (not "renewed")
  and an audit entry naming the overlapping ids. Read, end and insert run in
  one `BEGIN IMMEDIATE` transaction, so two concurrent approvals cannot both
  survive. If more than one active grant ever covers an id, minting refuses
  (fail closed) and audits it. The post-mint recheck
  (`api/github_token.rs`) checks that the *same* grant is still active.
- **Checking GitHub's mint answer:** `repositories` exactly `[id]` (this is the
  check that matters); returned `permissions` no wider than `PERMISSIONS`;
  `repository_selection` "selected" only if the first PR's real test against an
  installation set to *All repositories* confirms GitHub reports it so.
  **[guess]**
- **Pending slot:** keyed by the names
  lowercased and sorted, so `Owner/App` and `owner/app` share a slot.
- **Renewal after a rename:** when a renewal is created, the broker re-reads
  each id's current name with the scoped token and shows both on the page if
  they differ.
- **CLI checks the mint answer:** the broker returns the repository name and id
  with the token; the CLI refuses a token whose id or name (case-insensitive)
  is not what it asked for. The cache looks up case-insensitively.
- **Revocation residual:** a cached token keeps working up to an hour after a
  revoke, per repository, as today; the threat model's revocation bullet says
  so again.
- **Helper `path` parsing:** strip one trailing `/`, then exactly one `.git`
  suffix, then validate as `RepoName`; anything else (`owner/repo.git/info/lfs`
  from git-lfs included) gets no answer. Git LFS over the helper is therefore
  unsupported, fail closed, and documented.
- **Wrapper argument parsing:** `-R/--repo` accepts `OWNER/REPO`,
  `github.com/OWNER/REPO` and `https://github.com/OWNER/REPO`; any other host
  is refused. Repositories named positionally, by URL or by API path
  (`gh repo clone o/r`, `gh pr view <url>`, `gh api repos/o/r/...`) are not
  parsed: the wrapper uses `GH_REPO`/origin and the call may fail at GitHub.
  Documented. gh's own git calls use `gh auth git-credential`, i.e. the
  wrapper's token, not warden's helper.
- **The CLI's choice of repository is not a security boundary:** the agent
  controls its arguments, environment and checkout. The boundary is the grant
  and the broker's mint. The threat model says so.
- **Automatic requests are labelled:** the approval page shows that a request
  was filed automatically by the git helper or the gh wrapper (not by an
  explicit `warden request`) and the working directory the CLI saw, so a
  prompt caused by a crafted origin, submodule or dependency URL is not
  mistaken for a deliberate push. The pending cap per agent still bounds spam.

### Docs

Update in the same pull requests: `docs/github-app.md` (keep "never All
repositories" as defence in depth), `docs/agent-usage.md`,
`docs/agent-protocol.md`, `docs/configuration.md` if it names the grant,
`docs/threat-model.md` (GitHub tokens: an agent with a token for repository A
cannot reach repository B the App is installed on; the remaining risk is the
owner approving the wrong repository), `docs/assurance-case.md`,
`docs/security-assessment.md` (risk moved; update its date), README, `site/`
if it describes GitHub grants.

## Constraints

- Everything in `AGENTS.md`: fail closed, secrets never in logs or errors,
  no new dependency without need, files under ~800 lines. Near or over the
  limit and likely touched: `crates/broker/src/api.rs` (799),
  `crates/broker/src/approval/pages/tests.rs` (758), `crates/cli/src/doctor.rs`
  (837) and `crates/cli/src/agent.rs` (1028): split what the change touches in
  the same PR, or track it as an issue and say so.
- Version skew, both ways:
  - **New CLI, old broker:** `Access::GithubToken {}` has no
    `deny_unknown_fields`, so an old broker drops `repositories` and shows the
    owner an unscoped request (the old mint then refuses the new body, so no
    token flows, but the owner was asked to approve the wrong thing). The new
    CLI checks the broker's answer at creation and refuses, before waiting, a
    request or grant that comes back without its repositories, telling the
    agent the broker must be upgraded, as a second line of defence behind the
    capability flag (Hardening). **[call]**
  - **Old CLI, new broker:** its empty request and `{}` mint are refused with
    a message saying to upgrade the CLI. **[call]**
- Tests do not depend on timing; GitHub is faked (`github_app` tests already
  fake the mint endpoint).

## Left to the builder

- Splitting into pull requests (suggested: proto + broker grant/mint +
  migration; CLI repository detection + cache + setup; approval page + docs).
- Exact wire shapes and field names, the cache file layout, error wording.
- Whether name→id resolution uses `/installation/repositories` or
  `/repos/{owner}/{name}`.
