# GitHub token permissions: a configurable default and requested extras (#276)

Status: design, for the owner's approval. Date: 2026-11-14.

Tags: (owner's decision) decided in the design conversation; (owner's decision: #276) written
in #276 by the owner; (owner's idea) for later; **[call]** the designer's call, open to
correction; (left to the builder) for whoever builds it.

## Why

Every installation token the broker mints has the same four permissions, a constant
(`PERMISSIONS` in `crates/proto/src/github_token.rs`): `contents: write`,
`pull_requests: write`, `issues: write`, `metadata: read`. Agents that orchestrate work (seen
in foreman on 2026-11-14) need to read CI results to act on a failed check:
`GET /repos/{o}/{r}/commits/{sha}/check-runs` and `GET /repos/{o}/{r}/actions/runs` answer 403
without `checks: read` and `actions: read`, even though the owner granted both to the App.
Agents are blind to every CI failure and can only retry. (owner's decision: #276)

Success: an agent asks for `checks:read,actions:read` once, with a goal that says why; the
owner sees on the phone that those two are extra and approves; from then on
`GH_TOKEN=$(warden github token --repo o/r) gh run view …` works for that repository.

## Goals

1. The owner configures a **default permission set** that every GitHub grant gets, instead of
   a constant. Unconfigured, it is today's four. (owner's decision: #276)
2. A request can name **extra permissions** on top of the default. (owner's decision: #276)
3. Extras are capped by an **allowlist** the owner configures and by what the App holds.
   (owner's decision: #276)
4. The phone approval page **shows which permissions are extra**. (owner's decision: #276)
5. A grant records the set the owner approved; tokens under it never exceed that set.
   (owner's decision: #276)
6. The CLI's token cache is keyed by repository **and permission set**, a request for a set
   the cached token lacks mints a new one, and `--fresh` forces a mint. (owner's decision: #276)
7. The token response echoes the permissions GitHub actually granted, so a caller can tell a
   missing permission from another 403. (owner's decision: #276)
8. The docs tell agents how to ask for extras and that the goal must say why. (owner's decision: #276)

## Non-goals

- **Grants with fewer permissions than the default** (a read-only grant). The issue calls it a
  nice-to-have; narrowing at the token (below) covers least privilege. (owner's decision)
- **A sensitive tier**: extras that are never default, granted only for minutes or hours, as
  their own short-lived token. Tracked in #279. (owner's idea)
- **Extras for automatic requests.** The git credential helper and the `gh` wrapper ask for the
  default set only; extras always come from an explicit `warden request` with a goal. **[call]**
- **Per-repository allowlists.** One allowlist for the App. **[call]**
- **The local secret backend.** It cannot hold the GitHub App today (GitHub tokens are off on
  it), so it gains no permission fields. **[call]**

## Anti-goals

- A token that can do more than the owner saw on the phone.
- A configuration typo that silently grants something: an unknown permission name or level
  turns GitHub tokens off with a clear reason, and is never ignored.
- An allowlist that lets an agent reach past the repository: workflows (run with the
  repository's secrets), administration (branch protection, rulesets), secrets, environments,
  organization permissions. See the sensitive permissions below.
- A bad GitHub field taking down SSH, APIs or signing: only GitHub tokens stop.

## Constraints

- Threat model: when state is unreadable or ambiguous, refuse and audit.
- Requests the broker stored before this change, and grants made from them, have no
  permission field: they mean today's four, never the configured default. **[call]**
- `GithubTokenAccess` and `GithubTokenRequest` deserialize with `deny_unknown_fields`, so a
  0.14 broker refuses a request carrying a new field: the failure is closed. The CLI still
  checks a new `/v1/info` flag first so it can say "upgrade the broker" instead of a raw 400.
- Request creation never reads the App's private key: any enrolled agent reaches it
  (`check_github_token` in `requests/create.rs` says so today). It may read the two permission
  fields, through a backend call that returns only them.
- The request fingerprint is a hash of the request as the agent made it, and the CLI
  recomputes it to recognise its request (`request_context.rs`). The broker never rewrites
  what the agent sent; anything it derives is stored beside it.
- One migration, additive; never edit a released one.
- Files stay under about 800 lines. The touched files are well under today
  (`api/github_token.rs` 205, `approval/pages/github_token.rs` 275, CLI `cache.rs` 334);
  `requests/limits.rs` (693) and `requests/renewal.rs` (547) need a split if a change would
  take them past it. (left to the builder)

## Approaches considered

Where the owner configures the default set and the allowlist:

| | Approach | Trade-off |
|---|---|---|
| **Picked** | Two fields on the `warden:github-app` 1Password item | Next to the App it limits, in the vault the rest of the policy lives in; `doctor`'s `github-app` check validates it. |
| | Environment variables (`WARDEN_GITHUB_DEFAULT_PERMISSIONS`, …) | Changes go through the deployment repo with a reviewed commit, but the App's limits live apart from the App. |
| | One 1Password item per allowed permission | Many items for what is a list. Ruled out. |

The owner picked the item fields. (owner's decision)

What happens to an existing grant when one with extras is approved for the same repository:
**A, the new grant replaces it** (picked) (owner's decision); B, both live and a token request picks
the covering grant (drops the one-grant-per-repository invariant); C, refuse until the agent
revokes (the agent is without access meanwhile). A is already how the broker works:
approving a GitHub token grant ends the agent's grants that share a repository with it
(`requests/github_overlap.rs`), and the ids it ends are bound into the digest the owner signs
(`replaces`, checked in `requests/decide.rs`, `RequestError::ReplacedChanged`). This design
reuses that unchanged.

## The design

### Permission sets

A **permission** is `name:level`, with `name` a GitHub repository permission as the REST API
names it (`checks`, `actions`, `pull_requests`, …) and `level` `read` or `write`. **[call]**

- The proto crate holds the repository permission names GitHub documents for installation
  tokens, as a fixed list. Any other name is refused wherever it is parsed. `admin` levels are
  refused. **[call]**
- A **set** holds each name at most once. Written forms are canonical: sorted by name,
  `name:level`, comma-separated. `metadata:read` is always in a set (GitHub adds it anyway);
  writing it is allowed, leaving it out adds it. **[call]**
- `write` covers `read`: a set that has `checks:write` satisfies a request for `checks:read`.
  This is today's `rank` comparison in `github_app/answer.rs`. **[call]**

### Sensitive permissions (owner's decision, amended 2026-11-15; replaces the ceiling)

The ceiling is gone: no permission is refused by code. `administration`, `workflows`, `secrets`,
`environments`, `dependabot_secrets`, `repository_hooks` and the documented `organization_*`
permissions are **sensitive**. They are allowed in `extra_permissions`, where the owner's
allowlist decides, and a configured `default_permissions` that holds one makes the GitHub App
unusable (below). A sensitive permission reaches a grant only when an agent asks for it as an
extra and the owner approves; such a grant lasts at most one hour and the approval page marks it
red. See `docs/superpowers/plans/2026-11-15-github-permissions-sensitive-amendment.md`.

### Owner configuration (owner's decision) (fields), **[call]** (details)

Two optional text fields on the item tagged `warden:github-app`:

| Field | Meaning | When missing |
|---|---|---|
| `default_permissions` | The set every new grant gets. | Today's four. |
| `extra_permissions` | The permissions a request may add, each at most at the level written. | No extras allowed. |

- Both use the written form above. The default may be any set without a sensitive permission;
  `metadata:read` is added to it.
- The broker reads the item when it uses it, as it does today (`OnePassword::github_app()`
  fetches and parses it at each mint, resolution, renewal and offers call); nothing reads it
  at startup. A field that is present but empty, cannot be parsed, names an unknown
  permission or level, or a default that holds a sensitive permission, makes the App unusable, exactly as a bad
  `installation_id` does today: GitHub tokens are refused with the existing fixed error,
  and `doctor`'s `github-app` check fails with a fixed reason naming the field, never quoting
  its value. Everything else keeps working. **[call]**
- A new backend call returns only the two permission fields, parsed and checked, without the
  private key. Request creation and offers use it; mint and resolution keep reading the whole
  item. The 1Password backend implements it; the local backend answers "no App", as today;
  the testkit fake gets it too. **[call]**
- A changed field applies to the next request. It never changes a grant already approved or
  a request already pending: the full set is fixed when the request is created (below).

### Requesting extras

`warden request github <owner/name>... --extra-permissions checks:read,actions:read --goal "…"`
**[call]** (the owner suggested `--extra-permissions` in the issue).

- The wire access gains an optional `extra_permissions` set: what the agent asked for, stored
  as sent, so the fingerprint stays the agent's. The broker refuses at creation (400, a fixed
  message naming the permission) an extra outside the allowlist, above its allowed level, or
  a sensitive name the owner did not list. **[call]**
- The broker then computes the **full set**, the default read at that moment plus the extras,
  and stores it beside the request (not in the agent's access). The full set is the one
  thing the grant will hold. An extra the default already covers is kept in what the agent
  sent but is not marked extra on the page. **[call]**
- The agent never sends a full set: there is no wire field for one, so
  `deny_unknown_fields` refuses it.
- Extras apply to every repository of a multi-repository request. **[call]**
- The CLI refuses `--extra-permissions` against a broker whose `/v1/info` lacks the new flag
  (`github_token_permissions: true`), saying to upgrade it.
- Automatic requests (credential helper, `gh` wrapper) send no extras. **[call]**
- **A pending request for the same repositories with different extras.** Today `create`
  returns the request already pending in the slot (`created: false`), and the slot is the
  repository names alone. Here, when the pending request's extras differ from the new one's,
  the broker refuses with 409 and a fixed message: a request for these repositories with
  other permissions is pending; cancel it (`warden request cancel <id>`) or wait for it. Same
  extras: today's behaviour, the pending request is returned. Owner renewal follows the same
  rule. **[call]** (the other options, a slot that includes the set or a CLI warning, either
  let two requests for one repository coexist or let an agent wait on a request without the
  extras it asked for.)

### Checking what the App holds **[call]**

- Each time the approval page renders a GitHub token request (and a renewal), the broker reads
  the installation's permissions (`GET /app/installations/{id}` with the App JWT). It does not
  store them with the repository resolution, which keeps "first answer wins": a request that
  was missing `checks:read` becomes approvable as soon as the owner grants it to the App on
  GitHub, without the agent asking again. Requests left pending by 0.14 are read the same way.
- If the installation lacks any permission of the full set at the asked level, the page says
  the request cannot be approved and names the missing permissions, as it does for an
  unreachable repository, and approval is refused. If the installation cannot be read, the
  page cannot be approved either.
- Minting checks again: GitHub refuses a permission the App lacks, and `check_minted` refuses
  a token wider than asked.

### What the passkey approval binds **[call]**

Today the access is bound through the request fingerprint in `ApprovalBinding`, and the
destination digest (`GithubPending::digest_input`) covers the App, installation, resolved
repositories and replaced grants. This design adds the **full set** to `digest_input`, as a
new digest version, so the approval binds the permissions the grant will hold, not only what
the agent asked. The extras are covered by the fingerprint as today. The installation's
permissions are not bound: they are a precondition checked at render and at approval, and
the mint checks again.

### The approval page (owner's decision: #276) (marking), **[call]** (form)

The "Permissions" line lists the full set. Extras are marked, read extras in one style and
write extras in a stronger one, with a short line such as "2 beyond the default". When the
request replaces a grant, the replaced-grant text also lists that grant's permissions, so the
owner sees what changes. Follows `docs/design-language.md`; screenshots at the PR template's
sizes, light and dark.

### Grants and renewal (owner's decision) (replacement), **[call]** (rest)

- A grant holds its request's full set. Grants and requests stored before this change hold
  today's four.
- Approval replaces overlapping grants exactly as today.
- **Renewal rebuilds the set** as the current default plus the grant's extras (none for a
  grant stored before this change), so renewals follow the owner's current default and a
  narrowed default never strands a legacy grant. Each extra is checked against the current
  allowlist; one that is no longer allowed makes the renewal page unapprovable,
  saying which, and the agent asks again. The page marks the extras and shows how the full
  set differs from the grant being renewed, if it does.
- The grants page and `warden status` show each GitHub grant's extras.

### Minting

`warden github token [--repo o/r] [--permissions <set>] [--fresh]` (owner's decision: #276) **[call]**

- No `--permissions`: the token gets the grant's **full set**. Agents' existing
  `GH_TOKEN=$(warden github token --repo o/r) gh …` gets the extras without change.
  (owner's decision)
- `--permissions` asks for a subset (narrowing). The broker refuses anything outside the
  grant (403 with a fixed message naming the permission). `metadata:read` is implied.
- The wire request gains an optional `permissions` set; absent means the grant's full set.
- The broker asks GitHub for exactly the set it decided, `check_minted` compares GitHub's
  answer with that set instead of the constant, and the response carries `permissions`,
  GitHub's answer. The `github_token_minted` audit entry records what GitHub granted (today
  it records the constant).
- The hourly mint limit is unchanged and covers `--fresh`.

### The CLI's cache (owner's decision: #276) (keying, `--fresh`), **[call]** (rest)

- Entries are keyed by repository and the canonical written form of the asked set, with
  `full` standing for no `--permissions`. A request for a set no entry holds mints a new
  token; entries do not overwrite each other.
- `--fresh` skips the cache and replaces that entry.
- **A new grant drops the repository's entries.** When `warden request github` sees its
  request approved, it removes every cached entry for the repositories it named, as
  `warden revoke` already does. So in the success scenario the next `warden github token`
  mints under the new grant instead of serving the old token for up to an hour. The token
  response's grant id is stored with each entry; a minted token whose grant id differs from
  a cached one for the same repository replaces all of that repository's entries.
- The file version goes to 3; a version 2 file is ignored and replaced, as version 1 is today.
- Entries are each served while they have 5 minutes left and are dropped once expired.

### Discovery

`GET /v1/offers` and `warden list` add, under GitHub, the default set and the allowed extras.
`warden prime` and `docs/agent-instructions.md`'s GitHub section say: ask for extras only
when the task needs them, name them with `--extra-permissions`, and say why in the goal.
(owner's decision: #276)

### Audit **[call]**

- `request_created` carries a summary string, not the access. Its summary gains the extras
  (for example `github o/r +checks:read,actions:read`), so the log shows what was asked. The
  full set is recorded in the approval entry, which gains a `permissions` field with the
  set the grant holds. A new optional field; an older `audit verify` refusing it is noted in
  the changelog's upgrade notes, as for other new fields.
- `github_token_minted.permissions` is GitHub's granted set.
- A refused extra at creation and a refused narrowing at mint are recorded like today's other
  refusals. (left to the builder) picks the entry kinds, following the existing refused-request and
  `github_token_refused` patterns.

### Docs to update in the same change

`README`, `docs/github-app.md` (the item fields, sensitive permissions), `docs/1password-items.md`,
`docs/configuration.md` (CLI table, cache file version), `docs/agent-usage.md`,
`docs/agent-instructions.md`, `docs/agent-protocol.md` (wire fields, the info flag),
`docs/interfaces.md`, `docs/upgrading.md` (old grants keep four; upgrade the broker before
using the new flags), `docs/threat-model.md` (what an agent can now hold; sensitive permissions),
`docs/assurance-case.md`, `docs/security-assessment.md` and its date (the risk moves),
`CHANGELOG.md`.

## Left to the builder

- The list of GitHub repository permission names, from GitHub's REST API documentation for
  "Create an installation access token", with the source and date in a comment.
- How the PRs split (proto and config; broker request, page and mint; CLI and cache; docs),
  as long as each PR passes CI on its own and none ships a half-feature to users.
- Storage shape in the migration, within "old rows mean today's four" and "the agent's access
  is stored as sent".
- Exact refusal texts, kept fixed and free of anything an agent or GitHub sent.
