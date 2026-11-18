# One GitHub grant per permission set (warden-dqs)

## Problem

An agent's everyday GitHub grant for a repository disappears as soon as it asks for a
sensitive one. Seen twice on 2026-11-17: `pecheriere/foreman` had a 30-day grant. The agent
got a 30-minute `workflows:write` grant, pushed, and revoked it as the rules require.
Afterwards it had no grant at all, so every `git push` and `gh` call on the repository waited
for a new phone approval. All sessions on the Mac share one agent, so every one of them stalled.

## Root cause

`warden revoke` is not at fault: it ends only the grant it names, on the broker
(`requests/grants.rs`) and in the CLI's token cache (`github_token/cache.rs`). The everyday
grant ended earlier, **when the sensitive grant was approved**. The broker keeps at most one
GitHub grant per agent per repository, and approving one ends every grant that shares a
repository with it (`requests/github_overlap.rs`, recorded as `by: "replaced"`). Letting the
sensitive grant expire instead of revoking it leads to the same place.

The 2026-11-14 permissions design picked that replacement (option A, the new grant
replaces the old) over keeping both grants (option B). This design reverses it: adding or
removing a grant leaves the agent's other grants as they were. (owner's decision)

## The design

### One grant per permission set

- Approving a GitHub grant ends the agent's grants that overlap it (share a repository)
  **and asked for exactly the same extra permissions** (none counts as a set). Grants with
  other extras stay. (owner's decision: one grant per permission set)
- The set compared is the extras, what the agent asked for beyond the owner's default, not
  the full set. A renewal is a new request carrying the old grant's extras: comparing full
  sets would leave the renewed grant live whenever the owner changed the default in
  between. **[call]**
- The approval still binds the ids it ends into the digest the owner signs (`replaces`),
  so that mechanism stays as it is.
- A legacy grant, made before grants named repositories, is still ended by any approval.
  **[call]**
- So an agent can hold, on one repository, an everyday grant and a `workflows:write` grant,
  or an `actions:write` grant beside it. Revoking any of them leaves the others listed and
  usable. That is the bead's acceptance criterion.
- Asking again with one more permission no longer replaces the old grant: both are live
  until one is revoked or expires. To keep that visible, the approval page lists the agent's
  other live grants on the same repositories, with their permissions and end, under the
  heading "Also live". **[call]**
- Pending requests: the request slot key gains the extras, so requests for
  different extras wait side by side. `OtherPermissionsPending` goes away. **[call]**

### Minting: an extra permission only when it is named

Every grant holds the owner's default set (stored in it at approval) plus its extras, if any.
**A token carries an extra permission only when the request names it.** That covers sensitive
permissions and also non-sensitive extras such as `actions:write`. **[call]** The other rule
considered, "only sensitive permissions must be named", needs a plain request to pick among
grants whose extras do not nest (`issues:write` beside `actions:write`). Any such pick is
arbitrary.

- **The request names permissions** (`--permissions`, or the git credential variable
  below). The broker picks, among the agent's grants covering the repository that hold
  every permission named, the least privileged one: no sensitive permission first, then
  the fewest permissions, then the one ending soonest. **[call]** The token is narrowed to
  what was named, as today. So the pick decides only which grant the audit log names and
  which revoke stops it, never what the token can do. No grant holding them all is refused,
  naming the first missing permission, as today.
- **The request names nothing.** The token gets the default set, from the least privileged
  grant covering the repository (same order). A grant does not store the default set apart
  from its extras, and an extra can raise a default level (`contents:write` over
  `contents:read`), so the default set is **the owner's current `default_permissions`,
  limited to what the grant holds** (per name, the lower level). It can narrow an existing
  grant when the owner narrows the default, and never widen one. **[call]**
- Two grants with the same extras on one repository stay `AMBIGUOUS_GRANT`:
  storage holds that only if something went wrong.
- The check after GitHub answers repeats the same pick with the same request. It must pick
  the same grant, still active, or the token is withheld (`github_token_refused`), as today.
  If the `workflows:write` grant is revoked during a mint that named `workflows:write`, that
  mint gets nothing.
- `github_token_minted` already records the grant and the permissions minted, so the log
  shows which grant each token came from. No new entry. **[call]**

### Naming permissions

- `warden github token --permissions actions:write` already exists and works unchanged.
- **`warden git-credential` reads `WARDEN_GITHUB_PERMISSIONS`**, in the same syntax as
  `--permissions`. Git passes a credential helper nothing per command, so a variable is the
  only per-command channel: `WARDEN_GITHUB_PERMISSIONS=contents:write,workflows:write git push`.
  An invalid value makes the helper print the error on stderr and nothing on stdout, so git
  fails rather than push with another token. **[call]**
- The value narrows, like `--permissions`, so a push that changes a workflow names
  `contents:write` as well. The agent docs and `warden prime` give that exact line. **[call]**
  A flag meaning "the default set plus these" would read better, but it would give
  permission sets a second meaning.

### The CLI's token cache

- The cache's "nothing named" key (`AskedSet::Full`) is renamed `AskedSet::Default`, and
  the file version goes from 3 to 4, so a version 3 file, whose plain tokens may carry
  extras, is ignored rather than served after the upgrade. **[call]**
- Entries are already keyed by repository and asked permission set. Today `put` drops every
  entry of the repository minted under another grant. It changes to drop only the entry with
  the same repository and asked set. Tokens minted under other grants stay. **[call]**
- `warden revoke <grant>` already drops only that grant's entries, and `warden request
  github` already clears the repository's entries on approval. Neither changes.

### Agent guidance

- The rule "revoke sensitive GitHub grants right after use" stays. It now costs nothing,
  because the other grants survive the revoke. An agent that asks again with more
  permissions revokes the grant it no longer needs once the new one is approved.
- `warden prime`, `docs/agent-usage.md` and `rules/warden.md` say: name any extra permission
  on the command that needs it. A plain `git push` or `gh` call gets the default set.

### Docs

Update `docs/github-app.md`, `docs/agent-usage.md`, `docs/agent-protocol.md` (the pick),
`docs/configuration.md` (the variable), `docs/threat-model.md` ("at most one grant per
repository" becomes "at most one per permission set", plus "an extra permission reaches a
token only when the request names it"), `docs/security-assessment.md` and its date,
`docs/upgrading.md` and `CHANGELOG.md`. Add a note to the 2026-11-14 spec that this design
reverses its option A.

## Compatibility

- No migration: stored grants and requests keep their shape.
- **Breaking: an agent that relied on its grant's extras by default** gets the default set
  and is refused by GitHub. This covers a plain `git push` of a workflow change, and a
  `gh run rerun` with a plain `warden github token` under an `actions:write` grant. Each now
  names the permissions. `docs/upgrading.md` and the CHANGELOG say so.
- An older CLI against a new broker: plain requests get the default set, and
  `--permissions` reaches the extras. An older CLI's `git-credential` cannot name any.
- A new CLI against an older broker: the variable sends permissions the broker already
  understands, and it narrows from the single grant.

## Security

- Better than today: until now, while an extra was granted, every session on the agent
  got it in every token without asking for it.
- New cost: a superseded grant stays live until revoked or expired, where approval used to
  end it. The "Also live" list on the approval page and the agent guidance address it. A
  sensitive grant still lasts at most 1 hour.
- Unchanged: every session shares one agent, so any of them **can** name an extra
  permission while a grant holds it. Naming stops sessions from getting it by accident, not
  on purpose. Keeping sessions apart needs one warden agent per session, tracked as
  warden-30f.
- Revoking still stops minting under the revoked grant at the next mint and withholds a mint
  in flight. Revoking the agent still ends all of them.

## Tests

- Broker: the acceptance test. An everyday and a `workflows:write` grant on one repository,
  revoke the second, and the first is still listed and mints.
- Approval: a grant with another permission set keeps the existing ones, the same set
  replaces, and a legacy grant is replaced by any approval. The digest binds only what is
  ended.
- Pick: nothing named gives the default set; a named permission picks the least privileged
  holder, by each step of the order; a named permission that no grant holds; same-set
  ambiguity.
- Recheck: the picked grant revoked during the mint.
- Pending: requests for different sets wait side by side; the same set is still a duplicate.
- Approval page: "Also live" lists the other grants, rendered and screenshotted per
  `docs/design-language.md`.
- CLI: `put` keeps other grants' entries, and `git-credential` handles a valid, invalid
  and missing `WARDEN_GITHUB_PERMISSIONS`.

## Out of scope

- One warden agent per session: warden-30f.
- A grant for `B` still ends a grant with the same permissions for `A, B`, losing `A`.
  Replacement by exact repository set is a separate change, to file as its own bead if it
  bites.
