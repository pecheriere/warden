# Phone-approved releases

Date: 2026-11-10. Issue: #187. Phase 3 of the agent access model
(`docs/superpowers/specs/2026-11-08-agent-access-model-design.md`, "Release").
This document settles what that spec left to the builder, and widens it from
warden to every repository that publishes signed releases.

## Why

Today a release is the one step of the development cycle that still needs the
owner at the Mac: they sign the tag and the manifest with a key on disk, and
publish the draft from a terminal. The owner wants the whole cycle, release
included, to run through warden: an agent does the work, and the owner approves
from the phone (owner's decision, #187). The on-disk key is treated as exposed and
retires once releases no longer need it.

## Goals

- **Every GitHub step of a release goes through warden with one phone approval:**
  the signed annotated tag, the signed manifest where the repository has one, and
  publishing the draft. No step needs the owner to run a command or hold a key
  (owner's decision).
- **One approval per release, not a time window.** The grant is bound to one
  repository, one tag name and one commit, and each step it allows happens once
  (owner's decision).
- **Any repository that publishes signed releases** can use it, not only warden;
  landfall is the second today (owner's decision).
- **One release key per repository**, held by warden (owner's decision, on the
  recommendation that a leak or a slip then touches one repository, and each
  repository already pins its own key).
- **Adding a repository needs no code:** a 1Password item, the release App
  installed on it, and its tag ruleset.

## Non-goals

- **Warden does not check build attestations** (owner's decision, in the access
  model spec). Consumers do: the Homebrew tap and `docs/verifying-releases.md`.
- **Building, or deciding what to release.** The agent and the owner agree on the
  version in conversation, and each repository's release workflow builds it.
- **Moving landfall onto it.** **[call]** This work builds the general feature and
  moves warden onto it. Landfall's `scripts/release-tag` and release steps change in
  landfall's own repository, tracked as an issue there, once warden ships this.
- **Agents as a separate macOS user** (#186). The access model spec ordered it
  before this phase; doing this first still works (see "Order and residual risk").

## Anti-goals

- An approval that signs anything other than what the phone showed: another tag
  name, another commit, another repository, or a second manifest.
- A release token in an agent's hands. **[call]** The release App's token never
  leaves the broker: the broker creates the tag and publishes the draft itself.
  This tightens the access model spec, which had the agent hold one release token.
  An agent that cannot hold the token cannot create a second tag with it.
- Warden publishing a release without its signed manifest. Releases are
  immutable, so it could never gain one; the broker's publish step refuses until
  the manifest it signed is on the draft. This holds for the broker's own step
  only: the agent App's routine token can still publish or edit a draft itself,
  so an agent could publish early and lose that version's manifest. That costs a
  version, not integrity (the tap refuses a release without a valid manifest),
  and is accepted and recorded in `docs/threat-model.md` (owner's decision,
  2026-11-10, in line with the access model spec: release integrity rests on the
  signed manifest, not on who can press publish).
- Approval details that come from the agent. What the phone shows about the
  commit and the changelog the broker reads from GitHub itself.

## How it works

### Per-repository setup

A 1Password item per releasing repository, tagged `warden:release-signing`
(**[call]** the tag name), in the vault the broker already reads. Fields:

| Field | Meaning |
|---|---|
| `private_key` | The repository's release key, ed25519, as 1Password's SSH key item holds it |
| `repository` | `owner/name`, the only repository this key signs for |
| `manifest` | Optional. The manifest's file name with `{version}` in it, e.g. `warden-{version}-SHA256SUMS`. Absent: the repository signs only tags (landfall) |
| `manifest_namespace` | Required with `manifest`. The `ssh-keygen -Y` namespace, e.g. `warden-release` |
| `publish` | `true` or `false`: whether the broker publishes the draft. **[call]** `false` for a repository whose own workflow publishes |

Rules, failing closed like the other policy items:

- Two items naming the same repository, a missing or unreadable field, a
  `manifest` without `{version}` or with a path separator, a namespace outside
  `^[a-z0-9][a-z0-9-]{0,63}$`, or a key that is not ed25519 is a startup and doctor
  failure for that repository, and that repository cannot be released.
- **[call]** A release key must differ from the `warden:commit-signing` key and from
  every other repository's release key; a shared key is a failure. This keeps the
  existing rule that a commit grant can never produce a signature release
  verifiers trust (`docs/threat-model.md`, "Tags are kept apart").
- A repository with no item cannot be released through warden.

The **release GitHub App** is a second App, separate from the agent App, with
only `contents: write` and `metadata: read`. Its item is tagged
`warden:github-release-app` (**[call]**), with the same fields as
`warden:github-app` except that it has no single installation: the broker looks
up the installation for the repository at use. It is installed on each releasing
repository. Each repository's tag ruleset restricts creating, updating and
deleting `v*` tags to this App as the only bypass actor, replacing today's
repository-admin bypass on warden's `protect-release-tags`. **[guess]** An App can
be a ruleset bypass actor on a user-owned repository; the builder confirms this on
`warden-app-test` first, and if it cannot, stops and reports before building on it.

### The grant

An agent asks for a release:

```
warden request release <owner/name> <tag> --commit <full-sha> --goal "<goal>"
```

**[call]** on command names, here and below. The tag must match
`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$` (landfall uses `-rc.N`); the version
is the tag without the `v`. The commit is a full 40-hex SHA-1 id (**[call]**
GitHub does not host SHA-256 repositories, so a 64-hex id is refused). Before showing the request the broker checks, with a release App token for
that repository, and refuses on any failure or unreadable answer:

- the repository has a release item and the release App is installed on it;
- the commit exists and is on the default branch (the compare API says the branch
  is identical to or ahead of it) **[call]**;
- the tag does not exist yet, unless it already points at exactly that commit and
  carries a good signature from this repository's release key, in which case the
  tag step is already done (see "Reruns").

The approval page shows, besides the usual agent, session and goal:

- the repository, the tag and the full commit id, in the type the design
  language uses for identifiers;
- read by the broker from GitHub, never from the agent: the commit's title and
  date, and the section `## [<version>]` of `CHANGELOG.md` at that commit, as plain
  escaped text, or "no changelog section for this version" when there is none
  **[call]**; and a link to compare the previous release tag with the commit;
- the steps this approval allows, in plain words: "sign and create tag v1.2.3",
  "sign warden-1.2.3-SHA256SUMS", "publish the draft".

The page follows `docs/design-language.md`, with screenshots at the template's
sizes, light and dark.

**Lifetime.** **[call]** The grant ends when every step it allows has happened, or
24 hours after approval, whichever is first. A day covers warden's release
workflow; nothing stays open after the release is out. Revoking it from the grants
page ends it at once, as for other grants.

### The steps

Each runs only under an active release grant of the calling agent, at most once
per grant, and is audited with the grant, repository, tag and outcome.

1. **Tag.** `warden release tag <owner/name> <tag>`. The broker builds the tag object itself:
   object = the approved commit, type `commit`, tag = the approved name, tagger =
   the identity in the release item (**[call]** a `tagger` field, e.g. the owner's
   noreply address, since the tag stands for the owner's approval), the current
   time, and the message `<repo name> <version>` (warden's existing style). It
   signs that payload in the `git` namespace with the repository's key, creates the
   tag object through GitHub's API (the signature goes at the end of the message,
   which is where git keeps it), and checks that the id GitHub returns equals the
   id it computed for the object. On a mismatch it stops before creating the ref,
   so a stray tag object is left unreferenced and nothing is tagged. Then it
   creates `refs/tags/<tag>` as the release App. The agent names only the
   repository and tag; the broker finds its active release grant for them. **[guess]** GitHub's tag API stores the message and tagger byte for
   byte as given, so the ids match; the builder proves it against `warden-app-test`
   before building the rest, and if it does not hold, stops and reports.
2. **Manifest** (only when the repository has `manifest`).
   `warden release sign-manifest <owner/name> <tag> <file>`. The agent has already run the
   repository's attestation checks (warden: what `scripts/sign-release.sh` checks
   today). The broker accepts the file only if its name is the configured name for
   the approved version, it is at most 64 KiB, and every line is
   `<64 lowercase hex>  <name>`, at least one line, no duplicate names
   **[call]**. A name is either a file name (`^[A-Za-z0-9._+-]+$`, not `.` or
   `..`) or an image reference whose tag is exactly the approved version
   (`<registry>/<path>:<version>`, lowercase registry and path segments of
   `[a-z0-9._-]`), since warden's manifest ends with the line for
   `ghcr.io/pecheriere/warden:<version>` **[call]**. It signs the bytes
   in `manifest_namespace`, finds the draft release for the tag, and uploads the
   manifest and `<manifest>.sig` to it, replacing assets of those names. It
   refuses if no draft exists for the tag or the release is already published.
3. **Publish** (only when `publish` is `true`). `warden release publish <owner/name> <tag>`.
   The broker refuses unless the release for the tag is a draft, and, where the
   repository has a manifest, the draft holds the manifest and its signature with
   the SHA-256 digests of the files it signed and uploaded under this grant (GitHub
   reports each asset's digest). Then it sets `draft: false`.

**Reruns.** A rerun of warden's release workflow removes the manifest, and the
grant has already used its manifest step. **[call]** The agent then asks for a new
release grant for the same repository, tag and commit; the broker sees the tag
already there, on that commit, signed by this key, so the new grant covers only the
remaining steps, and the page says so. A tag on any other commit, or signed by any
other key, is refused.

### What changes in warden's release steps

- `AGENTS.md` "Releases": after the release pull request merges, the agent asks
  for the release grant and runs the tag step; the workflow runs; the agent runs
  `scripts/sign-release.sh vX.Y.Z`, which keeps every check it has today and then
  signs through `warden release sign-manifest` instead of a local key; then
  `warden release publish`. The owner's phone approval replaces the owner's tag,
  signing and publishing steps (owner's decision).
- **[call]** `scripts/sign-release.sh` loses its local-key mode. Keeping it would
  keep a path that needs an on-disk key, against the owner's goal, and would be
  dead once the old key retires. If warden is down, a release waits.
- `docs/release-signers` gains the new warden release key with namespaces
  `git,warden-release` (the script requires the tag and manifest to share a key);
  the tap's copy changes in the same step. After the first release signed through
  warden is out, the old key is removed from both, and `docs/verifying-releases.md`
  says to verify an older release against `docs/release-signers` as it was at that
  release's tag (access model spec).
- **The Homebrew tap** verifies each warden archive's build attestation before
  rendering the formula, as it does for landfall. Its warden path checks only the
  manifest signature today (checked: `scripts/formula.py` has no attestation
  check). That is a pull request in `pecheriere/homebrew-tap`, and it must land
  before the first warden-signed release (access model spec).
- `docs/verifying-releases.md` makes the attestation check required, and says why:
  the signature proves the owner approved the release, the attestation proves the
  workflow built it from the tag.

### Setup the owner does once

These need the owner's GitHub account or vault; the agent prepares exact steps.

1. Create the release App (`contents: write`, `metadata: read`, no webhooks) and
   install it on `pecheriere/warden` and `pecheriere/warden-app-test`.
2. Create the `warden:github-release-app` item and the `warden:release-signing`
   item for warden, with a new ed25519 key.
3. Approve the ruleset change on warden: the release App as the only bypass actor
   of `protect-release-tags`, which also blocks tag creation (the agent applies it
   with the owner's OK, as on 2026-11-09).

## Order and residual risk

- Until #186, agents run as the owner and can read the owner's `gh` token, which
  has admin rights: it could edit the ruleset or create a tag through the admin
  role. Against that, the release key living only in the broker still holds: no
  signature that `docs/release-signers` trusts can be made without a phone
  approval, once the old key is retired. **[call]** This is recorded in
  `docs/threat-model.md` and `docs/security-assessment.md` as open until #186.
- The broker signs a manifest of whatever archives the agent hashed (owner's
  decision not to check attestations). The tap's attestation check and the
  required check in `docs/verifying-releases.md` are what catch a manifest of
  someone else's archives.

## Left to the builder

- Table design and migrations (a new migration file; never edit a released one),
  the grant's wire types in `warden-broker-proto`, and how the steps' "used" state is
  recorded so that a step can never run twice, even across a restart.
- How the broker finds the release App installation for a repository, and caches
  it.
- Code layout: new modules for release signing and the release App, kept apart from
  `commit_signing` and `github_app`, each file under about 800 lines; #209 (split
  the broker's `main.rs`) if this would push `main.rs` over.
- Doctor checks for the new items.
- Splitting into pull requests, one per issue: open issues for the parts as the
  plan sets them out.

## Documentation to update

README, `docs/1password-items.md`, `docs/configuration.md`, `docs/agent-usage.md`,
`docs/agent-protocol.md`, `docs/interfaces.md`, `docs/github-app.md`,
`docs/threat-model.md`, `docs/assurance-case.md`, `docs/security-assessment.md`
(and its date), `docs/verifying-releases.md`, `docs/release-signers`, `AGENTS.md`
(release steps), `CHANGELOG.md`, `site/index.html` if it describes releases, and the
approval pages.
