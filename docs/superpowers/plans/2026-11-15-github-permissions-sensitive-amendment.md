# Amendment to the GitHub token permissions plan: sensitive permissions instead of a ceiling

Amends `docs/superpowers/plans/2026-11-14-github-token-permissions.md` (tasks 8–14) and the spec
`docs/superpowers/specs/2026-11-14-github-token-permissions-design.md` ("The ceiling").

Tags: **[call]** my decision, open to override; **[guess]** an assumption the builder confirms;
(owner's decision) yours.

## What changed

On #282, 2026-11-14 (owner's decision: no hard ceiling in code; the owner's config decides):

1. No permission is refused by code any more. The ceiling (`administration`, `workflows`, `secrets`,
   `environments`, `dependabot_secrets`, `repository_hooks`, `organization_*`) stops being a hard limit.
2. `default_permissions` stays the safe set every grant gets.
3. `extra_permissions`, the owner's allowlist, decides what an agent may ask for, former ceiling names
   included. A name not listed is refused at request creation, before any phone prompt.
4. The former ceiling names become **sensitive**: allowed when listed, marked red on the approval page
   with one line on what each allows, and their grant window capped at 1 hour.

## Decisions (2026-11-15)

### A. Sensitive names only as agent-asked extras

(owner's decision: the stricter variant, chosen over both window options) A sensitive name is
allowed in `extra_permissions` only. In `default_permissions` it makes the App unusable and doctor
fails, exactly as a malformed field does today, naming the field and never quoting it. So a sensitive
permission reaches a grant only when an agent names it as an extra and the owner approves it, and
every grant that holds one is capped at 1 hour. This refines the 2026-11-14 note's "default with a
sensitive name: allowed, doctor warns": it keeps the git helper's and `gh` wrapper's 30-day automatic
grants free of sensitive permissions.

### B. Doctor

Follows from A: no warning status is needed. A sensitive name in the default fails the `github-app`
check; one in the allowlist passes.

### C. A separate pull request first

**[call]** The proto and configuration change stands alone, so it goes first as its own issue and PR
("PR B0"). The red marking and the window rule cannot be reached until agents can send extras, so
they land in PR B's tasks 8 and 10 instead of as dead code in B0.

## Task 7a (PR B0): Sensitive names replace the ceiling in proto and configuration

**Files:**

- Modify: `crates/proto/src/github_permissions.rs` (`CEILING` → `SENSITIVE`, `under_ceiling` →
  `is_sensitive`, `PermissionError::Ceiling` → `PermissionError::SensitiveInDefault` used only by the
  default field's check, `KNOWN` gains the sensitive names), the GitHub App item parsing under
  `crates/broker/src/policy/` (the allowlist accepts sensitive names, the default refuses them), and
  wherever `known()` or `stored_view` relied on the ceiling refusal
- Test: `crates/proto/src/github_permissions/tests.rs`, `crates/broker/tests/policy/github_app.rs`,
  `crates/broker/tests/doctor.rs`

**Interfaces:**

- `pub const SENSITIVE: &[&str]`: `administration`, `workflows`, `secrets`, `environments`,
  `dependabot_secrets`, `repository_hooks`, and each `organization_*` permission GitHub documents for
  installation tokens, read from the same page as `KNOWN` and dated. **[call]** An `organization_*`
  name GitHub does not document stays `Unknown` and refused, as any unknown name is today, so every
  text the broker shows stays a fixed one.
- `pub fn is_sensitive(name: &str) -> bool`; `Permission::is_sensitive(&self)`;
  `PermissionSet::sensitive(&self) -> impl Iterator<Item = Permission>`.
- Parsing a `Permission` or `PermissionSet` accepts sensitive names; refusing them is the caller's
  rule, so the configuration check refuses them in the default only. `GrantedPermissions::known()`
  accepts them (GitHub may echo one a grant holds); the wider-answer check stays.
- Stored sets and grants: unchanged. No stored set can hold a sensitive name yet.

**Steps:**

- [ ] Failing tests: proto `sensitive_names_parse` (each former ceiling name and a documented
  `organization_*` name, read and write), `undocumented_organization_name_is_unknown`,
  `admin_level_still_refused_on_sensitive`, `granted_permissions_accepts_sensitive`; broker
  `sensitive_in_allowlist_is_usable` (replaces `ceiling_in_allowlist_makes_the_app_unusable`),
  `sensitive_in_default_makes_the_app_unusable` (doctor fails naming the field, the value never
  quoted; SSH still works).
- [ ] Run (fail), implement, run (pass).
- [ ] Docs in the same PR: `docs/github-app.md` (the ceiling section becomes "Sensitive permissions":
  listing one lets agents ask for it; until agents can ask for extras, listing it has no effect),
  `docs/1password-items.md`, `docs/configuration.md` (doctor row), `docs/threat-model.md` (the risk
  moves to the owner's allowlist), `docs/assurance-case.md` (R3, the input table),
  `docs/security-assessment.md` (risks 1 and 2, date), the spec's "The ceiling" section, `CHANGELOG.md`.
- [ ] Commit `Treat former ceiling GitHub permissions as sensitive, allowed only as listed extras
  (#<issue B0>)`; full "Before you push" list; PR; two reviewers.

## Changes to tasks 8–14

- **Global constraint "The ceiling, which no configuration lifts"** is replaced by: sensitive names are
  grantable only as agent-asked extras the owner lists in `extra_permissions`, never in the default,
  and such a grant lasts at most 1 hour. (owner's decision)
- **Task 8:** adds the window rule. GitHub token grants gain `15m`, `30m` and `1h`
  (`Window::is_github_token_sensitive()`, **[call]**) for a request whose extras hold a sensitive
  permission, and only for it; any longer window is refused at creation with the fixed
  `SENSITIVE_WINDOW: &str = "a GitHub token grant with a sensitive permission lasts 15m, 30m or 1h"`.
  **[guess]** Renewal is not offered for such short grants; the builder confirms, and if it is, caps the
  renewed window the same way. `access_refuses_ceiling_extra` becomes `extra_not_in_allowlist_refused_before_prompt`
  for a sensitive name the owner did not list; add `sensitive_extra_needs_a_short_window` (a `30d`
  request with `workflows:write` listed is refused with `SENSITIVE_WINDOW`, a `1h` one is stored) and
  `sensitive_extra_allows_short_window_only_then`. `EXTRA_NOT_ALLOWED` text unchanged; it may name a
  sensitive name, which is a known name.
- **Task 9:** `not_allowed` is the extras the current allowlist refuses (no ceiling any more).
- **Task 10:** adds the sensitive marking. Each sensitive permission is shown in the danger colour
  the design language names, with one fixed line on what it allows under the list
  (`sensitive_meaning(name) -> &'static str` in proto, for instance `workflows` "change GitHub Actions
  workflows, which run with the repository's secrets"; the builder writes the rest from GitHub's
  docs). Red wins over the read and write extra styles. Test
  `page_marks_sensitive_permissions_with_their_meaning`.
- **Task 11:** `warden request github --extra-permissions` with a sensitive name and no `--for` defaults
  to `1h` **[call]** (the default `30d` would be refused); with `--for 30d` the broker's refusal is
  printed as is. `warden list` marks sensitive names among the allowed extras.
- **Task 12:** `docs/agent-instructions.md` tells agents a sensitive extra means a 1-hour grant and a
  goal that says exactly why.
- **Tasks 13–14:** unchanged.
- **Notes from PR A on #282** still apply, except "`PermissionError::Ceiling` names no permission",
  which goes away with the variant.
