# Roadmap

What warden intends to work on over the next year, written in November 2026. It
comes from the [open issues](https://github.com/pecheriere/warden/issues), which
are always more current than this page.

**This can change.** warden has one maintainer, and these are intentions rather
than promises, with no dates and in no fixed order. Security fixes come first
whenever they are needed.

## Easier to try and to run

Fewer things to set up before warden is useful.

- [#71](https://github.com/pecheriere/warden/issues/71) Distribute the CLI:
  attested binaries, Linux packages and a Homebrew tap
- [#72](https://github.com/pecheriere/warden/issues/72) README: say who warden
  is for, and recommend one setup
- [#73](https://github.com/pecheriere/warden/issues/73) Try warden in five
  minutes on one machine
- [#74](https://github.com/pecheriere/warden/issues/74) Run the broker without
  Docker
- [#75](https://github.com/pecheriere/warden/issues/75) Approve without
  Tailscale
- [#76](https://github.com/pecheriere/warden/issues/76) Secrets and policy
  without 1Password: [local files](local-backend.md) exist, and are weaker;
  other backends can follow if people ask
- [#77](https://github.com/pecheriere/warden/issues/77) Guided setup: doctor
  and setup checks
- [#78](https://github.com/pecheriere/warden/issues/78) Make it easy to set up
  an agent

Several of these are partly done. The [changelog](../CHANGELOG.md) says what has
landed.

## Git and GitHub for agents

Let agents work with Git and GitHub with no long-lived credential on their
machine.

- [#80](https://github.com/pecheriere/warden/issues/80) Git over warden: one
  key, per-repo grants, and plain `git push`
- [#81](https://github.com/pecheriere/warden/issues/81) Commit signing through
  warden, with limits per grant
- [#82](https://github.com/pecheriere/warden/issues/82) Use `gh` through warden
  without giving agents a token

## Tighter grants and clearer approvals

- [#35](https://github.com/pecheriere/warden/issues/35) Make revoking a
  certificate grant effective on the target
- [#49](https://github.com/pecheriere/warden/issues/49) Use a grant only for the
  task it was approved for
- [#45](https://github.com/pecheriere/warden/issues/45) Live connections: idle
  time per relay session, and the last certificate issued
- [#43](https://github.com/pecheriere/warden/issues/43) Fingerprint as short
  English words instead of hex
- [#39](https://github.com/pecheriere/warden/issues/39) Approval UI:
  screen-reader check

## Assurance and project health

Show the work that a tool asking for trust should show.

- [#93](https://github.com/pecheriere/warden/issues/93) OpenSSF badges: Baseline
  Level 2, Passing and Silver, with the issues it tracks: security policy,
  commit sign-off, test coverage, repeatable builds, advisory exemptions,
  assurance case, signed releases and continuity
- [#91](https://github.com/pecheriere/warden/issues/91) Fuzz the code that
  parses untrusted input
- [#90](https://github.com/pecheriere/warden/issues/90) Fix a flaky test
- [#92](https://github.com/pecheriere/warden/issues/92) CLI: separate the exit
  codes of usage errors and denied requests
- [#60](https://github.com/pecheriere/warden/issues/60) Move to `ssh-key` 0.7
  once it is stable
