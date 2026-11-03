# Security policy

warden holds SSH and API credentials, so reports are welcome and taken
seriously. It has one maintainer, who is also the security contact. This policy
promises only what one person can keep.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub security advisories:
<https://github.com/pecheriere/warden/security/advisories/new>. Only the
maintainer and the people added to the report can read it. You need a GitHub
account.

Please do not open a public issue or pull request for a suspected
vulnerability. Include the version, the setup (Docker, relay, API proxy) and
steps to reproduce. Do not include real secrets or private details of your
systems.

The [threat model](docs/threat-model.md) says what warden protects and which
risks it accepts. If you are unsure whether something counts, report it anyway.

## Response time

You get a first response **within 14 days** of your report, acknowledging it and
saying what happens next.

If you have heard nothing after 14 days, add a comment to the report. If that
gets no answer either, open a public issue asking the maintainer to look at it,
without any details of the vulnerability.

There is no fixed deadline for the fix, because it depends on the problem. The
maintainer tells you the plan once the report is assessed, and tells you if it
changes.

## How reports are handled

1. **Triage.** The maintainer reproduces the problem in the private report,
   decides whether it is a vulnerability and how severe it is, and tells you the
   outcome. If it is not a vulnerability, the report says why.
2. **Fix.** The fix is prepared privately where possible, and you are welcome to
   review it. It ships in a new release.
3. **Coordinated disclosure.** The disclosure date is agreed with you. Nothing is
   disclosed before the fix is available, unless the vulnerability is already
   being exploited or is already public. In that case users may first get an
   advisory that describes how to protect themselves.
4. **Publication.** An advisory is published when the release is out, and the
   release's changelog entry lists the fix.

## Credit

Reporters are credited by name or GitHub account in the advisory and in the
changelog entry, unless they ask not to be. Say in the report if you would rather
stay anonymous, or which name to use.

## Verifying what you download

[Verifying a release](docs/verifying-releases.md) says how to check the
signatures and attestations on a release, and which older releases lack them.

## Where vulnerabilities are published

- **GitHub security advisories:**
  <https://github.com/pecheriere/warden/security/advisories>. Vulnerabilities
  found in warden through this process are published here.
- **The changelog:** every security fix in a release is listed in that release's
  `### Security` section of [CHANGELOG.md](CHANGELOG.md), which is also the
  release's notes on GitHub. This includes vulnerabilities in dependencies that
  affect warden. Entries in releases before 0.8.1 are marked `Security:` instead.

Not every past fix has an advisory, so read the changelog as well.

## Supported versions

Only the latest release receives security fixes. Fixes are not backported, and
an older version stays vulnerable under its own tag. warden is before 1.0, so
the release with a fix can also contain breaking changes.

## Getting a fix

No warden install updates itself. To be told about a new release, watch the
repository's releases on GitHub. Then upgrade every part that the release's
changelog entry names:

- **Docker image.** Each release has its own image tag, such as `0.9.0`, and
  warden publishes no moving tag such as `latest`. A `compose.yaml` that pins a
  version and digest keeps running the old image until you **change that pin to
  the new version and digest**: pulling or restarting is not enough. Change it
  everywhere you use the image, then follow the
  [upgrade steps](docs/deployment.md#upgrades). Migrations are one-way, so back
  up `/data` first.
- **systemd service.** Build the new release tag from source and install it, as
  described in [docs/deployment-systemd.md](docs/deployment-systemd.md), with the
  same backup first.
- **`warden` CLI on agent machines.** Install it again at the new release tag, or
  use the release's binaries where it has them: see
  [docs/agent-usage.md](docs/agent-usage.md). `cargo install` needs `--tag`
  changed to the new version.
