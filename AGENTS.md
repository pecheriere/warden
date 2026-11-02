# AGENTS.md

Instructions for coding agents (and humans) working on warden. The
README explains what warden is; `docs/design.md` and
`docs/threat-model.md` explain how and why it is built the way it is. Read
the threat model before touching anything that handles secrets, grants or
approval.

## Ground rules

- **Do it right the first time.** No shortcuts, no "fix it later", no
  `TODO` comments: do the work now or open an issue.
- **Security is not optional.** Validation, error handling and fail-closed
  behaviour ship with the change, never after it. When state is unreadable
  or ambiguous, refuse and audit; never allow.
- **Secrets never leak.** Never log, print, format into errors or store a
  secret in clear. Keep secrets in `secrecy`/`zeroize` types, and redact
  anything an upstream might echo back (see `proxy/redact.rs`).
- **No silenced lints.** No `#[allow(...)]` or `#[expect(...)]` without a
  comment saying why it is right. Fix the code instead where you can.
- **No dead code.** If something is unused, delete it.

## This is a public repository

Never commit private infrastructure details: real hostnames, tailnet
names, IP addresses, user names, email addresses, device or gear names,
1Password account or vault names. Examples and tests use generic names
only, such as `build-agent`, `home-api`, `switch-01`, `warden.example.ts.net`
and documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`).

Commit messages and PR descriptions carry no AI attribution lines
(`Co-Authored-By`, session links, "Generated with").

## Layout

| Path | What |
|---|---|
| `crates/proto` | `warden-broker-proto`: wire types shared by broker and CLI, request signing |
| `crates/broker` | `warden-broker`: the server (`api`, `approval` UI, `policy` from 1Password, `ssh_ca`, `relay`, `proxy`, `notify`, `audit`, `store`) |
| `crates/broker/migrations` | SQLite migrations, applied at startup; never edit a released one, add a new file |
| `crates/broker/src/testkit` | test helpers (throwaway `sshd`, fixtures), behind the `testkit` feature |
| `crates/cli` | `warden-broker-cli`, the `warden` command agents run |
| `crates/demo` | `warden-demo`: the throwaway local demo, never shipped (`docs/demo.md`) |
| `docs/` | user and design documentation |
| `site/` | the landing page on GitHub Pages: static HTML and CSS, no scripts, no external resources. It names no version and leaves setup commands to the README, so a release does not touch it |
| `deploy/systemd` | the systemd unit that `docs/deployment-systemd.md` installs |
| `scripts/` | CI guards and UI check tools (each script documents its usage) |

## Before you push

CI (`.github/workflows/ci.yml` and `zizmor.yml`) runs exactly these, and
every one must pass:

```sh
cargo fmt --check
scripts/check-no-reqwest-decompression.sh
scripts/check-demo-not-shipped.sh
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo deny check
python3 -I .github/scripts/crate_age.py --base main
uvx zizmor@1.31.1 .   # when a workflow or the Dependabot config changes
```

- The toolchain is pinned in `rust-toolchain.toml`. Clippy `all` and
  `pedantic` are denied workspace-wide and `unsafe_code` is forbidden.
- On Linux, the relay's password-target tests need
  `WARDEN_TEST_LOGIN_PASSWORD` (the current user's login password) and an
  OpenSSH server binary at `/usr/sbin/sshd`; they fail rather than skip
  without them. They do not exist on macOS.
- Tests must not depend on timing. Wait on a condition, not a sleep.
- Dependencies: add them to `[workspace.dependencies]` with a comment when
  the reason is not obvious, keep default features off where practical,
  and make sure `cargo deny check` passes. reqwest must never gain a
  decompression feature (a CI script enforces it). A crate version must
  have been published at least 7 days before it lands in `Cargo.lock`,
  except the oldest release that fixes a security advisory (RUSTSEC or GHSA), listed in
  `.github/crate-age-allow.toml` (see "Dependency age" in the README).
- GitHub Actions are pinned to the full commit SHA of a release at least
  7 days old.

## Changes and pull requests

- One branch and one pull request per issue. `main` is protected: squash
  merges only, and commits must be signed.
- Fill in `.github/pull_request_template.md`.
- Every user-visible change gets a line under `## [Unreleased]` in
  `CHANGELOG.md` ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/)).
- When behaviour changes, update the docs in the same pull request: the
  README, `docs/configuration.md`, `docs/deployment.md`,
  `docs/agent-usage.md`, `docs/agent-protocol.md`, `docs/building.md`,
  `docs/upgrading.md`, `docs/threat-model.md` and `site/index.html` must stay
  consistent with the code.
- **Approval UI pages** follow `docs/design-language.md`. Render and
  screenshot them with `scripts/screenshot-pages.sh <out-dir>` at the sizes
  the PR template lists, light and dark, and attach the screenshots.
  `scripts/check-grants-live.py <out-dir>` checks the grants page's live
  refresh.

## Releases

Semantic versioning, one version for the whole workspace.

1. A release pull request bumps `version` in `Cargo.toml` (the workspace
   package and the internal crates' dependency entries), updates
   `Cargo.lock`, moves `## [Unreleased]` to a dated `## [x.y.z]`
   section in `CHANGELOG.md` (noting any new migration), and updates every
   mention of the previous version in the README and `docs/` (install
   commands, image tags, attestation examples). The notes saying that
   binaries start after v0.8.1 stay as they are.
2. After it merges, the maintainer, or an agent the maintainer has
   confirmed, creates a signed annotated `vx.y.z` tag (`git tag -s`) on that
   commit of `main`. `.github/workflows/release.yml` refuses a tag that
   does not match the version, reruns CI, builds the multi-arch image,
   pushes it to `ghcr.io/pecheriere/warden`, builds the CLI archives, attests
   both, and leaves a draft release for the tag, with the archives attached
   and the changelog section as its notes.
3. When the workflow has finished, the maintainer, or an agent the
   maintainer has confirmed, checks the draft and publishes it:
   `gh release edit vx.y.z --draft=false`. Do not use `gh release create`
   here: releases are immutable, so a release published without the files
   can never gain them.

An agent creates a tag or a release only after asking the maintainer and
getting a yes for that specific version and commit. A yes for one release
does not carry over to the next, and being able to run the command is not
permission to run it.
