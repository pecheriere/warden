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
(`Co-Authored-By`, session links, "Generated with"). A `Signed-off-by` line
is not one: see [Sign-off](#sign-off-dco).

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
| `fuzz` | `cargo-fuzz` targets for code that parses untrusted input; its own workspace, on its own nightly |
| `scripts/` | CI guards, UI check tools and release signing (each script documents its usage) |

## Before you push

CI (`.github/workflows/ci.yml`, `dco.yml` and `zizmor.yml`) runs exactly
these, and every one must pass:

```sh
python3 -I .github/scripts/dco.py pull-request --base origin/main --head HEAD
cargo fmt --check
scripts/check-no-reqwest-decompression.sh
scripts/check-demo-not-shipped.sh
scripts/test-sign-release.sh
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo deny check
cargo deny --manifest-path fuzz/Cargo.toml check
cargo metadata --locked --manifest-path fuzz/Cargo.toml --format-version 1 > /dev/null
python3 -I .github/scripts/crate_age.py --base main
uvx zizmor@1.31.1 .   # when a workflow or the Dependabot config changes
```

- CI's `coverage` job also measures test coverage with `cargo llvm-cov`,
  shown in the run's summary with the lcov file as an artifact. It is not a
  required check and no threshold fails it yet (#97).
- The toolchain is pinned in `rust-toolchain.toml`. Clippy `all` and
  `pedantic` are denied workspace-wide and `unsafe_code` is forbidden.
- On Linux, the relay's password-target tests need
  `WARDEN_TEST_LOGIN_PASSWORD` (the current user's login password) and an
  OpenSSH server binary at `/usr/sbin/sshd`; they fail rather than skip
  without them. They do not exist on macOS.
- On Linux, one local-backend test needs a real bind mount of a single file,
  which takes root: `WARDEN_TEST_BIND_MOUNT_SOURCE` names a file you own, and
  `WARDEN_TEST_BIND_MOUNTED_FILE` names where it is mounted (`mount --bind`). It
  fails rather than skips without them. It does not exist on macOS.
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

## Fuzzing

`fuzz/` holds `cargo-fuzz` targets for the input an attacker reaches most
easily. It is its own workspace, so workspace builds and the image never
compile it, with the nightly pinned in `fuzz/rust-toolchain.toml` and its own
`fuzz/Cargo.lock`. The lints match the workspace's, `unsafe_code = "forbid"`
included.

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
scripts/fuzz.sh 60 redaction   # one target for 60 seconds
scripts/fuzz.sh 60             # each target for 60 seconds
```

`.github/workflows/fuzz.yml` runs each target for 3 minutes every night, and
on pull requests that change the fuzzing setup. It also runs `cargo fmt` and
clippy on the crate from `fuzz/`, which `--workspace` does not reach.

- A change to a requirement in `Cargo.toml` or to the workspace version
  needs `fuzz/Cargo.lock` updated too: `cargo update --workspace` in `fuzz/`.
  CI refuses a stale one. Keep the versions the root `Cargo.lock` has.
- A crash is treated as a possible vulnerability, because this repository is
  public: follow `SECURITY.md`. Do not put the input or its details in an
  issue, pull request or commit message until a fix is released. CI withholds
  the fuzzer's output for the same reason; it logs the target and seed.
- Fix it, then add the input to `fuzz/seeds/<target>`, the committed
  corpus: every run replays it. Add the input in or after the release of the
  fix. A local run keeps what it discovers in the ignored `fuzz/corpus`.
- A new target needs a `[[bin]]` entry in `fuzz/Cargo.toml` and a seed.
  Check a property where one exists, not only that nothing panics.
- Private steps reach the targets through `warden_broker::signed::fuzzing`,
  behind the `fuzzing` feature, which nothing that ships may enable.

## Changes and pull requests

- One branch and one pull request per issue. `main` is protected: squash
  merges only, and commits must be signed.
- Fill in `.github/pull_request_template.md`.
- Every user-visible change gets a line under `## [Unreleased]` in
  `CHANGELOG.md` ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/)).
- When behaviour changes, update the docs in the same pull request: the
  README, `docs/configuration.md`, `docs/deployment.md`,
  `docs/agent-usage.md`, `docs/agent-protocol.md`, `docs/building.md`,
  `docs/upgrading.md`, `docs/interfaces.md`, `docs/threat-model.md`,
  `docs/assurance-case.md` and `site/index.html` must stay consistent with the
  code. A change that moves a risk also updates `docs/security-assessment.md`
  and its date.
- **Approval UI pages** follow `docs/design-language.md`. Render and
  screenshot them with `scripts/screenshot-pages.sh <out-dir>` at the sizes
  the PR template lists, light and dark, and attach the screenshots.
  `scripts/check-grants-live.py <out-dir>` checks the grants page's live
  refresh.

## Sign-off (DCO)

Every commit is signed off with `git commit -s`.
[`CONTRIBUTING.md`](CONTRIBUTING.md#sign-off-dco) says what that means and what the
`dco` check accepts.

**Agents.** A sign-off is a person's statement, and an agent cannot make it. An
agent adds one on behalf of the maintainer, only:

- with `git commit -s` under the maintainer's own git identity, as already
  configured: never by changing `user.name` or `user.email`, and never by typing
  the line or an address by hand;
- for work that maintainer asked for, who then answers for it as for any change
  they sign off.

If no person with that standing asked for the work, leave the commit without a
sign-off and say so: the check fails, and a person decides. The line names the
maintainer and never the agent, so it fits the rule against AI attribution, and
it does not replace that rule: add no other trailer for the agent.

## Releases

Semantic versioning, one version for the whole workspace.

1. A release pull request bumps `version` in `Cargo.toml` (the workspace
   package and the internal crates' dependency entries) and in the internal
   crates' entries in `fuzz/Cargo.toml`, updates `Cargo.lock` and
   `fuzz/Cargo.lock`, moves `## [Unreleased]` to a dated `## [x.y.z]`
   section in `CHANGELOG.md` (noting any new migration), and updates every
   mention of the previous version in the README and `docs/` (install
   commands, image tags, attestation examples). The notes saying that
   binaries start after v0.8.1 stay as they are. A minor release also reviews
   `docs/security-assessment.md` and updates its date.
2. After it merges, the maintainer, or an agent the maintainer has
   confirmed, creates a signed annotated `vx.y.z` tag (`git tag -s`) on that
   commit of `main`. `.github/workflows/release.yml` refuses a tag that
   does not match the version, reruns CI, builds the multi-arch image,
   pushes it to `ghcr.io/pecheriere/warden`, builds the CLI archives, attests
   both, and leaves a draft release for the tag, with the archives attached
   and the changelog section as its notes.
3. When the workflow has finished, the maintainer signs the manifest with
   `scripts/sign-release.sh vx.y.z`. It checks the tag's signature and the
   attestations of the draft's archives and of the image, then uploads
   `warden-x.y.z-SHA256SUMS` and its `.sig` to the draft. The key must be
   listed in `docs/release-signers` and is never on GitHub, so the workflow
   cannot do this step. Nothing enforces it, so do not skip it: a release
   published without a manifest can never gain one. Rerunning the workflow
   removes the manifest, so sign again after a rerun.
4. The maintainer, or an agent the maintainer has confirmed, checks the
   draft and publishes it: `gh release edit vx.y.z --draft=false`. Do not use
   `gh release create` here: releases are immutable, so a release published
   without the files can never gain them, including the signed manifest.

An agent creates a tag or a release only after asking the maintainer and
getting a yes for that specific version and commit. A yes for one release
does not carry over to the next, and being able to run the command is not
permission to run it.
