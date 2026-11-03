# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Upgrading

- New migration `0008_commit_signing_renewal`. An older `warden-server audit verify`
  refuses a log with the new entries.
- A `request_created` audit entry can have a new `session` field. An older
  `warden-server audit verify` refuses a log with such an entry, and an older
  `warden-server` does not start on one, because it verifies the log when it opens
  it. So once an agent has sent a label, rolling back also means restoring the
  audit log from the backup taken before the upgrade.
- Upgrade the broker before relying on labels and links: an older broker ignores
  them, and `warden request` warns that the owner does not see them.
- If you build the server from source: the `vendored-openssl` feature is gone. Run
  `scripts/build-openssl.sh` and set `OPENSSL_DIR`, `OPENSSL_STATIC` and
  `WARDEN_OPENSSL_PINNED`, as
  [docs/building.md](docs/building.md) shows, or link a system OpenSSL.

### Added

- `GET /v1/requests` lists an agent's own pending requests, and `warden status` shows
  them, so an agent that lost the output of `warden request` can find them again.
  Listing notifies nobody and counts against no limit, and the approval link is never
  included.
- `warden request collect <grant>` starts using an `api` grant the owner approved after
  the `warden request` that asked for it was gone. `warden status` marks such grants. An
  SSH grant cannot be collected, as its key was lost with that run: the docs say what to
  do instead. A commit signing grant needs no collecting.
- Releases attach the `warden` CLI as `.deb` and `.rpm` packages for amd64 and arm64,
  built from the same binaries, attested and listed in the signed manifest. See
  [docs/agent-usage.md](docs/agent-usage.md). There is no package repository, so nothing
  updates them automatically.
- Commit signing through the broker, so that the signing key is not on the agent's
  machine, every signature is recorded and one agent can be cut off. The broker holds
  an `ssh-ed25519` key (a 1Password item tagged `warden:commit-signing`, or
  `[commit_signing]` in a local policy) and signs only the `git` namespace, only what
  parses strictly as a commit, and only under the agent's own grant. `warden request
  signing` asks for that grant, `warden setup git` makes `warden` git's signing program,
  and `git commit` then works with no prompt. A signature means warden signed the commit
  for that agent, not that anyone reviewed the change. Tag signing is not part of this:
  a tag object is refused.
- A commit signing grant lasts 30 days by default, up to
  `WARDEN_COMMIT_SIGNING_MAX_WINDOW`. It is the only grant allowed past 4 hours, and
  [the threat model](docs/threat-model.md#commit-signing) says why. warden tells the
  owner a few days before one ends, and a new Renew button on the grants page takes one
  passkey approval. Revoking stops new signatures at once. A grant can make 5000
  signatures per UTC day by default (`WARDEN_COMMIT_SIGNING_MAX_PER_DAY`), so that a
  looping agent cannot fill the audit log's disk, and warden tries to notify the owner if it gets there.
- With a commit signing setup, a commit fails, saying why and how to ask for a grant,
  when the agent has no active grant or the broker cannot be reached. Nothing makes the
  commit unsigned instead.
- `warden doctor` and `warden-server doctor` check the commit signing setup, and the SSH CA
  key cannot also be the commit signing key.
- Releases attach `warden-server-<version>-<platform>.tar.gz` for Linux amd64 and arm64:
  a static, attested server binary for
  [running without Docker](docs/deployment-systemd.md). The signed manifest lists it, and
  `scripts/sign-release.sh` requires it on a draft. Docker stays the recommended setup.
- `warden request --session <label>`, or `WARDEN_SESSION`, says which session of an
  agent is asking. The approval page, Pending, Active grants, History, the
  notification and the audit log show it as what the agent stated, not as verified.
  It is part of the fingerprint.
- `warden request --link <url>` adds a page about the work for the owner to open:
  on the same pages and in the fingerprint, in no notification or audit entry. Off by
  default; `WARDEN_REQUEST_LINK_HOSTS` lists the hosts allowed, and a request linking
  to any other host is refused.
- `docs/agent-instructions.md` tells an agent to name its session, and says that this
  is a claim.
- The Active grants page shows how long each relay session has been idle (since
  bytes last moved either way), and when a certificate grant's certificate was
  issued and when it expires. warden still cannot see logins made with a
  certificate, and the page says it does not show whether one was used.
- Releases attach `warden-demo-<version>-<platform>.tar.gz` for macOS arm64, Linux
  amd64 and Linux arm64: the local demo as its own attested binary, so trying warden
  needs no Rust ([docs/demo.md](docs/demo.md)). It is labelled as a demo, is not secure
  for real use, and stays out of the server image. The signed manifest lists it.

### Changed

- The image, the server binaries and the demo binaries link OpenSSL 3.5.9, the current
  release of the 3.5 long-term support line, in place of 3.6.3, as support for 3.6 has
  ended. It is built from a release tarball pinned by hash, and stored passkeys are
  unaffected. A check now fails CI when the pinned line's support ends. A nightly run,
  which opens an issue, and the release workflow also fail 90 days before that or when a
  newer release of the line is out.
- Fingerprints are easier to compare: the approval pages and `warden request` now write
  one as five English words, such as `oceanic-receipt-varied-amuser-aftershave`, with the hex
  form beside them. They are the same 48 bits, so nothing about the API, the database or
  the audit log changes, and the broker and the CLI can be upgraded in either order. A
  script that reads the fingerprint from `warden request`'s stderr needs checking, as the
  hex is now in brackets after the words.
- `warden-demo` names the `warden` beside it in its printed steps, or the one on the
  `PATH`, rather than `target/debug/warden`.
- `scripts/package-cli.sh` is now `scripts/package-binary.sh`, and takes the product
  as its first argument.
- `scripts/sign-release.sh` requires the demo archives on a draft, from the next
  release on.

### Fixed

- `warden-server --version` names `warden-server`, not `warden-broker`.
- Approval UI accessibility: the selected grant window now has a border with at
  least 3:1 contrast against its track in light and dark, the two navigation
  landmarks have different labels, each card on the pending screen is a heading a
  screen reader can move to, and the text of an ended pending card keeps 4.5:1.

## [0.9.0] - 2026-11-02

### Upgrading

Read [docs/upgrading.md](https://github.com/pecheriere/warden/blob/v0.9.0/docs/upgrading.md)
and back up warden's data first. It also says how to run `warden-server doctor` on the
new version before starting it, and how to read the result.

- warden refuses to start if others can write to its data directory and it cannot
  correct that, if a file's permissions cannot be corrected, or if a symbolic link
  stands in place of the database, the audit log or the audience.
- warden refuses to start on plain `http` to a host that is not clearly local or
  private, unless the variable is listed in `WARDEN_ALLOW_PLAIN_HTTP`. This includes
  `.ts.net` names.
- New migrations `0006_requests_agent_index` and `0007_unwritten_audit`. An older
  `warden-server audit verify` refuses a log with the new entries.
- `warden` exits 64 for wrong arguments, 5 from `warden http` for an expired grant
  and 8 from it when a call's grant state cannot be read. Scripts that read these
  need checking.
- Opening a request from the new Pending page stops its notification link working.
- Each agent is limited to 5 pending requests and 10 new ones per 10 minutes by
  default, cancelled ones included. A busier agent gets `429`: raise the limits if
  yours needs more.
- A `Warden-Signature` must be the exact SSHSIG encoding, as `ssh-keygen` and
  `ssh-agent` produce it. A client that builds its own needs checking.
- A proxied call with more than 100 headers gets a 400.
- A tool reading warden's data as another non-root user, such as a backup job using
  group permissions, loses access.
- `warden-server agent revoke` can exit with an error after revoking, when its audit
  entries could not reach the log. The agent is revoked: read the message.

### Security

- warden keeps its files private to its user. The database and its `-wal` and
  `-shm` files, the audit log and the audience are created 0600 and corrected at
  start, and a symbolic link in place of one is refused. A file that cannot be
  corrected stops warden with a message naming it. The data directory is set to
  0700 when warden's non-root user owns it and nothing but warden's own files is
  in it. Otherwise warden leaves it alone: it logs a warning, or refuses to start
  if others can write to it. `warden-server doctor` fails on any of these with
  group or other permissions. See
  [docs/upgrading.md](docs/upgrading.md#private-files).
- The image's `/data` directory has mode 0700 and belongs to warden's user, and CI
  checks both in the built image.
- The approval listener refuses every request that came through Tailscale Funnel
  with `401`, as the agent API does, instead of relying on such a request carrying
  no owner login.
- warden refuses to start when `WARDEN_OP_CONNECT_URL` or a notifier URL is plain
  `http` to a host that is not clearly local or private, or uses another scheme.
  Private and tailnet addresses, names without a dot, and names such as
  `homeassistant.local` keep working unchanged. `.ts.net` names are not among them.
  List a variable in the new `WARDEN_ALLOW_PLAIN_HTTP` to keep plain `http` to
  another host; warden then warns
  at each start. A new `plain-http` check in `warden-server doctor` shows what a
  setup uses. See [docs/upgrading.md](docs/upgrading.md#plain-http-urls).
- The `warden` CLI no longer links `rsa` or `crypto-bigint` 0.5, and the broker
  no longer links `crypto-bigint` 0.5, which clears RUSTSEC-2026-0387 from the
  tree. The CLI talks to `ssh-agent` with a small client of its own instead of
  `ssh-agent-lib`, and the broker verifies ECDSA P-256 request signatures with
  `p256` 0.14 instead of through `ssh-key` 0.6. RUSTSEC-2023-0071 stays exempted
  for the `rsa` pre-release that russh pins, which only verifies targets' RSA
  host keys. Nothing changes for agents.
- Revoking a grant or an agent now stops proxied API calls already in flight, also
  while a response is still arriving: the connection to the upstream closes and
  the agent gets the same 409 as before, with nothing of the response. The end of
  the grant's window does the same, a revocation by another process is found within
  seconds, and a call whose grant state cannot be read for 10 s ends with a 503. A
  revocation waits for none of this. The upstream may still have acted on a call
  it received, so the outcome is unknown: `warden http` says to find out before
  repeating such a call, and exits 8 for the 503. The `proxy_call` audit entry of a
  stopped call gains `aborted`, with the reason, and has the status and bytes received
  so far, and it waits in the database if the log cannot take it. As with any new audit
  field, a `warden-server` older than this release refuses a log that holds one.
- A certificate is no longer given out if its `cert_issued` audit entry cannot
  be written. The entry is now written with the approval, before anything is
  committed: if it fails, nothing is approved, the owner is told so and can try
  again, and the request stays pending.
- Making a passkey enrollment code is audited as `enrollment_code_created`, and
  no code is made if that entry cannot be written. The entry holds neither the
  code nor its hash. Audit logs with these entries cannot be read by
  `warden-server audit verify` from an older release.
- A failed agent creation or key change that had already written an audit entry
  now records that it did not take effect.
- Ending access no longer depends on the audit log: stopping access matters more
  than recording it. Revoking, denying, cancelling and expiring take effect first, and
  their entries wait in the database until they reach the log. Until then the grants
  page warns, `warden-server doctor` fails and `warden-server audit verify` warns; a
  revocation also notifies the owner, and `warden-server agent revoke` prints the
  entries and exits with an error after revoking. New migration
  `0007_unwritten_audit`.
- The log is no longer written during a database write, so writing it cannot hold up
  a revocation or any other change.
- A proxied call or a relay session that waited to record its start now checks its
  grant again, and does not go out if the grant ended meanwhile.

### Added

- A **Pending** page in the approval UI lists every request waiting for a decision,
  with the agent, access, goal, fingerprint and expiry, so a notification that was
  dismissed or missed is no longer a dead end. It keeps itself current while open, as
  Active grants does. Deny works from the list. **Approve…**
  gives the request a new approval link and opens the usual approval page, where the
  passkey is still required; the link in the notification stops working, and a page
  still open on it ends in the usual "no longer pending" outcome. This is audited as
  the new `approval_link_replaced` entry, which holds no token. A `warden-server`
  older than this release refuses a log that holds one. Passkey prompts in progress
  are now limited per request, to its 4 newest, with 8 for enrollment apart and 1024
  approvals in all, in place of the shared 64. See
  [docs/notifications.md](docs/notifications.md#if-you-miss-a-notification).
- `WARDEN_SECRET_BACKEND=local`: targets, API secrets and the SSH CA key from a
  policy file and private secret files on warden's host, with no 1Password account
  or Connect ([docs/local-backend.md](docs/local-backend.md)). It is weaker: a
  compromised host gets every secret, and there is no read-only token boundary.
  1Password stays the recommended backend and the default when the setting is
  unset, so existing deployments do not change. Files with loose permissions, links
  or invalid content refuse the server's start or the request, and refusals are
  audited. A policy file ends with `[end_of_policy]` and a digest of its content,
  so that a read cut short or mixing two versions is refused; the new
  `warden-server seal-policy` writes the digest and replaces the file atomically,
  and will not seal a file in place whose digest does not match until you have seen
  what it allows and pass `--accept-unverified`. A
  policy or secret file mounted on its own is refused, because it would keep showing
  the old file after a change. `warden-server doctor` checks all of it. warden does
  not generate the CA key.
- Contributions now need a Developer Certificate of Origin sign-off
  (`git commit -s`). A new `dco` check reads every commit of a pull request, and
  `CONTRIBUTING.md` explains the rule, including merge commits and Dependabot.
- CI measures test coverage with `cargo llvm-cov`, including the Linux-only
  relay tests, and reports it in each run's summary. No threshold fails the
  build yet.
- Project documents: `CONTRIBUTING.md` (where to discuss, reporting bugs, the
  test policy), `GOVERNANCE.md`, `CODE_OF_CONDUCT.md`, `docs/roadmap.md`,
  `docs/building.md` and `docs/upgrading.md`.
- Releases get a manifest of the archives' and the image's hashes, signed by the
  maintainer off GitHub (`warden-<version>-SHA256SUMS` and its `.sig`), and
  [docs/verifying-releases.md](docs/verifying-releases.md) says how to verify
  each kind of asset and the signer. It starts with this release: v0.8.1 and
  earlier have no manifest, and tags before v0.8.0 are not signed.
- Each agent is limited in how many requests it can make, so that it cannot
  flood the owner: by default 5 pending at once and 10 new ones per 10 minutes,
  cancelled ones included. Over a limit it gets `429` with `Retry-After`, the
  refusal is audited as `request_limited`, and the owner gets one notification
  per agent per hour at most. Set them with
  `WARDEN_REQUEST_MAX_PENDING_PER_AGENT`, `WARDEN_REQUEST_MAX_NEW_PER_AGENT` and
  `WARDEN_REQUEST_LIMIT_WINDOW_SECS`. New migration `0006_requests_agent_index`.
  Audit logs with these entries cannot be read by `warden-server audit verify`
  from an older release.
- Release builds are meant to be repeatable from this release:
  [docs/reproducing-builds.md](docs/reproducing-builds.md) says how to rebuild one
  and what must match, and a workflow builds each output twice and compares them.
  The CLI no longer holds the build machine's paths, the image's times come from
  the commit, BuildKit is pinned, and `rust-toolchain.toml` names an exact Rust
  version. `scripts/package-cli.sh` now needs `python3`.
- Fuzz targets for signed agent requests, agent-supplied keys and names, the
  proxy rules and redaction, run by a scheduled CI job (`fuzz/`, see "Fuzzing"
  in `AGENTS.md`). The fuzz crate is not part of the workspace or the image.
- `warden-demo`: try the approval flow on one machine with no setup
  ([docs/demo.md](docs/demo.md)). A separate, unpublished binary that is not
  part of `warden-server` or the image; a CI guard keeps it that way. It is not
  secure for real use, and it needs Rust to build.
- A hardened systemd unit (`deploy/systemd/warden.service`) and a guide to run
  warden without Docker (`docs/deployment-systemd.md`), which says what holds,
  what is replaced and what is lost compared with Docker. Docker stays the
  recommended setup, and the unit has not yet been tested on a clean host.
- `WARDEN_OP_CONNECT_TOKEN_FILE`,
  `WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL_FILE`, `WARDEN_NOTIFY_NTFY_URL_FILE`
  and `WARDEN_NOTIFY_NTFY_TOKEN_FILE` read these secrets from a file, so that
  they can come from systemd credentials and stay out of the process
  environment.
- `warden-server doctor` and `warden doctor` check a setup and report each
  check as pass, fail or could-not-check, with what to do. They exit 1 when a
  check failed and otherwise 0, and the summary lists what could not be checked
  and how to check it by hand. With `--strict` those items make them exit 7.
  They are read-only: only `warden-server doctor
  --send-test-notification` sends anything, one message through each channel
  to the owner's phone.
- Releases attach `warden` CLI binaries for macOS arm64, Linux amd64 and
  Linux arm64, so the CLI installs without Rust. The Linux binaries are
  fully static. Each `.tar.gz` has a build-provenance attestation to check
  with `gh attestation verify`.
- `warden-server agent add` prints what to run on the agent's machine, on
  stderr: the exact `warden login` command, with the broker's audience for a
  key-signed agent. `--server <url>` gives it the agent API's URL. A bearer key
  is still printed once, alone on stdout, and never in these instructions.
- `docs/agent-instructions.md`, a block to paste into an agent's `AGENTS.md` or
  `CLAUDE.md`, and `docs/agent-examples.md`, with an SSH deployment and an API
  call end to end.
- A landing page in `site/`, published to GitHub Pages by
  `.github/workflows/pages.yml`. It is static, with no scripts or external
  resources.
- `docs/assurance-case.md` (trust boundaries, design principles, how common
  weaknesses are countered, cryptography, how to replace each credential, including
  a procedure for the SSH CA key), `docs/security-assessment.md` (a dated ranking
  of the most likely and most damaging problems; the project's own, not an
  independent review) and `docs/interfaces.md` (every external interface, with the
  approval UI's routes and the SSH relay).

### Changed

- A proxied call may carry at most 100 headers; more is a 400.
- `warden` now exits 64, not 2, for wrong arguments, so that a usage error
  cannot be taken for a denied request, which stays exit 2. A script that reads
  exit 2 as a usage error needs updating. `--help` and `--version` still exit 0,
  and `warden-server` keeps exit 2 for wrong arguments.
- A `Warden-Signature` must be the exact SSHSIG encoding, as `ssh-keygen` and
  `ssh-agent` produce it (`docs/agent-protocol.md`).
- README: says who warden is for and how stable it is, names Tailscale, Docker
  and 1Password as the recommended setup and what each part protects, and adds
  a table of the setups supported today with their security cost. It also lists
  the notification channel as a requirement.
- `warden request` and `warden ssh`/`warden http` say what to do next when a
  request is denied, expires or is revoked, or there is no active grant.
- `warden http` now exits 5, not 1, when the broker says the grant has expired,
  and removes its local record.
- `SECURITY.md`: a first response within 14 days (it said "a few days"), how
  reports are handled, credit for reporters, where vulnerabilities are
  published, and how to get a fix, including that a pinned Docker image does not
  change until you change the pin.
- When `warden request` stops on a pending request it is not waiting on, it prints
  that request's ID, how to withdraw it (`warden request cancel <id>`) and that it
  expires within 10 minutes of being made, not only its fingerprint.

## [0.8.1] - 2026-11-01

The `v0.8.0` tag was created by mistake, before the version bump, and was
never published. This is the first release with these changes.

### Added

- `AGENTS.md`: contributor rules for coding agents and humans (the CI
  checks to run, public-repo hygiene, changelog, docs and UI screenshot
  expectations, the release steps). `CLAUDE.md` imports it.
- `SECURITY.md`: report vulnerabilities through private GitHub security
  advisories.
- CI: a dependency age check refuses crate versions published less than 7
  days before a pull request or release adds them; zizmor audits the
  workflows on every pull request; `cargo deny check advisories` runs
  nightly; OpenSSF Scorecard runs weekly; Dependabot proposes cargo,
  action and base image updates once they are 7 days old.
- README: a "Why warden" section. Password managers keep secrets from
  agents, but only while someone approves each use on an unlocked computer.
  warden moves that approval to the phone, per goal and time window.

### Changed

- The minimum supported Rust version is now 1.99, for building both the broker
  and the `warden` CLI. The builder image and CI moved to Rust 1.99 too.
- Docs overhaul. The README is now a short introduction with a quick start.
  New guides: `docs/deployment.md`, `docs/configuration.md` and
  `docs/ssh-targets.md`.
  - `docs/deployment.md` is the recommended deployment:
    - Tailscale Services, with the policy grants and tests, Funnel kept
      off, and the approval UI reachable from the phone only;
    - who on the host can reach the listeners, and how to contain it;
    - Docker Engine 28 and Compose 2.33 as a security requirement;
    - a dedicated 1Password vault with a read-only Connect token;
    - Connect run non-root, with an explicit bus, on its own network;
    - egress rules for warden and Connect, with checks;
    - Home Assistant over the tailnet without `local_only`;
    - backups, and attested, pinned upgrades;
    - a sidecar layout for SSH relay targets (not yet tested end to end).
  - `docs/configuration.md` lists every server and CLI setting and command.
  - `docs/ssh-targets.md` covers one certificate-only user per agent,
    checking sshd's effective settings, login alerts by CA fingerprint,
    and relay targets.
  - The threat model says what warden does not protect: the host is the
    root of trust; grants shared by one agent's sessions (#49); revoke and
    calls in flight (#44).
  - Corrected: the certificate key id, the Ctrl-C cancel wait (5 s), the
    published image, what losing the database loses, warden's egress
    (relay targets) and the Linux bearer-key setup.

### Security

- russh is updated to 0.65.0. On the relay, this fixes a stack overflow an
  unauthenticated client could trigger with a crafted OpenSSH certificate
  (GHSA-3hm4-p7h4-rvwp), unbounded memory use from a target's repeated
  `EXT_INFO` messages (GHSA-4p9f-7p9m-5vfg) and channel writes that a peer
  could stall by declaring a maximum packet size of zero
  (GHSA-fw5c-8223-6h42). The release's SSH agent fixes do not affect warden,
  which does not use russh's agent server.

## [0.7.0] - 2026-10-29

### Added

- The Active grants page shows what each grant is doing right now. A relay
  grant lists its open sessions (start time, bytes to and from the target), an
  API grant its proxied calls in flight (method, path, start time), each under
  a live indicator ("2 sessions open", "1 call in flight"); a certificate
  grant says that its logins are not visible to warden. The page renders this
  server-side, so it works without script, and `warden.js` refreshes it every
  5 s from the new owner-only `GET /grants/live` while the page is visible,
  never with two requests at once, and stops when the broker no longer
  recognizes the viewer as the owner (401/403). A grant that is revoked or
  expires drops off the page, and one approved meanwhile appears (the page
  reloads once). Revoking an API grant stops new calls, but a call already in
  flight runs to completion (at most the proxy timeout) and is no longer
  listed. Times show in the viewer's local time. A path is shown as the audit
  log records it: without query string or fragment, and `invalid` when it does
  not parse or is longer than 512 bytes with its origin. Headers, bodies and
  secrets are never shown.

### Changed

- Docs: Secretive (Secure Enclave keys on macOS) is no longer suggested for
  signed requests. Such keys, like those in the 1Password SSH agent, refuse
  to sign while the Mac is locked, which is exactly when an agent needs
  warden. The docs now require a signer that works unattended with the
  screen locked (TPM, YubiKey PIV) and point an unattended Mac at a bearer
  key in the login Keychain.
- Docs: Tailscale Services (tested on Tailscale 1.104) is documented as a
  second deployment beside the dedicated sidecar node, with its policy,
  header-forwarding and trust-boundary differences.

## [0.6.0] - 2026-10-29

### Added

- Signed agent requests (protocol `warden-request-v1`, specified in
  `docs/agent-protocol.md`): an agent holds no reusable secret and proves
  itself with an SSH key, ideally one in hardware behind an `ssh-agent`
  (Secretive on the Secure Enclave, `ssh-tpm-agent`, YubiKey PIV). A captured
  request cannot be replayed, altered or sent to another broker. Bearer-key
  agents keep working unchanged.
  - CLI: `warden login --server <url> --agent <name> --ssh-key <path to .pub>
    [--ssh-agent-socket <path>] [--audience <id>]` pins the broker's audience
    from `/v1/info` (refusing one other than `--audience`, or than the one
    pinned before for that URL), checks that the agent holds the key, makes
    one signed call to confirm the enrollment and records the server, agent,
    public key, socket (default: `$SSH_AUTH_SOCK` at each run) and audience in
    the configuration. Nothing secret is stored and no Keychain is needed, so
    it also works on Linux. Every call, each long poll and retry included, is
    signed anew (fresh timestamp and nonce) over the exact method, target and
    body bytes sent; the private key is never read by the CLI. The server URL
    must have no path. A refused signed call says when the broker's audience
    has changed. `docs/agent-usage.md` covers the key setups and migrating a
    bearer-key agent.
  - Enrollment: `warden-server agent add <name> --public-key '<line>'`
    creates a key-signed agent without a bearer key; `warden-server agent
    set-key <name> '<line>'` switches an existing agent (its bearer key stops
    working at once); `agent list` shows the kind of authentication and the
    key's `SHA256:` fingerprint. Each change is audited as `agent_key_set`.
    Accepted keys are `ssh-ed25519` and `ecdsa-sha2-nistp256`; security keys,
    RSA, other curves, certificates and the published test keys of the
    protocol document are refused, by the broker and by the CLI, which share
    one policy (`warden_broker_proto::signing::SigningPublicKey`). A key
    belongs to one agent, and a revoked agent keeps its key: it can never be
    enrolled again, so make a new key after a revocation.
  - Migrating: on macOS, `warden login --ssh-key` over a bearer-key
    configuration prints the `security delete-generic-password` command that
    deletes the old key from the Keychain (it deletes nothing itself).
  - Verification: a key-signed agent sends `Warden-Agent`, `Warden-Timestamp`,
    `Warden-Nonce` and `Warden-Signature` (an SSHSIG, namespace
    `warden-request-v1`, hash `sha512` or `sha256`) on every call, including
    long polls and proxied calls. The broker refuses with 401 a missing,
    repeated or malformed header, an oversized signature, any other
    (reserved) `Warden-*` header, a `Warden-*` header together with
    `Authorization`, an unknown, revoked or bearer-key agent, a timestamp more
    than 60 seconds off, a signature by any other key or over anything else,
    and a nonce already used. An oversized body is a 413 and a body not
    received in time a 408, both before the signature is checked; the time
    scales with the route's body limit (the larger of 10 seconds and the limit
    at 128 KiB/s: 10 s, or 16 s for the 2 MiB of a proxied call).
    Nonces are recorded only once the signature verified, kept 10 minutes and
    swept with expired requests.
  - `GET /v1/info` returns the accepted signing protocols and the broker's
    audience, a random id created on first start in `WARDEN_AUDIENCE_PATH`
    (default `/data/audience`, next to the relay host key; never
    overwritten). It needs neither an agent key nor the owner's Tailscale
    login.
  - The worked shell client of the protocol document is run by the tests,
    as published, against a broker with Ed25519 and P-256 keys in an
    `ssh-agent`.

### Changed

- Security: key-signed agents do not need the owner's `Tailscale-User-Login`
  (tagged devices have none), a deliberate exemption. For them the signature
  authenticates the agent, and the tailnet policy (Serve and the gateway
  capability) alone decides which devices may reach the API, so keep that
  grant as narrow as the agents that need it. Bearer-key agents and the
  approval UI still require the owner's login. See the threat model, which
  also notes that agent names are not secret (a peer can tell an enrolled
  key-signed agent's name by the 413 or 408 its oversized or slow body gets).
- Security: the agent API is for tailnet peers only. Every route of its
  listener, `/healthz` and `/v1/info` included, refuses with 401 a request
  that came through Tailscale Funnel (`Tailscale-Funnel-Request` header),
  whatever credentials it carries. Never publish the API through Funnel.
- Upgrade note: schema migration `0005` rebuilds `agents` (and, below it,
  `requests` and `grants`, with all rows preserved) for the key columns and
  adds the nonce table; it runs on first start and is one-way. A 0.5.0 broker
  cannot open a database that 0.6.0 has migrated, so back up `/data`
  (database and audit log) before upgrading if you may need to go back.
- The approval UI follows the Sky Guard design language
  (`docs/design-language.md`): every page (approve, the finished and error
  states, Active grants, History, Enroll a passkey) shares one stylesheet with
  light and dark themes, the mascot, cards and 44 px touch targets, and works
  on phones, foldables and desktops. Active grants and History are cards on
  a phone; History is a table from 720 px.

## [0.5.0] - 2026-10-29

### Changed

- Breaking: the notification variables `WARDEN_HA_WEBHOOK_URL`,
  `WARDEN_NTFY_URL` and `WARDEN_NTFY_TOKEN` are replaced by `WARDEN_NOTIFY`
  and the `WARDEN_NOTIFY_*` settings (see Added). Startup fails, naming the
  replacement, if an old variable is set; update the broker's environment
  before upgrading.
- Schema migrations `0003` (widens the status check of `requests`, rebuilding
  it and `grants` with all rows preserved) and `0004` (the passkey counter
  column) run on first start.
- Upgrade note: the migrations are one-way. A 0.4.0 broker cannot open a
  database that 0.5.0 has migrated (it does not know migrations `0003` and
  `0004`), so back up `/data` (database and audit log) before upgrading if
  you may need to go back.

### Added

- Pluggable notification channels: `WARDEN_NOTIFY` lists the enabled channels
  (`homeassistant`, `ntfy`) in priority order and the first that accepts wins,
  the rest are fallbacks. Any single channel works alone. Settings are
  `WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL`, `WARDEN_NOTIFY_NTFY_URL` and
  `WARDEN_NOTIFY_NTFY_TOKEN`. Startup refuses an empty list, unknown,
  upper-case or repeated names, missing settings, and settings for a channel
  not listed in `WARDEN_NOTIFY`. Logs, errors and the audit log call each
  channel by its `WARDEN_NOTIFY` name, and the `notified` audit entry names
  the channel that delivered the notification (it was always `fallback`).
  `docs/notifications.md` documents the built-ins and a checklist for adding
  a channel.
- An agent can cancel its own pending request: `warden request cancel <id>`
  (`POST /v1/requests/{id}/cancel`, 404 for another agent's or an unknown
  request, 409 once it is no longer pending), audited as `request_cancelled`.
  The approval page of a cancelled request says "Cancelled by the agent." and
  cannot be approved, and the history lists it as `cancelled`. Ctrl-C while
  `warden request` waits cancels the pending request (waiting at most about
  10 s) and exits 130, revoking the grant if the owner approved first; a
  second Ctrl-C, or one while the approved grant is being installed, exits
  130 at once and says what may be left behind. A request cancelled from
  another terminal ends the waiting command with exit 6. `warden request` now prints the request id, which
  `warden request cancel` takes.
- Proxied API calls in flight are limited per agent
  (`WARDEN_PROXY_MAX_CALLS_PER_AGENT`, default 4, 1 to 64) and overall
  (`WARDEN_PROXY_MAX_CALLS`, default 16, 1 to 256, at least the per-agent
  limit; the broker refuses to start otherwise). A call over a limit gets a
  429 `too many concurrent calls`, is audited as a refused `proxy_call`, and
  never reaches the upstream. A slot is released when the call ends,
  whatever the outcome, including an agent that disconnects.
- CI check (`scripts/check-no-reqwest-decompression.sh`) that fails if
  reqwest's gzip, brotli, zstd or deflate feature is enabled, which secret
  redaction relies on. Tests cover the proxy's call-time failures (item
  removed, backend down, connect timeout).

### Fixed

- `warden http` exits 4 (revoked) with a message telling to request access
  again when the broker says the grant was revoked, and removes the stale
  local record, instead of exiting 1 with the broker's raw refusal.
- Redaction drops a response header whose name carries the secret whatever
  its letter case (names arrive lowercased from the HTTP stack, so a secret
  with uppercase letters was not matched).
- A relay session whose target stopped reading its input ends about 2 s
  after the agent disconnects (reason `client closed`), instead of when the
  60 s flow-control stall watchdog fires: the relay reads the agent's
  connection ahead of the SSH library (bounded: 64 KiB counted before
  login, 4 MiB after, twice the agent's window), so the agent leaving is
  seen even while that library is held up. Input still held for the target
  when the agent leaves is dropped. The session still gets exactly one
  `relay_session_ended` entry, and a session the relay ends (shutdown,
  revocation, expiry, grant state unavailable) keeps that reason although
  the agent's side closes as a result.
- The relay's login-time grant lookup is bounded to 1.5 s, like the grant
  checks of live sessions, instead of only by the 10 s login timeout: an
  attempt whose lookup does not answer in time is refused and audited as
  `relay_login_refused`, like any other refused login.
- A relay session revoked (or expired) while it was also ending normally is
  recorded with the reason `revoked` (or `expired`) rather than `exited`, as
  long as the revocation reached it before its teardown completed. It still
  gets exactly one `relay_session_ended` entry.
- The relay no longer hangs up 2 s after a session ends on an agent still
  taking the end of its output: such an agent (on a slow link, or with a busy
  reader) lost the rest of its output and got exit code 255 instead of the
  session's exit status. An agent now has the stall timeout (60 s) to take it
  and leave, and its connection keeps its place in the session limits until
  it is gone.
- A passkey's signature counter is never stored lower than it was: it lives in
  its own column (migration `0004`, backfilled from the stored credential) and
  is raised with one conditional update, so two concurrent approvals cannot
  overwrite each other's newer value. An assertion whose counter does not
  increase (unless the authenticator always reports 0) is refused as a
  possible cloned authenticator with a fixed message, no grant is issued, and
  it is audited as `passkey_counter_regressed`. Approving a request that was
  already decided is refused as already decided before the passkey is checked,
  so a second approval finishing after the first is not taken for a clone.
- A 1Password vault that was deleted and recreated under the same name is
  picked up without restarting the broker: on a Connect 404 the vault id is
  resolved again (once, shared by concurrent callers) and the request retried
  once. A vault that is gone, or a missing item in an unchanged vault, still
  fails closed with the same error.
- The CLI's cleanup on every run also removes leftover grant-record temporary
  files (`.<name>.<id>.tmp`, from a run that crashed mid-write) once they are
  over ten minutes old, in the grants and api-grants directories; fresher ones
  and live grants are never touched. Its failures are reported in a single
  warning. A per-grant `ssh-agent` still lingers until the next `warden` run
  after its grant ends (the agent's lifetime limit covers its keys, not the
  process), but that run stops it.

## [0.4.0] - 2026-10-29

### Added

- Narrowed API requests. `warden request api <secret> [--methods GET,POST]
  [--path /prefix] --goal … --for …` asks for a scope inside the 1Password
  item's policy. The item is the ceiling: requested methods and path prefix
  can only narrow it, `CONNECT` and `TRACE` are never allowed, and anything
  outside the item is refused when the request is made.
- The broker stores the approved scope in the grant and enforces it on every
  call, in addition to the item's policy.
- The approval page shows **Read-only**, or **Can modify:** with the
  non-read-only methods, as a warning. The notification (Home Assistant and
  ntfy) and the `request_created` audit summary read `api <secret>
  (read-only)` or `api <secret> (CAN MODIFY: POST, PUT)`.
- An agent may hold several grants for one secret. `warden http` uses the
  covering active grant that stays valid longest, and otherwise exits 5
  with the `warden request api … --methods` command to run.

### Changed

- Behaviour change: a request without `--methods` is now read-only (the
  item's methods that are `GET` or `HEAD`; refused if there are none).
  Previously it received every method of the item. This also applies to
  0.3 CLIs, which send no scope: against a 0.4 broker they receive read-only
  grants and must be upgraded to ask for write access.
- Wire format: `Access::Api` has optional `methods` and `path_prefix`, and
  the API grant carries the approved methods and prefix. Requests without them
  keep their fingerprint. The CLI's local API grant record stores them;
  records from 0.3 read as `GET` and `/`, so they are never widened.
- Upgrade the broker before the CLIs. A 0.4 CLI refuses, and does not record,
  a grant from an older broker that is wider than it asked for (methods
  beyond `--methods`, or beyond `GET` and `HEAD` without it, or a path outside
  `--path`); the message says to upgrade the broker.
- Requests still pending when the broker is upgraded are approved read-only
  (they carry no scope), and may not be deduplicated with a new identical
  request, which is then a second pending request.
- A requested path prefix may be at most 512 bytes.
- The active-grants page shows **Read-only** or **Can modify:** for API grants.

## [0.3.0] - 2026-10-27

### Added

- SSH relay mode for targets that cannot trust a CA. `warden request ssh` and
  `warden ssh` work as before; the broker runs an SSH relay that
  authenticates the agent by the ephemeral public key the owner approved
  (user name = target name; a key can be bound to one live request or grant
  at a time) and logs in to the target with the item's Ed25519 private key or
  password. The target's host keys must be pinned; key exchange negotiates only
  their algorithms (Ed25519, RSA and ECDSA host keys verify, SHA-1 is never
  negotiated). Port, agent and X11 forwarding and subsystems are refused, the
  environment is filtered, and there are limits of 4 sessions per grant,
  `WARDEN_RELAY_MAX_SESSIONS` overall (default 16) and for connections not yet
  logged in.
- Sessions end at revocation, expiry, 15 minutes without traffic, a 30 s wait
  for an unstarted session, or a flow-control watchdog (2 s wedge, 60 s
  stall), and fail closed when grant state cannot be read for 10 s.
- Audit events `relay_session_started` (before any byte reaches the target),
  `relay_session_ended`, `relay_session_refused` and `relay_login_refused`.
- Configuration `WARDEN_RELAY_LISTEN`, `WARDEN_RELAY_PUBLIC_ADDR`,
  `WARDEN_RELAY_HOST_KEY_PATH` and `WARDEN_RELAY_MAX_SESSIONS`.
- Target items accept `private_key` (unencrypted Ed25519) or `password` for
  `mode=relay`.

### Changed

- Wire format: `GrantAccess` has a new `relay` kind (target, user, relay host
  and port, relay host key); the CLI's local `grant.json` records a `route`
  (`direct` or `relay`, default `direct`). Agents and brokers should both be
  0.3.0; a 0.2.x CLI cannot use a relay grant.
- A public key can be bound to one live request or grant at a time across all
  agents; reusing one is a 409.
- The SSH destination digest covers the target's mode.

## [0.2.0] - 2026-10-27

### Added

- HTTP proxy mode. An agent runs `warden request api <secret> --for <window>
  --goal "…"`, the owner approves with a passkey, and `warden http <secret>
  <METHOD> <url>` makes the call through the broker. The broker builds the
  secret header from the policy, sends the call only to the secret's origin
  under its path prefix with an allowed method, and returns the response with
  the secret redacted. No redirects, compressed responses refused, 1 MiB
  request and response limits (`WARDEN_PROXY_MAX_RESPONSE_BYTES`), 30 s total
  and 10 s connect timeouts, optional pinned CA per secret.
- 1Password API secret items (tag `warden:api-secret`).
- Audit events `proxy_call_started` (before sending) and `proxy_call`.
- `warden http --fail` exits 22 on an upstream status of 400 or more.

### Changed

- Breaking: the `GrantView` wire format replaces the `ssh` field with a
  tagged `access` field (`{"kind": "ssh" | "api", …}`). Agents and brokers
  must both be 0.2.0.
- Approval and call time check a digest of the secret's destination (origin,
  path prefix, header, format, pinned CA, methods); any change since approval
  is a 409.

## [0.1.0] - 2026-10-25

### Added

- SSH certificate mode: short-lived certificates for an ephemeral Ed25519 key
  held in a per-grant `ssh-agent`, policy in 1Password via Connect.
- Passkey (WebAuthn) approval over the tailnet, phone-only approval port,
  Home Assistant and ntfy notifications, tamper-evident audit log, SQLite
  state, agent keys, and the `warden` CLI (`login`, `request ssh`, `ssh`,
  `status`, `revoke`).
