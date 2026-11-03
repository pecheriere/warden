# Building and dependencies

How to build warden from source, and how its dependencies are chosen, obtained
and tracked. To run warden rather than work on it, see
[Deployment](deployment.md) and [Agent usage](agent-usage.md).

## Tools

| Tool | For |
|---|---|
| [rustup](https://rustup.rs/) | Installs the Rust toolchain pinned in [`rust-toolchain.toml`](../rust-toolchain.toml) when you first run `cargo` here |
| A C toolchain, `pkg-config` and the OpenSSL headers | The broker and the demo link OpenSSL. On Debian or Ubuntu: `sudo apt install build-essential pkg-config libssl-dev`. The CLI needs only the C toolchain |
| `curl`, `make` and `perl`, instead of the OpenSSL headers | Building against the OpenSSL release warden ships, with `scripts/build-openssl.sh` |
| Docker with Buildx | Only to build the image |

The checks in [`AGENTS.md`](../AGENTS.md#before-you-push) also need:

- an OpenSSH server binary at `/usr/sbin/sshd`, for the relay tests;
- [cargo-deny](https://github.com/EmbarkStudios/cargo-deny);
- Python 3, for the crate age check;
- [uv](https://docs.astral.sh/uv/), to run zizmor when a workflow changes.

## Build

Always pass `--locked`, so that the build uses exactly the versions in
`Cargo.lock`.

```sh
git clone https://github.com/pecheriere/warden && cd warden

# Everything, for development: target/debug/warden-server, warden, warden-demo
cargo build --workspace --locked

# The CLI alone: target/release/warden
cargo build --release --locked -p warden-broker-cli

# The server, with the pinned OpenSSL linked statically, as in the image:
# target/release/warden-server
scripts/build-openssl.sh "$(rustc -vV | sed -n 's/^host: //p')" "$PWD/target/openssl"
OPENSSL_DIR="$PWD/target/openssl" OPENSSL_STATIC=1 WARDEN_OPENSSL_PINNED=1 \
  cargo build --release --locked -p warden-broker

# The image
docker buildx build -t warden:dev --load .
```

## Test

```sh
cargo test --workspace --all-features --locked
```

On Linux, the password-target tests of the relay also need
`WARDEN_TEST_LOGIN_PASSWORD`. [`AGENTS.md`](../AGENTS.md#before-you-push) has
this detail and the full list of checks, which CI runs and which must all pass.

## Dependencies

### How they are chosen

A dependency has to earn its place: warden holds credentials, and everything it
links runs in that process. When you add one:

- check that warden really needs it, and that the crate is maintained;
- add it to `[workspace.dependencies]` in [`Cargo.toml`](../Cargo.toml), with a
  comment when the reason is not obvious;
- keep default features off where practical. `reqwest` must never gain a
  decompression feature, which a CI script enforces;
- make sure its license and advisories pass `cargo deny check`, which applies
  the rules in [`deny.toml`](../deny.toml).

### How they are obtained

Everything comes through the standard tool for each ecosystem, pinned:

| What | From | Pinned by |
|---|---|---|
| Crates | Cargo, from crates.io only: `deny.toml` refuses other registries and Git sources | Version and checksum in [`Cargo.lock`](../Cargo.lock) |
| Rust toolchain | rustup | [`rust-toolchain.toml`](../rust-toolchain.toml) |
| Base images | Docker | Digest in the [`Dockerfile`](../Dockerfile) |
| GitHub Actions | GitHub | Full commit SHA in each [workflow](../.github/workflows) |
| Lint tools for CI | pip | Hash in [`.github/requirements-lint.txt`](../.github/requirements-lint.txt) |

A new crate version must be at least 7 days old, with one exception for security
fixes. See [Dependency age](../README.md#dependency-age).

### How they are tracked

- [Dependabot](../.github/dependabot.yml) proposes updates every week, and
  security updates as advisories appear.
- Dependency review checks the changes in each pull request.
- `cargo deny check` runs on each pull request, and its advisory check also runs
  every night on `main`. Current exemptions are listed, with reasons, in
  `deny.toml`.
- [`CHANGELOG.md`](../CHANGELOG.md) records the updates that matter to users.
