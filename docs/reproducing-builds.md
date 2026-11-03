# Reproducing a build

From the first release after v0.8.1, building warden twice from the same commit
with the same tools is meant to give the same bits. The
[repeatable build](../.github/workflows/repeatable-build.yml) workflow checks this
every week, and when the build's configuration or dependencies change: it builds
each output twice, on separate runners, from checkouts at different paths. A change
to the sources alone is not checked until the next weekly run.

v0.8.1 and earlier do not reproduce: their files carry build times, and their
archives did not exist.

## What must match

| Input | Archives (CLI, server, demo) | Image |
|---|---|---|
| Source | The tag's commit | The tag's commit |
| Rust | `rust-toolchain.toml`, an exact version | The Dockerfile's base image, by digest |
| Dependencies | `Cargo.lock` | `Cargo.lock` |
| C compiler, linker | **The runner's**: see the limits below | The Dockerfile's base image, by digest |
| Base image | None | The Dockerfile's two digests |
| Time | The commit's, set by the script | `SOURCE_DATE_EPOCH`, the commit's |
| BuildKit | None | The version in `release.yml` |
| Paths | Need not match | Need not match |
| User name, home directory | Need not match, measured on Linux only | Not measured; the build runs in a container |
| CPU count | Need not match, measured with 2 and 3 | Not measured |

## Reproduce the image

This needs only Docker with Buildx. Create a builder with the BuildKit that
`release.yml` names:

```sh
version=x.y.z
git clone --branch "v$version" --depth 1 https://github.com/pecheriere/warden
cd warden
buildkit=$(sed -n 's/.*driver-opts: image=//p' .github/workflows/release.yml | head -n 1)
docker buildx create --name warden-repro --driver docker-container --driver-opt "image=$buildkit"
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) docker buildx build --builder warden-repro \
  --no-cache --platform linux/arm64 --provenance=false --sbom=false \
  --output type=oci,dest=image.tar,rewrite-timestamp=true .
```

Use `linux/amd64` on an amd64 machine. Then compare the digest of the image's
manifest with the published one for that platform:

```sh
mkdir image && tar -xf image.tar -C image
jq -r '.manifests[0].digest' image/index.json
docker buildx imagetools inspect "ghcr.io/pecheriere/warden:$version" --raw \
  | jq -r '.manifests[] | select(.platform.architecture == "arm64") | .digest'
```

Compare per platform, not the digest of the tag. The published index also holds
each platform's provenance, which records when and where it was built, so the
index's own digest never repeats. The digest of the tag is the one the signed
manifest and the attestation name; the index links it to the platform digest you
checked here.

## Reproduce an archive

```sh
git clone --branch "v$version" --depth 1 https://github.com/pecheriere/warden
cd warden
rustup toolchain install
rustup target add x86_64-unknown-linux-musl     # the platform's target
scripts/package-binary.sh cli x86_64-unknown-linux-musl linux-amd64 dist   # or server, demo
shasum -a 256 dist/*.tar.gz
```

Compare the result with the hash in the release's `warden-<version>-SHA256SUMS`,
if it has one, or with the archive you downloaded. You need `python3`, and on Linux
`musl-tools`. The server and the demo also need `perl` and `make`, for OpenSSL, which records its
build directory in the binary. So the script always uses
`/tmp/warden-package-build`, and that one path must match wherever you build.
`.github/workflows/build-archives.yml` has the runner and targets of each
platform.

## Limits

These are known limits, not gaps in the check.

- **The archives' C compiler and linker come from the runner.** The Linux archives use
  the `musl-tools` and GCC that Ubuntu 24.04 offers on the day, and the macOS
  archives use the Xcode on `macos-15`. The workflow checks two builds on the same
  runner image. A later rebuild can differ when those tools change, and the
  versions are recorded only in the run's log, which GitHub deletes after a time.
  The image does not have this limit, because everything is pinned by digest.
- **A build on another machine type or a different OS can differ**, for the same
  reason. To compare, use the runner image the release used.

## What was measured

Measured on the source of version 0.8.1 plus these changes, for `linux/arm64` and
macOS arm64, on one machine, with Rust 1.99.1 and BuildKit v0.34.1. Each pair was
built without a cache in two different directories. The CLI pairs also used
different CPU counts. The Linux CLI pair also differed in user name and home
directory, each in a new Ubuntu 24.04 container, and the second image build's
source files had new times.

| Output | Before these changes | After |
|---|---|---|
| CLI binary, Linux arm64 | Differs: 415 registry paths hold the user's home | Identical |
| CLI archive, Linux arm64 | Differs: owner, times, and the binary | Identical |
| CLI binary, macOS arm64 | Identical with the same home directory; holds it in 412 paths | Identical, with no such paths |
| Image, `linux/arm64` | Differs: only the times in the config and on two layers' files. `warden-server` was already identical | Identical, in every blob |

The workflow's runs are the evidence for `linux/amd64` and for GitHub's runners.
Each pair of builds runs on two runner instances of the same runner image; GitHub
does not show whether those are on different hardware. A build on a developer's
machine was not compared with one on a runner, and a release's published digest has
not yet been compared with a rebuild, because no release has been built this way
yet.
