#!/usr/bin/env bash
# Builds the `warden` CLI for one target and packs it for a release, so CI and
# the release workflow build the same way.
#
# Usage: scripts/package-cli.sh <rust-target> <platform> <out-dir>
#   e.g. scripts/package-cli.sh x86_64-unknown-linux-musl linux-amd64 dist
#
# Writes <out-dir>/warden-<version>-<platform>.tar.gz. Run it on a machine of
# the target's architecture: it runs the binary it built. A Linux binary must be
# fully static, so it does not depend on the distribution's libc; a dynamic one
# fails the build here rather than on a user's machine.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <rust-target> <platform> <out-dir>" >&2
  exit 2
fi
target=$1
platform=$2
out_dir=$3

cargo build --release --locked -p warden-broker-cli --target "$target"
binary="target/$target/release/warden"

case "$target" in
  *-linux-*)
    # `file` and `ldd` word a static-pie binary differently across versions;
    # the ELF headers say it directly: no interpreter, no needed libraries.
    headers="$(readelf --program-headers --dynamic --wide "$binary")"
    if grep -E 'INTERP|\(NEEDED\)' <<< "$headers"; then
      echo "error: $binary is not statically linked" >&2
      exit 1
    fi
    ;;
esac

# Running it also proves it starts on the machine that built it. Its reported
# version names the archive, and the release workflow has already checked the
# tag against the same workspace version.
reported="$("$binary" --version)"
version="${reported#warden }"
if [ -z "$version" ] || [ "$version" = "$reported" ]; then
  echo "error: unexpected version output: $reported" >&2
  exit 1
fi

name="warden-$version-$platform"
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT
mkdir "$staging/$name"
cp "$binary" LICENSE-MIT LICENSE-APACHE "$staging/$name/"

mkdir -p "$out_dir"
tar -czf "$out_dir/$name.tar.gz" -C "$staging" "$name"
echo "$out_dir/$name.tar.gz"
