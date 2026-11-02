#!/usr/bin/env bash
# Builds the `warden` CLI for one target and packs it for a release, so CI and
# the release workflow build the same way. The build is repeatable: see
# docs/reproducing-builds.md, which also lists what must match.
#
# Usage: scripts/package-cli.sh <rust-target> <platform> <out-dir>
#   e.g. scripts/package-cli.sh x86_64-unknown-linux-musl linux-amd64 dist
#
# Writes <out-dir>/warden-<version>-<platform>.tar.gz. Run it on a machine of
# the target's architecture: it runs the binary it built. A Linux binary must be
# fully static, so it does not depend on the distribution's libc; a dynamic one
# fails the build here rather than on a user's machine.
#
# Files in the archive carry the time of SOURCE_DATE_EPOCH, or of the checked-out
# commit when that is not set.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <rust-target> <platform> <out-dir>" >&2
  exit 2
fi
target=$1
platform=$2
out_dir=$3

epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}

# Without this, the binary holds the absolute paths of the checkout and of cargo's
# registry, in panic messages, and so differs by directory and user name. RUSTFLAGS
# splits on spaces, so a path holding one would turn into wrong flags.
source_dir=$PWD
cargo_home=${CARGO_HOME:-$HOME/.cargo}
case "$source_dir$cargo_home" in
  *' '*)
    echo "error: this script cannot build from a path with a space: $source_dir, $cargo_home" >&2
    exit 1
    ;;
esac
RUSTFLAGS="--remap-path-prefix=$source_dir=/warden --remap-path-prefix=$cargo_home=/cargo" \
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
mkdir -p "$out_dir"

# In Python rather than with tar, whose flags for a fixed order, owner and time
# differ between GNU tar on Linux and bsdtar on macOS. The gzip header holds no
# time or file name.
python3 -I - "$out_dir/$name.tar.gz" "$name" "$epoch" "$binary" <<'PACK'
import gzip
import io
import os
import sys
import tarfile

archive, name, epoch, binary = sys.argv[1:]
epoch = int(epoch)


def add(tar, arcname, mode, source=None):
    info = tarfile.TarInfo(arcname)
    info.mtime = epoch
    info.mode = mode
    if source is None:
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
        return
    info.size = os.path.getsize(source)
    with open(source, "rb") as data:
        tar.addfile(info, data)


buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
    add(tar, name, 0o755)
    add(tar, f"{name}/LICENSE-APACHE", 0o644, "LICENSE-APACHE")
    add(tar, f"{name}/LICENSE-MIT", 0o644, "LICENSE-MIT")
    add(tar, f"{name}/warden", 0o755, binary)
with open(archive, "wb") as out:
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as packed:
        packed.write(buffer.getvalue())
PACK
echo "$out_dir/$name.tar.gz"
