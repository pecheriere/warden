#!/usr/bin/env bash
# Builds one binary for one target and packs it for a release, so CI and the
# release workflow build the same way. The build is repeatable: see
# docs/reproducing-builds.md, which also lists what must match.
#
# Usage: scripts/package-binary.sh <product> <rust-target> <platform> <out-dir>
#   e.g. scripts/package-binary.sh cli x86_64-unknown-linux-musl linux-amd64 dist
#
# Products and what they write in <out-dir>:
#   cli   warden-<version>-<platform>.tar.gz, the `warden` command
#   demo  warden-demo-<version>-<platform>.tar.gz, the local demo, which is not
#         secure for real use and says so in its name, its files and its output
#   server  warden-server-<version>-<platform>.tar.gz, Linux only
#
# Run it on a machine of the target's architecture: it runs the binary it built.
# A Linux binary must be fully static, so it does not depend on the
# distribution's libc; a dynamic one fails the build here rather than on a user's
# machine.
#
# Files in the archive carry the time of SOURCE_DATE_EPOCH, or of the checked-out
# commit when that is not set.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <cli|demo|server> <rust-target> <platform> <out-dir>" >&2
  exit 2
fi
product=$1
target=$2
platform=$3
out_dir=$4

# The server and the demo link OpenSSL through the broker: vendored, so that they
# need no system libssl. The demo's archive name and notice file label it for
# someone who only sees the download.
extra_file=
case "$product" in
  cli)
    build_args=(-p warden-broker-cli)
    bin=warden
    prefix=warden
    ;;
  demo)
    build_args=(-p warden-demo --features warden-broker/vendored-openssl)
    bin=warden-demo
    prefix=warden-demo
    extra_file=crates/demo/NOT-FOR-REAL-USE.txt
    ;;
  server)
    case "$target" in
      *-linux-*) ;;
      *)
        echo "error: the server is released for Linux only, not $target" >&2
        exit 2
        ;;
    esac
    build_args=(-p warden-broker --features vendored-openssl)
    bin=warden-server
    prefix=warden-server
    ;;
  *)
    echo "error: unknown product: $product" >&2
    exit 2
    ;;
esac

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
#
# OpenSSL records its build directory in the library, which a remap cannot reach
# because it is C and takes the path as a compile-time string. So build
# directories get one fixed path, whatever the checkout's or this machine's Cargo
# configuration. /tmp is shared, so refuse a directory another user made first.
build_dir=/tmp/warden-package-build
[ -e "$build_dir" ] || mkdir -m 0700 "$build_dir"
if [ ! -O "$build_dir" ] || [ -L "$build_dir" ]; then
  echo "error: $build_dir is not this user's own directory" >&2
  exit 1
fi
RUSTFLAGS="--remap-path-prefix=$source_dir=/warden --remap-path-prefix=$cargo_home=/cargo" \
  cargo build --config "build.build-dir='$build_dir'" \
  --release --locked "${build_args[@]}" --target "$target"
binary="target/$target/release/$bin"

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

# The demo's startup banner is in its binary. Only the demo may hold it, and the
# demo must, so a mix-up in the table above cannot ship under the wrong name.
if grep -q 'WARDEN DEMO' "$binary"; then
  if [ "$product" != demo ]; then
    echo "error: $binary contains the demo" >&2
    exit 1
  fi
elif [ "$product" = demo ]; then
  echo "error: $binary does not say that it is a demo" >&2
  exit 1
fi

# Running it also proves it starts on the machine that built it. Its reported
# version names the archive, and the release workflow has already checked the
# tag against the same workspace version.
reported="$("$binary" --version)"
version="${reported#"$bin" }"
if [ -z "$version" ] || [ "$version" = "$reported" ]; then
  echo "error: unexpected version output: $reported" >&2
  exit 1
fi

name="$prefix-$version-$platform"
mkdir -p "$out_dir"

# In Python rather than with tar, whose flags for a fixed order, owner and time
# differ between GNU tar on Linux and bsdtar on macOS. The gzip header holds no
# time or file name.
python3 -I - "$out_dir/$name.tar.gz" "$name" "$epoch" "$binary" "$extra_file" <<'PACK'
import gzip
import io
import os
import sys
import tarfile

archive, name, epoch, binary, extra_file = sys.argv[1:]
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
    add(tar, f"{name}/NOTICE", 0o644, "NOTICE")
    add(tar, f"{name}/{os.path.basename(binary)}", 0o755, binary)
    if extra_file:
        add(tar, f"{name}/{os.path.basename(extra_file)}", 0o644, extra_file)
with open(archive, "wb") as out:
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0) as packed:
        packed.write(buffer.getvalue())
PACK
echo "$out_dir/$name.tar.gz"
