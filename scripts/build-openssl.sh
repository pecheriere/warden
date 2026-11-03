#!/usr/bin/env bash
# Builds the OpenSSL release pinned in scripts/openssl-pin.env as static libraries,
# for the broker to link. Afterwards, point the build at it:
#   OPENSSL_DIR=<prefix> OPENSSL_STATIC=1 WARDEN_OPENSSL_PINNED=1 cargo build ...
# With WARDEN_OPENSSL_PINNED set, crates/broker/build.rs fails the build on any other
# OpenSSL.
#
# From a release tarball because no `openssl-src` crate carries a current release of
# a line that `openssl-sys` accepts. The tarball's hash is pinned, so a changed
# download fails the build.
#
# Usage: scripts/build-openssl.sh <rust-target> <prefix>
#   e.g. scripts/build-openssl.sh x86_64-unknown-linux-musl "$PWD/target/openssl"
#
# The library records its build directory, which sits next to <prefix>: use the same
# <prefix> for a repeatable build. A <prefix> that already holds this exact build is
# kept, and any other content in it is replaced.
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <rust-target> <prefix>" >&2
  exit 2
fi
target=$1
prefix=$2

case "$prefix" in
  /*' '*)
    echo "error: OpenSSL cannot build under a path with a space: $prefix" >&2
    exit 1
    ;;
  /?*) ;;
  *)
    echo "error: the prefix must be an absolute path: $prefix" >&2
    exit 1
    ;;
esac

# Only the platforms warden builds on. The options that turn off what the broker does
# not use, and those musl needs, match what `openssl-src` used for these targets.
extra_options=()
case "$target" in
  x86_64-unknown-linux-gnu) configure_target=linux-x86_64 ;;
  aarch64-unknown-linux-gnu) configure_target=linux-aarch64 ;;
  x86_64-unknown-linux-musl | aarch64-unknown-linux-musl)
    case "$target" in
      x86_64-*) configure_target=linux-x86_64 ;;
      *) configure_target=linux-aarch64 ;;
    esac
    export CC=musl-gcc
    # The broker uses none of these, and musl-gcc sees no kernel headers, which the
    # engine and secure heap code include. musl lacks what the async code uses.
    extra_options=(no-engine no-async -DOPENSSL_NO_SECURE_MEMORY)
    ;;
  aarch64-apple-darwin)
    configure_target=darwin64-arm64-cc
    # The oldest macOS Rust builds for, or the compiler assumes the machine's own, and
    # the library would claim to need that.
    deployment_target="$(rustc --print deployment-target --target "$target")"
    export "${deployment_target?}"
    ;;
  *)
    echo "error: no OpenSSL build is set up for $target" >&2
    exit 2
    ;;
esac

sha256() {
  if command -v sha256sum > /dev/null; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# shellcheck source=scripts/openssl-pin.env
. "$script_dir/openssl-pin.env"
version=$WARDEN_OPENSSL_VERSION

stamp_file="$prefix/warden-build-stamp"
stamp="$WARDEN_OPENSSL_SHA256 $target $(sha256 "$0")"
if [ -f "$stamp_file" ] && [ "$(cat "$stamp_file")" = "$stamp" ]; then
  echo "OpenSSL $version for $target is already in $prefix"
  exit 0
fi

work_dir="$prefix.build"
rm -rf "$prefix" "$work_dir"
mkdir -p "$work_dir"

tarball="$work_dir/openssl-$version.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 3 \
  --output "$tarball" \
  "https://github.com/openssl/openssl/releases/download/openssl-$version/openssl-$version.tar.gz"
actual=$(sha256 "$tarball")
if [ "$actual" != "$WARDEN_OPENSSL_SHA256" ]; then
  echo "error: the OpenSSL $version tarball has hash $actual, not $WARDEN_OPENSSL_SHA256" >&2
  exit 1
fi
tar -xzf "$tarball" -C "$work_dir"
source_dir="$work_dir/openssl-$version"

jobs=$(getconf _NPROCESSORS_ONLN)
(
  cd "$source_dir"
  # OpenSSL writes the time of the build into the library, or this when it is set.
  # Zero would count as unset.
  export SOURCE_DATE_EPOCH=1
  # /usr/local/ssl is the default config directory, as with `openssl-src`: the build
  # directory goes away, and the broker reads no OpenSSL configuration or certificates.
  perl ./Configure "$configure_target" \
    "--prefix=$prefix" --libdir=lib --openssldir=/usr/local/ssl \
    no-shared no-module no-tests no-comp no-zlib no-zlib-dynamic no-legacy \
    no-ssl3 no-md2 no-rc5 no-weak-ssl-ciphers no-camellia no-idea no-seed \
    "${extra_options[@]+"${extra_options[@]}"}" \
    -fPIC -ffunction-sections -fdata-sections
  make -j"$jobs" build_libs > /dev/null
  make install_dev > /dev/null
)
rm -rf "$work_dir"
printf '%s\n' "$stamp" > "$stamp_file"
echo "OpenSSL $version for $target is in $prefix"
