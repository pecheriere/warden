#!/usr/bin/env bash
# Installs the packages scripts/package-linux.sh made in clean containers, the way the
# docs say to, runs the installed `warden`, checks that the dependencies came along, and
# removes it again. Needs only Docker, and changes nothing on this machine. The packages
# must be for this machine's architecture.
#
# Usage: scripts/test-linux-packages-docker.sh <linux-amd64|linux-arm64> <dir with packages>
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <linux-amd64|linux-arm64> <dir with packages>" >&2
  exit 2
fi
case "$1" in
  linux-amd64) deb_arch=amd64 rpm_arch=x86_64 ;;
  linux-arm64) deb_arch=arm64 rpm_arch=aarch64 ;;
  *)
    echo "error: no packages for $1" >&2
    exit 2
    ;;
esac
packages=$(cd "$2" && pwd)
debian=debian:12@sha256:d74df7598108a173a621eda4d58a2adbf850b2d9a9d81bc2cca1a6c21174a880
fedora=fedora:43@sha256:f01112b9a1f1d0504ad962d9adfa401425033f8ab067e0a821904ebdde5b8ca5

# shellcheck disable=SC2016 # Expanded by the container's shell, not this one.
docker run --rm -e "ARCH=$deb_arch" -v "$packages:/packages:ro" "$debian" bash -euc '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq /packages/warden_*_"$ARCH".deb > /dev/null
  warden --version
  command -v ssh-add > /dev/null
  test -s /etc/ssl/certs/ca-certificates.crt
  if command -v warden-demo || command -v warden-server; then exit 1; fi
  apt-get remove -y -qq warden > /dev/null
  test ! -e /usr/bin/warden'
echo 'ok: the .deb installs, runs and removes on Debian 12'

# shellcheck disable=SC2016 # Expanded by the container's shell, not this one.
docker run --rm -e "ARCH=$rpm_arch" -v "$packages:/packages:ro" "$fedora" bash -euc '
  dnf install -y -q /packages/warden-*."$ARCH".rpm > /dev/null
  warden --version
  command -v ssh-add > /dev/null
  test -s /etc/pki/tls/certs/ca-bundle.crt
  if command -v warden-demo || command -v warden-server; then exit 1; fi
  dnf remove -y -q warden > /dev/null
  test ! -e /usr/bin/warden'
echo 'ok: the .rpm installs, runs and removes on Fedora 43'
