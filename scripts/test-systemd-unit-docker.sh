#!/usr/bin/env bash
# Runs scripts/test-systemd-unit.sh in a throwaway privileged Debian 13 container, whose
# systemd enforces SocketBind*. Ubuntu's may not, and that script refuses a host where
# the rules do nothing. Needs only Docker, and changes nothing on this machine.
#
# Usage: scripts/test-systemd-unit-docker.sh <warden-server binary for this architecture>
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <warden-server binary>" >&2
  exit 2
fi
binary=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
[ -x "$binary" ] || {
  echo "error: cannot run $binary" >&2
  exit 1
}
image=debian:13@sha256:2dc419c6d7fe3dad0a2f9fd469c34cc90b0f9ba642d8fde837fe3d7d34a0e7f1
name=warden-unit-test-$$

echo "This host's systemd, for the record:"
systemctl --version 2> /dev/null | head -n 2 || echo "none"

trap 'docker rm -f "$name" > /dev/null 2>&1 || true' EXIT
# shellcheck disable=SC2016 # Expanded by the container's shell, not this one.
docker run -d --name "$name" --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
  -v "$PWD:/repo:ro" -v "$binary:/warden-server-under-test:ro" "$image" bash -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq systemd systemd-sysv dbus ca-certificates openssh-client libbpf1 python3
    exec /sbin/init' > /dev/null

# Waits on the condition, with a limit: installing the packages takes a while.
for _ in $(seq 1 300); do
  if docker exec "$name" sh -c 'readlink /proc/1/exe | grep -q systemd' 2> /dev/null; then
    booted=yes
    break
  fi
  [ "$(docker inspect -f '{{.State.Running}}' "$name")" = true ] || {
    docker logs "$name" 2>&1 | tail -n 20
    echo "error: the container stopped before systemd started" >&2
    exit 1
  }
  sleep 1
done
[ "${booted:-}" = yes ] || {
  docker logs "$name" 2>&1 | tail -n 20
  echo "error: systemd did not start in the container" >&2
  exit 1
}
# It reports degraded in a container, which is fine: only the wait matters here.
docker exec "$name" systemctl is-system-running --wait > /dev/null 2>&1 || true
docker exec "$name" systemctl --version | head -n 1
docker exec "$name" /repo/scripts/test-systemd-unit.sh --throwaway-host /warden-server-under-test
