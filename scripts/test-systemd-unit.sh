#!/usr/bin/env bash
# Runs warden-server under deploy/systemd/warden.service, with its bind and sandbox
# rules enforced, and checks that it can start, resolve a name and make a TLS call,
# and that the unit allows no other bind. A unit that looks right can still stop a
# binary working: musl's resolver binds its UDP socket to port 0, which
# SocketBindDeny=any refuses unless the unit allows it.
#
# It uses the local backend, so it needs no Connect, and the unit's own address rules
# are widened to reach one public host. It does not cover Connect, Tailscale or an
# approval.
#
# Usage: sudo scripts/test-systemd-unit.sh --throwaway-host <warden-server binary>
# scripts/test-systemd-unit-docker.sh runs it in a container, which is usually what you
# want, and is what CI does.
#
# It creates a user and writes under /etc, /usr/local and /var/lib, so it refuses to
# run without that flag. It needs root, a running systemd with BPF_FRAMEWORK, libbpf,
# python3 and ssh-keygen. systemd loads libbpf once: after installing it, run
# `systemctl daemon-reexec`. Without enforcement this fails rather than pass by testing
# nothing.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

if [ "$#" -ne 2 ] || [ "$1" != --throwaway-host ]; then
  echo "usage: $0 --throwaway-host <warden-server binary>" >&2
  exit 2
fi
binary=$2
[ "$(id -u)" -eq 0 ] || fail "this needs root"
[ -x "$binary" ] || fail "cannot run $binary"
unit=deploy/systemd/warden.service
results=/run/warden-unit-test
# A name on the public internet, resolved through /etc/resolv.conf. Any HTTP status
# shows that the name resolved and TLS worked. The doctor's test message goes nowhere.
notify_url=https://github.com/warden-unit-test

id warden > /dev/null 2>&1 \
  || useradd --system --user-group --home-dir /var/lib/warden --no-create-home \
    --shell /usr/sbin/nologin warden
install -d -m 0755 /usr/local/lib/warden /etc/warden
install -m 0755 "$binary" /usr/local/lib/warden/warden-server-test
ln -sfn /usr/local/lib/warden/warden-server-test /usr/local/bin/warden-server
install -d -m 0755 "$results"
cat > /etc/warden/warden.conf <<EOF
WARDEN_PUBLIC_URL=https://warden.example.ts.net
WARDEN_OWNER_LOGIN=owner@example.com
WARDEN_NOTIFY=ntfy
WARDEN_NOTIFY_NTFY_URL=$notify_url
EOF
install -d -o warden -g warden -m 0700 /var/lib/warden /var/lib/warden/secrets
if [ ! -e /var/lib/warden/secrets/ssh-ca ]; then
  ssh-keygen -q -t ed25519 -N '' -f /var/lib/warden/secrets/ssh-ca
  rm /var/lib/warden/secrets/ssh-ca.pub
  chown warden:warden /var/lib/warden/secrets/ssh-ca
  chmod 0600 /var/lib/warden/secrets/ssh-ca
fi
printf '[ca]\nprivate_key_file = "ssh-ca"\n\n[end_of_policy]\n' > /etc/warden/policy.draft
/usr/local/bin/warden-server seal-policy --from /etc/warden/policy.draft /etc/warden/policy.toml > /dev/null
chmod 0644 /etc/warden/policy.toml

# Installs the repository's unit under a name, changing only what is passed.
install_unit() {
  local name=$1 command=$2 type=$3 extra=$4
  sed -e "s|^ExecStart=.*|ExecStart=$command|" -e 's/^Restart=.*/Restart=no/' \
    -e "s/^Type=exec/Type=$type/" "$unit" > "/etc/systemd/system/$name.service"
  install -d "/etc/systemd/system/$name.service.d"
  cat > "/etc/systemd/system/$name.service.d/test.conf" <<EOF
[Service]
LoadCredential=
Environment=WARDEN_OP_CONNECT_TOKEN_FILE=
Environment=WARDEN_SECRET_BACKEND=local
Environment=WARDEN_LOCAL_POLICY_FILE=/etc/warden/policy.toml
Environment=WARDEN_LOCAL_SECRETS_DIR=/var/lib/warden/secrets
IPAddressAllow=any
StandardOutput=truncate:$results/$name.out
StandardError=inherit
$extra
EOF
  systemctl daemon-reload
}

# 1. The unit's bind rules are enforced, and allow only what they should. Python
#    needs its own directories executable, and this changes nothing else.
cat > /etc/warden/bind-probe.py <<'PROBE'
import socket

for name, kind, port in (
    ("udp", socket.SOCK_DGRAM, 0),
    ("udp", socket.SOCK_DGRAM, 53),
    ("udp", socket.SOCK_DGRAM, 8080),
    ("tcp", socket.SOCK_STREAM, 0),
    ("tcp", socket.SOCK_STREAM, 9000),
    ("tcp", socket.SOCK_STREAM, 8080),
    ("tcp", socket.SOCK_STREAM, 8081),
):
    with socket.socket(socket.AF_INET, kind) as probe:
        try:
            probe.bind(("127.0.0.1", port))
            print(f"{name}:{port} allowed", flush=True)
        except PermissionError:
            print(f"{name}:{port} refused", flush=True)
PROBE
chmod 0644 /etc/warden/bind-probe.py
install_unit warden-test-probe "/usr/bin/python3 /etc/warden/bind-probe.py" oneshot \
  'ExecPaths=-/usr/bin -/bin
MemoryDenyWriteExecute=no'
systemctl start warden-test-probe.service || fail "the bind probe did not run"
expected='udp:0 allowed
udp:53 refused
udp:8080 refused
tcp:0 refused
tcp:9000 refused
tcp:8080 allowed
tcp:8081 allowed'
found=$(cat "$results/warden-test-probe.out")
if grep -Fxq 'tcp:9000 allowed' <<< "$found"; then
  fail "SocketBindDeny is not enforced here, so this tests nothing: check BPF_FRAMEWORK and libbpf, and run systemctl daemon-reexec"
fi
[ "$found" = "$expected" ] || fail "the unit's bind rules are not as expected:"$'\n'"$found"
echo 'ok: the unit allows only its two ports and an ephemeral UDP socket'

# 2. warden starts under the unit as it is, and answers.
install_unit warden-test '/usr/local/bin/warden-server serve' exec ''
trap 'systemctl stop warden-test.service' EXIT
systemctl start warden-test.service
set -a
# shellcheck source=/dev/null
. /etc/warden/warden.conf
set +a
for _ in $(seq 1 120); do
  if runuser -u warden -- /usr/local/bin/warden-server healthcheck > /dev/null 2>&1; then
    healthy=yes
    break
  fi
  systemctl is-active --quiet warden-test.service || fail "warden-server stopped: $(systemctl status warden-test.service --no-pager | tail -n 5)"
  sleep 0.5
done
[ "${healthy:-}" = yes ] || fail "warden-server did not answer its health check"
echo 'ok: warden-server starts under the unit and answers'

# 3. Under the same rules, it resolves a name and makes a TLS call. Doctor exits
#    non-zero on this host for reasons of its own, so only this line counts.
install_unit warden-test-doctor '/usr/local/bin/warden-server doctor --send-test-notification' oneshot ''
systemctl start warden-test-doctor.service || true
line=$(grep -E '(^|[[:space:]])notify\.ntfy[[:space:]]' "$results/warden-test-doctor.out" || true)
[ -n "$line" ] || fail "doctor did not report the notifier: $(cat "$results/warden-test-doctor.out")"
case "$line" in
  *'returned HTTP'* | pass*) ;;
  *) fail "warden-server could not resolve a name and reach it under the unit: $line" ;;
esac
echo 'ok: warden-server resolves a name and makes a TLS call under the unit'
