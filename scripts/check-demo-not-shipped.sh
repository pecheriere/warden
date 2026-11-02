#!/usr/bin/env bash
# Fail if the local demo (crates/demo) could reach a real deployment.
#
# warden-demo treats every local caller as the owner and serves plain HTTP, so
# it must stay out of warden-server, the warden CLI, the image and the release
# workflow. Each check below reads what is actually resolved or built, and
# fails if what it inspects is missing, so that a renamed package or a
# rewritten Dockerfile cannot make it pass by matching nothing.
#
# Usage: scripts/check-demo-not-shipped.sh
set -euo pipefail

cd "$(dirname "$0")/.."

fail() {
  echo "error: $*" >&2
  echo "The demo must not reach production; see docs/demo.md." >&2
  exit 1
}

# 1. What gets linked: neither shipped binary may depend on the demo, or on the
#    broker's testkit (soft passkey, fake backend). Dev dependencies are left
#    out because they are not linked into the binaries.
for spec in 'warden-broker --features vendored-openssl' 'warden-broker-cli'; do
  package="${spec%% *}"
  # Word splitting of $spec is the point: it holds the package and its flags.
  # shellcheck disable=SC2086
  tree="$(cargo tree -p $spec -e features,normal,build --target all --locked --prefix none)"
  grep -q "^$package v" <<<"$tree" || fail "$package not found in its own dependency graph"
  if grep -q '^warden-demo' <<<"$tree"; then
    fail "$package depends on warden-demo"
  fi
  if grep -q '^warden-broker feature "testkit"' <<<"$tree"; then
    fail "$package enables the broker's testkit feature"
  fi
done

# 2. The broker's own code and manifest never mention the demo, and the only
#    source of identity outside the testkit is Tailscale Serve.
if offending="$(grep -rIlw -e demo -e warden-demo crates/broker/src crates/broker/Cargo.toml)"; then
  fail "the broker mentions the demo: $offending"
fi
identities="$(grep -rn --exclude-dir=testkit --exclude=testkit.rs 'impl IdentitySource for' crates/broker/src)"
case "$identities" in
  *$'\n'*) fail "more than one identity source in the broker: $identities" ;;
  *'TailscaleServeIdentity'*) ;;
  *) fail "the broker's identity source is not TailscaleServeIdentity: $identities" ;;
esac
grep -q 'identity: Arc::new(TailscaleServeIdentity)' crates/broker/src/main.rs \
  || fail "warden-server does not use TailscaleServeIdentity"

# 3. The Dockerfile builds only warden-server, and the image holds only that.
builds="$(grep -E 'cargo +(build|install|test)' Dockerfile || true)"
[ -n "$builds" ] || fail "no cargo build found in the Dockerfile"
while IFS= read -r line; do
  case "$line" in
    *'cargo build --release --locked -p warden-broker --features vendored-openssl'*) ;;
    *) fail "the Dockerfile builds something else: $line" ;;
  esac
done <<<"$builds"
# Only the empty placeholder that lets Cargo load the workspace may name it.
demo_lines="$(grep -n 'crates/demo\|warden-demo\|warden_demo' Dockerfile || true)"
expected_demo_lines=3
if [ "$(grep -c . <<<"$demo_lines")" -ne "$expected_demo_lines" ] \
  || ! grep -q 'COPY crates/demo/Cargo.toml crates/demo/$' <<<"$demo_lines" \
  || ! grep -q 'RUN mkdir -p .* crates/demo/src \\$' <<<"$demo_lines" \
  || ! grep -q "echo 'fn main() {}' > crates/demo/src/main.rs" <<<"$demo_lines"; then
  fail "the Dockerfile uses the demo beyond its placeholder: $demo_lines"
fi
final_stage="$(awk '/^FROM /{stage=""} {stage=stage $0 "\n"} END{printf "%s", stage}' Dockerfile)"
copies="$(grep '^COPY' <<<"$final_stage")"
expected_copies='COPY --from=builder /out/warden-server /warden-server
COPY --from=builder --chown=65532:65532 --chmod=0700 /out/data /data'
[ "$copies" = "$expected_copies" ] \
  || fail "the image's final stage copies something unexpected: $copies"
grep -q '^ENTRYPOINT \["/warden-server"\]$' <<<"$final_stage" \
  || fail "the image's entrypoint is not warden-server"

# 4. The demo's sources never enter the build context of any image.
for path in crates/demo/src crates/demo/tests; do
  grep -qx "$path" .dockerignore || fail ".dockerignore does not exclude $path"
done

# 5. The release workflow, and the script it builds the CLI with, neither build
#    nor publish the demo.
for file in .github/workflows/release.yml scripts/package-cli.sh; do
  [ -f "$file" ] || fail "$file not found"
  if offending="$(grep -nE 'warden-demo|crates/demo|--workspace|cargo install' "$file")"; then
    fail "$file could build the demo: $offending"
  fi
done
grep -q 'cargo build --release --locked -p warden-broker-cli ' scripts/package-cli.sh \
  || fail "scripts/package-cli.sh builds something other than the CLI"

# 6. The demo cannot be published to a registry.
grep -qx 'publish = false' crates/demo/Cargo.toml || fail "warden-demo is publishable"

echo "ok: the demo is not linked, built, shipped or published"
