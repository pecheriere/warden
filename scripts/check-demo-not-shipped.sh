#!/usr/bin/env bash
# Fail if the local demo (crates/demo) could reach a real deployment.
#
# warden-demo treats every local caller as the owner and serves plain HTTP, so
# it must stay out of warden-server, the warden CLI and the image. A release
# attaches it only as its own archive, named as a demo. Each check below reads
# what is actually resolved or built, and fails if what it inspects is missing,
# so that a renamed package or a rewritten Dockerfile cannot make it pass by
# matching nothing.
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

# The demo itself keeps real passkey checks: it never enables the testkit.
tree="$(cargo tree -p warden-demo --features warden-broker/vendored-openssl \
  -e features,normal,build --target all --locked --prefix none)"
grep -q '^warden-demo v' <<<"$tree" || fail "warden-demo not found in its own dependency graph"
if grep -q '^warden-broker feature "testkit"' <<<"$tree"; then
  fail "warden-demo enables the broker's testkit feature"
fi

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
# Any cargo command at all, so that an alias such as `cargo b` cannot pass.
cargo_word='(^|[^[:alnum:]_/.-])cargo([^[:alnum:]_.-]|$)'
builds="$(grep -v '^ *#' Dockerfile | grep -E "$cargo_word" || true)"
[ -n "$builds" ] || fail "no cargo build found in the Dockerfile"
while IFS= read -r line; do
  case "$line" in
    *'cargo build --release --locked -p warden-broker --features vendored-openssl'*) ;;
    'RUN cargo clean --release -p warden-broker -p warden-broker-proto '*) ;;
    *) fail "the Dockerfile runs something else: $line" ;;
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
COPY NOTICE /NOTICE
COPY --from=builder --chown=65532:65532 --chmod=0700 /out/data /data'
[ "$copies" = "$expected_copies" ] \
  || fail "the image's final stage copies something unexpected: $copies"
grep -q '^ENTRYPOINT \["/warden-server"\]$' <<<"$final_stage" \
  || fail "the image's entrypoint is not warden-server"

# 4. The demo's sources never enter the build context of any image.
for path in crates/demo/src crates/demo/tests; do
  grep -qx "$path" .dockerignore || fail ".dockerignore does not exclude $path"
done

# 5. The release workflow builds binaries in one place only, the script, which
#    builds each product by itself, so the demo's archive holds the demo and no
#    other archive does. The script refuses a binary whose banner does not match
#    its product. The image's jobs use the Dockerfile, checked above.
workflow=.github/workflows/release.yml
builder=.github/workflows/build-archives.yml
script=scripts/package-binary.sh
for file in "$workflow" "$builder" "$script"; do
  [ -f "$file" ] || fail "$file not found"
  if offending="$(grep -nE -e '--workspace|--all-features|cargo install' "$file")"; then
    fail "$file could build the demo into something else: $offending"
  fi
done
# The one mention of the demo's name allowed is the line that limits its attestation.
for file in "$workflow" "$builder"; do
  if offending="$(grep -v '^ *#' "$file" \
    | grep -vx ' *subject-path: dist/warden-demo-\*\.tar\.gz' \
    | grep -nE "$cargo_word|warden-demo|crates/demo")"; then
    fail "$file must leave building the demo to $script: $offending"
  fi
done
[ "$(grep -c "$script" "$builder")" -eq 1 ] \
  || fail "$builder must call $script once"
if grep -n "$script" "$workflow"; then
  fail "$workflow must build through $builder"
fi
builds="$(grep -E '^ *build_args=' "$script")"
expected_builds='    build_args=(-p warden-broker-cli)
    build_args=(-p warden-demo --features warden-broker/vendored-openssl)
    build_args=(-p warden-broker --features vendored-openssl)'
[ "$builds" = "$expected_builds" ] \
  || fail "$script builds something unexpected: $builds"
commands="$(grep -v '^ *#' "$script" | grep -E "$cargo_word" || true)"
[ "$commands" = "  cargo build --config \"build.build-dir='\$build_dir'\" \\" ] \
  || fail "$script runs cargo in an unexpected way: $commands"
grep -qx ' *prefix=warden-demo' "$script" || fail "the demo's archive is not named as a demo"
[ -s crates/demo/NOT-FOR-REAL-USE.txt ] || fail "the demo's notice file is missing"
grep -qx ' *extra_file=crates/demo/NOT-FOR-REAL-USE.txt' "$script" \
  || fail "$script does not put the notice in the demo's archive"
# CI runs this on each archive, and the release workflow before attesting anything,
# so a notice dropped from the archive itself fails there.
grep -Fq 'extra_files=("NOT-FOR-REAL-USE.txt",)' .github/scripts/collect_archives.py \
  || fail "the release's archive check does not require the demo's notice"
grep -q "'WARDEN DEMO'" "$script" || fail "$script does not check binaries for the demo"

# 6. The demo cannot be published to a registry.
grep -qx 'publish = false' crates/demo/Cargo.toml || fail "warden-demo is publishable"

echo "ok: the demo is not in warden-server, warden or the image, and ships only as its own archive"
