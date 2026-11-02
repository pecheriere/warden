#!/usr/bin/env bash
# Tests scripts/sign-release.sh, which otherwise only runs during a release. It
# copies the script into a throwaway repository with a throwaway key and replaces
# `gh` with a stub, so it touches neither GitHub nor this machine's keys. Each
# case that must refuse also checks that nothing was uploaded.
#
# Usage: scripts/test-sign-release.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
identity=pecheriere@users.noreply.github.com
version=1.2.3
tag=v$version
image_digest=$(printf 'image' | shasum -a 256 | cut -d' ' -f1)

ssh-keygen -q -t ed25519 -N '' -C test-release -f "$work/release-key"
ssh-keygen -q -t ed25519 -N '' -C test-other -f "$work/other-key"

repo=$work/repo
mkdir -p "$repo/scripts" "$repo/docs"
cp "$root/scripts/sign-release.sh" "$repo/scripts/"
printf '%s namespaces="git,warden-release" %s\n' "$identity" "$(cat "$work/release-key.pub")" > "$repo/docs/release-signers"
git -C "$repo" init -q
git -C "$repo" add .
git -C "$repo" config user.name test
git -C "$repo" config user.email "$identity"
git -C "$repo" config gpg.format ssh
git -C "$repo" config user.signingkey "$work/release-key.pub"
git -C "$repo" commit -q --no-gpg-sign -m initial

# The stub answers from files in $STUB, so that each case can break one answer.
export STUB=$work/stub
mkdir -p "$work/bin" "$STUB/assets"
cat > "$work/bin/gh" <<'STUB_GH'
#!/usr/bin/env bash
set -euo pipefail
case "$1 ${2:-}" in
  'api repos/'*) cat "$STUB/remote-commit" ;;
  'release view')
    if [ "$7" = assets ]; then
      ls "$STUB/assets"
      cat "$STUB/also-listed"
    else
      cat "$STUB/is-draft"
    fi
    ;;
  'release download') cp "$STUB"/assets/* "$9/" ;;
  'release upload') cp "$4" "$5" "$STUB/uploaded/" ;;
  'attestation verify')
    subject=$3
    if [ -e "$STUB/unattested" ] && [ "$(basename "$subject")" = "$(cat "$STUB/unattested")" ]; then exit 1; fi
    digest=
    while [ "$#" -gt 1 ]; do
      if [ "$1" = --source-digest ]; then digest=$2; fi
      shift
    done
    if [ "$digest" != "$(cat "$STUB/attested-commit")" ]; then exit 1; fi
    case "$subject" in oci://*) cat "$STUB/image-digest" ;; esac
    ;;
  *)
    echo "stub gh: unexpected call: $*" >&2
    exit 64
    ;;
esac
STUB_GH
chmod +x "$work/bin/gh"
export PATH="$work/bin:$PATH"

reset_stub() {
  rm -rf "$STUB/uploaded" "$STUB/unattested" "$STUB/assets"
  mkdir -p "$STUB/uploaded" "$STUB/assets"
  git -C "$repo" rev-parse "$tag^{commit}" > "$STUB/remote-commit"
  cp "$STUB/remote-commit" "$STUB/attested-commit"
  : > "$STUB/also-listed"
  echo true > "$STUB/is-draft"
  echo "$image_digest" > "$STUB/image-digest"
  for platform in linux-amd64 linux-arm64 macos-arm64; do
    echo "$platform" > "$STUB/assets/warden-$version-$platform.tar.gz"
  done
}

sign() {
  "$repo/scripts/sign-release.sh" "$@"
}

must_refuse() {
  local name=$1 expected=$2
  shift 2
  local output status=0
  output=$(sign "$@" 2>&1) || status=$?
  if [ "$status" -eq 0 ]; then
    echo "FAIL: $name: it signed" >&2
    exit 1
  fi
  if ! grep -Fq "$expected" <<< "$output"; then
    echo "FAIL: $name: wrong reason: $output" >&2
    exit 1
  fi
  if [ -n "$(ls "$STUB/uploaded")" ]; then
    echo "FAIL: $name: it uploaded files" >&2
    exit 1
  fi
  echo "ok: $name"
}

# A tag signed by a key that is not listed comes first, then the good tag.
git -C "$repo" config user.signingkey "$work/other-key.pub"
git -C "$repo" tag -s -m other-signer v9.9.9
git -C "$repo" config user.signingkey "$work/release-key.pub"
git -C "$repo" tag -a --no-sign -m unsigned v8.8.8
git -C "$repo" tag -s -m "warden $version" "$tag"
git -C "$repo" update-ref refs/tags/v6.6.6 "$(git -C "$repo" rev-parse "refs/tags/$tag")"

reset_stub
must_refuse 'not a release tag' 'not a release tag' main
must_refuse 'tag signed by an unlisted key' 'no good signature' v9.9.9
must_refuse 'unsigned tag' 'no good signature' v8.8.8
must_refuse 'tag that does not exist' 'not an annotated tag' v7.7.7
must_refuse 'signed tag moved to another name' 'signed as' v6.6.6
must_refuse 'signing key that is not listed' 'not listed' "$tag" "$work/other-key.pub"

echo 0000000000000000000000000000000000000000 > "$STUB/remote-commit"
must_refuse 'tag that differs on GitHub' 'on GitHub' "$tag"

reset_stub
echo false > "$STUB/is-draft"
must_refuse 'release already published' 'already published' "$tag"

reset_stub
rm "$STUB/assets/warden-$version-linux-arm64.tar.gz"
must_refuse 'missing archive' 'unexpected archives' "$tag"

reset_stub
echo extra > "$STUB/assets/warden-$version-windows-amd64.tar.gz"
must_refuse 'extra archive' 'unexpected asset' "$tag"

reset_stub
echo checksums.txt > "$STUB/also-listed"
must_refuse 'file that is not an archive' 'unexpected asset' "$tag"

reset_stub
echo "warden-$version-macos-arm64.tar.gz" > "$STUB/unattested"
must_refuse 'archive without an attestation' 'no valid attestation' "$tag"

reset_stub
echo "warden:$version" > "$STUB/unattested"
must_refuse 'image without an attestation' 'no valid attestation' "$tag"

reset_stub
echo 1111111111111111111111111111111111111111 > "$STUB/attested-commit"
must_refuse 'attestations from another commit' 'no valid attestation' "$tag"

reset_stub
echo not-a-digest > "$STUB/image-digest"
must_refuse 'malformed image digest' 'unexpected digest' "$tag"

# The good case, then the steps docs/verifying-releases.md gives to users.
reset_stub
printf 'warden-%s-SHA256SUMS\nwarden-%s-SHA256SUMS.sig\n' "$version" "$version" > "$STUB/also-listed"
sign "$tag" > /dev/null
manifest=$STUB/uploaded/warden-$version-SHA256SUMS
verify_manifest() {
  ssh-keygen -Y verify -f "$repo/docs/release-signers" -I "$identity" -n warden-release \
    -s "$manifest.sig" < "$manifest" > /dev/null 2>&1
}
verify_manifest || { echo "FAIL: the signature does not verify" >&2; exit 1; }
echo 'ok: the signature verifies'

(
  cd "$STUB/assets"
  file=warden-$version-linux-amd64.tar.gz
  grep -F "  $file" "$manifest" | shasum -a 256 -c - > /dev/null
  echo tampered > "$file"
  if grep -F "  $file" "$manifest" | shasum -a 256 -c - > /dev/null 2>&1; then
    echo "FAIL: a changed archive passed the check" >&2
    exit 1
  fi
)
echo 'ok: the manifest catches a changed archive'

if ! grep -Fxq "$image_digest  ghcr.io/pecheriere/warden:$version" "$manifest"; then
  echo "FAIL: the manifest does not name the image" >&2
  exit 1
fi
echo 'ok: the manifest names the image digest'

if ssh-keygen -Y verify -f "$repo/docs/release-signers" -I "$identity" -n git \
  -s "$manifest.sig" < "$manifest" > /dev/null 2>&1; then
  echo "FAIL: the signature verifies in the git namespace" >&2
  exit 1
fi
echo 'ok: a manifest signature is not valid for git'

echo tampered >> "$manifest"
if verify_manifest; then
  echo "FAIL: a changed manifest verified" >&2
  exit 1
fi
echo 'ok: a changed manifest fails'
