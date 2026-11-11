#!/usr/bin/env bash
# Tests scripts/sign-release.sh, which otherwise only runs during a release. It
# copies the script into a throwaway repository with a throwaway key and replaces
# `gh` and `warden` with stubs, so it touches neither GitHub, the broker nor this
# machine's keys. The stub `warden` signs with the throwaway key, as the broker
# signs with its own, and "uploads" to the stub draft. The script reads the
# signers from docs/release-signers of the repository it sits in, so the test
# needs no override: its copy of the script sits in a repository with its own list.
# Each case that must refuse before signing also checks that nothing was uploaded.
#
# Usage: scripts/test-sign-release.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
identity=warden-release
old_identity=pecheriere@users.noreply.github.com
version=1.2.3
tag=v$version
image_digest=$(printf 'image' | shasum -a 256 | cut -d' ' -f1)

ssh-keygen -q -t ed25519 -N '' -C test-release -f "$work/release-key"
ssh-keygen -q -t ed25519 -N '' -C test-other -f "$work/other-key"
ssh-keygen -q -t ed25519 -N '' -C test-old -f "$work/old-key"

repo=$work/repo
mkdir -p "$repo/scripts" "$repo/docs"
cp "$root/scripts/sign-release.sh" "$repo/scripts/"
printf '%s namespaces="git,warden-release" %s\n' "$old_identity" "$(cat "$work/old-key.pub")" > "$repo/docs/release-signers"
printf '%s namespaces="git,warden-release" %s\n' "$identity" "$(cat "$work/release-key.pub")" >> "$repo/docs/release-signers"
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
  'release download')
    from=$STUB/assets
    case "$*" in *SHA256SUMS*) from=$STUB/uploaded ;; esac
    while [ "$1" != --dir ]; do shift; done
    cp "$from"/* "$2/"
    ;;
  'attestation verify')
    subject=$3
    if [ -e "$STUB/unattested" ] && [ "$(basename "$subject")" = "$(cat "$STUB/unattested")" ]; then exit 1; fi
    digest=
    while [ "$#" -gt 1 ]; do
      if [ "$1" = --source-digest ]; then digest=$2; fi
      shift
    done
    if [ "$digest" != "$(cat "$STUB/attested-commit")" ]; then exit 1; fi
    case "$subject" in
      oci://*) cat "$STUB/image-digest" ;;
      # What the attestation records: the digest and name of each file it covers.
      *)
        name=$(basename "$subject")
        if [ -e "$STUB/attested-as" ]; then name=$(cat "$STUB/attested-as"); fi
        sum=$(shasum -a 256 "$subject" | cut -d' ' -f1)
        if [ -e "$STUB/attested-digest" ]; then sum=$(cat "$STUB/attested-digest"); fi
        printf '%s  %s\n' "$sum" "$name"
        printf '%s  %s\n' 0000000000000000000000000000000000000000000000000000000000000000 other.tar.gz
        ;;
    esac
    ;;
  *)
    echo "stub gh: unexpected call: $*" >&2
    exit 64
    ;;
esac
STUB_GH
chmod +x "$work/bin/gh"

# The stub warden gets the manifest's path and the tag, as the real one does, signs
# the manifest as the broker would and puts both on the stub draft.
cat > "$work/bin/warden" <<'STUB_WARDEN'
#!/usr/bin/env bash
set -euo pipefail
[ "$1 $2" = 'release sign-manifest' ] || { echo "stub warden: unexpected call: $*" >&2; exit 64; }
printf '%s\n' "$*" > "$STUB/warden-args"
file=$5
cp "$file" "$STUB/warden-manifest"
key=$STUB/signing-key
if [ -e "$STUB/signs-with" ]; then key=$(cat "$STUB/signs-with"); fi
dir=$(mktemp -d)
cp "$file" "$dir/"
ssh-keygen -q -Y sign -n warden-release -f "$key" "$dir/$(basename "$file")"
if [ -e "$STUB/alters-manifest" ]; then
  # What was signed is not what the script built.
  printf '%s  extra.tar.gz\n' "$(printf 'x' | shasum -a 256 | cut -d' ' -f1)" >> "$dir/$(basename "$file")"
fi
cp "$dir/$(basename "$file")" "$dir/$(basename "$file").sig" "$STUB/uploaded/"
rm -rf "$dir"
echo "manifest $(basename "$file")"
STUB_WARDEN
chmod +x "$work/bin/warden"
export PATH="$work/bin:$PATH"

reset_stub() {
  rm -rf "$STUB/uploaded" "$STUB/unattested" "$STUB/assets" "$STUB/attested-as" "$STUB/attested-digest" \
    "$STUB/warden-args" "$STUB/warden-manifest" "$STUB/signs-with" "$STUB/alters-manifest"
  cp "$work/release-key" "$STUB/signing-key"
  mkdir -p "$STUB/uploaded" "$STUB/assets"
  git -C "$repo" rev-parse "$tag^{commit}" > "$STUB/remote-commit"
  cp "$STUB/remote-commit" "$STUB/attested-commit"
  : > "$STUB/also-listed"
  echo true > "$STUB/is-draft"
  echo "$image_digest" > "$STUB/image-digest"
  for name in warden warden-demo; do
    for platform in linux-amd64 linux-arm64 macos-arm64; do
      echo "$name $platform" > "$STUB/assets/$name-$version-$platform.tar.gz"
    done
  done
  for platform in linux-amd64 linux-arm64; do
    echo "server $platform" > "$STUB/assets/warden-server-$version-$platform.tar.gz"
  done
  for package in "warden_${version}_amd64.deb" "warden_${version}_arm64.deb" \
    "warden-$version-1.x86_64.rpm" "warden-$version-1.aarch64.rpm"; do
    echo "$package" > "$STUB/assets/$package"
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
git -C "$repo" config user.signingkey "$work/old-key.pub"
git -C "$repo" tag -s -m old-signer v5.5.5
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
# The older key stays listed for its own identity, so that old tags verify, but a
# new release's tag must come from the identity warden-release.
must_refuse 'tag not signed by a listed warden-release key' 'no good signature' v5.5.5

echo 0000000000000000000000000000000000000000 > "$STUB/remote-commit"
must_refuse 'tag that differs on GitHub' 'on GitHub' "$tag"

reset_stub
echo false > "$STUB/is-draft"
must_refuse 'release already published' 'already published' "$tag"

reset_stub
rm "$STUB/assets/warden-$version-linux-arm64.tar.gz"
must_refuse 'missing archive' 'unexpected archives' "$tag"

reset_stub
rm "$STUB/assets/warden-demo-$version-macos-arm64.tar.gz"
must_refuse 'missing demo archive' 'unexpected archives' "$tag"

reset_stub
rm "$STUB/assets/warden_${version}_arm64.deb"
must_refuse 'missing .deb' 'unexpected archives' "$tag"

reset_stub
rm "$STUB/assets/warden-$version-1.x86_64.rpm"
must_refuse 'missing .rpm' 'unexpected archives' "$tag"

reset_stub
echo extra > "$STUB/assets/warden-demo_${version}_amd64.deb"
must_refuse 'a package of the demo' 'unexpected asset' "$tag"

reset_stub
echo extra > "$STUB/assets/warden-server-$version-1.x86_64.rpm"
must_refuse 'a package of the server' 'unexpected asset' "$tag"

reset_stub
echo "warden-$version-1.aarch64.rpm" > "$STUB/unattested"
must_refuse '.rpm without an attestation' 'no valid attestation' "$tag"

reset_stub
echo "warden-demo-$version-linux-amd64.tar.gz" > "$STUB/attested-as"
must_refuse 'demo archive renamed as a package' 'not what was attested' "$tag"

reset_stub
rm "$STUB/assets/warden-server-$version-linux-arm64.tar.gz"
must_refuse 'missing server archive' 'unexpected archives' "$tag"

reset_stub
echo extra > "$STUB/assets/warden-server-$version-macos-arm64.tar.gz"
must_refuse 'server archive for a platform it is not released for' 'unexpected asset' "$tag"

reset_stub
echo "warden-server-$version-linux-amd64.tar.gz" > "$STUB/unattested"
must_refuse 'server archive without an attestation' 'no valid attestation' "$tag"

reset_stub
echo "warden-demo-$version-linux-amd64.tar.gz" > "$STUB/attested-as"
must_refuse 'demo archive renamed as the server' 'not what was attested' "$tag"

reset_stub
echo extra > "$STUB/assets/warden-demo-$version-windows-amd64.tar.gz"
must_refuse 'extra demo archive' 'unexpected asset' "$tag"

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
echo "warden-demo-$version-linux-amd64.tar.gz" > "$STUB/unattested"
must_refuse 'demo archive without an attestation' 'no valid attestation' "$tag"

reset_stub
echo "warden:$version" > "$STUB/unattested"
must_refuse 'image without an attestation' 'no valid attestation' "$tag"

reset_stub
echo "warden-demo-$version-linux-amd64.tar.gz" > "$STUB/attested-as"
must_refuse 'demo archive renamed as the CLI' 'not what was attested' "$tag"

reset_stub
printf 'a%.0s' {1..64} > "$STUB/attested-digest"
must_refuse 'attestation of other bytes under the same name' 'not what was attested' "$tag"

reset_stub
echo 1111111111111111111111111111111111111111 > "$STUB/attested-commit"
must_refuse 'attestations from another commit' 'no valid attestation' "$tag"

reset_stub
echo not-a-digest > "$STUB/image-digest"
must_refuse 'malformed image digest' 'unexpected digest' "$tag"

# warden returns, and the draft holds, a signature that does not verify.
reset_stub
echo "$work/other-key" > "$STUB/signs-with"
output=$(sign "$tag" 2>&1) && { echo "FAIL: refuses_when_returned_signature_does_not_verify: it signed" >&2; exit 1; }
grep -Fq 'does not verify' <<< "$output" \
  || { echo "FAIL: refuses_when_returned_signature_does_not_verify: wrong reason: $output" >&2; exit 1; }
grep -Fq 'Signed' <<< "$output" && { echo "FAIL: refuses_when_returned_signature_does_not_verify: said Signed" >&2; exit 1; }
echo 'ok: refuses_when_returned_signature_does_not_verify'

# The draft's manifest is not the one the script built and sent.
reset_stub
touch "$STUB/alters-manifest"
output=$(sign "$tag" 2>&1) && { echo "FAIL: draft manifest that differs: it signed" >&2; exit 1; }
grep -Fq 'is not the one that was sent' <<< "$output" \
  || { echo "FAIL: draft manifest that differs: wrong reason: $output" >&2; exit 1; }
echo 'ok: draft manifest that differs from the one sent'

# The good case, then the steps docs/verifying-releases.md gives to users.
reset_stub
printf 'warden-%s-SHA256SUMS\nwarden-%s-SHA256SUMS.sig\n' "$version" "$version" > "$STUB/also-listed"
sign "$tag" > /dev/null
manifest=$STUB/uploaded/warden-$version-SHA256SUMS
[ "$(cut -d' ' -f1-4 "$STUB/warden-args")" = "release sign-manifest pecheriere/warden $tag" ] \
  || { echo "FAIL: signs_through_warden: warden got: $(cat "$STUB/warden-args")" >&2; exit 1; }
[ "$(basename "$(cut -d' ' -f5 "$STUB/warden-args")")" = "warden-$version-SHA256SUMS" ] \
  || { echo "FAIL: signs_through_warden: wrong manifest name: $(cat "$STUB/warden-args")" >&2; exit 1; }
cmp -s "$STUB/warden-manifest" "$manifest" \
  || { echo "FAIL: signs_through_warden: the manifest warden got is not the draft's" >&2; exit 1; }
echo 'ok: signs_through_warden'
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

for name in warden warden-demo; do
  for platform in linux-amd64 linux-arm64 macos-arm64; do
    if ! grep -Fq "  $name-$version-$platform.tar.gz" "$manifest"; then
      echo "FAIL: the manifest does not list $name for $platform" >&2
      exit 1
    fi
  done
done
for platform in linux-amd64 linux-arm64; do
  if ! grep -Fq "  warden-server-$version-$platform.tar.gz" "$manifest"; then
    echo "FAIL: the manifest does not list warden-server for $platform" >&2
    exit 1
  fi
done
for package in "warden_${version}_amd64.deb" "warden_${version}_arm64.deb" \
  "warden-$version-1.x86_64.rpm" "warden-$version-1.aarch64.rpm"; do
  if ! grep -Fq "  $package" "$manifest"; then
    echo "FAIL: the manifest does not list $package" >&2
    exit 1
  fi
done
echo 'ok: the manifest lists every archive'

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
