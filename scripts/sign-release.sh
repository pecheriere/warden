#!/usr/bin/env bash
# Has warden sign the manifest of a draft release, once the release workflow has
# left the draft and before it is published: a published release is immutable, so it
# cannot gain these files later. docs/verifying-releases.md explains what the
# signature is for.
#
# Usage: scripts/sign-release.sh vX.Y.Z
#
# The signing key is the broker's, behind the owner's phone approval of the release
# grant (`warden request release`). This script holds no key and uploads nothing:
# `warden release sign-manifest` signs the manifest and attaches it, with its
# signature, to the draft. The script refuses to ask for that unless the tag carries
# a good signature from a key docs/release-signers lists under the identity
# warden-release, the draft holds exactly the expected files, and each archive, under
# its own name, and the image have a build attestation from the release workflow at
# that tag and commit. It then fetches the draft's manifest and signature and checks
# them against docs/release-signers before it says Signed. It never publishes. It
# needs gh (with a token from `warden github token`, in GH_TOKEN: it refuses to run
# without one, so that gh never falls back to a stored login), warden, git,
# ssh-keygen and shasum.
#
# A rerun is safe only until `warden release sign-manifest` has succeeded: the broker
# signs once per release grant, even when the check afterwards fails. If the workflow
# is rerun after signing (it replaces the archives and removes the manifest), or the
# script fails after signing, ask for a new release grant for the same tag and
# commit, which covers only the steps left, and run the script again. Never publish
# unless the script printed Signed for this tag.
set -euo pipefail

cd "$(dirname "$0")/.."

repo=pecheriere/warden
image=ghcr.io/pecheriere/warden
workflow=pecheriere/warden/.github/workflows/release.yml
signers=docs/release-signers
identity=warden-release
namespace=warden-release
# Every archive the release workflow attaches. warden-demo is the local demo: it is
# signed like the rest, because the signature says who approved a file, not that it
# is fit for real use. warden-server is released for Linux only.
archive_names=(warden warden-demo)
platforms=(linux-amd64 linux-arm64 macos-arm64)
linux_platforms=(linux-amd64 linux-arm64)

fail() {
  echo "error: $*" >&2
  exit 1
}

if [ "$#" -ne 1 ]; then
  echo "usage: $0 vX.Y.Z" >&2
  exit 2
fi
tag=$1
[ -n "${GH_TOKEN:-}" ] || fail "GH_TOKEN is not set: token=\$(warden github token) && GH_TOKEN=\$token $0 $tag"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "not a release tag: $tag"
version=${tag#v}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Checks the tag with ssh-keygen directly, so that the result depends on the
# list in this repository and not on this machine's git configuration.
git cat-file tag "refs/tags/$tag" > "$work/tag" 2> /dev/null || fail "$tag is not an annotated tag here: git fetch --tags"
sed -n '/^-----BEGIN SSH SIGNATURE-----$/,$p' "$work/tag" > "$work/tag.sig"
sed '/^-----BEGIN SSH SIGNATURE-----$/,$d' "$work/tag" > "$work/tag.payload"
tag_verdict=$(ssh-keygen -Y verify -f "$signers" -I "$identity" -n git -s "$work/tag.sig" < "$work/tag.payload" 2> /dev/null) \
  || fail "$tag has no good signature from a key in $signers"
# ssh-keygen ends its verdict with the key's fingerprint.
tag_key=${tag_verdict##* }
[[ "$tag_key" =~ ^SHA256: ]] || fail "unexpected verdict for the signature on $tag: $tag_verdict"
# A signed tag object can be moved to another ref, so its signed name must match.
signed_name=$(sed -n 's/^tag //p' "$work/tag.payload" | head -n 1)
[ "$signed_name" = "$tag" ] || fail "the tag at $tag was signed as $signed_name"
local_commit=$(git rev-parse "refs/tags/$tag^{commit}")
remote_commit=$(gh api "repos/$repo/commits/refs/tags/$tag" --jq .sha)
[ "$local_commit" = "$remote_commit" ] || fail "$tag is $local_commit here but $remote_commit on GitHub"

is_draft=$(gh release view "$tag" --repo "$repo" --json isDraft --jq .isDraft) || fail "no release for $tag yet"
[ "$is_draft" = true ] || fail "$tag is already published, so it cannot gain files"

# Only the archives are downloaded, so anything else on the draft must be refused
# here: publishing the draft would ship it, outside the manifest.
expected=$(
  for name in "${archive_names[@]}"; do
    for platform in "${platforms[@]}"; do
      echo "$name-$version-$platform.tar.gz"
    done
  done
  for platform in "${linux_platforms[@]}"; do
    echo "warden-server-$version-$platform.tar.gz"
  done
  # The CLI's Linux packages.
  echo "warden_${version}_amd64.deb"
  echo "warden_${version}_arm64.deb"
  echo "warden-$version-1.x86_64.rpm"
  echo "warden-$version-1.aarch64.rpm"
)
expected=$(LC_ALL=C sort <<< "$expected")
allowed=$expected$'\n'warden-$version-SHA256SUMS$'\n'warden-$version-SHA256SUMS.sig
assets=$(gh release view "$tag" --repo "$repo" --json assets --jq '.assets[].name')
while IFS= read -r asset; do
  [ -z "$asset" ] || grep -Fxq "$asset" <<< "$allowed" || fail "unexpected asset on the draft: $asset"
done <<< "$assets"

mkdir "$work/assets"
gh release download "$tag" --repo "$repo" --dir "$work/assets" \
  --pattern 'warden-*.tar.gz' --pattern 'warden_*.deb' --pattern 'warden-*.rpm'
found=$(cd "$work/assets" && LC_ALL=C ls)
[ "$found" = "$expected" ] || fail "the draft holds unexpected archives:"$'\n'"$found"

# The ref alone is not enough: an account able to bypass the tag ruleset could
# build other code under this tag and then restore the signed tag.
attestation_args=(--repo "$repo" --signer-workflow "$workflow" --source-ref "refs/tags/$tag"
  --source-digest "$local_commit")
manifest=$work/warden-$version-SHA256SUMS
: > "$manifest"
# gh finds an attestation by digest alone, so any file attested at this tag would
# pass under any name, such as a demo archive renamed as the CLI's. The attestation
# also records each file's name: the draft's file must match both.
while IFS= read -r file; do
  subjects=$(gh attestation verify "$work/assets/$file" "${attestation_args[@]}" --format json \
    --jq '.[].verificationResult.statement.subject[] | "\(.digest.sha256)  \(.name)"') \
    || fail "no valid attestation for $file"
  sum=$(cd "$work/assets" && shasum -a 256 "$file")
  grep -Fxq "$sum" <<< "$subjects" || fail "$file on the draft is not what was attested under that name"
  printf '%s\n' "$sum" >> "$manifest"
done <<< "$expected"

image_ref=$image:$version
image_digest=$(gh attestation verify "oci://$image_ref" "${attestation_args[@]}" --format json \
  --jq '.[0].verificationResult.statement.subject[0].digest.sha256') \
  || fail "no valid attestation for $image_ref"
[[ "$image_digest" =~ ^[0-9a-f]{64}$ ]] || fail "unexpected digest for $image_ref: $image_digest"
printf '%s  %s\n' "$image_digest" "$image_ref" >> "$manifest"

# From here on warden has signed, and signs once per grant: a failure below means
# do not publish, and a new release grant is needed before running this again.
after_signing() {
  fail "$* (do not publish; ask for a new release grant for $tag and run this again)"
}

# warden signs and attaches the manifest; it never leaves this machine's hands unchecked.
warden release sign-manifest "$repo" "$tag" "$manifest" || after_signing "warden could not sign the manifest"

# What the draft now holds is what counts, so it is fetched back and checked against
# the list in this repository, and against the manifest that was sent.
mkdir "$work/draft"
gh release download "$tag" --repo "$repo" --dir "$work/draft" \
  --pattern "warden-$version-SHA256SUMS" --pattern "warden-$version-SHA256SUMS.sig" \
  || after_signing "could not fetch the draft's manifest and signature"
drafted=$work/draft/warden-$version-SHA256SUMS
cmp -s "$manifest" "$drafted" || after_signing "the draft's manifest is not the one that was sent"
manifest_verdict=$(ssh-keygen -Y verify -f "$signers" -I "$identity" -n "$namespace" -s "$drafted.sig" < "$drafted" 2> /dev/null) \
  || after_signing "the signature on the draft does not verify against $signers"
# One key must stand behind both, so a retired key's tag cannot pass with a new key's manifest.
[ "${manifest_verdict##* }" = "$tag_key" ] \
  || after_signing "the manifest is not signed by the key that signed the tag"

cat "$manifest"
echo "Signed. Check the draft, then publish it: warden release publish $repo $tag"
