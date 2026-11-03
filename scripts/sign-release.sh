#!/usr/bin/env bash
# Signs the manifest of a draft release, with a key that is not on GitHub. The
# maintainer runs this after the release workflow has left the draft, and before
# publishing it: a published release is immutable, so it cannot gain these files
# later. docs/verifying-releases.md explains what the signature is for.
#
# Usage: scripts/sign-release.sh vX.Y.Z [public-key-file]
#
# The key defaults to git's user.signingkey, and must be listed in
# docs/release-signers for the warden-release namespace. The script refuses to
# sign unless the tag carries a good signature from that same key and was signed
# under that name, the draft holds
# exactly the expected files, and each archive, under its own name, and the image
# have a build attestation from the release workflow at that tag and commit. It
# then uploads warden-<version>-SHA256SUMS and its .sig to the draft. It never
# publishes. It needs gh, git, ssh-keygen and shasum, and is safe to rerun. A rerun
# of the workflow replaces the archives and removes the manifest, so sign again.
set -euo pipefail

cd "$(dirname "$0")/.."

repo=pecheriere/warden
image=ghcr.io/pecheriere/warden
workflow=pecheriere/warden/.github/workflows/release.yml
signers=docs/release-signers
identity=pecheriere@users.noreply.github.com
namespace=warden-release
# Every archive the release workflow attaches. warden-demo is the local demo: it is
# signed like the rest, because the signature says who approved a file, not that it
# is fit for real use.
archive_names=(warden warden-demo)
platforms=(linux-amd64 linux-arm64 macos-arm64)

fail() {
  echo "error: $*" >&2
  exit 1
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 vX.Y.Z [public-key-file]" >&2
  exit 2
fi
tag=$1
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "not a release tag: $tag"
version=${tag#v}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The key can be a file or, as with an agent-held key, the literal public key.
key=${2:-$(git config --type=path user.signingkey || true)}
key=${key#key::}
case "$key" in
  '') fail "no key given, and git has no user.signingkey" ;;
  ssh-*)
    printf '%s\n' "$key" > "$work/key.pub"
    key=$work/key.pub
    ;;
esac
[ -r "$key" ] || fail "cannot read the public key: $key"
read -r key_type key_blob _ < "$key"
grep -Fq "$key_type $key_blob" "$signers" || fail "the key is not listed in $signers"
grep -v '^#' "$signers" | grep -F "$key_type $key_blob" | grep -q 'namespaces="[^"]*warden-release' \
  || fail "the key may not sign manifests: $signers limits it to other namespaces"
key_fingerprint=$(ssh-keygen -lf "$key" | awk '{ print $2 }')

# Checks the tag with ssh-keygen directly, so that the result depends on the
# list in this repository and not on this machine's git configuration.
git cat-file tag "refs/tags/$tag" > "$work/tag" 2> /dev/null || fail "$tag is not an annotated tag here: git fetch --tags"
sed -n '/^-----BEGIN SSH SIGNATURE-----$/,$p' "$work/tag" > "$work/tag.sig"
sed '/^-----BEGIN SSH SIGNATURE-----$/,$d' "$work/tag" > "$work/tag.payload"
tag_check=$(ssh-keygen -Y verify -f "$signers" -I "$identity" -n git -s "$work/tag.sig" < "$work/tag.payload" 2>&1) \
  || fail "$tag has no good signature from a key in $signers"
# An older key stays listed so that its tags verify, but a new release's tag must
# come from the key that signs its manifest. Otherwise git's default key can sign a
# tag without anyone noticing.
[ "${tag_check##* }" = "$key_fingerprint" ] \
  || fail "$tag was signed by another key, not $key_fingerprint: sign the tag with the release key"
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
  done | LC_ALL=C sort
)
allowed=$expected$'\n'warden-$version-SHA256SUMS$'\n'warden-$version-SHA256SUMS.sig
assets=$(gh release view "$tag" --repo "$repo" --json assets --jq '.assets[].name')
while IFS= read -r asset; do
  [ -z "$asset" ] || grep -Fxq "$asset" <<< "$allowed" || fail "unexpected asset on the draft: $asset"
done <<< "$assets"

mkdir "$work/assets"
gh release download "$tag" --repo "$repo" --pattern 'warden-*.tar.gz' --dir "$work/assets"
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

# Signs the way git does, so a key held in an agent works the same as for a tag.
program=$(git config gpg.ssh.program || echo ssh-keygen)
"$program" -Y sign -n "$namespace" -f "$key" "$manifest"
ssh-keygen -Y verify -f "$signers" -I "$identity" -n "$namespace" -s "$manifest.sig" < "$manifest" \
  || fail "the new signature does not verify against $signers"

gh release upload "$tag" "$manifest" "$manifest.sig" --repo "$repo" --clobber

cat "$manifest"
echo "Signed. Check the draft, then publish it: gh release edit $tag --repo $repo --draft=false"
