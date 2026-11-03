# Verifying a release

Each warden release from the first one after v0.8.1 can be checked in two
independent ways. They answer different questions, so check both.

| Check | Signed by | It answers |
|---|---|---|
| **Signed manifest** (`warden-<version>-SHA256SUMS` and its `.sig`) | The maintainer's SSH key, off GitHub | Did the maintainer approve exactly these files and this image? |
| **Build attestation** (`gh attestation verify`) | A short-lived key on the GitHub Actions runner, certified by Sigstore | Did warden's release workflow build this from this tag? |

The attestation alone is not enough if GitHub itself, or an account that can
change this repository, is compromised: that attacker could run a workflow and
get a valid attestation. They could not produce the maintainer's signature,
because that key is never on GitHub. The signature only helps, though, if you got
the maintainer's public key before the compromise: see step 1. It also does not
say how the files were built.

Nothing stops a release being published without a manifest, because signing is a
manual step and the workflow cannot do it. Treat a release after v0.8.1 that has
no manifest as unsigned.

GitHub also attests each immutable release (`gh release verify`). GitHub signs
that with its own key, so it shows that the release has not changed since it was
published, not who approved it.

## 1. Get the maintainer's key

The public key is in [`docs/release-signers`](release-signers), in the format
`ssh-keygen` reads:

```sh
curl -fsSLO https://raw.githubusercontent.com/pecheriere/warden/main/docs/release-signers
grep -v '^#' release-signers | awk '{ print $3, $4 }' | ssh-keygen -lf -
```

Compare that fingerprint with the signing keys on the maintainer's GitHub account:

```sh
curl -fsSL https://api.github.com/users/pecheriere/ssh_signing_keys | jq -r '.[].key' | ssh-keygen -lf -
```

The first command should print
`SHA256:aF+0knqtnI3TWceyXtxVRGbcfH64yoZfRGJ3HnDbPT4`, and the second should list
it. The account can hold other signing keys; only the ones in `release-signers`
sign releases.

**There is no source for this key off GitHub yet.** The file, the account and this
page are all on GitHub, so a compromise of GitHub could change them together, and
checking one against another does not detect that. If you first fetch the key after
such a compromise, the signature check proves nothing. Keep your copy of the file
and reuse it for later releases: a compromise after that cannot replace the key you
hold.

If the key ever changes, the file changes in a pull request and `CHANGELOG.md` says
so. Merges to `main` are squashed, so the commit carries GitHub's signature rather
than the maintainer's, and it does not show who made the change. Treat an unexplained
change as a reason to stop.

## 2. Verify an archive

A release can hold these archives, and the manifest lists each one it holds. Each
is built by its own job, and the workflow stops before attesting anything unless each
job's upload holds exactly its own file. They are attested one product at a time: the
CLI, its packages and the image first, then the server, then the demo, so a file changed after
its attestation is refused. That does not cover earlier in the run: see
[Not covered yet](#not-covered-yet).

| File | What it is | Platforms | In releases |
|---|---|---|---|
| `warden-<version>-<platform>.tar.gz` | The `warden` CLI | `linux-amd64`, `linux-arm64`, `macos-arm64` | v0.9.0 onward |
| `warden_<version>_<arch>.deb`, `warden-<version>-1.<arch>.rpm` | The `warden` CLI as a package, holding the same binary as its archive. Not signed with a package key: these checks are what cover them. | `amd64`, `arm64` (`x86_64`, `aarch64` for `.rpm`) | After v0.9.0 |
| `warden-server-<version>-<platform>.tar.gz` | `warden-server`, for [running without Docker](deployment-systemd.md) | `linux-amd64`, `linux-arm64` | After v0.9.0 |
| `warden-demo-<version>-<platform>.tar.gz` | [The local demo](demo.md). **Not secure for real use**: verifying it shows where it came from, not that it is safe to rely on. | `linux-amd64`, `linux-arm64`, `macos-arm64` | After v0.9.0 |

```sh
version=x.y.z         # the release you picked
platform=linux-amd64  # or linux-arm64, macos-arm64
file="warden-$version-$platform.tar.gz"   # or any file in the table above
base="https://github.com/pecheriere/warden/releases/download/v$version"
curl -fLO "$base/$file"
curl -fLO "$base/warden-$version-SHA256SUMS"
curl -fLO "$base/warden-$version-SHA256SUMS.sig"

# The maintainer signed this list of hashes. Expect: Good "warden-release" signature
ssh-keygen -Y verify -f release-signers -I pecheriere@users.noreply.github.com \
  -n warden-release -s "warden-$version-SHA256SUMS.sig" < "warden-$version-SHA256SUMS"

# The archive is the one on the list. Expect: <file>: OK
grep -F "  $file" "warden-$version-SHA256SUMS" | shasum -a 256 -c -

# warden's release workflow built it from that tag.
gh attestation verify "$file" --repo pecheriere/warden \
  --signer-workflow pecheriere/warden/.github/workflows/release.yml \
  --source-ref "refs/tags/v$version"
```

`gh` must be logged in. Any step that fails means you should not use the file.

The attestation step finds an attestation by the file's digest, not its name. The
signed manifest ties each name to a digest, and `scripts/sign-release.sh` refuses to
sign a file attested under another name, so check the manifest as well.

## 3. Verify the image

The manifest lists the digest of the multi-arch image. Run warden by that digest,
not by its tag: a registry can move a tag.

```sh
digest=$(awk -v ref="ghcr.io/pecheriere/warden:$version" '$2 == ref { print "sha256:" $1 }' \
  "warden-$version-SHA256SUMS")
echo "$digest"   # stop if this is empty
gh attestation verify "oci://ghcr.io/pecheriere/warden@$digest" --repo pecheriere/warden \
  --signer-workflow pecheriere/warden/.github/workflows/release.yml \
  --source-ref "refs/tags/v$version"
```

Verify the manifest's signature first, as in step 2. Then pin
`ghcr.io/pecheriere/warden@$digest` in your Compose file.

## 4. Verify the source

Release tags are signed with the same key. This checks a tag in a clone, whatever
your git configuration says:

```sh
tag=vx.y.z
git cat-file tag "$tag" > tag.txt
sed -n '/^-----BEGIN SSH SIGNATURE-----$/,$p' tag.txt > tag.sig
sed '/^-----BEGIN SSH SIGNATURE-----$/,$d' tag.txt > tag.payload
ssh-keygen -Y verify -f release-signers -I pecheriere@users.noreply.github.com \
  -n git -s tag.sig < tag.payload
grep -x "tag $tag" tag.payload   # the name it was signed under; expect one line
```

## What older releases have

| Version | Tag | Image attestation | Archives | Signed manifest |
|---|---|---|---|---|
| After v0.9.0 | Signed | Yes | CLI with `.deb` and `.rpm`, server and demo, attested | Yes |
| v0.9.0 | Signed | Yes | CLI, attested | Yes |
| v0.8.1 | Signed | Yes | None | **No** |
| v0.8.0 | Signed | Never released | Never released | No |
| v0.1.0 to v0.7.0 | **Not signed** (lightweight tags) | Yes | None | **No** |

The commits under the unsigned tags carry GitHub's web-flow signature from the
merge, which shows only that GitHub made them. v0.8.0 was tagged but never
released, so nothing was published for it. For v0.8.1, check the tag as in step 4
and the image's attestation as in step 3, using the digest from
`docker buildx imagetools inspect ghcr.io/pecheriere/warden:0.8.1`; no maintainer
signature covers that image.

## Where the signing key is

The private key is not on GitHub: the repository has no Actions secret holding it,
no workflow uses it, and only its public half is listed on the account and in this
repository. It is a file on the maintainer's machine, so it guards against a
compromise of GitHub, and not against something running as the maintainer there. The release workflow
cannot sign the manifest, which is why the maintainer signs it after the workflow
has finished, with `scripts/sign-release.sh`, before publishing the draft.

## Not covered yet

**A malicious dependency that runs before the attestations.** The release's `ci` job
tests every workspace crate, so each dependency's build script runs in the same
workflow run before anything is attested. That has to come first, so that no image or
attestation exists until the tests pass. A build script that stole that job's runner
token could try to replace an artifact from another job in the run, such as a CLI
archive or an image digest, before it is attested. That file would then be attested
as genuine. Whether such a token still works after its job ends has not been tested.
The risk applies to every crate in the workspace, and the server's and the demo's extra
crates add to it. The order of the release's jobs protects only what happens after attestation. The
image digests are not pinned between the jobs that record and use them: a replaced one
could only name an image already in the registry, but that image would get the tag and
the attestation.

**The checks on the `.deb` and `.rpm` share a job with what they check.** The `packages`
job runs nfpm and the checks on the same runner, where it also has passwordless `sudo`
to install the tools, and `attest-packages` attests whatever digests that job recorded.
So a bad nfpm download, despite its pinned checksum, or a bad `rpm` package could change
a package and the verdict together. The job compiles no dependencies and has no
attestation identity, and the packages are rebuilt in the
[repeatable build](reproducing-builds.md), which would show a difference only if the bad
tool were not on both runners.

**The demo archive itself.** Anything in the demo's dependencies can change the demo
binary, and the result is attested and signed as the demo. Those checks show which
workflow produced it, not that its dependencies are honest. It runs on your machine, so
try it somewhere you would run any other unaudited program.

Release assets have no software bill of materials. Baseline Level 3 asks for one
on compiled assets (`osps_qa_02_02`).
