#!/usr/bin/env bash
# Builds the `warden` CLI's .deb and .rpm from a release's CLI archive, compiling
# nothing, and checks what they hold before anyone relies on them: exactly the expected
# files with the expected modes and owners, so nothing setuid, no install scripts or
# triggers, no demo, and the very binary the archive holds.
#
# Usage: scripts/package-linux.sh <linux-amd64|linux-arm64> <cli-archive> <out-dir>
#
# Writes warden_<version>_<arch>.deb and warden-<version>-1.<arch>.rpm in <out-dir>.
# Needs curl, python3, tar, sha256sum, dpkg-deb, rpm, rpm2cpio and cpio. Downloads nfpm,
# pinned below by version and checksum. To update it, take both from the release's
# checksums.txt, for a release at least 7 days old.
#
# Files in the packages carry the time of SOURCE_DATE_EPOCH, or of the checked-out commit
# when that is not set.
set -euo pipefail

cd "$(dirname "$0")/.."

nfpm_version=2.48.0
nfpm_sha256_x86_64=6d7f9a28b2f397934403950fcbba83f598b08d02edbe79a0815b3b4897341750
nfpm_sha256_arm64=a9a75213763783b7669719e505474c748c5ad7dc66591a195619deb50f85c2f4

fail() {
  echo "error: $*" >&2
  exit 1
}

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <linux-amd64|linux-arm64> <cli-archive> <out-dir>" >&2
  exit 2
fi
platform=$1
archive=$2
out_dir=$3
for tool in curl python3 tar sha256sum dpkg-deb rpm rpm2cpio cpio; do
  command -v "$tool" > /dev/null || fail "$tool is not installed"
done
collect=.github/scripts/collect_archives.py

case "$platform" in
  linux-amd64) deb_arch=amd64 rpm_arch=x86_64 ;;
  linux-arm64) deb_arch=arm64 rpm_arch=aarch64 ;;
  *) fail "no packages for $platform" ;;
esac

# The archive must be exactly the CLI's, which also refuses a demo under its name.
python3 -I "$collect" check cli "$platform" "$archive" > /dev/null || fail "$archive is not the CLI's archive"
root=$(basename "$archive" .tar.gz)
version=${root#warden-}
version=${version%-"$platform"}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# nfpm for the machine running this, which need not be the packages' architecture.
case "$(uname -m)" in
  x86_64) nfpm_arch=x86_64 nfpm_sha256=$nfpm_sha256_x86_64 ;;
  aarch64 | arm64) nfpm_arch=arm64 nfpm_sha256=$nfpm_sha256_arm64 ;;
  *) fail "no nfpm pinned for $(uname -m)" ;;
esac
nfpm_file=nfpm_${nfpm_version}_Linux_${nfpm_arch}.tar.gz
curl -fsSL -o "$work/$nfpm_file" \
  "https://github.com/goreleaser/nfpm/releases/download/v$nfpm_version/$nfpm_file"
(cd "$work" && printf '%s  %s\n' "$nfpm_sha256" "$nfpm_file" | sha256sum -c --quiet -) \
  || fail "the nfpm download does not match its pinned checksum"
mkdir "$work/nfpm"
tar -xzf "$work/$nfpm_file" -C "$work/nfpm" nfpm

mkdir "$work/stage"
tar -xzf "$archive" --strip-components=1 -C "$work/stage"
binary_sum=$(sha256sum "$work/stage/warden" | cut -d' ' -f1)

epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
deb=warden_${version}_${deb_arch}.deb
rpm=warden-${version}-1.${rpm_arch}.rpm
mkdir -p "$out_dir"
out_dir=$(cd "$out_dir" && pwd)
config=$PWD/packaging/nfpm.yaml
(
  cd "$work/stage"
  export WARDEN_PACKAGE_ARCH=$deb_arch WARDEN_PACKAGE_VERSION=$version SOURCE_DATE_EPOCH=$epoch
  "$work/nfpm/nfpm" package --config "$config" --packager deb --target "$out_dir/$deb" > /dev/null
  "$work/nfpm/nfpm" package --config "$config" --packager rpm --target "$out_dir/$rpm" > /dev/null
)

# Every entry with its mode and owner, so a setuid, setgid or writable file cannot pass.
expected_deb='drwxr-xr-x root/root ./usr/
drwxr-xr-x root/root ./usr/bin/
-rwxr-xr-x root/root ./usr/bin/warden
drwxr-xr-x root/root ./usr/share/
drwxr-xr-x root/root ./usr/share/doc/
drwxr-xr-x root/root ./usr/share/doc/warden/
-rw-r--r-- root/root ./usr/share/doc/warden/LICENSE-APACHE
-rw-r--r-- root/root ./usr/share/doc/warden/LICENSE-MIT
-rw-r--r-- root/root ./usr/share/doc/warden/NOTICE'
expected_rpm='-rwxr-xr-x root root /usr/bin/warden
-rw-r--r-- root root /usr/share/doc/warden/LICENSE-APACHE
-rw-r--r-- root root /usr/share/doc/warden/LICENSE-MIT
-rw-r--r-- root root /usr/share/doc/warden/NOTICE'

# What dpkg would install, and that it would run nothing while doing so. A trigger or
# install script would be one more control file.
files=$(dpkg-deb --fsys-tarfile "$out_dir/$deb" | tar -tv | awk '{ print $1, $2, $6 }' | LC_ALL=C sort -k3)
[ "$files" = "$expected_deb" ] || fail "$deb holds unexpected files or modes:"$'\n'"$files"
mkdir "$work/control"
dpkg-deb --control "$out_dir/$deb" "$work/control"
control_files=$(find "$work/control" -mindepth 1 -printf '%f\n' | LC_ALL=C sort | tr '\n' ' ')
[ "$control_files" = "control md5sums " ] || [ "$control_files" = "control " ] \
  || fail "$deb has install scripts or other control files: $control_files"
[ "$(dpkg-deb --field "$out_dir/$deb" Package)" = warden ] || fail "$deb is not the warden package"
[ "$(dpkg-deb --field "$out_dir/$deb" Architecture)" = "$deb_arch" ] || fail "$deb is for another architecture"
[ "$(dpkg-deb --field "$out_dir/$deb" Version)" = "$version-1" ] || fail "$deb has another version"
deb_sum=$(dpkg-deb --fsys-tarfile "$out_dir/$deb" | tar -xO ./usr/bin/warden | sha256sum | cut -d' ' -f1)
[ "$deb_sum" = "$binary_sum" ] || fail "$deb does not hold the archive's binary"

# The same for rpm, which reads a package's headers without its signature here because
# nfpm signs nothing: the release's attestation and signed manifest cover these files.
files=$(rpm -qp --nosignature \
  --queryformat '[%{FILEMODES:perms} %{FILEUSERNAME} %{FILEGROUPNAME} %{FILENAMES}\n]' "$out_dir/$rpm" \
  | LC_ALL=C sort -k4)
[ "$files" = "$expected_rpm" ] || fail "$rpm holds unexpected files or modes:"$'\n'"$files"
scripts=$(rpm -qp --nosignature --scripts --triggers --filetriggers "$out_dir/$rpm")
[ -z "$scripts" ] || fail "$rpm has install scripts or triggers: $scripts"
identity=$(rpm -qp --nosignature --queryformat '%{NAME} %{VERSION} %{RELEASE} %{ARCH}' "$out_dir/$rpm")
[ "$identity" = "warden $version 1 $rpm_arch" ] || fail "$rpm is not what it should be: $identity"
rpm_sum=$(rpm2cpio "$out_dir/$rpm" | cpio --quiet -i --to-stdout ./usr/bin/warden | sha256sum | cut -d' ' -f1)
[ "$rpm_sum" = "$binary_sum" ] || fail "$rpm does not hold the archive's binary"

echo "$out_dir/$deb"
echo "$out_dir/$rpm"
