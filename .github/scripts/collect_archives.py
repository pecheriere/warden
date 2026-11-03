"""Check a release's archives, each against the one job that may produce it.

Every binary builds on its own runner, so that the build scripts of one binary's
dependencies cannot touch another binary. That only holds if a job's upload cannot
replace another job's file. So each artifact must hold exactly the one file named
for it, and nothing is merged until that is checked.

`name` prints the file a job must produce. A job runs it before building, so that
nothing the build runs can change the answer.

`check` looks inside one archive, without unpacking it, for the files it must hold.
CI runs this on each build.

`packages` prints the names of the CLI's .deb and .rpm files, which
scripts/package-linux.sh makes and checks from the attested CLI archives.

`collect` runs on the artifacts of one product's builds, in the job that attests
them and not in a build, and copies the archives into one directory only when each
is exactly what it should be. That directory is what gets attested.

The version comes from the workspace's Cargo.toml. The release workflow has already
checked it against the tag.
"""

import argparse
import shutil
import stat
import sys
import tarfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

LINUX = ("linux-amd64", "linux-arm64")
PLATFORMS = (*LINUX, "macos-arm64")
LICENSES = ("LICENSE-APACHE", "LICENSE-MIT", "NOTICE")


@dataclass(frozen=True)
class Product:
    """A binary the release workflow builds."""

    prefix: str
    binary: str
    extra_files: tuple[str, ...] = ()
    platforms: tuple[str, ...] = PLATFORMS


PRODUCTS = {
    "cli": Product(prefix="warden", binary="warden"),
    "demo": Product(
        prefix="warden-demo",
        binary="warden-demo",
        extra_files=("NOT-FOR-REAL-USE.txt",),
    ),
    "server": Product(prefix="warden-server", binary="warden-server", platforms=LINUX),
}


class ArchiveError(Exception):
    """An archive or artifact is not exactly what it should be."""


def archive_name(product: str, version: str, platform: str) -> str:
    """Name the one file the job for this product and platform may produce."""
    spec = PRODUCTS[product]
    if platform not in spec.platforms:
        message = f"{product} is not released for {platform}"
        raise ArchiveError(message)
    return f"{spec.prefix}-{version}-{platform}.tar.gz"


def package_names(version: str) -> list[str]:
    """Name the CLI's Linux packages, the only ones a release holds."""
    return [
        name
        for deb_arch, rpm_arch in (("amd64", "x86_64"), ("arm64", "aarch64"))
        for name in (f"warden_{version}_{deb_arch}.deb", f"warden-{version}-1.{rpm_arch}.rpm")
    ]


def check_archive(path: Path, product: str, version: str, platform: str) -> None:
    """Refuse an archive unless it holds exactly this product's files."""
    expected_name = archive_name(product, version, platform)
    if path.name != expected_name:
        message = f"{path.name} should be named {expected_name}"
        raise ArchiveError(message)
    spec = PRODUCTS[product]
    root = expected_name.removesuffix(".tar.gz")
    expected = {f"{root}/{name}" for name in (*LICENSES, *spec.extra_files, spec.binary)}
    try:
        with tarfile.open(path, mode="r:gz") as tar:
            members = tar.getmembers()
    except (OSError, EOFError, tarfile.TarError) as error:
        message = f"{path.name} cannot be read: {error}"
        raise ArchiveError(message) from error
    directories = [member.name for member in members if member.isdir()]
    if directories != [root]:
        message = f"{path.name} should have the one directory {root}, not {directories}"
        raise ArchiveError(message)
    files = {member.name: member for member in members if not member.isdir()}
    if set(files) != expected or len(files) + 1 != len(members):
        found = sorted(member.name for member in members if not member.isdir())
        message = f"{path.name} should hold {sorted(expected)}, not {found}"
        raise ArchiveError(message)
    for name, member in files.items():
        if not member.isfile() or member.size == 0:
            message = f"{path.name}: {name} is not a regular file with content"
            raise ArchiveError(message)


def collect(product: str, artifacts: Path, out: Path, version: str) -> list[Path]:
    """Copy a product's archives into `out` if each artifact holds exactly its own file."""
    wanted = {f"archive-{product}-{platform}": platform for platform in PRODUCTS[product].platforms}
    found = {entry.name for entry in artifacts.iterdir()}
    if found != set(wanted):
        message = (
            f"unexpected artifacts: missing {sorted(set(wanted) - found)}, "
            f"extra {sorted(found - set(wanted))}"
        )
        raise ArchiveError(message)
    checked = []
    for artifact, platform in sorted(wanted.items()):
        name = archive_name(product, version, platform)
        entries = sorted(entry.name for entry in (artifacts / artifact).iterdir())
        if entries != [name]:
            message = f"{artifact} should hold only {name}, not {entries}"
            raise ArchiveError(message)
        source = artifacts / artifact / name
        if not stat.S_ISREG(source.lstat().st_mode):
            message = f"{artifact}: {name} is not a regular file"
            raise ArchiveError(message)
        check_archive(source, product, version, platform)
        checked.append(source)
    out.mkdir()
    return [Path(shutil.copyfile(source, out / source.name)) for source in checked]


def workspace_version() -> str:
    """Read the version from the Cargo.toml of the checkout holding this script."""
    with (Path(__file__).resolve().parents[2] / "Cargo.toml").open("rb") as manifest:
        return tomllib.load(manifest)["workspace"]["package"]["version"]


def main(argv: list[str]) -> int:
    """Run the command line, and return the exit code."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("name", "check"):
        sub = commands.add_parser(command)
        sub.add_argument("product", choices=sorted(PRODUCTS))
        sub.add_argument("platform", choices=PLATFORMS)
        if command == "check":
            sub.add_argument("archive", type=Path)
    commands.add_parser("packages")
    sub = commands.add_parser("collect")
    sub.add_argument("product", choices=sorted(PRODUCTS))
    sub.add_argument("artifacts", type=Path)
    sub.add_argument("out", type=Path)
    args = parser.parse_args(argv)

    version = workspace_version()
    try:
        if args.command == "name":
            print(archive_name(args.product, version, args.platform))
        elif args.command == "packages":
            print("\n".join(package_names(version)))
        elif args.command == "check":
            check_archive(args.archive, args.product, version, args.platform)
            print(f"ok: {args.archive.name}")
        else:
            for path in collect(args.product, args.artifacts, args.out, version):
                print(f"ok: {path.name}")
    except (ArchiveError, OSError) as error:
        print(f"::error::{error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
