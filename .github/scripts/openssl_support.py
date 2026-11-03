"""Fail when the OpenSSL release warden links is out of support or out of date.

Advisory scanners report published advisories only: they do not notice a line that
stopped getting fixes, and neither they nor Dependabot read scripts/openssl-pin.env.

By default, with no network: fails on or after the pinned line's end-of-support date,
warns in the UPCOMING days before it, and fails if `openssl-src` is back in Cargo.lock
or a build that ships no longer sets PINNED_FLAG, either of which would mean that it may
not use the pin.

With --nightly, for the scheduled run: also fails in the UPCOMING days before the end,
and if OpenSSL has published a newer release of the line.

Usage: openssl_support.py [--nightly]
"""

import argparse
import re
import subprocess
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
PIN_FILE = ROOT / "scripts" / "openssl-pin.env"
LOCKFILE = ROOT / "Cargo.lock"
PINNED_FLAG = "WARDEN_OPENSSL_PINNED=1"
SHIPPING_BUILDS = (ROOT / "Dockerfile", ROOT / "scripts" / "package-binary.sh")
UPCOMING = timedelta(days=90)
REPOSITORY = "https://github.com/openssl/openssl"
VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")
SETTING = re.compile(r"WARDEN_OPENSSL_([A-Z0-9_]+)=(\S+)")
RELEASE_TAG = re.compile(r"refs/tags/openssl-(\d+)\.(\d+)\.(\d+)")
TIMEOUT = 60


class CheckError(Exception):
    """The check could not establish an answer, which fails like a bad one."""


def parse_pin(text: str) -> tuple[tuple[int, int, int], date]:
    """Return the pinned version and the end of its support."""
    settings = {}
    for line in text.splitlines():
        match = SETTING.fullmatch(line)
        if match:
            settings[match[1]] = match[2]
    version = VERSION.fullmatch(settings.get("VERSION", ""))
    if not version:
        message = "no valid WARDEN_OPENSSL_VERSION"
        raise CheckError(message)
    try:
        ends = date.fromisoformat(settings.get("SUPPORT_ENDS", ""))
    except ValueError as error:
        message = "no valid WARDEN_OPENSSL_SUPPORT_ENDS"
        raise CheckError(message) from error
    return (int(version[1]), int(version[2]), int(version[3])), ends


def support_problem(ends: date, today: date, *, nightly: bool) -> tuple[bool, str | None]:
    """Return whether the date fails the check, and what to say about it."""
    if today >= ends:
        return True, f"OpenSSL support for the pinned line ended on {ends}"
    if today >= ends - UPCOMING:
        return nightly, f"OpenSSL support for the pinned line ends on {ends}: move off it"
    return False, None


def has_openssl_src(lockfile: str) -> bool:
    """Say whether a Cargo.lock holds the `openssl-src` package."""
    return 'name = "openssl-src"' in lockfile


def newest_of_line(ls_remote: str, line: tuple[int, int]) -> tuple[int, int, int] | None:
    """Return the newest final release of a line from `git ls-remote` output."""
    newest = None
    for row in ls_remote.splitlines():
        match = RELEASE_TAG.fullmatch(row.split("\t")[-1])
        if not match:
            continue
        version = (int(match[1]), int(match[2]), int(match[3]))
        if version[:2] == line and (newest is None or version > newest):
            newest = version
    return newest


def list_release_tags(line: tuple[int, int]) -> str:
    """Return `git ls-remote` output for the tags of a line."""
    pattern = f"refs/tags/openssl-{line[0]}.{line[1]}.*"
    result = subprocess.run(
        ["git", "ls-remote", "--tags", "--refs", REPOSITORY, pattern],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    if result.returncode != 0:
        message = f"could not list OpenSSL's tags: {result.stderr.strip()}"
        raise CheckError(message)
    return result.stdout


def show(version: tuple[int, int, int]) -> str:
    """Write a version the usual way."""
    return ".".join(str(part) for part in version)


def newer_release(version: tuple[int, int, int]) -> tuple[int, int, int] | None:
    """Return a newer release of the pinned line, if OpenSSL has published one."""
    line = version[:2]
    newest = newest_of_line(list_release_tags(line), line)
    if newest is None:
        message = f"found no release of the {line[0]}.{line[1]} line"
        raise CheckError(message)
    return newest if newest > version else None


def check(*, nightly: bool) -> bool:
    """Print what is wrong, and return whether all is well."""
    version, ends = parse_pin(PIN_FILE.read_text(encoding="utf-8"))
    fails, message = support_problem(ends, datetime.now(UTC).date(), nightly=nightly)
    if message:
        print(f"::{'error' if fails else 'warning'}::{message}")
    passed = not fails
    if has_openssl_src(LOCKFILE.read_text(encoding="utf-8")):
        print("::error::openssl-src is in Cargo.lock: builds must use scripts/build-openssl.sh")
        passed = False
    for build in SHIPPING_BUILDS:
        if PINNED_FLAG not in build.read_text(encoding="utf-8"):
            print(f"::error::{build.name} does not set {PINNED_FLAG}")
            passed = False
    if nightly:
        newer = newer_release(version)
        if newer:
            print(f"::error::OpenSSL {show(newer)} is out and the pin is {show(version)}")
            passed = False
    if passed:
        print(f"ok: OpenSSL {show(version)}, supported until {ends}")
    return passed


def main() -> int:
    """Run the check."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--nightly", action="store_true")
    try:
        return 0 if check(nightly=parser.parse_args().nightly) else 1
    except (CheckError, OSError, subprocess.TimeoutExpired) as error:
        print(f"::error::{error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
