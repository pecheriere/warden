"""Unit tests for collect_archives.py, and for how the workflows use it."""

import contextlib
import io
import re
import tarfile
import tempfile
import unittest
from pathlib import Path

import collect_archives
from collect_archives import PLATFORMS, PRODUCTS, ArchiveError, archive_name, check_archive, collect

VERSION = "1.2.3"
ROOT = Path(__file__).resolve().parents[2]


def write_archive(path: Path, root: str, names: list[str]) -> None:
    """Write a .tar.gz with a top directory and one small file for each name."""
    source = path.parent / f"{path.name}.content"
    source.write_text("content")
    with tarfile.open(path, mode="w:gz") as tar:
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        tar.addfile(directory)
        for name in names:
            tar.add(source, arcname=f"{root}/{name}")
    source.unlink()


def files_of(product: str) -> list[str]:
    """List the files a product's archive must hold."""
    spec = PRODUCTS[product]
    return [*collect_archives.LICENSES, *spec.extra_files, spec.binary]


def good_archive(directory: Path, product: str, platform: str) -> Path:
    """Write a correct archive for this product and platform."""
    name = archive_name(product, VERSION, platform)
    path = directory / name
    write_archive(path, name.removesuffix(".tar.gz"), files_of(product))
    return path


def job_text(workflow: str, job: str) -> str:
    """Return the text of one job of a workflow."""
    text = (ROOT / ".github/workflows" / workflow).read_text()
    found = re.search(rf"^  {job}:\n(.*?)(?=^  [a-z-]+:\n|\Z)", text, re.MULTILINE | re.DOTALL)
    if found is None:
        message = f"no job {job} in {workflow}"
        raise AssertionError(message)
    return found.group(1)


class Names(unittest.TestCase):
    """The archive names, which the signing script and the docs also use."""

    def test_names_the_cli_and_the_demo(self) -> None:
        """Only the demo's archive has the demo's name."""
        self.assertEqual(
            archive_name("cli", VERSION, "linux-amd64"), "warden-1.2.3-linux-amd64.tar.gz"
        )
        self.assertEqual(
            archive_name("demo", VERSION, "macos-arm64"), "warden-demo-1.2.3-macos-arm64.tar.gz"
        )


class CheckArchive(unittest.TestCase):
    """What must be inside one archive."""

    def setUp(self) -> None:
        """Make a directory for the test's archives."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.dir = Path(temporary.name)

    def refuses(self, path: Path, reason: str) -> None:
        """Check that the demo archive for linux-amd64 is refused, for this reason."""
        with self.assertRaisesRegex(ArchiveError, reason):
            check_archive(path, "demo", VERSION, "linux-amd64")

    def test_accepts_each_product(self) -> None:
        """Correct archives pass."""
        for product in PRODUCTS:
            check_archive(
                good_archive(self.dir, product, "linux-amd64"), product, VERSION, "linux-amd64"
            )

    def test_refuses_a_demo_archive_without_its_notice(self) -> None:
        """The notice is what labels the demo for someone who only sees the download."""
        path = self.dir / "warden-demo-1.2.3-linux-amd64.tar.gz"
        names = [name for name in files_of("demo") if name != "NOT-FOR-REAL-USE.txt"]
        write_archive(path, "warden-demo-1.2.3-linux-amd64", names)
        self.refuses(path, "should hold")

    def test_refuses_an_extra_file(self) -> None:
        """Publishing an archive would ship anything else in it."""
        path = self.dir / "warden-demo-1.2.3-linux-amd64.tar.gz"
        write_archive(path, "warden-demo-1.2.3-linux-amd64", [*files_of("demo"), "warden"])
        self.refuses(path, "should hold")

    def test_refuses_another_top_directory(self) -> None:
        """A demo cannot unpack under the CLI's directory."""
        path = self.dir / "warden-demo-1.2.3-linux-amd64.tar.gz"
        write_archive(path, "warden-1.2.3-linux-amd64", files_of("demo"))
        self.refuses(path, "one directory")

    def test_refuses_a_file_named_for_another_product(self) -> None:
        """The CLI's archive name does not pass as the demo's."""
        self.refuses(good_archive(self.dir, "cli", "linux-amd64"), "should be named")

    def test_refuses_a_link_in_place_of_a_file(self) -> None:
        """A link could point anywhere when unpacked."""
        path = self.dir / "warden-demo-1.2.3-linux-amd64.tar.gz"
        root = "warden-demo-1.2.3-linux-amd64"
        write_archive(path, root, [name for name in files_of("demo") if name != "warden-demo"])
        with tarfile.open(path, mode="r:gz") as tar:
            members = [(member, tar.extractfile(member)) for member in tar.getmembers()]
            contents = [(member, data.read() if data else None) for member, data in members]
        with tarfile.open(path, mode="w:gz") as tar:
            for member, data in contents:
                tar.addfile(member, io.BytesIO(data) if data is not None else None)
            link = tarfile.TarInfo(f"{root}/warden-demo")
            link.type = tarfile.SYMTYPE
            link.linkname = "/bin/sh"
            tar.addfile(link)
        self.refuses(path, "regular file")

    def test_refuses_a_file_that_is_not_an_archive(self) -> None:
        """Damage is an error, not an empty list."""
        path = self.dir / "warden-demo-1.2.3-linux-amd64.tar.gz"
        path.write_text("not an archive")
        self.refuses(path, "cannot be read")


class Collect(unittest.TestCase):
    """One job's upload must not be able to replace another job's file."""

    def setUp(self) -> None:
        """Lay out correct artifacts, as the download action unpacks them."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.artifacts = Path(temporary.name) / "artifacts"
        self.out = Path(temporary.name) / "dist"
        for product in PRODUCTS:
            for platform in PLATFORMS:
                artifact = self.artifacts / f"archive-{product}-{platform}"
                artifact.mkdir(parents=True)
                good_archive(artifact, product, platform)

    def refuses(self, reason: str) -> None:
        """Check that nothing is collected, for this reason."""
        with self.assertRaisesRegex(ArchiveError, reason):
            collect(self.artifacts, self.out, VERSION)
        self.assertFalse(self.out.exists())

    def test_collects_each_archive_from_its_own_artifact(self) -> None:
        """Each collected file has the bytes of the artifact that may produce it."""
        collected = collect(self.artifacts, self.out, VERSION)
        self.assertEqual(len(collected), len(PRODUCTS) * len(PLATFORMS))
        for path in collected:
            product = "demo" if path.name.startswith("warden-demo") else "cli"
            platform = path.name.removesuffix(".tar.gz").rsplit("-", 2)
            source = self.artifacts / f"archive-{product}-{platform[1]}-{platform[2]}" / path.name
            self.assertEqual(path.read_bytes(), source.read_bytes())

    def test_refuses_a_demo_job_planting_the_cli_archive(self) -> None:
        """The demo's build scripts may not supply the file named for the CLI."""
        good_archive(self.artifacts / "archive-demo-linux-amd64", "cli", "linux-amd64")
        self.refuses("should hold only")

    def test_refuses_a_cli_job_planting_another_platform(self) -> None:
        """A job for one platform may not supply another's file."""
        good_archive(self.artifacts / "archive-cli-linux-amd64", "cli", "macos-arm64")
        self.refuses("should hold only")

    def test_refuses_an_artifact_holding_only_another_jobs_file(self) -> None:
        """Replacing the file rather than adding one changes nothing."""
        artifact = self.artifacts / "archive-demo-linux-amd64"
        (artifact / "warden-demo-1.2.3-linux-amd64.tar.gz").unlink()
        good_archive(artifact, "cli", "linux-amd64")
        self.refuses("should hold only")

    def test_refuses_a_missing_artifact(self) -> None:
        """A release lacking a platform stops here."""
        artifact = self.artifacts / "archive-demo-macos-arm64"
        (artifact / "warden-demo-1.2.3-macos-arm64.tar.gz").unlink()
        artifact.rmdir()
        self.refuses("missing")

    def test_refuses_an_unknown_artifact(self) -> None:
        """Nothing else is carried along."""
        (self.artifacts / "archive-cli-windows-amd64").mkdir()
        self.refuses("extra")

    def test_refuses_a_link_in_place_of_the_archive(self) -> None:
        """A link is not the file the job built."""
        path = self.artifacts / "archive-cli-linux-amd64" / "warden-1.2.3-linux-amd64.tar.gz"
        path.unlink()
        path.symlink_to(self.artifacts / "archive-cli-linux-arm64" / path.name)
        self.refuses("regular file")

    def test_refuses_good_names_with_bad_contents(self) -> None:
        """Contents are checked before anything is copied."""
        path = self.artifacts / "archive-cli-linux-arm64" / "warden-1.2.3-linux-arm64.tar.gz"
        path.write_text("not an archive")
        self.refuses("cannot be read")


class CommandLine(unittest.TestCase):
    """The commands the workflows call."""

    def test_name_uses_the_workspace_version(self) -> None:
        """The name comes from Cargo.toml, as the workflows expect."""
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = collect_archives.main(["name", "demo", "linux-arm64"])
        self.assertEqual(status, 0)
        version = collect_archives.workspace_version()
        self.assertEqual(output.getvalue().strip(), f"warden-demo-{version}-linux-arm64.tar.gz")

    def test_a_refusal_is_a_failed_exit(self) -> None:
        """A refusal must stop the workflow's step."""
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "archive.tar.gz"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = collect_archives.main(["check", "cli", "linux-amd64", str(missing)])
        self.assertEqual(status, 1)
        self.assertIn("::error::", output.getvalue())


class Workflows(unittest.TestCase):
    """The workflows cannot run here, so check that they keep the rules in the script."""

    def test_release_builds_upload_only_their_exact_file(self) -> None:
        """A wildcard would carry a planted file along."""
        job = job_text("release.yml", "binaries")
        self.assertIn("path: dist/${{ steps.archive.outputs.file }}", job)
        self.assertNotIn("*", job.split("upload-artifact", 1)[1])
        self.assertLess(job.index("collect_archives.py name"), job.index("package-binary.sh"))

    def test_only_the_collecting_job_reads_the_builds_artifacts(self) -> None:
        """Everything later uses what the collecting job checked."""
        collecting = job_text("release.yml", "collect-archives")
        self.assertIn("pattern: archive-*", collecting)
        self.assertNotIn("merge-multiple", collecting)
        self.assertIn("collect_archives.py collect", collecting)
        for job in ("attest-binaries", "draft-release"):
            text = job_text("release.yml", job)
            self.assertNotIn("archive-*", text)
            self.assertIn("name: checked-archives", text)
            self.assertIn("collect-archives", text.split("steps:", 1)[0])

    def test_no_image_tag_or_attestation_before_the_check(self) -> None:
        """A refusal stops the release, including the image's tag."""
        self.assertIn("collect-archives", job_text("release.yml", "merge").split("steps:", 1)[0])
        self.assertIn("needs: collect-archives", job_text("release.yml", "attest-binaries"))

    def test_repeatable_builds_upload_only_their_exact_file(self) -> None:
        """A comparison needs one file on each side."""
        job = job_text("repeatable-build.yml", "binaries")
        self.assertIn("/dist/${{ steps.archive.outputs.file }}", job)
        self.assertNotIn("*", job.split("upload-artifact", 1)[1])
        self.assertLess(job.index("collect_archives.py name"), job.index("package-binary.sh"))

    def test_ci_checks_what_each_build_produced(self) -> None:
        """A dropped notice fails on the pull request, not on a release tag."""
        self.assertIn("collect_archives.py check", job_text("ci.yml", "binaries"))


if __name__ == "__main__":
    unittest.main()
