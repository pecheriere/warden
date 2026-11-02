"""Unit tests for dco.py; every commit is made in a temporary repository."""

import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import dco

GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "alice",
    "GIT_AUTHOR_EMAIL": "alice@example.com",
    "GIT_COMMITTER_NAME": "alice",
    "GIT_COMMITTER_EMAIL": "alice@example.com",
}
SIGNED = "Change\n\nSigned-off-by: alice <alice@example.com>\n"
DEPENDABOT_MESSAGE = (
    "ci: bump\n\nBumps a thing.\n\nSigned-off-by: dependabot[bot] <support@github.com>"
)


class RepoTest(unittest.TestCase):
    """Base for tests that commit in a temporary repository and run main() on it."""

    def setUp(self) -> None:
        """Create a repository with one commit on `main` and a `feature` branch."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for patcher in (
            mock.patch.object(dco, "ROOT", self.root),
            mock.patch.dict(os.environ, GIT_ENV),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.git("init", "--quiet", "--initial-branch=main")
        self.commit("Base, from before the check existed\n", files={"base.txt": "line\n"})
        self.git("switch", "--quiet", "-c", "feature")

    def git(self, *args: str, stdin: str | None = None, check: bool = True) -> str:
        """Run git in the temporary repository."""
        return subprocess.run(
            ["git", *args], check=check, capture_output=True, text=True, cwd=self.root, input=stdin
        ).stdout

    def commit(
        self,
        message: str,
        *,
        address: str = "alice@example.com",
        name: str = "alice",
        files: dict[str, str] | None = None,
    ) -> str:
        """Commit the given files with a message taken literally, and return the commit ID."""
        for path, text in (files or {}).items():
            (self.root / path).write_text(text, encoding="utf-8")
        self.git("add", "-A")
        author = {"GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": address}
        with mock.patch.dict(os.environ, author):
            self.git("commit", "--allow-empty", "--cleanup=verbatim", "-F", "-", stdin=message)
        return self.git("rev-parse", "HEAD").strip()

    def merge_without_committing(self, *branches: str) -> None:
        """Start a merge and leave it for the test to finish; conflicts are expected."""
        self.git("merge", "--no-ff", "--no-commit", *branches, check=False)

    def run_pull_request(self, *extra: str) -> tuple[int, str]:
        """Check main..HEAD and return the exit status and the output."""
        return self.run_main("pull-request", "--base", "main", "--head", "HEAD", *extra)

    @staticmethod
    def run_main(*args: str) -> tuple[int, str]:
        """Run main() and return the exit status and the output."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = dco.main(list(args))
        return status, out.getvalue()


class SignOffTest(RepoTest):
    """The sign-off a commit needs."""

    def assert_passes(self, message: str, **commit: str) -> None:
        """Check that a commit with this message passes."""
        self.commit(message, **commit)
        self.assertEqual(self.run_pull_request()[0], 0)

    def assert_fails(self, message: str, reason: str, **commit: str) -> None:
        """Check that a commit with this message fails for this reason."""
        sha = self.commit(message, **commit)
        status, out = self.run_pull_request()
        self.assertEqual(status, 1)
        self.assertIn(f"::error title=DCO::Commit {sha}: {reason}", out)

    def test_sign_off_from_the_author_passes(self) -> None:
        """What `git commit -s` writes passes."""
        self.assert_passes(SIGNED)

    def test_real_git_commit_signoff_passes(self) -> None:
        """The check accepts the actual output of `git commit -s`."""
        self.git("commit", "--allow-empty", "--signoff", "-m", "Change")
        self.assertEqual(self.run_pull_request()[0], 0)

    def test_sign_off_among_other_trailers_passes(self) -> None:
        """Other trailers in the block do not matter."""
        self.assert_passes(
            "Change\n\nBody.\n\nRefs #1\nSigned-off-by: alice <alice@example.com>\nFixes: abc\n"
        )

    def test_second_sign_off_from_the_author_passes(self) -> None:
        """Someone else's sign-off beside the author's is fine."""
        self.assert_passes(
            "Change\n\nSigned-off-by: bob <bob@example.com>\n"
            "Signed-off-by: alice <alice@example.com>\n"
        )

    def test_address_compares_without_case(self) -> None:
        """Addresses are compared without case."""
        self.assert_passes("Change\n\nSigned-off-by: alice <ALICE@Example.COM>\n")

    def test_name_is_not_compared(self) -> None:
        """A different spelling of the name passes: the address is what is compared."""
        self.assert_passes("Change\n\nSigned-off-by: Alice Example <alice@example.com>\n")

    def test_no_sign_off_fails(self) -> None:
        """A message with no sign-off fails."""
        self.assert_fails("Change\n\nBody.\n", dco.MISSING)

    def test_other_address_fails(self) -> None:
        """A sign-off from another address than the author's fails."""
        self.assert_fails("Change\n\nSigned-off-by: bob <bob@example.com>\n", dco.WRONG_ADDRESS)

    def test_sign_off_in_the_body_fails(self) -> None:
        """A sign-off line followed by more text is not in the trailer block."""
        self.assert_fails(
            "Change\n\nSigned-off-by: alice <alice@example.com>\n\nMore explanation.\n", dco.MISSING
        )

    def test_sign_off_as_subject_fails(self) -> None:
        """The subject line is not a trailer."""
        self.assert_fails("Signed-off-by: alice <alice@example.com>\n", dco.MISSING)

    def test_quoted_sign_off_fails(self) -> None:
        """Quoting a sign-off in the message does not count."""
        self.assert_fails("Change\n\n> Signed-off-by: alice <alice@example.com>\n", dco.MISSING)

    def test_similar_trailer_fails(self) -> None:
        """Another trailer that starts the same way does not count."""
        self.assert_fails(
            "Change\n\nRefs #1\nSigned-off-by-proxy: alice <alice@example.com>\n", dco.MISSING
        )

    def test_malformed_values_fail(self) -> None:
        """A sign-off needs a name and an address in the usual form."""
        for value in (
            "alice",
            "alice@example.com",
            "<alice@example.com>",
            "alice <alice>",
            "alice <alice@example.com> extra",
            "alice <<alice@example.com>>",
        ):
            with self.subTest(value=value):
                self.assert_fails(f"Change\n\nSigned-off-by: {value}\n", dco.MISSING)

    def test_author_without_an_address_cannot_pass(self) -> None:
        """An author address that is not one never matches a sign-off."""
        self.assert_fails("Change\n\nSigned-off-by: a <a>\n", dco.MISSING, address="a")

    def test_only_the_bad_commit_is_reported(self) -> None:
        """Every commit is checked, and the good ones are not reported."""
        good = self.commit(SIGNED)
        bad = self.commit("Change\n")
        also_good = self.commit(SIGNED)
        status, out = self.run_pull_request()
        self.assertEqual(status, 1)
        self.assertIn(bad, out)
        self.assertNotIn(good, out)
        self.assertNotIn(also_good, out)

    def test_commits_from_the_base_are_not_checked(self) -> None:
        """History from before the check, which has no sign-offs, is out of range."""
        self.commit(SIGNED)
        self.assertEqual(self.run_pull_request()[0], 0)


class ModesAgreeTest(RepoTest):
    """A message that passes on a pull request must pass once it is in a squash commit."""

    def check_both(self, message: str) -> tuple[int, int]:
        """Return the exit status of both checks for a commit with this message."""
        self.commit(message)
        return self.run_pull_request()[0], self.run_main("squash", "--commit", "HEAD")[0]

    def test_forms_both_checks_refuse(self) -> None:
        """Forms git reads as a trailer but `git commit -s` never writes fail in both."""
        for line in (
            "signed-off-by: alice <alice@example.com>",
            "SIGNED-OFF-BY: alice <alice@example.com>",
            "Signed-off-by : alice <alice@example.com>",
            "Signed-off-by:alice <alice@example.com>",
            "Signed-off-by: alice\n  <alice@example.com>",
            "Signed-off-by:\n alice <alice@example.com>",
            "Signed-off-by: alice <alice@example.com>\r",
        ):
            with self.subTest(line=line):
                self.assertEqual(self.check_both(f"Change\n\n{line}\n"), (1, 1))

    def test_forms_both_checks_accept(self) -> None:
        """What `git commit -s` writes passes in both, also below a `---` line."""
        for message in (SIGNED, f"Change\n\n---\nDetails.\n\n{SIGNED.splitlines()[-1]}\n"):
            with self.subTest(message=message):
                self.assertEqual(self.check_both(message), (0, 0))


class MergeTest(RepoTest):
    """Merge commits, which `gh pr update-branch` creates without a sign-off."""

    def advance_main(self, files: dict[str, str]) -> None:
        """Add an unsigned commit to main, as history from before the check."""
        self.git("switch", "--quiet", "main")
        self.commit("Later change on main\n", files=files)
        self.git("switch", "--quiet", "feature")

    def test_clean_update_merge_passes(self) -> None:
        """Merging main in cleanly needs no sign-off, and main's commits are out of range."""
        self.commit(SIGNED, files={"feature.txt": "a\n"})
        self.advance_main({"main.txt": "b\n"})
        self.merge_without_committing("main")
        self.commit("Merge branch 'main' into feature\n")
        self.assertEqual(self.run_pull_request()[0], 0)

    def test_merge_does_not_excuse_the_commits_it_brings_in(self) -> None:
        """An unsigned commit on a merged side branch is still reported."""
        self.commit(SIGNED, files={"feature.txt": "a\n"})
        self.git("switch", "--quiet", "-c", "side", "main")
        unsigned = self.commit("Unsigned\n", files={"side.txt": "c\n"})
        self.git("switch", "--quiet", "feature")
        self.merge_without_committing("side")
        self.commit("Merge branch 'side' into feature\n")
        status, out = self.run_pull_request()
        self.assertEqual(status, 1)
        self.assertIn(unsigned, out)

    def test_merge_with_changes_of_its_own_needs_a_sign_off(self) -> None:
        """Work hidden in a merge commit is new work."""
        self.commit(SIGNED, files={"feature.txt": "a\n"})
        self.advance_main({"main.txt": "b\n"})
        self.merge_without_committing("main")
        (self.root / "hidden.txt").write_text("not from either parent\n", encoding="utf-8")
        sha = self.commit("Merge branch 'main' into feature\n")
        status, out = self.run_pull_request()
        self.assertEqual(status, 1)
        self.assertIn(sha, out)

    def make_conflict(self) -> None:
        """Start a merge that conflicts and resolve it by hand."""
        self.commit(SIGNED, files={"base.txt": "feature\n"})
        self.advance_main({"base.txt": "main\n"})
        self.merge_without_committing("main")
        (self.root / "base.txt").write_text("resolved\n", encoding="utf-8")

    def test_resolved_conflict_needs_a_sign_off(self) -> None:
        """A conflict resolution is new work."""
        self.make_conflict()
        sha = self.commit("Merge branch 'main' into feature\n")
        status, out = self.run_pull_request()
        self.assertEqual(status, 1)
        self.assertIn(sha, out)

    def test_resolved_conflict_with_a_sign_off_passes(self) -> None:
        """A signed-off conflict resolution passes."""
        self.make_conflict()
        self.commit(f"Merge branch 'main' into feature\n\n{SIGNED.splitlines()[-1]}\n")
        self.assertEqual(self.run_pull_request()[0], 0)

    def test_octopus_merge_needs_a_sign_off(self) -> None:
        """A merge of more than two parents is not what an update creates."""
        for branch in ("one", "two"):
            self.git("switch", "--quiet", "-c", branch, "main")
            self.commit(SIGNED, files={f"{branch}.txt": "x\n"})
        self.git("switch", "--quiet", "feature")
        self.commit(SIGNED, files={"feature.txt": "a\n"})
        self.git("merge", "--no-ff", "--quiet", "-m", "Octopus", "one", "two")
        self.assertEqual(self.run_pull_request()[0], 1)

    def test_merge_of_unrelated_history_needs_a_sign_off(self) -> None:
        """Unrelated history has no merge to compare with."""
        self.git("switch", "--quiet", "--orphan", "other")
        self.commit(SIGNED, files={"other.txt": "x\n"})
        self.git("switch", "--quiet", "feature")
        self.git("merge", "--no-ff", "--quiet", "--allow-unrelated-histories", "-m", "M", "other")
        self.assertEqual(self.run_pull_request()[0], 1)


class DependabotTest(RepoTest):
    """Dependabot needs both its address on the commit and its account on the pull request."""

    OPENED_BY_DEPENDABOT = ("--pr-author-id", str(dco.DEPENDABOT_ACCOUNT_ID))
    OPENED_BY_A_PERSON = ("--pr-author-id", "1234")

    def test_dependabot_commit_on_its_pull_request_passes(self) -> None:
        """Its own trailer has another address than its commits, and it still passes."""
        self.commit(DEPENDABOT_MESSAGE, name="dependabot[bot]", address=dco.DEPENDABOT_ADDRESS)
        self.assertEqual(self.run_pull_request(*self.OPENED_BY_DEPENDABOT)[0], 0)

    def test_dependabot_commit_without_any_sign_off_passes(self) -> None:
        """Passing does not depend on the wording of Dependabot's messages."""
        self.commit("ci: bump\n", name="dependabot[bot]", address=dco.DEPENDABOT_ADDRESS)
        self.assertEqual(self.run_pull_request(*self.OPENED_BY_DEPENDABOT)[0], 0)

    def test_forged_author_on_a_persons_pull_request_fails(self) -> None:
        """Anyone can write Dependabot's name and address into a commit."""
        self.commit("Change\n", name="dependabot[bot]", address=dco.DEPENDABOT_ADDRESS)
        self.assertEqual(self.run_pull_request(*self.OPENED_BY_A_PERSON)[0], 1)
        self.assertEqual(self.run_pull_request()[0], 1)

    def test_persons_commit_on_a_dependabot_pull_request_fails(self) -> None:
        """A person who adds to a Dependabot pull request signs off."""
        self.commit("Fix up the bump\n")
        self.assertEqual(self.run_pull_request(*self.OPENED_BY_DEPENDABOT)[0], 1)

    def test_update_merge_on_a_dependabot_pull_request_passes(self) -> None:
        """A maintainer updating a Dependabot pull request is a clean merge."""
        self.commit(DEPENDABOT_MESSAGE, name="dependabot[bot]", address=dco.DEPENDABOT_ADDRESS)
        self.git("switch", "--quiet", "main")
        self.commit("Later change on main\n", files={"main.txt": "b\n"})
        self.git("switch", "--quiet", "feature")
        self.merge_without_committing("main")
        self.commit("Merge branch 'main' into feature\n")
        self.assertEqual(self.run_pull_request(*self.OPENED_BY_DEPENDABOT)[0], 0)


class UntrustedInputTest(RepoTest):
    """Commit metadata is written by whoever opens the pull request."""

    HOSTILE = (
        "::error::forged",
        "##[add-mask]forged",
        "$(touch pwned)",
        "`touch pwned`",
        "; touch pwned;",
    )

    def test_metadata_never_reaches_the_output_or_a_shell(self) -> None:
        """Nothing a commit says appears in the log, and nothing is executed."""
        for text in self.HOSTILE:
            with self.subTest(text=text):
                self.commit(
                    f"{text}\n\n{text}\n\nSigned-off-by: {text} <{text}@example.com>\n",
                    name=text,
                    address=f"{text}@example.com",
                )
                _status, out = self.run_pull_request()
                self.assertNotIn("forged", out)
                self.assertNotIn("touch", out)
                self.assertFalse((self.root / "pwned").exists())

    def test_every_output_line_is_fixed_text(self) -> None:
        """Workflow commands in the output are only the check's own."""
        self.commit("::warning::forged\n", name="::warning::forged", address="x@example.com")
        _status, out = self.run_pull_request()
        for line in out.splitlines():
            self.assertRegex(line, r"^(::error title=DCO::Commit [0-9a-f]{40}: |Add the sign-off)")


class FailClosedTest(RepoTest):
    """Commits that cannot be read are an error, not a pass."""

    def test_unknown_revision(self) -> None:
        """A revision that does not exist is an error."""
        status, out = self.run_main("pull-request", "--base", "nonexistent", "--head", "HEAD")
        self.assertEqual(status, 2)
        self.assertNotIn("nonexistent", out)

    def test_revision_that_looks_like_an_option(self) -> None:
        """A revision cannot turn into an option for git."""
        status, _out = self.run_main("pull-request", "--base=--all", "--head", "HEAD")
        self.assertEqual(status, 2)

    def test_empty_range(self) -> None:
        """A range with nothing in it means the wrong commits were given."""
        self.assertEqual(self.run_pull_request()[0], 2)

    def test_squash_unknown_revision(self) -> None:
        """The squash check fails closed too."""
        self.assertEqual(self.run_main("squash", "--commit", "nonexistent")[0], 2)


class SquashTest(RepoTest):
    """The commit a squash merge leaves on main."""

    def check(self, message: str) -> int:
        """Return the squash check's exit status for a commit with this message."""
        self.commit(message)
        return self.run_main("squash", "--commit", "HEAD")[0]

    def test_single_commit_message_passes(self) -> None:
        """A pull request of one commit keeps that commit's message."""
        self.assertEqual(self.check("Change (#1)\n\nBody.\n\nRefs #1\n\n" + SIGNED), 0)

    def test_list_of_commits_passes(self) -> None:
        """A longer pull request lists its commits, so sign-offs sit in the middle."""
        message = (
            "Change (#1)\n\n* Change\n\nBody.\n\nSigned-off-by: alice <alice@example.com>\n\n"
            "* Another\n\nSigned-off-by: bob <bob@example.com>\n\n"
            "Co-authored-by: bob <bob@example.com>\n"
        )
        self.assertEqual(self.check(message), 0)

    def test_dependabot_message_passes(self) -> None:
        """Dependabot's own sign-off stays in the squash message and has another address."""
        self.assertEqual(self.check(DEPENDABOT_MESSAGE), 0)

    def test_replaced_message_fails(self) -> None:
        """A message written at merge time can lose the sign-off."""
        self.assertEqual(self.check("Change (#1)\n\nA new description.\n"), 1)

    def test_lines_that_only_look_like_a_sign_off_fail(self) -> None:
        """Only a whole, well-formed line after the subject counts."""
        for message in (
            "Signed-off-by: alice <alice@example.com>\n",
            "Change\n\nSee Signed-off-by: alice <alice@example.com>\n",
            "Change\n\n    Signed-off-by: alice <alice@example.com>\n",
            "Change\n\nSigned-off-by: alice\n",
        ):
            with self.subTest(message=message):
                self.assertEqual(self.check(message), 1)


if __name__ == "__main__":
    unittest.main()
