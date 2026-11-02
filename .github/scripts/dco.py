"""Check that commits carry a Developer Certificate of Origin sign-off.

`pull-request` checks every commit a pull request adds. A commit passes when the
trailer block at the end of its message has a `Signed-off-by: Name <address>`
line whose address is the commit author's. `git commit -s` writes exactly that.

Two kinds of commit pass without a sign-off:

- A merge of two parents whose tree is what git's own merge produces, such as the
  one `gh pr update-branch` creates. It adds no work of its own to certify, and
  the commits it brings in are checked themselves. A merge with hand-made changes
  or resolved conflicts is new work and needs a sign-off.
- A Dependabot commit on a pull request Dependabot opened. Both conditions are
  needed: anyone can write Dependabot's address into a commit, but only Dependabot
  can open a pull request as that account.

`squash` checks the commit a merge left on main. GitHub writes its message when
the pull request merges, so no check can run on it first: this one reports a
sign-off lost at that point. It needs one well-formed line anywhere after the
subject and compares no address, because a squash message lists the sign-offs of
all the pull request's commits and GitHub chooses the squash commit's author.

Commit metadata is untrusted. It only ever goes to the comparisons here, never to
a shell, and never to the output: the runner acts on workflow commands in log
lines, so the output holds only commit IDs and fixed text.

Exit status: 0 when every commit passes, 1 when one does not, 2 when the commits
could not be read.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[2]

MERGE_PARENTS = 2  # An update merge has two; a merge of more is never a clean one.
DEPENDABOT_ACCOUNT_ID = 49699333
DEPENDABOT_ADDRESS = "49699333+dependabot[bot]@users.noreply.github.com"

# What `git commit -s` writes, as one whole line: both checks read this form, so a
# message that passes on a pull request also passes once it is in a squash commit.
SIGN_OFF_LINE = re.compile(
    r"^Signed-off-by: [^\s<>](?:[^<>\n]*[^\s<>])? <([^\s<>@]+@[^\s<>@]+)>$", re.MULTILINE
)

MISSING = "no Signed-off-by trailer at the end of the commit message"
WRONG_ADDRESS = "no Signed-off-by trailer with the commit author's address"
SQUASH_MISSING = "no Signed-off-by line in the squash commit's message"
HELP = (
    "Add the sign-off with `git rebase --signoff <base>` and push again with "
    "`git push --force-with-lease`. That signs with your committer address, so if your "
    "commit's author address differs, fix your own commit with "
    "`git commit --amend --reset-author -s` as well. "
    "CONTRIBUTING.md explains what it means."
)
SQUASH_HELP = "The sign-off was lost at merge time: do not replace the default squash message."


class DcoError(Exception):
    """The commits could not be read; the message is fixed text, safe to print."""


class Commit(NamedTuple):
    """The parts of a commit the check reads."""

    sha: str
    author_address: str
    tree: str
    parents: tuple[str, ...]
    trailer_block: str


def _git(*args: str) -> subprocess.CompletedProcess[bytes]:
    """Run git in the repository, with fixed arguments and object IDs only."""
    return subprocess.run(["git", *args], check=False, capture_output=True, cwd=ROOT)


def _git_output(*args: str) -> str:
    """Return git's standard output, or fail without repeating what it printed."""
    result = _git(*args)
    if result.returncode != 0:
        message = f"git {args[0]} failed"
        raise DcoError(message)
    return result.stdout.decode(errors="replace")


def _resolve(revision: str) -> str:
    """Turn a revision from the command line into a commit ID."""
    return _git_output(
        "rev-parse", "--verify", "--quiet", "--end-of-options", f"{revision}^{{commit}}"
    ).strip()


def _read_commit(sha: str) -> Commit:
    """Read a commit. NUL cannot occur in the fields, so it separates them safely.

    `%(trailers)` with no options is git's trailer block exactly as written; options
    would normalize the key's case and spacing, and join folded lines.
    """
    output = _git_output(
        "log", "-1", "--no-show-signature", "--format=%ae%x00%T%x00%P%x00%(trailers)", sha
    )
    author_address, tree, parents, trailer_block = output.split("\0", 3)
    return Commit(sha, author_address, tree, tuple(parents.split()), trailer_block)


def _commits_between(base: str, head: str) -> list[Commit]:
    """Read the commits reachable from head but not from base, oldest first."""
    output = _git_output("rev-list", "--reverse", f"{base}..{head}")
    if not output:
        message = "the range holds no commits"
        raise DcoError(message)
    return [_read_commit(sha) for sha in output.split()]


def _is_clean_merge(commit: Commit) -> bool:
    """Say whether a commit is exactly what git's merge makes of its two parents."""
    if len(commit.parents) != MERGE_PARENTS:
        return False
    # A conflict (exit status 1) or unrelated histories (above 1) mean work was added by hand.
    result = _git("merge-tree", "--write-tree", "--no-messages", *commit.parents)
    return result.returncode == 0 and result.stdout.decode(errors="replace").strip() == commit.tree


def problem_with(commit: Commit, *, opened_by_dependabot: bool) -> str | None:
    """Return what is wrong with a pull request's commit, or None when it passes."""
    if opened_by_dependabot and commit.author_address == DEPENDABOT_ADDRESS:
        return None
    addresses = {address.casefold() for address in SIGN_OFF_LINE.findall(commit.trailer_block)}
    if commit.author_address.casefold() in addresses:
        return None
    if _is_clean_merge(commit):
        return None
    return WRONG_ADDRESS if addresses else MISSING


def _report(failures: list[tuple[str, str]], total: int, help_text: str) -> int:
    """Print the outcome. Only commit IDs and fixed text reach the log."""
    for sha, reason in failures:
        print(f"::error title=DCO::Commit {sha}: {reason}")
    if failures:
        print(help_text)
        return 1
    print(f"{total} commit(s) checked: all pass")
    return 0


def check_pull_request(base: str, head: str, pr_author_id: int | None) -> int:
    """Check every commit a pull request adds to its base."""
    commits = _commits_between(_resolve(base), _resolve(head))
    opened_by_dependabot = pr_author_id == DEPENDABOT_ACCOUNT_ID
    failures = []
    for commit in commits:
        reason = problem_with(commit, opened_by_dependabot=opened_by_dependabot)
        if reason:
            failures.append((commit.sha, reason))
    return _report(failures, len(commits), HELP)


def check_squash(revision: str) -> int:
    """Check that the commit a merge left on main still has a sign-off."""
    sha = _resolve(revision)
    message = _git_output("log", "-1", "--no-show-signature", "--format=%B", sha)
    _subject, _, body = message.partition("\n")
    failures = [] if SIGN_OFF_LINE.search(body) else [(sha, SQUASH_MISSING)]
    return _report(failures, 1, SQUASH_HELP)


def main(argv: list[str] | None = None) -> int:
    """Run the check the command line asks for."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    pull_request = commands.add_parser("pull-request", help="check a pull request's commits")
    pull_request.add_argument("--base", required=True, help="revision the pull request merges into")
    pull_request.add_argument("--head", required=True, help="the pull request's last commit")
    pull_request.add_argument(
        "--pr-author-id", type=int, help="numeric GitHub account ID of the pull request's author"
    )
    squash = commands.add_parser("squash", help="check a squash commit on main")
    squash.add_argument("--commit", required=True, help="revision to check")
    args = parser.parse_args(argv)
    try:
        if args.command == "squash":
            return check_squash(args.commit)
        return check_pull_request(args.base, args.head, args.pr_author_id)
    except DcoError as err:
        print(f"::error title=DCO::{err}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
