# Contributing to warden

Contributions are welcome: bug reports, documentation, tests and code. warden
is a security tool with [one maintainer](GOVERNANCE.md), so a reply can take a
while, and a change is judged first on whether it keeps warden safe.

By taking part you agree to the [code of conduct](CODE_OF_CONDUCT.md).

## Where to discuss

Public discussion happens in
[GitHub issues](https://github.com/pecheriere/warden/issues) and pull requests.
Discussions are not enabled. Use an issue for questions and ideas too.

The exception is a suspected vulnerability: never open a public issue for one.
Follow the [security policy](SECURITY.md).

## Reporting a bug

[Open an issue](https://github.com/pecheriere/warden/issues/new) and say:

- which version you run (`warden --version`, and the image tag or
  `warden-server --version` on the server);
- what you did, what you expected and what happened;
- the setup, if it matters: Docker or systemd, which platform;
- the output of `warden-server doctor` or `warden doctor`, if the problem looks
  like a setup problem.

Before you post logs or output, remove tokens, hostnames, addresses and
anything else you would not publish.

## Making a change

1. Find or open an issue first, unless the change is small. A change that
   affects the design or the security model should be agreed there before you
   write it.
2. Read [`AGENTS.md`](AGENTS.md). It holds the rules for everyone, people and
   coding agents alike: ground rules, the repository layout, the checks to run,
   and how changes and releases work.
3. Before you touch anything that handles secrets, grants or approval, read
   the [threat model](docs/threat-model.md).
4. Set up your tools with [Building and dependencies](docs/building.md).
5. Open one pull request per issue, and fill in
   [the template](.github/pull_request_template.md). Say what you tested and
   what you did not.

## Sign-off (DCO)

warden uses the [Developer Certificate of Origin](https://developercertificate.org/).
Every commit ends with a line saying that its author has the right to
contribute the change under the project's licenses, as the certificate sets
out. Commit signatures do not say this: they say who made a commit, not whether
they were entitled to contribute it.

```sh
git commit -s
```

That adds `Signed-off-by: Your Name <your address>` from your git identity. The
line is public for good, so use an address you are happy to publish: GitHub's
`users.noreply.github.com` address for your account works. To add missing
sign-offs to a branch, run `git rebase --signoff origin/main` and push with
`git push --force-with-lease`. That signs with your committer address, so if
your own commit's author address differs, the check stays red until you also run
`git commit --amend --reset-author -s` on it.

Coding agents have [their own rule](AGENTS.md#sign-off-dco).

**What the `dco` check accepts** (`.github/workflows/dco.yml`, running
`.github/scripts/dco.py` on every commit a pull request adds):

| Commit | Rule |
|---|---|
| Ordinary commit | Needs a well-formed `Signed-off-by` in the trailer block at the end of the message, with the commit author's address. The name is not compared. A line elsewhere in the message does not count. |
| Clean merge of two parents, such as `gh pr update-branch` makes | Passes without a sign-off: its tree is exactly what git's merge produces, so it adds no work, and the commits it brings in are checked themselves. |
| Merge with resolved conflicts or other changes of its own, or of more than two parents | Is new work, so it needs a sign-off like any commit. |
| Dependabot's commit on a pull request Dependabot opened | Passes: a bot cannot certify anything, and the maintainer reviews the bump. The check takes the pull request's author from GitHub, because anyone can put Dependabot's address on a commit. A person's commit on that pull request needs a sign-off. |

The check shows that the statement was made. It does not prove who made it: a
commit's author is whatever the committer typed.

**Squash merges.** `main` keeps only squash commits. The repository's default
squash message includes the commit messages, so the sign-offs carry over: merge
with that default, and do not replace it (`gh pr merge --body`, or by editing it
in the merge box) unless the new message keeps a `Signed-off-by`. GitHub writes
that message at merge time, so nothing can check it first; the `dco-squash` job
checks each commit on `main` afterwards and reports one that lost its sign-off.
It needs one well-formed line and compares no address, since GitHub chooses the
squash commit's author. Dependabot's messages already carry its own sign-off.

The repository setting "require contributors to sign off on web-based commits"
applies to commits made in GitHub's web interface. The check covers those commits
like any other.

## What makes a contribution acceptable

A pull request can be merged when:

- every required check passes;
- every commit is signed off, as above;
- it follows `AGENTS.md`, including its rules on secrets, lints, dependencies
  and private details;
- it meets the test policy below;
- user-visible changes have a line in the changelog, and the docs match the new
  behaviour;
- the maintainer agrees that warden should have the change.

A change can be declined even if it passes every check, for example if it adds
more risk or upkeep than it is worth. The reason will be given on the pull
request.

## Test policy

- **New functionality gets tests.** Major new functionality must add tests to
  the automated suite in the same pull request.
- **A fix gets a regression test.** A bug fix must add a test that fails without
  the fix.

If a change really cannot be tested automatically, for example a documentation
change, say so and why in the pull request. CI runs the suite on every pull
request, and it must pass before a merge. `AGENTS.md` lists what the tests need
to run, and the rule that they must not depend on timing.
