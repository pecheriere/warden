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

## What makes a contribution acceptable

A pull request can be merged when:

- every required check passes;
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
