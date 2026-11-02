# Governance

warden has one maintainer, who makes the decisions. This document says how that
works today. It will change when the project has more people.

## Roles

**Maintainer:** [pecheriere](https://github.com/pecheriere), the only member of
the project with write access. The maintainer:

- sets the project's direction and [roadmap](docs/roadmap.md);
- triages issues, and reviews and merges pull requests;
- handles vulnerability reports under the [security policy](SECURITY.md);
- handles reports under the [code of conduct](CODE_OF_CONDUCT.md);
- creates releases, and keeps the repository's settings and dependencies in
  order.

**Contributors:** anyone who opens an issue or a pull request, as described in
[CONTRIBUTING.md](CONTRIBUTING.md). Contributing grants no access to the
repository.

Someone who contributes significantly and over time may be invited to take on a
role, with only the access that role needs. This document will be updated in the
same change.

## How decisions are made

The maintainer decides, in public where possible: in issues and pull requests,
with the reasons written down. Lasting design decisions go in
[`docs/design.md`](docs/design.md) and
[`docs/threat-model.md`](docs/threat-model.md). The exception is an undisclosed
vulnerability, which stays private until it is disclosed.

Disagreement is welcome, and the place for it is the issue or the pull request.

## Review

All changes reach `main` through a pull request, and the rules that protect it
list no exceptions, not even for the maintainer, who is also the only person
able to change them. Required status checks must pass, and commits on `main`
must be signed.

These rules do not need a second person's approval, because there is no second
person. The maintainer's own changes are merged without review by anyone else.

## Access to sensitive resources

| Resource | Who has access |
|---|---|
| Repository administration: settings, rulesets, collaborators | The maintainer |
| Merging to `main`, and creating releases and tags | The maintainer. Release tags cannot be moved or deleted |
| Private vulnerability reports, and security alerts | The maintainer |
| Container images in `ghcr.io/pecheriere/warden` | The maintainer's account owns them. The release workflow publishes them with GitHub's short-lived workflow token |
| The project website on GitHub Pages | Published by the Pages workflow from `main` |

The repository stores no long-lived secrets for GitHub Actions.

What happens if the maintainer becomes unavailable is tracked in
[#102](https://github.com/pecheriere/warden/issues/102).
