//! What the pages say about GitHub tokens. Its wording matters: the owner must see
//! which repositories a grant covers (for a grant from before grants were scoped,
//! every repository the App is installed on), which grants approving ends, and that
//! a minted token outlives the grant's revocation.

use maud::{Markup, html};
use warden_broker_proto::github_token::{
    AutomaticCaller, GithubTokenAccess, GrantScope, PERMISSIONS,
};
use warden_broker_proto::{Access, AgentName};

use super::{icon, warning_icon};
use crate::policy::GithubTokenPolicy;
use crate::requests::{GithubPending, PendingView, ReplacedGrant, Resolution};

/// What the approval page says instead of offering Approve, when the request names
/// no repository (a CLI from before grants were scoped) or GitHub says the App cannot
/// reach one it names; `None` when it can be approved.
pub(super) fn not_approvable(view: &PendingView) -> Option<Markup> {
    let (Access::GithubToken(access), Some(github)) = (&view.request.access, &view.github) else {
        return None;
    };
    if access.is_legacy() {
        return Some(html! {
            p.cannot #cannot-approve role="alert" {
                "This request cannot be approved: it names no repository. The agent's warden "
                "CLI predates repository-scoped GitHub grants; it needs an upgrade."
            }
        });
    }
    if github.resolution != Resolution::NotAccessible {
        return None;
    }
    Some(html! {
        p.cannot #cannot-approve role="alert" {
            "This request cannot be approved: the App is not installed on "
            @for (i, repo) in access.repositories.iter().enumerate() {
                @if i > 0 { ", " }
                code { bdi { (repo.as_str()) } }
            }
            ", or one of them does not exist."
        }
    })
}

/// The warning of what the access can change.
fn reach() -> Markup {
    html! {
        strong.badge.modify {
            (icon(14, "2.4", &warning_icon()))
            " Can push and merge on every repository the App is installed on"
        }
    }
}

/// The permissions every token has.
fn permissions() -> Markup {
    html! {
        span.detail {
            "Permissions: "
            @for (i, (name, level)) in PERMISSIONS.into_iter().enumerate() {
                @if i > 0 { ", " }
                code.perm { (name) ": " (level) }
            }
        }
    }
}

/// What a revocation does and does not stop.
const REVOKING: &str = "Revoking the grant stops new tokens at once, but tokens last 1 hour and \
                        cannot be recalled when revoked.";

/// The App and installation, as the owner approves and later reads them.
fn app(app_id: &str, installation_id: u64) -> Markup {
    html! { "GitHub App " code { bdi { (app_id) } } ", installation " code { (installation_id) } }
}

/// A repository as the page names it.
struct Named {
    name: String,
    /// The name it was approved under, when GitHub's differs.
    renamed_from: Option<String>,
}

/// The repositories to show: GitHub's resolution when there is one, otherwise the
/// names the request asked for.
fn named(request: &GithubTokenAccess, pending: Option<&GithubPending>) -> Vec<Named> {
    if let Some(GithubPending {
        resolution: Resolution::Resolved(list),
        ..
    }) = pending
    {
        return list
            .iter()
            .map(|r| Named {
                name: r.name.as_str().to_owned(),
                renamed_from: r.renamed_from.as_ref().map(|n| n.as_str().to_owned()),
            })
            .collect();
    }
    request
        .repositories
        .iter()
        .map(|r| Named {
            name: r.as_str().to_owned(),
            renamed_from: None,
        })
        .collect()
}

/// A repository's name in the identifier type, with the name it was approved under
/// when GitHub's differs.
fn repository(repo: &Named) -> Markup {
    html! {
        code { bdi { (repo.name) } }
        @if let Some(old) = &repo.renamed_from {
            " (approved as " code { bdi { (old) } } ")"
        }
    }
}

/// The warning of what the access can change, for the repositories it covers.
fn reach_of(repos: &[Named]) -> Markup {
    html! {
        strong.badge.modify {
            (icon(14, "2.4", &warning_icon()))
            // One child, so the badge's flex layout does not split the name from the words.
            span {
                @if let [only] = repos {
                    "Can push and merge on " bdi { (only.name) }
                } @else {
                    "Can push and merge on these " (repos.len()) " repositories"
                }
            }
        }
    }
}

/// The grants that approving would end, as a warning block of its own: the owner
/// decides on these as much as on the repositories, so they are not fine print.
fn replaced(agent: &AgentName, replaces: &[ReplacedGrant]) -> Markup {
    html! {
        @if !replaces.is_empty() {
            div.replaces {
                strong {
                    (icon(14, "2.4", &warning_icon()))
                    // One child, so the flex layout does not split the name from the words.
                    span {
                        "Approving also ends "
                        @if let [_] = replaces { "1 existing grant" } @else { (replaces.len()) " existing grants" }
                        " of " bdi { (agent) }
                    }
                }
                @for grant in replaces {
                    p {
                        "Approving ends " bdi { (agent) } "\u{2019}s grant for "
                        @match &grant.scope {
                            GrantScope::Legacy => "all repositories of the installation",
                            GrantScope::Repositories(list) => {
                                @for (i, repo) in list.iter().enumerate() {
                                    @if i > 0 { ", " }
                                    code { bdi { (repo.name) } }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Which tool filed the request, when one did.
fn automatic(request: &GithubTokenAccess) -> Markup {
    html! {
        @if let Some(auto) = &request.automatic {
            // Normal text, not muted: the owner must not mistake it for a deliberate push.
            span.automatic {
                "Filed automatically by "
                (match auto.by {
                    AutomaticCaller::GitCredential => "the git credential helper",
                    AutomaticCaller::GhWrapper => "the gh wrapper",
                })
                @if let Some(dir) = &auto.dir {
                    ". Working directory: " code { bdi { (dir) } }
                }
            }
        }
    }
}

/// What approving GitHub tokens gives, for the approval page; the pending list has
/// no resolution (`pending` is `None`) and shows the names as asked.
pub(super) fn access(
    policy: &GithubTokenPolicy,
    request: &GithubTokenAccess,
    agent: &AgentName,
    pending: Option<&GithubPending>,
) -> Markup {
    let repos = named(request, pending);
    let reachable = !matches!(
        pending,
        Some(GithubPending {
            resolution: Resolution::NotAccessible,
            ..
        })
    );
    html! {
        @if repos.len() > 1 {
            strong.badge.modify {
                (icon(14, "2.4", &warning_icon()))
                " This request covers " (repos.len()) " repositories"
            }
        }
        @match repos.as_slice() {
            [] => span { "Mint tokens for " (app(&policy.app_id, policy.installation_id)) },
            [only] => span.repos { (repository(only)) },
            many => ul.repos {
                @for repo in many { li { (repository(repo)) } }
            },
        }
        @if reachable && !repos.is_empty() {
            (reach_of(&repos))
        }
        @if let (true, Some(pending)) = (reachable, pending) {
            (replaced(agent, &pending.replaces))
        }
        @if !repos.is_empty() {
            span.detail { "Mints tokens for " (app(&policy.app_id, policy.installation_id)) }
        }
        (permissions())
        (automatic(request))
        span.detail {
            "warden mints a token whenever this agent asks, until the grant ends or is revoked, \
             and records each one. " (REVOKING)
        }
    }
}

/// What an active GitHub token grant gives, for the grants page.
pub(super) fn grant_access(app_id: &str, installation_id: u64) -> Markup {
    html! {
        span { "Mints tokens for " (app(app_id, installation_id)) }
        (reach())
        (permissions())
        span.detail { (REVOKING) }
    }
}

/// The grants page's note where other grants show what they are doing.
pub(super) fn live_note() -> Markup {
    html! {
        p.detail {
            "Tokens are minted when the agent asks, each lasting 1 hour, and every mint is in \
             the audit log."
        }
    }
}
