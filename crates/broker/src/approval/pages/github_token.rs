//! What the pages say about GitHub tokens. Its wording matters: the owner must see
//! which repositories a grant covers (for a grant from before grants were scoped,
//! every repository the App is installed on), which grants approving ends, and that
//! a minted token outlives the grant's revocation.

use maud::{Markup, html};
use warden_broker_proto::github_permissions::{
    GrantedPermissions, Level, Permission, PermissionSet, sensitive_meaning,
};
use warden_broker_proto::github_token::{
    AutomaticCaller, EXTRA_NOT_ALLOWED, EXTRAS_NOT_ALLOWED, GithubTokenAccess, GrantScope,
};
use warden_broker_proto::{Access, AgentName};

use super::github_also_live::also_live;
use super::{icon, warning_icon};
use crate::policy::GithubTokenPolicy;
use crate::requests::{GithubPending, InstallationCheck, PendingView, ReplacedGrant, Resolution};

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
    if github.resolution == Resolution::NotAccessible {
        return Some(html! {
            p.cannot #cannot-approve role="alert" {
                "This request cannot be approved: the App is not installed on "
                @for (i, repo) in access.repositories.iter().enumerate() {
                    @if i > 0 { ", " }
                    code { bdi { (repo.as_str()) } }
                }
                ", or one of them does not exist."
            }
        });
    }
    // Before the installation: an extra the owner no longer allows is the owner's
    // own configuration, and holds whatever the App has.
    if !github.not_allowed.is_empty() {
        return Some(html! {
            p.cannot #cannot-approve role="alert" {
                "This request cannot be approved: "
                (if github.not_allowed.len() == 1 { EXTRA_NOT_ALLOWED } else { EXTRAS_NOT_ALLOWED })
                @for (i, refused) in github.not_allowed.iter().enumerate() {
                    @if i > 0 { ", " }
                    code { (refused.to_string()) }
                }
                "."
            }
        });
    }
    // Only after the repositories: what the installation holds is moot for a
    // repository the App cannot reach.
    match &github.installation {
        InstallationCheck::Holds => None,
        InstallationCheck::Missing(missing) => Some(html! {
            p.cannot #cannot-approve role="alert" {
                "This request cannot be approved: the App does not hold "
                @for (i, permission) in missing.iter().enumerate() {
                    @if i > 0 { ", " }
                    code { (permission.to_string()) }
                }
                " on GitHub."
            }
        }),
        InstallationCheck::Unreadable => Some(html! {
            p.cannot #cannot-approve role="alert" {
                "This request cannot be approved: the broker could not read the App\u{2019}s \
                 permissions on GitHub."
            }
        }),
    }
}

/// A permission as the page writes it: `name: level`. One in `extras` is marked
/// as an extra, a write one more strongly than a read one; a sensitive one, which
/// is always an extra, is in the danger colour instead of either.
fn permission(permission: &Permission, extras: &[Permission]) -> Markup {
    let class = if permission.is_sensitive() {
        "perm sensitive"
    } else if !extras.contains(permission) {
        "perm"
    } else if permission.level() == Level::Write {
        "perm extra-write"
    } else {
        "perm extra-read"
    };
    html! { code class=(class) { (permission.name()) ": " (permission.level().as_str()) } }
}

/// What each sensitive permission among `extras` allows, one fixed line each, under
/// the list: the owner decides on these as much as on the repositories.
fn sensitive_note(extras: &[Permission]) -> Markup {
    let sensitive: Vec<&Permission> = extras.iter().filter(|p| p.is_sensitive()).collect();
    html! {
        @if !sensitive.is_empty() {
            div.sensitive-note {
                strong {
                    (icon(14, "2.4", &warning_icon()))
                    span { "Sensitive permissions" }
                }
                ul {
                    @for item in sensitive {
                        li {
                            (permission(item, extras)) " can "
                            (sensitive_meaning(item)) "."
                        }
                    }
                }
            }
        }
    }
}

/// The permissions a token has: the whole set with its extras marked, how many
/// there are beyond what `beyond` says (`what`), and what the sensitive ones allow.
fn permissions(set: &PermissionSet, extras: &[Permission], beyond: &str) -> Markup {
    html! {
        span.detail {
            "Permissions: "
            (permission_list(set, extras))
        }
        @if !extras.is_empty() {
            span.detail { (extras.len()) " " (beyond) }
        }
        (sensitive_note(extras))
    }
}

/// How `set`, what approving grants, differs from the sets of the grants it ends:
/// one line "was ..." for each distinct set that is not `set`. A renewal that follows
/// a changed default shows what the grant held before.
fn was(set: &PermissionSet, replaces: &[ReplacedGrant]) -> Markup {
    let mut earlier: Vec<&PermissionSet> = Vec::new();
    for grant in replaces {
        if grant.permissions != *set && !earlier.contains(&&grant.permissions) {
            earlier.push(&grant.permissions);
        }
    }
    html! {
        @for old in earlier {
            span.detail { "was " (permission_list(old, &[])) }
        }
    }
}

/// The permissions of `set`, comma separated.
pub(super) fn permission_list(set: &PermissionSet, extras: &[Permission]) -> Markup {
    html! {
        @for (i, item) in set.iter().enumerate() {
            @if i > 0 { ", " }
            (permission(&item, extras))
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

/// The repositories: one is the page's headline when `headline`, several are a list.
fn listing(repos: &[Named], headline: bool) -> Markup {
    html! {
        @match repos {
            [only] if headline => span.repos.headline { (repository(only)) },
            [only] => span.repos { (repository(only)) },
            many => ul.repos {
                @for repo in many { li { (repository(repo)) } }
            },
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
                        ". Its permissions: " (permission_list(&grant.permissions, &[]))
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
            p.notice-count { "This request covers " (repos.len()) " repositories" }
        }
        @if repos.is_empty() {
            span { "Mint tokens for " (app(&policy.app_id, policy.installation_id)) }
        } @else {
            (listing(&repos, true))
        }
        @if reachable && !repos.is_empty() {
            (reach_of(&repos))
        }
        @if let (true, Some(pending)) = (reachable, pending) {
            (replaced(agent, &pending.replaces))
            (also_live(agent, &pending.also_live))
        }
        @if !repos.is_empty() {
            span.detail { "Mints tokens for " (app(&policy.app_id, policy.installation_id)) }
        }
        // The pending list has no stored set to show, only the approval page does.
        @if let Some(pending) = pending {
            (permissions(&pending.permissions.full, &pending.permissions.beyond_default, "beyond the default"))
            (was(&pending.permissions.full, &pending.replaces))
        }
        (automatic(request))
        span.detail {
            "warden mints a token whenever this agent asks, until the grant ends or is revoked, \
             and records each one. " (REVOKING)
        }
    }
}

/// What an active GitHub token grant gives, for the grants page: its repositories,
/// one per line. A grant from before grants were scoped mints nothing, so it carries
/// no warning.
pub(super) fn grant_access(
    app_id: &str,
    installation_id: u64,
    scope: &GrantScope,
    granted: &GrantedPermissions,
    extras: Option<&GrantedPermissions>,
) -> Markup {
    let repos: Vec<Named> = scope
        .list()
        .iter()
        .map(|r| Named {
            name: r.name.as_str().to_owned(),
            renamed_from: None,
        })
        .collect();
    html! {
        @if repos.is_empty() {
            span.legacy { "All repositories of the installation (ended at upgrade)" }
        } @else {
            (listing(&repos, false))
            (reach_of(&repos))
        }
        @if scope.is_legacy() {
            span.detail { "Minted tokens for " (app(app_id, installation_id)) " until it ended" }
        } @else {
            span.detail { "Mints tokens for " (app(app_id, installation_id)) }
        }
        @match (granted.known(), extra_list(extras)) {
            (Ok(set), Some(extras)) => (permissions(&set, &extras, "extra")),
            // Not reachable: grants are read from storage strictly, which refuses a set
            // this version cannot act on.
            _ => span.detail { "Permissions this broker cannot read" },
        }
        span.detail { (REVOKING) }
    }
}

/// The extras a grant was asked for, without `metadata`, in name order; `None` when
/// the stored set cannot be read.
fn extra_list(extras: Option<&GrantedPermissions>) -> Option<Vec<Permission>> {
    let Some(extras) = extras else {
        return Some(Vec::new());
    };
    extras.known().ok().map(|set| {
        set.extras_beyond(&PermissionSet::metadata_only())
            .iter()
            .collect()
    })
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
