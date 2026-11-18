//! The agent's other live grants on the repositories of a GitHub token request, as a
//! block of its own on the approval page. Approving leaves them as they are, so it
//! informs and never warns: it takes the soft colours, not the warning ones.
//! Nothing here links to or acts on them; revoking stays on the grants page.

use maud::{Markup, html};
use warden_broker_proto::AgentName;
use warden_broker_proto::github_token::GrantScope;

use super::format::utc_parts;
use super::github_token::permission_list;
use crate::requests::ReplacedGrant;

/// One line for each grant of `agent` in `grants`: its repositories, its
/// permissions and when it ends. Nothing when there are none.
pub(super) fn also_live(agent: &AgentName, grants: &[ReplacedGrant]) -> Markup {
    html! {
        @if !grants.is_empty() {
            div.also-live {
                strong { "Also live" }
                span.detail {
                    "Approving leaves " bdi { (agent) } "\u{2019}s other grants on these repositories as they are."
                }
                ul {
                    @for grant in grants {
                        // A date as well as a time: these grants can last 30 days.
                        @let (date, time) = utc_parts(grant.not_after);
                        li {
                            @match &grant.scope {
                                GrantScope::Legacy => "all repositories of the installation",
                                GrantScope::Repositories(list) => {
                                    @for (i, repo) in list.iter().enumerate() {
                                        @if i > 0 { ", " }
                                        code { bdi { (repo.name) } }
                                    }
                                }
                            }
                            ": " (permission_list(&grant.permissions, &[]))
                            ", until " (date) " " (time)
                        }
                    }
                }
            }
        }
    }
}
