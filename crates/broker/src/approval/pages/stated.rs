//! What a request says about where it came from: its session label and link. Both
//! are the agent's words, so every line here says so and none implies a check. The
//! label is free text, in `<bdi>` and escaped like a goal. A link is rendered as one
//! only while its host is on the owner's list; its text is the host it really goes
//! to, and the page behind it is the agent's too, so it is not called evidence.

use maud::{Markup, html};
use warden_broker_proto::{CreateRequest, SessionLink};

use crate::requests::LinkHosts;

/// The link itself: a new tab, with nothing of this page passed on.
fn anchor(link: &SessionLink, text: &Markup) -> Markup {
    html! {
        a.stated-link href=(link) target="_blank" rel="noopener noreferrer" { (text) }
    }
}

/// Said in place of a link whose host is not on the list: this request was made
/// before the list changed. Only the host, as text.
fn not_a_link(link: &SessionLink) -> Markup {
    html! {
        span.detail.stated-line {
            code { (link.host()) } " is not on your list of link hosts, so this is not a link."
        }
    }
}

/// The label and link as fields of a card, for the pages where the owner decides.
pub(super) fn stated_fields(request: &CreateRequest, hosts: &LinkHosts) -> Markup {
    html! {
        @if let Some(session) = &request.session {
            div.field {
                span.label { "Session · stated by the agent" }
                span { bdi { (session) } }
                span.detail { "Not verified: any session of this agent can state any name." }
            }
        }
        @if let Some(link) = &request.link {
            div.field {
                span.label { "Link · stated by the agent" }
                @if hosts.allows(link) {
                    (anchor(link, &html! { "Open " code { (link.host()) } }))
                    @if link.path() != "/" {
                        span.detail { code { (link.path()) } }
                    }
                    span.detail {
                        "Not verified: the agent chose this page, so it is context, not evidence."
                    }
                } @else {
                    (not_a_link(link))
                }
            }
        }
    }
}

/// The label and link in one short line each, for the lists of what already happened.
pub(super) fn stated_lines(request: &CreateRequest, hosts: &LinkHosts) -> Markup {
    html! {
        @if let Some(session) = &request.session {
            span.detail.stated-line { "Session stated by the agent: " bdi { (session) } }
        }
        @if let Some(link) = &request.link {
            @if hosts.allows(link) {
                span.detail.stated-line {
                    "Link stated by the agent: "
                    (anchor(link, &html! { code { (link.host()) } }))
                }
            } @else {
                (not_a_link(link))
            }
        }
    }
}
