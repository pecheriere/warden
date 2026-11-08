//! End states: the large mascot in a halo, a chip, a heading and a message, for
//! a page with nothing to act on.

use maud::{Markup, html};

use super::{icon, layout, mascot, warning_icon};

/// A link onward from an end state.
pub(super) struct Link {
    href: &'static str,
    text: &'static str,
}

/// The link from an end state to the owner's active grants.
const TO_GRANTS: Link = Link {
    href: "/grants",
    text: "View active grants",
};

/// The link from an end state to what is still waiting for the owner.
const TO_PENDING: Link = Link {
    href: "/pending",
    text: "View pending requests",
};

/// The status chip of an end state: an icon and a short text.
pub(super) struct Chip<'a> {
    pub(super) icon: Markup,
    pub(super) text: &'a str,
}

/// A finished or empty state: the large mascot in a halo, a status chip, a
/// heading, a short message and, if given, a link onward.
pub(super) fn end_state(
    chip: &Chip<'_>,
    heading: &str,
    message: &Markup,
    link: Option<&Link>,
) -> Markup {
    html! { main.done { (end_state_parts(chip, heading, message, link)) } }
}

/// What [`end_state`] puts in its `main`.
pub(super) fn end_state_parts(
    chip: &Chip<'_>,
    heading: &str,
    message: &Markup,
    link: Option<&Link>,
) -> Markup {
    html! {
        div.halo { (mascot()) }
        span.chip.center { (icon(14, "2.4", &chip.icon)) " " (chip.text) }
        h1 { (heading) }
        p { (message) }
        @if let Some(link) = link {
            a.btn.ghost.block href=(link.href) { (link.text) }
        }
    }
}

/// A crossed circle: withdrawn, or nothing there.
fn none_icon() -> Markup {
    html! { circle cx="12" cy="12" r="9" {} path d="m9 9 6 6M15 9l-6 6" {} }
}

/// An empty tray: nothing listed yet.
pub(super) fn empty_icon() -> Markup {
    html! { path d="M3 13h5l1 3h6l1-3h5" {} path d="M5 13 7 5h10l2 8v6H5z" {} }
}

/// The request behind a link is unknown, decided or expired, or a newer link
/// replaced this one. Says nothing about which, so links reveal nothing, and
/// words everything to hold in each case: the request may still be waiting.
#[must_use]
pub fn not_pending() -> Markup {
    let content = end_state(
        &Chip {
            icon: none_icon(),
            text: "Link not active",
        },
        "Nothing to approve on this link",
        &html! {
            "This request is no longer pending on this link: it was decided or expired, a newer "
            "link replaced this one, or it never existed. A request still waiting is under Pending."
        },
        Some(&TO_PENDING),
    );
    layout("Nothing to approve on this link", None, false, &content)
}

/// The agent withdrew the request behind a link. Shown only to the owner,
/// who holds the link, so it can say what happened.
#[must_use]
pub fn cancelled() -> Markup {
    let content = end_state(
        &Chip {
            icon: none_icon(),
            text: "Cancelled",
        },
        "Nothing to approve",
        &html! { "Cancelled by the agent." },
        Some(&TO_GRANTS),
    );
    layout("Nothing to approve", None, false, &content)
}

/// No page at this address.
#[must_use]
pub fn not_found() -> Markup {
    let content = end_state(
        &Chip {
            icon: none_icon(),
            text: "No page here",
        },
        "Not found",
        &html! { "There is no page at this address." },
        Some(&TO_GRANTS),
    );
    layout("Not found", None, false, &content)
}

/// The policy backend could not answer.
#[must_use]
pub fn unavailable(message: &str) -> Markup {
    let content = end_state(
        &Chip {
            icon: warning_icon(),
            text: "Unavailable",
        },
        "Policy unavailable",
        &html! { "The request cannot be shown right now: " strong { bdi { (message) } } },
        None,
    );
    layout("Policy unavailable", None, false, &content)
}

/// Something failed on the server; details are in its log.
#[must_use]
pub fn internal_error() -> Markup {
    let content = end_state(
        &Chip {
            icon: warning_icon(),
            text: "Error",
        },
        "Something went wrong",
        &html! { "The server logged the details." },
        None,
    );
    layout("Error", None, false, &content)
}
