//! The pending screen: every request waiting for the owner, each with a way to
//! approve it (on the same approval page a notification links to) or deny it.

use maud::{Markup, html};
use warden_broker_proto::Access;

use super::{
    Chip, Nav, clock, destination_access, empty_icon, end_state_parts, fingerprint_forms, icon,
    key_icon, layout, stated_fields, window_words,
};
use crate::requests::{LinkHosts, PendingEntry};

/// What `entry` asks for when its current policy could not be read. It claims
/// nothing about whether the access can modify anything: the approval page does
/// that once it can read the policy, and refuses until then.
fn stored_access(entry: &PendingEntry) -> Markup {
    let subject = match &entry.request.access {
        Access::Ssh { target, user, .. } => format!("ssh {user}@{target}"),
        Access::Api { secret, .. } => format!("api {secret}"),
    };
    html! {
        code { bdi { (subject) } }
        span.detail { "Its current policy could not be read right now." }
    }
}

/// What the page says about itself. The script fills these in. In the list they
/// are overlaid, so that a message appearing moves no card under the owner's finger.
fn notices() -> Markup {
    html! {
        div.notices {
            p.result #result role="status" {}
            p.live-state #live-state role="status" {}
        }
    }
}

/// The card of one pending request. Both buttons are described by whose request
/// it is and its fingerprint, since every card has the same two labels. The agent
/// is a heading so that a screen reader can move from card to card.
fn card(entry: &PendingEntry, hosts: &LinkHosts, now: i64) -> Markup {
    let who = format!("agent-{}", entry.id);
    let fingerprint = format!("fingerprint-{}", entry.id);
    let described_by = format!("{who} {fingerprint}");
    let remaining = (entry.expires_at - now).max(0);
    html! {
        section.card.pending data-request=(entry.id) {
            div.field {
                span.label { "Requested by" }
                h2.who #(who) { bdi { (entry.agent) } }
            }
            div.field.tight {
                span.label { "Access" }
                @match &entry.destination {
                    Some(destination) => (destination_access(&entry.request, destination)),
                    None => (stored_access(entry)),
                }
            }
            div.field {
                span.label { "Goal" }
                span { bdi { (entry.request.goal) } }
            }
            // Above the meta line, so that the link is not next to the buttons.
            (stated_fields(&entry.request, hosts))
            div.meta {
                span #(fingerprint) { "Fingerprint " (fingerprint_forms(&entry.fingerprint)) }
                span { "Asks for " (window_words(entry.request.window)) }
                span {
                    "Expires " (clock(entry.expires_at)) " "
                    // The script keeps this phrase current.
                    span.remaining data-remaining=(remaining) {
                        "(in " ((remaining + 59) / 60) " min)"
                    }
                }
            }
            div.btns {
                button.btn.approve type="button" aria-describedby=(described_by) {
                    (icon(20, "2.2", &key_icon())) " Approve…"
                }
                button.btn.deny type="button" aria-describedby=(described_by) { "Deny" }
            }
        }
    }
}

/// Every request waiting for a decision, soonest expiry first. `data-pending` is
/// what the script refreshes, from the empty state as well, so both forms have
/// the notices, which it keeps when it replaces this `main`.
#[must_use]
pub fn pending(entries: &[PendingEntry], hosts: &LinkHosts, now: i64) -> Markup {
    if entries.is_empty() {
        let parts = end_state_parts(
            &Chip {
                icon: empty_icon(),
                text: "Nothing waiting",
            },
            "Pending requests",
            &html! { "No request is waiting for you. A request shows here until it is decided or expires." },
            None,
        );
        let content = html! {
            main.done data-pending="empty" {
                // First, so that what a denial said is on screen on a small phone.
                (notices())
                (parts)
            }
        };
        return layout("Pending requests", Some(Nav::Pending), true, &content);
    }
    let content = html! {
        main.wide data-pending="list" {
            h1 { "Pending requests" }
            p.lead {
                "Approve… opens the request's approval page on a new link. "
                "The link in its notification then stops working."
            }
            (notices())
            @for entry in entries { (card(entry, hosts, now)) }
        }
    };
    layout("Pending requests", Some(Nav::Pending), true, &content)
}
