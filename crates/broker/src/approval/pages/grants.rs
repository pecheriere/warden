//! The active grants page, with what each grant is doing now.

use maud::{Markup, html};
use warden_broker_proto::GrantAccess;

use super::super::LiveGrant;
use super::end_states::end_state;
use super::format::{bytes, idle_label};
use super::stated::stated_lines;
use super::{
    Chip, Nav, clock, commit_signing, empty_icon, fingerprint_forms, grant_access, layout,
};
use crate::requests::{ActiveGrant, LinkHosts};

/// What warden can see of a grant's use, by its kind.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LiveKind {
    /// SSH certificate: the logins go straight to the target.
    Cert,
    /// SSH through the relay: sessions.
    Relay,
    /// API secret through the proxy: calls.
    Api,
    /// Commit signing: each signature is one quick call, recorded in the log.
    CommitSigning,
}

impl LiveKind {
    const fn of(access: &GrantAccess) -> Self {
        match access {
            GrantAccess::Ssh(_) => Self::Cert,
            GrantAccess::Relay(_) => Self::Relay,
            GrantAccess::Api(_) => Self::Api,
            GrantAccess::CommitSigning(_) => Self::CommitSigning,
        }
    }

    /// The `data-kind` of the live area, read by `warden.js`.
    const fn name(self) -> &'static str {
        match self {
            Self::Cert => "cert",
            Self::Relay => "relay",
            Self::Api => "api",
            Self::CommitSigning => "commit-signing",
        }
    }
}

/// `n` and `one`, or `n` and `many` unless `n` is 1 (`1 session`, `2 sessions`).
fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The live area of a grant card: what the grant is doing right now
/// (`live`), refreshed by `warden.js` from `GET /grants/live`, which builds
/// the same markup.
fn live_area(grant: &ActiveGrant, live: Option<&LiveGrant<'_>>) -> Markup {
    let kind = LiveKind::of(&grant.access);
    let (sessions, calls) = live.map_or((&[][..], &[][..]), |l| {
        (&l.relay_sessions[..], &l.proxy_calls[..])
    });
    let summary = [
        (!sessions.is_empty()).then(|| count(sessions.len(), "session", "sessions") + " open"),
        (!calls.is_empty()).then(|| count(calls.len(), "call", "calls") + " in flight"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" · ");
    html! {
        div.live-area data-grant=(grant.grant_id) data-kind=(kind.name()) {
            @if kind == LiveKind::Cert {
                // Issued, never "used": warden cannot know.
                p.detail {
                    "Certificate issued " (clock(grant.not_before))
                    ", expires " (clock(grant.not_after)) "."
                }
                p.detail { "Certificate logins are not visible to warden, so this does not show whether it was used." }
            } @else if kind == LiveKind::CommitSigning {
                (commit_signing::live_note())
            } @else if summary.is_empty() {
                p.detail { (if kind == LiveKind::Relay { "No sessions open" } else { "No calls in flight" }) }
            } @else {
                p.live { (summary) }
                ul.live-list role="list" {
                    @for session in sessions {
                        li {
                            span { "Session since " (clock(session.started_at)) }
                            // The two counts break apart only between them.
                            span {
                                span.nowrap { (bytes(session.bytes_to_target)) " to target" }
                                " · "
                                span.nowrap { (bytes(session.bytes_from_target)) " from target" }
                            }
                            span.nowrap.idle { (idle_label(session.idle_secs)) }
                        }
                    }
                    @for call in calls {
                        li {
                            code { bdi { (call.method) " " (call.path) } }
                            span { "since " (clock(call.started_at)) }
                        }
                    }
                }
            }
        }
    }
}

/// The warning that changes ending access took effect but are not in the audit
/// log yet.
/// It comes from the server's state, so it lasts until they are, whatever the
/// page reloads for.
fn unwritten_warning(unwritten: i64) -> Markup {
    html! {
        @if unwritten > 0 {
            p.warning role="alert" {
                strong { "Not in the audit log. " }
                "The access or request was ended, but " (unwritten)
                " audit log entries could not be written yet. warden keeps trying. Check the \
                 server's log and the disk that holds the audit log."
            }
        }
    }
}

/// Active grants, one card each, with what each is doing now (`live`, one
/// entry per grant) and revoke buttons, under a warning if `unwritten` audit
/// entries are waiting for the log.
#[must_use]
pub fn grants(
    grants: &[ActiveGrant],
    live: &[LiveGrant<'_>],
    hosts: &LinkHosts,
    now: i64,
    unwritten: i64,
) -> Markup {
    if grants.is_empty() {
        let content = end_state(
            &Chip {
                icon: empty_icon(),
                text: "None active",
            },
            "Active grants",
            &html! { "No active grants. A grant shows here once you approve a request." },
            None,
        );
        let content = html! { (unwritten_warning(unwritten)) (content) };
        return layout("Active grants", Some(Nav::Grants), false, &content);
    }
    let content = html! {
        main.wide {
            h1 { "Active grants" }
            (unwritten_warning(unwritten))
            @for grant in grants {
                section.card.grant {
                    div.field.tight {
                        span.who #(format!("agent-{}", grant.grant_id)) { bdi { (grant.agent) } }
                        (grant_access(grant))
                        (stated_lines(&grant.request, hosts))
                        div.meta {
                            span { "Fingerprint " (fingerprint_forms(&grant.fingerprint)) }
                            @if matches!(grant.access, GrantAccess::CommitSigning(_)) {
                                (commit_signing::ends(grant.not_after, now))
                            } @else {
                                span {
                                    "Ends " (clock(grant.not_after))
                                    " (in " (((grant.not_after - now).max(0) + 59) / 60) " min)"
                                }
                            }
                            span #(format!("grant-{}", grant.grant_id)) {
                                "Grant " code { (grant.grant_id) }
                            }
                        }
                    }
                    // Every button reads "Revoke"; the description says whose
                    // grant and which one.
                    div.grant-actions {
                        @if matches!(grant.access, GrantAccess::CommitSigning(_)) {
                            (commit_signing::renew_button(grant))
                        }
                        button.revoke type="button" data-grant=(grant.grant_id)
                            aria-describedby=(format!("agent-{0} grant-{0}", grant.grant_id)) { "Revoke" }
                    }
                    // Under the details and the button, across the card.
                    (live_area(grant, live.iter().find(|l| l.grant_id == grant.grant_id)))
                }
            }
            p.result #result role="status" {}
        }
    };
    layout("Active grants", Some(Nav::Grants), true, &content)
}
