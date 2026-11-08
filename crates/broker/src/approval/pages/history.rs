//! The history page: recent requests, newest first.

use maud::{Markup, html};
use warden_broker_proto::Access;

use super::end_states::end_state;
use super::format::secs_label;
use super::stated::stated_lines;
use super::{Chip, Nav, empty_icon, fingerprint_forms, layout, utc_parts};
use crate::requests::{HistoryEntry, LinkHosts, window_label};

/// Read-only list of recent requests, newest first: a card per request on a
/// phone, a table from 720 px.
#[must_use]
pub fn history(entries: &[HistoryEntry], hosts: &LinkHosts) -> Markup {
    if entries.is_empty() {
        let content = end_state(
            &Chip {
                icon: empty_icon(),
                text: "Nothing yet",
            },
            "History",
            &html! { "No requests yet. Every request an agent makes shows here." },
            None,
        );
        return layout("History", Some(Nav::History), false, &content);
    }
    let content = html! {
        main.wide {
            h1 { "History" }
            table.history {
                thead {
                    tr {
                        th.label { "Time" } th.label { "Agent" } th.label { "Goal" } th.label { "Access" }
                        th.label { "Fingerprint" } th.label { "Status" } th.label { "Window" }
                    }
                }
                tbody {
                    @for entry in entries {
                        @let subject = match &entry.request.access {
                            Access::Ssh { target, user, .. } => format!("{user}@{target}"),
                            Access::Api { secret, .. } => format!("api:{secret}"),
                            Access::CommitSigning {} => "commit signing".to_owned(),
                        };
                        // On a phone each row is a card; `data-label` names
                        // the cell there, where the header row is hidden.
                        @let (date, time) = utc_parts(entry.created_at);
                        tr {
                            td data-label="Time" {
                                span { span.nowrap { (date) } " " span.nowrap { (time) } }
                            }
                            td.who data-label="Agent" { bdi { (entry.agent) } }
                            td data-label="Goal" {
                                bdi { (entry.request.goal) }
                                (stated_lines(&entry.request, hosts))
                            }
                            td data-label="Access" { code { (subject) } }
                            td data-label="Fingerprint" { span { (fingerprint_forms(&entry.fingerprint)) } }
                            td data-label="Status" { span.chip { (entry.status) } }
                            td data-label="Window" {
                                @match entry.granted_secs {
                                    Some(secs) => (secs_label(secs)),
                                    None => { "asked " (window_label(entry.request.window)) },
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    layout("History", Some(Nav::History), false, &content)
}
