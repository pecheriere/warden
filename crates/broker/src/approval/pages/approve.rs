//! The approval page for a pending request.

use maud::{Markup, html};

use super::{
    destination_access, github_token, icon, key_icon, layout, release, stated_fields, window_words,
    windows_for,
};
use crate::requests::{Destination, LinkHosts, PendingView, window_label};

/// The approval page for a pending request: the details on one side, the
/// fingerprint and the decision (grant window, Approve, Deny) on the other.
#[must_use]
pub fn approve(view: &PendingView, hosts: &LinkHosts, now: i64) -> Markup {
    let max = view.destination.max_window();
    let default = view.request.window.min(max);
    let remaining = (view.expires_at - now).max(0);
    let clock = html! {
        circle cx="12" cy="12" r="9" {}
        path d="M12 7v5l3 2" {}
    };
    // The script sends `data-target` back when the approval begins, binding
    // it to the destination shown here.
    let content = html! {
        main.split #approval data-target=(view.destination_digest()) {
            div.col {
                span.chip {
                    (icon(14, "2.4", &clock))
                    span {
                        "Pending · "
                        // The script rewrites the whole phrase: "expires in
                        // m:ss", then "expired".
                        span #countdown data-remaining=(remaining) {
                            "expires in " (remaining / 60) " min"
                        }
                    }
                }
                h1 { "Approve access?" }
                // Access before goal: the decision comes first, and long
                // agent-written text cannot push it off screen.
                section.card {
                    div.field {
                        span.label { "Requested by" }
                        span.who { bdi { (view.agent) } }
                    }
                    div.field.tight {
                        span.label { "Access" }
                        (destination_access(&view.agent, &view.request, &view.destination, view.github.as_ref()))
                    }
                    div.field {
                        span.label { "Goal" }
                        span { bdi { (view.request.goal) } }
                    }
                    (stated_fields(&view.request, hosts))
                    @if let (Destination::Release(policy), Some(facts)) = (&view.destination, &view.release) {
                        (release::facts(&view.request, policy, facts))
                    }
                }
            }
            div.col {
                section.fp {
                    span.label { "Fingerprint · must match the agent" }
                    code.fingerprint { (view.fingerprint.words()) }
                    span.fp-hex { "In hex " code { (view.fingerprint) } }
                }
                div.actions {
                    fieldset {
                        legend.label { "Grant for" }
                        // A release has one lifetime, said once below, so no cap to explain.
                        @let capped_by = match view.destination {
                            Destination::Ssh(_) => Some("target"),
                            Destination::Api(_) => Some("secret"),
                            Destination::CommitSigning(_) => Some("signing key"),
                            Destination::GithubToken(_) => Some("GitHub App"),
                            Destination::Release(_) => None,
                        };
                        @if let (true, Some(noun)) = (view.request.window > max, capped_by) {
                            p.detail.capped {
                                "Asked for " (window_words(view.request.window)) "; at most "
                                (window_words(max)) " for this " (noun) "."
                            }
                        }
                        @if matches!(view.destination, Destination::Release(_)) {
                            p.detail { (release::LIFETIME) }
                        }
                        div.seg {
                            @for window in windows_for(&view.destination).iter().copied().filter(|w| *w <= max) {
                                @let id = format!("window-{}", window_label(window));
                                input #(id) type="radio" name="window"
                                    value=(window_label(window)) checked[window == default];
                                label for=(id) { (window_words(window)) }
                            }
                        }
                    }
                    @let not_approvable = github_token::not_approvable(view);
                    @if let Some(message) = &not_approvable {
                        (message)
                    }
                    div.btns {
                        @if not_approvable.is_none() {
                            button.btn.approve #approve type="button" {
                                (icon(20, "2.2", &key_icon())) " Approve with passkey"
                            }
                        }
                        button.btn.deny #deny type="button" { "Deny" }
                    }
                    p.result #result role="status" {}
                }
            }
        }
    };
    layout("Approve access", None, true, &content)
}
