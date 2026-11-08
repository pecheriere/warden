//! HTML pages of the approval UI, rendered with maud (all text escaped).
//!
//! Text that agents control (goals, agent names) is wrapped in `<bdi>` so
//! bidirectional overrides inside it cannot reorder the surrounding page.
//! Pages carry no inline script; behaviour lives in `/static/warden.js`.
//!
//! This module holds the layout and the helpers the pages share; each page or
//! group of pages has its own submodule.

use maud::{DOCTYPE, Markup, html};
use warden_broker_proto::{Access, ApiGrant, CreateRequest, Fingerprint, GrantAccess, Window};

use crate::policy::{ApiScope, SshMode};
use crate::requests::{ActiveGrant, Destination};

mod approve;
mod commit_signing;
mod end_states;
mod enroll;
mod format;
mod grants;
mod history;
mod pending;
mod stated;
#[cfg(test)]
mod stated_tests;
#[cfg(test)]
mod tests;

pub use self::approve::approve;
use self::end_states::{Chip, empty_icon, end_state_parts};
pub use self::end_states::{cancelled, internal_error, not_found, not_pending, unavailable};
pub use self::enroll::enroll;
use self::format::{clock, utc_parts};
pub use self::grants::grants;
pub use self::history::history;
pub use self::pending::pending;
use self::stated::stated_fields;

/// Every window, shortest first.
const WINDOWS: [Window; 4] = [Window::M15, Window::M30, Window::H1, Window::H4];

/// The page of the header navigation a page is, marked `aria-current`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Nav {
    Pending,
    Grants,
    History,
    Enroll,
}

/// The header navigation links, `current` marked as the current page.
fn nav_links(current: Option<Nav>) -> Markup {
    html! {
        @for (page, href, text) in [
            (Nav::Pending, "/pending", "Pending"),
            (Nav::Grants, "/grants", "Active grants"),
            (Nav::History, "/history", "History"),
            (Nav::Enroll, "/enroll", "Enroll a passkey"),
        ] {
            a href=(href) aria-current=[(current == Some(page)).then_some("page")] { (text) }
        }
    }
}

/// The warden mascot (master: `docs/design/mascot.svg`), inlined so the page
/// makes no image request. Decoration: hidden from assistive technology.
fn mascot() -> Markup {
    html! {
        svg.mascot xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" aria-hidden="true" {
            ellipse cx="60" cy="114" rx="30" ry="4" fill="#0F1E3D" opacity="0.12" {}
            path d="M62 22 C62 8 78 2 90 8 C80 10 72 14 68 22 Z" fill="#F5B800" {}
            path d="M66 20 C70 12 80 10 86 14" fill="none" stroke="#0F1E3D" stroke-width="2"
                stroke-linecap="round" opacity="0.25" {}
            rect x="34" y="70" width="52" height="38" rx="16" fill="#2557D6" {}
            rect x="34" y="70" width="52" height="38" rx="16" fill="#0F1E3D" opacity="0.15" {}
            path d="M22 72 C22 38 38 20 60 20 C82 20 98 38 98 72 Z" fill="#2557D6" {}
            path d="M60 20 L60 72" stroke="#0F1E3D" stroke-width="3" opacity="0.18" {}
            rect x="28" y="46" width="64" height="22" rx="11" fill="#0F1E3D" {}
            circle cx="47" cy="57" r="5.5" fill="#FFFFFF" {}
            circle cx="73" cy="57" r="5.5" fill="#FFFFFF" {}
            circle cx="48.5" cy="55.5" r="1.8" fill="#0F1E3D" {}
            circle cx="74.5" cy="55.5" r="1.8" fill="#0F1E3D" {}
            rect x="18" y="68" width="84" height="8" rx="4" fill="#DCE6FB" {}
            circle cx="60" cy="90" r="9" fill="#F5B800" {}
            circle cx="60" cy="88" r="2.6" fill="#0F1E3D" {}
            path d="M60 89 L60 94" stroke="#0F1E3D" stroke-width="2.6" stroke-linecap="round" {}
            rect x="40" y="104" width="14" height="8" rx="4" fill="#0F1E3D" {}
            rect x="66" y="104" width="14" height="8" rx="4" fill="#0F1E3D" {}
        }
    }
}

/// A 24-unit line icon drawn in the current text colour, `size` px square.
/// Decoration: the text next to it says the same.
fn icon(size: u8, stroke_width: &str, shapes: &Markup) -> Markup {
    html! {
        svg width=(size) height=(size) viewBox="0 0 24 24" fill="none" stroke="currentColor"
            stroke-width=(stroke_width) stroke-linecap="round" stroke-linejoin="round"
            aria-hidden="true" { (shapes) }
    }
}

fn layout(title: &str, current: Option<Nav>, with_script: bool, content: &Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover";
                title { (title) " · warden" }
                link rel="stylesheet" href="/static/warden.css";
                @if with_script {
                    script src="/static/warden.js" defer {}
                }
            }
            body {
                header {
                    (mascot())
                    span.brand { "warden" }
                    nav aria-label="Main" { (nav_links(current)) }
                    // Under 720 px the links hide behind this disclosure, which
                    // needs no script.
                    details.nav-menu {
                        summary.menu aria-label="Menu" {
                            (icon(20, "2", &html! { path d="M4 7h16M4 12h16M4 17h16" {} }))
                        }
                        nav aria-label="Main menu" { (nav_links(current)) }
                    }
                }
                (content)
            }
        }
    }
}

/// `ssh user@target (host:port)` for a request and the address it reaches.
fn access_line(request: &CreateRequest, host: &str, port: u16) -> String {
    match &request.access {
        Access::Ssh { target, user, .. } if host.contains(':') => {
            format!("ssh {user}@{target} ([{host}]:{port})")
        }
        Access::Ssh { target, user, .. } => format!("ssh {user}@{target} ({host}:{port})"),
        Access::Api { secret, .. } => format!("api {secret}"),
        Access::CommitSigning {} => "commit signing".to_owned(),
    }
}

/// `use secret <name> for <METHODS> on <origin><prefix> (header <header>)`:
/// what an API grant lets the broker do with the secret.
fn api_access(grant: &ApiGrant) -> Markup {
    html! {
        "use secret " code { bdi { (grant.secret) } }
        " for " code { bdi { (grant.methods.join(", ")) } }
        " on " code { bdi { (grant.origin) (grant.path_prefix) } }
        " (header " code { bdi { (grant.header) } } ")"
    }
}

/// Whether `scope` can change anything upstream: a **Read-only** badge, or a
/// warning naming every method that can modify.
fn modify_line(scope: &ApiScope) -> Markup {
    let modifying = scope.modifying_methods();
    if modifying.is_empty() {
        read_only_badge()
    } else {
        can_modify_badge(&modifying.join(", "))
    }
}

/// The badge for access that cannot change anything upstream.
fn read_only_badge() -> Markup {
    let lock = html! {
        rect x="5" y="11" width="14" height="10" rx="2" {}
        path d="M8 11V8a4 4 0 0 1 8 0v3" {}
    };
    html! { strong.badge.readonly { (icon(14, "2.4", &lock)) " Read-only" } }
}

/// The badge for access that can change things upstream through `what`.
fn can_modify_badge(what: &str) -> Markup {
    html! { strong.badge.modify { (icon(14, "2.4", &warning_icon())) " Can modify: " (what) } }
}

/// A warning triangle.
fn warning_icon() -> Markup {
    html! {
        path d="M12 3 2 20h20L12 3z" {}
        path d="M12 10v4M12 17h.01" {}
    }
}

/// A fingerprint where it is not the page's main fact: the words people compare,
/// then the hex that the API, the audit log and older CLIs show.
fn fingerprint_forms(fingerprint: &Fingerprint) -> Markup {
    html! {
        code.fp-words { (fingerprint.words()) } " " code.fp-other { (fingerprint) }
    }
}

/// A key: approving or creating with a passkey.
fn key_icon() -> Markup {
    html! {
        circle cx="8" cy="15" r="4" {}
        path d="m10.8 12.2 8.2-8.2M16 7l3 3M14 9l2 2" {}
    }
}

/// What approving `request` gives access to under `destination`: for a
/// relay target also that the session goes through the warden relay; for an
/// API secret also how its value is written (the secret shown as `…`) and
/// whether a pinned CA replaces the system roots.
fn destination_access(request: &CreateRequest, destination: &Destination) -> Markup {
    match destination {
        Destination::Ssh(target) => html! {
            span {
                code { (access_line(request, &target.host, target.port)) }
                @if target.mode == SshMode::Relay { " via the warden relay" }
            }
        },
        Destination::Api(policy) => html! {
            @match super::api_scope(request, policy) {
                Ok(scope) => {
                    span { (api_access(&policy.grant_for(&scope))) }
                    (modify_line(&scope))
                }
                Err(message) => span { bdi { (message) } },
            }
            span.detail {
                "value " code { bdi { (policy.format.prefix()) "…" (policy.format.suffix()) } }
                ", pinned CA: " (if policy.ca_pem.is_some() { "yes" } else { "no" })
            }
        },
        Destination::CommitSigning(policy) => commit_signing::access(&policy.key_fingerprint),
    }
}

/// What an active grant gives access to: the access line and, for an API
/// secret, its badge, each a child of the card's field.
fn grant_access(grant: &ActiveGrant) -> Markup {
    match &grant.access {
        GrantAccess::Ssh(ssh) => {
            html! { code { (access_line(&grant.request, &ssh.host, ssh.port)) } }
        }
        GrantAccess::Api(api) => html! {
            span { (api_access(api)) }
            @match ApiScope::try_from(api) {
                Ok(scope) => (modify_line(&scope)),
                // A damaged record: the label must not claim read-only.
                Err(_) => (can_modify_badge("unverified scope")),
            }
        },
        GrantAccess::Relay(relay) => html! {
            span {
                code { "ssh " bdi { (relay.user) "@" (relay.target) } }
                " via the warden relay"
            }
        },
        GrantAccess::CommitSigning(signing) => {
            commit_signing::grant_access(&signing.key_fingerprint)
        }
    }
}

/// A grant window in words for the window picker (`15 min`, `1 h`).
const fn window_words(window: Window) -> &'static str {
    match window {
        Window::M15 => "15 min",
        Window::M30 => "30 min",
        Window::H1 => "1 h",
        Window::H4 => "4 h",
        Window::D1 => "1 day",
        Window::D7 => "7 days",
        Window::D30 => "30 days",
        Window::D90 => "90 days",
    }
}

/// The windows a grant of `destination` can have, shortest first.
const fn windows_for(destination: &Destination) -> [Window; 4] {
    match destination {
        Destination::CommitSigning(_) => Window::COMMIT_SIGNING,
        Destination::Ssh(_) | Destination::Api(_) => WINDOWS,
    }
}
