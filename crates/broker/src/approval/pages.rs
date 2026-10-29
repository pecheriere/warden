//! HTML pages of the approval UI, rendered with maud (all text escaped).
//!
//! Text that agents control (goals, agent names) is wrapped in `<bdi>` so
//! bidirectional overrides inside it cannot reorder the surrounding page.
//! Pages carry no inline script; behaviour lives in `/static/warden.js`.

use maud::{DOCTYPE, Markup, html};
use warden_broker_proto::{Access, ApiGrant, CreateRequest, GrantAccess, Window};

use crate::policy::{ApiScope, SshMode};
use crate::requests::{ActiveGrant, Destination, HistoryEntry, PendingView, window_label};

/// Every window, shortest first.
const WINDOWS: [Window; 4] = [Window::M15, Window::M30, Window::H1, Window::H4];

/// The page of the header navigation a page is, marked `aria-current`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Nav {
    Grants,
    History,
    Enroll,
}

/// The header navigation links, `current` marked as the current page.
fn nav_links(current: Option<Nav>) -> Markup {
    html! {
        @for (page, href, text) in [
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
                    nav.links aria-label="Main" { (nav_links(current)) }
                    // Under 720 px the links hide behind this disclosure, which
                    // needs no script.
                    details.nav-menu {
                        summary.menu aria-label="Menu" {
                            (icon(20, "2", &html! { path d="M4 7h16M4 12h16M4 17h16" {} }))
                        }
                        nav aria-label="Main" { (nav_links(current)) }
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
    }
}

/// A grant window in words for the window picker (`15 min`, `1 h`).
const fn window_words(window: Window) -> &'static str {
    match window {
        Window::M15 => "15 min",
        Window::M30 => "30 min",
        Window::H1 => "1 h",
        Window::H4 => "4 h",
    }
}

/// The approval page for a pending request: the details on one side, the
/// fingerprint and the decision (grant window, Approve, Deny) on the other.
#[must_use]
pub fn approve(view: &PendingView, now: i64) -> Markup {
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
        main.split #approval data-target=(view.destination.digest()) {
            div.col {
                span.chip {
                    (icon(14, "2.4", &clock))
                    span {
                        "Pending · expires "
                        span #countdown data-remaining=(remaining) { "in " (remaining / 60) " min" }
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
                        (destination_access(&view.request, &view.destination))
                    }
                    div.field {
                        span.label { "Goal" }
                        span { bdi { (view.request.goal) } }
                    }
                }
            }
            div.col {
                section.fp {
                    span.label { "Fingerprint · must match the agent" }
                    code.fingerprint { (view.fingerprint) }
                }
                div.actions {
                    fieldset {
                        legend.label { "Grant for" }
                        div.seg {
                            @for window in WINDOWS.into_iter().filter(|w| *w <= max) {
                                @let id = format!("window-{}", window_label(window));
                                input #(id) type="radio" name="window"
                                    value=(window_label(window)) checked[window == default];
                                label for=(id) { (window_words(window)) }
                            }
                        }
                    }
                    div.btns {
                        button.btn.approve #approve type="button" {
                            (icon(20, "2.2", &key_icon())) " Approve with passkey"
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

/// A link onward from an end state.
struct Link {
    href: &'static str,
    text: &'static str,
}

/// The link from an end state to the owner's active grants.
const TO_GRANTS: Link = Link {
    href: "/grants",
    text: "View active grants",
};

/// The status chip of an end state: an icon and a short text.
struct Chip<'a> {
    icon: Markup,
    text: &'a str,
}

/// A finished or empty state: the large mascot in a halo, a status chip, a
/// heading, a short message and, if given, a link onward.
fn end_state(chip: &Chip<'_>, heading: &str, message: &Markup, link: Option<&Link>) -> Markup {
    html! {
        main.done {
            div.halo { (mascot()) }
            span.chip.center { (icon(14, "2.4", &chip.icon)) " " (chip.text) }
            h1 { (heading) }
            p { (message) }
            @if let Some(link) = link {
                a.btn.ghost.block href=(link.href) { (link.text) }
            }
        }
    }
}

/// A tick in a circle: the request is over.
fn done_icon() -> Markup {
    html! { circle cx="12" cy="12" r="9" {} path d="m8 12 3 3 5-6" {} }
}

/// A crossed circle: withdrawn, or nothing there.
fn none_icon() -> Markup {
    html! { circle cx="12" cy="12" r="9" {} path d="m9 9 6 6M15 9l-6 6" {} }
}

/// An empty tray: nothing listed yet.
fn empty_icon() -> Markup {
    html! { path d="M3 13h5l1 3h6l1-3h5" {} path d="M5 13 7 5h10l2 8v6H5z" {} }
}

/// The request behind a link is unknown, decided or expired. Says nothing
/// about which, so links reveal nothing.
#[must_use]
pub fn not_pending() -> Markup {
    let content = end_state(
        &Chip {
            icon: done_icon(),
            text: "No longer pending",
        },
        "Nothing to approve",
        &html! { "This request is no longer pending: it was decided, expired or never existed." },
        Some(&TO_GRANTS),
    );
    layout("Nothing to approve", None, false, &content)
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

/// Active grants, one card each, with revoke buttons.
#[must_use]
pub fn grants(grants: &[ActiveGrant], now: i64) -> Markup {
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
        return layout("Active grants", Some(Nav::Grants), false, &content);
    }
    let content = html! {
        main.wide {
            h1 { "Active grants" }
            @for grant in grants {
                section.card.grant {
                    div.field.tight {
                        span.who #(format!("agent-{}", grant.grant_id)) { bdi { (grant.agent) } }
                        (grant_access(grant))
                        div.meta {
                            span { "Fingerprint " code { (grant.fingerprint) } }
                            span {
                                "Ends " (utc(grant.not_after))
                                " (in " (((grant.not_after - now).max(0) + 59) / 60) " min)"
                            }
                            span #(format!("grant-{}", grant.grant_id)) {
                                "Grant " code { (grant.grant_id) }
                            }
                        }
                    }
                    // Every button reads "Revoke"; the description says whose
                    // grant and which one.
                    button.revoke type="button" data-grant=(grant.grant_id)
                        aria-describedby=(format!("agent-{0} grant-{0}", grant.grant_id)) { "Revoke" }
                }
            }
            p.result #result role="status" {}
        }
    };
    layout("Active grants", Some(Nav::Grants), true, &content)
}

/// Read-only list of recent requests, newest first: a card per request on a
/// phone, a table from 720 px.
#[must_use]
pub fn history(entries: &[HistoryEntry]) -> Markup {
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
                        };
                        // On a phone each row is a card; `data-label` names
                        // the cell there, where the header row is hidden.
                        @let (date, time) = utc_parts(entry.created_at);
                        tr {
                            td data-label="Time" {
                                span { span.nowrap { (date) } " " span.nowrap { (time) } }
                            }
                            td.who data-label="Agent" { bdi { (entry.agent) } }
                            td data-label="Goal" { bdi { (entry.request.goal) } }
                            td data-label="Access" { code { (subject) } }
                            td data-label="Fingerprint" { code.nowrap { (entry.fingerprint) } }
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

/// The passkey enrollment form.
#[must_use]
pub fn enroll() -> Markup {
    let content = html! {
        main {
            h1 { "Enroll a passkey" }
            p.lead {
                "Run " code { "warden-server enroll" } " on the server and enter the code it prints."
            }
            section.card {
                div.field {
                    label.label for="code" { "Enrollment code" }
                    input.input #code type="text" autocomplete="one-time-code"
                        autocapitalize="characters" spellcheck="false" maxlength="32";
                }
                div.field {
                    label.label for="label" { "Name for this passkey" }
                    input.input #label type="text" autocomplete="off" maxlength="64"
                        placeholder="My phone";
                }
                button.btn.approve #enroll type="button" { (icon(20, "2.2", &key_icon())) " Create passkey" }
            }
            p.result #result role="status" {}
        }
    };
    layout("Enroll a passkey", Some(Nav::Enroll), true, &content)
}

/// A granted window length in words (`15m`, …), or seconds if unusual.
fn secs_label(secs: i64) -> String {
    WINDOWS
        .into_iter()
        .find(|w| u64::try_from(secs).is_ok_and(|s| s == w.secs()))
        .map_or_else(|| format!("{secs}s"), |w| window_label(w).to_owned())
}

/// `YYYY-MM-DD HH:MM:SS UTC` for Unix seconds `ts`.
fn utc(ts: i64) -> String {
    let (date, time) = utc_parts(ts);
    format!("{date} {time}")
}

/// `YYYY-MM-DD` and `HH:MM:SS UTC` for Unix seconds `ts`, so a narrow
/// column can break between them and nowhere else.
fn utc_parts(ts: i64) -> (String, String) {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    (
        format!("{year:04}-{month:02}-{day:02}"),
        format!(
            "{:02}:{:02}:{:02} UTC",
            secs / 3600,
            secs % 3600 / 60,
            secs % 60
        ),
    )
}

/// Proleptic Gregorian date of the day `days` after 1970-01-01 (Howard
/// Hinnant's `civil_from_days`).
const fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use http::{HeaderName, Method};
    use maud::Markup;
    use url::Url;
    use warden_broker_proto::{
        Access, AgentName, ApiGrant, CreateRequest, Fingerprint, Goal, GrantAccess, Id, RelayGrant,
        SecretName, SshGrant, TargetName, UnixUser, Window,
    };

    use super::{
        super::STYLESHEET, approve, cancelled, enroll, grants, history, internal_error, not_found,
        not_pending, secs_label, unavailable, utc,
    };
    use crate::policy::{ApiSecretPolicy, SshMode, SshTarget, ValueFormat};
    use crate::requests::{ActiveGrant, Destination, HistoryEntry, PendingView};

    const NOW: i64 = 1_800_000_000;

    fn id(n: u8) -> Id {
        Id::try_from(format!("{n:032x}")).unwrap()
    }

    fn agent(name: &str) -> AgentName {
        AgentName::try_from(name.to_owned()).unwrap()
    }

    fn fingerprint(n: u8) -> Fingerprint {
        Fingerprint::try_from(format!("ab{n:02x}-cd{n:02x}-ef{n:02x}")).unwrap()
    }

    /// 300 characters of goal text, the longest realistic wrapping case.
    fn long_goal() -> Goal {
        let text = "Rotate the build cache credentials and verify the nightly pipeline \
            still reaches the artifact store, then compare the checksum manifest \
            against the previous release before publishing the signed tarballs to \
            the mirror and notifying the maintainers in the release channel, as \
            agreed in the plan, today.";
        let goal = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(
            goal.chars().count(),
            300,
            "fixture must stay 300 characters"
        );
        Goal::try_from(goal).unwrap()
    }

    /// The longest agent name the protocol allows (32 characters).
    fn long_agent() -> AgentName {
        let name = format!("a{}", "b-c".repeat(10) + "d");
        assert_eq!(name.len(), 32);
        agent(&name)
    }

    fn goal(text: &str) -> Goal {
        Goal::try_from(text.to_owned()).unwrap()
    }

    fn ssh_request(goal: Goal, window: Window) -> CreateRequest {
        CreateRequest {
            goal,
            access: Access::Ssh {
                target: TargetName::try_from("switch-01".to_owned()).unwrap(),
                user: UnixUser::try_from("deploy".to_owned()).unwrap(),
                public_key: "ssh-ed25519 AAAA".to_owned(),
            },
            window,
        }
    }

    fn api_request(goal: Goal, methods: &[&str]) -> CreateRequest {
        CreateRequest {
            goal,
            access: Access::Api {
                secret: SecretName::try_from("home-api".to_owned()).unwrap(),
                methods: Some(methods.iter().map(|m| (*m).to_owned()).collect()),
                path_prefix: Some("/v1/devices/".to_owned()),
            },
            window: Window::H1,
        }
    }

    fn ssh_destination(mode: SshMode) -> Destination {
        Destination::Ssh(SshTarget {
            name: TargetName::try_from("switch-01".to_owned()).unwrap(),
            host: "switch-01.lan".to_owned(),
            port: 22,
            mode,
            users: vec![UnixUser::try_from("deploy".to_owned()).unwrap()],
            max_window: Window::H4,
            host_keys: Vec::new(),
        })
    }

    fn api_destination() -> Destination {
        Destination::Api(ApiSecretPolicy {
            name: SecretName::try_from("home-api".to_owned()).unwrap(),
            origin: Url::parse("https://api.example.com").unwrap().origin(),
            header: HeaderName::from_static("authorization"),
            format: ValueFormat::default(),
            methods: vec![Method::GET, Method::HEAD, Method::POST, Method::DELETE],
            path_prefix: "/v1/".to_owned(),
            ca_pem: None,
            max_window: Window::H1,
        })
    }

    fn pending(agent: AgentName, request: CreateRequest, destination: Destination) -> PendingView {
        PendingView {
            id: id(1),
            agent,
            fingerprint: fingerprint(1),
            request,
            destination,
            expires_at: NOW + 240,
        }
    }

    fn api_grant(methods: &[&str]) -> ApiGrant {
        ApiGrant {
            secret: SecretName::try_from("home-api".to_owned()).unwrap(),
            origin: "https://api.example.com".to_owned(),
            methods: methods.iter().map(|m| (*m).to_owned()).collect(),
            path_prefix: "/v1/devices/".to_owned(),
            header: "authorization".to_owned(),
            digest: "0".repeat(64),
        }
    }

    fn active(n: u8, request: CreateRequest, access: GrantAccess) -> ActiveGrant {
        ActiveGrant {
            grant_id: id(n),
            agent: agent("build-agent"),
            fingerprint: fingerprint(n),
            request,
            access,
            not_after: NOW + 1800,
        }
    }

    fn active_grants() -> Vec<ActiveGrant> {
        let ssh = ssh_request(goal("Deploy the nightly build"), Window::M30);
        vec![
            active(
                2,
                ssh.clone(),
                GrantAccess::Ssh(SshGrant {
                    certificate: "ssh-ed25519-cert-v01@openssh.com AAAA".to_owned(),
                    host: "switch-01.lan".to_owned(),
                    port: 22,
                    user: UnixUser::try_from("deploy".to_owned()).unwrap(),
                    host_keys: Vec::new(),
                }),
            ),
            active(
                3,
                api_request(long_goal(), &["GET"]),
                GrantAccess::Api(api_grant(&["GET", "HEAD"])),
            ),
            active(
                4,
                api_request(goal("Update a device"), &["POST"]),
                GrantAccess::Api(api_grant(&["GET", "POST"])),
            ),
            active(
                5,
                ssh,
                GrantAccess::Relay(RelayGrant {
                    target: TargetName::try_from("switch-01".to_owned()).unwrap(),
                    user: UnixUser::try_from("deploy".to_owned()).unwrap(),
                    relay_host: "relay.lan".to_owned(),
                    relay_port: 2222,
                    relay_host_key: "ssh-ed25519 AAAA".to_owned(),
                    digest: "0".repeat(64),
                }),
            ),
        ]
    }

    fn history_entries() -> Vec<HistoryEntry> {
        let entry = |n: u8, agent: AgentName, request, status: &str, granted_secs| HistoryEntry {
            id: id(n),
            agent,
            fingerprint: fingerprint(n),
            request,
            status: status.to_owned(),
            created_at: NOW - i64::from(n) * 600,
            granted_secs,
        };
        vec![
            entry(
                6,
                long_agent(),
                api_request(long_goal(), &["GET"]),
                "approved",
                Some(900),
            ),
            entry(
                7,
                agent("build-agent"),
                ssh_request(goal("Deploy the nightly build"), Window::H1),
                "denied",
                None,
            ),
            entry(
                8,
                agent("build-agent"),
                api_request(goal("Update a device"), &["POST"]),
                "expired",
                None,
            ),
        ]
    }

    /// Every page with fixture data, named for the screenshot script.
    fn pages() -> Vec<(&'static str, Markup)> {
        let long = long_goal();
        vec![
            (
                "approve-ssh-cert",
                approve(
                    &pending(
                        long_agent(),
                        ssh_request(long.clone(), Window::H1),
                        ssh_destination(SshMode::Cert),
                    ),
                    NOW,
                ),
            ),
            (
                "approve-ssh-relay",
                approve(
                    &pending(
                        agent("build-agent"),
                        ssh_request(goal("Deploy the nightly build"), Window::M30),
                        ssh_destination(SshMode::Relay),
                    ),
                    NOW,
                ),
            ),
            (
                "approve-api-read-only",
                approve(
                    &pending(
                        agent("build-agent"),
                        api_request(goal("Read device status"), &["GET"]),
                        api_destination(),
                    ),
                    NOW,
                ),
            ),
            (
                "approve-api-modify",
                approve(
                    &pending(
                        long_agent(),
                        api_request(long, &["GET", "POST", "DELETE"]),
                        api_destination(),
                    ),
                    NOW,
                ),
            ),
            ("not-pending", not_pending()),
            ("cancelled", cancelled()),
            ("not-found", not_found()),
            ("unavailable", unavailable("The broker is starting up.")),
            ("internal-error", internal_error()),
            ("grants-empty", grants(&[], NOW)),
            ("grants", grants(&active_grants(), NOW)),
            ("history-empty", history(&[])),
            ("history", history(&history_entries())),
            ("enroll", enroll()),
        ]
    }

    /// The text of every tag (`<...>`) in `html`. Maud escapes `<` and `>` in
    /// text and attribute values, so tags split cleanly; text content (such
    /// as an API origin shown to the owner) is not a resource reference and
    /// is left out.
    fn tags(html: &str) -> Vec<&str> {
        let mut found = Vec::new();
        let mut rest = html;
        while let Some(start) = rest.find('<') {
            let after = &rest[start..];
            let end = after.find('>').expect("unterminated tag");
            found.push(&after[..=end]);
            rest = &after[end + 1..];
        }
        found
    }

    fn assert_self_contained(name: &str, html: &str) {
        assert!(!html.contains("style="), "{name}: inline style attribute");
        assert!(!html.contains("<style"), "{name}: style element");
        assert!(!html.contains("<img"), "{name}: image element");
        for tag in tags(html) {
            let without_svg = tag.replace("http://www.w3.org/2000/svg", "");
            assert!(
                !without_svg.contains("http://") && !without_svg.contains("https://"),
                "{name}: external origin in {tag}"
            );
            if tag.starts_with("<link") {
                assert_eq!(
                    tag, r#"<link rel="stylesheet" href="/static/warden.css">"#,
                    "{name}: unexpected link"
                );
            }
            if tag.starts_with("<script") {
                assert_eq!(
                    tag, r#"<script src="/static/warden.js" defer>"#,
                    "{name}: unexpected script"
                );
            }
        }
    }

    #[test]
    fn every_page_renders_self_contained() {
        let out = std::env::var_os("WARDEN_RENDER_PAGES_DIR").map(PathBuf::from);
        if let Some(dir) = &out {
            std::fs::create_dir_all(dir.join("static")).unwrap();
            std::fs::write(dir.join("static/warden.css"), STYLESHEET).unwrap();
        }
        for (name, page) in pages() {
            let html = page.into_string();
            assert_self_contained(name, &html);
            if let Some(dir) = &out {
                std::fs::write(dir.join(format!("{name}.html")), &html).unwrap();
            }
        }
    }

    #[test]
    fn the_self_contained_check_catches_violations() {
        for bad in [
            r#"<p style="color:red">x</p>"#,
            "<style>p{}</style>",
            r#"<img src="/x.png">"#,
            r#"<link rel="stylesheet" href="https://cdn.example.com/a.css">"#,
            r#"<script src="https://cdn.example.com/a.js"></script>"#,
            r#"<a href="http://example.com">x</a>"#,
            r#"<link rel="stylesheet" href="/static/other.css">"#,
        ] {
            assert!(
                std::panic::catch_unwind(|| assert_self_contained("bad", bad)).is_err(),
                "not caught: {bad}"
            );
        }
        assert_self_contained(
            "svg",
            r#"<svg xmlns="http://www.w3.org/2000/svg"></svg><p>https://api.example.com</p>"#,
        );
    }

    #[test]
    fn marks_the_current_page_in_the_navigation() {
        let html = grants(&[], NOW).into_string();
        // Both the inline links and the menu's copy mark it.
        assert_eq!(
            html.matches(r#"<a href="/grants" aria-current="page">"#)
                .count(),
            2,
            "{html}"
        );
        assert!(
            !html.contains(r#"<a href="/history" aria-current"#),
            "{html}"
        );
        let html = not_found().into_string();
        assert!(!html.contains("aria-current"), "{html}");
        assert!(html.contains("viewport-fit=cover"), "{html}");
        assert!(
            html.contains("<summary class=\"menu\" aria-label=\"Menu\">"),
            "{html}"
        );
    }

    #[test]
    fn inline_svg_shapes_are_closed() {
        // In inline SVG an unclosed `<rect>` would swallow the shapes after it.
        let html = approve(
            &pending(
                agent("build-agent"),
                api_request(goal("Read device status"), &["GET"]),
                api_destination(),
            ),
            NOW,
        )
        .into_string();
        for shape in ["rect", "circle", "path", "ellipse"] {
            assert_eq!(
                html.matches(&format!("<{shape} ")).count(),
                html.matches(&format!("</{shape}>")).count(),
                "{shape}: {html}"
            );
        }
        assert!(html.contains(r#"<svg class="mascot" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" aria-hidden="true">"#));
    }

    #[test]
    fn window_picker_offers_windows_up_to_the_max_with_the_request_checked() {
        let html = approve(
            &pending(
                agent("build-agent"),
                ssh_request(goal("Deploy the nightly build"), Window::M30),
                ssh_destination(SshMode::Cert),
            ),
            NOW,
        )
        .into_string();
        assert!(
            html.contains(r#"<fieldset><legend class="label">Grant for</legend>"#),
            "{html}"
        );
        assert!(
            html.contains(
                r#"<input id="window-30m" type="radio" name="window" value="30m" checked><label for="window-30m">30 min</label>"#
            ),
            "{html}"
        );
        assert!(html.contains(r#"value="4h">"#), "{html}");
        assert_eq!(html.matches(r#"name="window""#).count(), 4, "{html}");
        assert_eq!(html.matches(" checked").count(), 1, "{html}");

        // The requested 4h is above the secret's 1h max: capped and preselected.
        let mut request = api_request(goal("Read device status"), &["GET"]);
        request.window = Window::H4;
        let html = approve(
            &pending(agent("build-agent"), request, api_destination()),
            NOW,
        )
        .into_string();
        assert!(html.contains(r#"value="1h" checked>"#), "{html}");
        assert!(!html.contains(r#"value="4h""#), "{html}");
    }

    #[test]
    fn approve_page_keeps_the_script_hooks() {
        let html = approve(
            &pending(
                agent("build-agent"),
                ssh_request(goal("Deploy the nightly build"), Window::M30),
                ssh_destination(SshMode::Cert),
            ),
            NOW,
        )
        .into_string();
        for hook in [
            r#"<main class="split" id="approval" data-target=""#,
            r#"id="countdown" data-remaining="240">in 4 min</span>"#,
            r#"<code class="fingerprint">ab01-cd01-ef01</code>"#,
            r#"<button class="btn approve" id="approve" type="button">"#,
            r#"<button class="btn deny" id="deny" type="button">Deny</button>"#,
            r#"<p class="result" id="result" role="status"></p>"#,
        ] {
            assert!(html.contains(hook), "{hook}: {html}");
        }
    }

    #[test]
    fn end_states_show_the_mascot_in_a_halo_with_a_chip() {
        for (name, page) in [
            ("not_pending", not_pending()),
            ("cancelled", cancelled()),
            ("not_found", not_found()),
            ("unavailable", unavailable("x")),
            ("internal_error", internal_error()),
            ("grants_empty", grants(&[], NOW)),
            ("history_empty", history(&[])),
        ] {
            let html = page.into_string();
            assert!(
                html.contains(r#"<main class="done"><div class="halo"><svg class="mascot" "#),
                "{name}: {html}"
            );
            assert!(
                html.contains(r#"<span class="chip center"><svg "#),
                "{name}: {html}"
            );
            // Header mascot, menu icon, halo mascot, chip icon: all decoration.
            assert_eq!(html.matches(r#"aria-hidden="true""#).count(), 4, "{name}");
            assert!(!html.contains("<script"), "{name}: {html}");
        }
        assert!(
            not_pending()
                .into_string()
                .contains(r#"<a class="btn ghost block" href="/grants">View active grants</a>"#)
        );
    }

    #[test]
    fn unavailable_escapes_and_isolates_the_message() {
        let html = unavailable("<b>\u{202e}x").into_string();
        assert!(
            html.contains("<strong><bdi>&lt;b&gt;\u{202e}x</bdi></strong>"),
            "{html}"
        );
    }

    #[test]
    fn grants_are_cards_with_the_revoke_hook() {
        let html = grants(&active_grants(), NOW).into_string();
        assert_eq!(
            html.matches(r#"<section class="card grant">"#).count(),
            4,
            "{html}"
        );
        let grant = id(2);
        assert!(
            html.contains(&format!(
                r#"<button class="revoke" type="button" data-grant="{grant}" aria-describedby="agent-{grant} grant-{grant}">Revoke</button>"#
            )),
            "{html}"
        );
        // The description points at that card's agent and grant id.
        assert!(
            html.contains(&format!(
                r#"<span class="who" id="agent-{grant}"><bdi>build-agent</bdi></span>"#
            )),
            "{html}"
        );
        assert!(
            html.contains(&format!(
                r#"<span id="grant-{grant}">Grant <code>{grant}</code></span>"#
            )),
            "{html}"
        );
        assert_eq!(html.matches("aria-describedby=").count(), 4, "{html}");
        assert!(html.contains(r#"<p class="result" id="result" role="status"></p>"#));
        assert!(html.contains(r#"<script src="/static/warden.js" defer></script>"#));
    }

    #[test]
    fn history_labels_every_cell_for_the_phone_cards() {
        let html = history(&history_entries()).into_string();
        assert!(html.contains(r#"<table class="history">"#), "{html}");
        for label in [
            "Time",
            "Agent",
            "Goal",
            "Access",
            "Fingerprint",
            "Status",
            "Window",
        ] {
            assert_eq!(
                html.matches(&format!(r#"data-label="{label}""#)).count(),
                3,
                "{label}: {html}"
            );
            assert!(html.contains(&format!(r#"<th class="label">{label}</th>"#)));
        }
        assert!(
            html.contains(
                r#"<span><span class="nowrap">2027-01-15</span> <span class="nowrap">07:00:00 UTC</span></span>"#
            ),
            "{html}"
        );
    }

    #[test]
    fn enroll_page_keeps_the_script_hooks() {
        let html = enroll().into_string();
        for hook in [
            r#"<label class="label" for="code">Enrollment code</label>"#,
            r#"<input class="input" id="code" type="text" autocomplete="one-time-code""#,
            r#"<label class="label" for="label">Name for this passkey</label>"#,
            r#"<input class="input" id="label" type="text" autocomplete="off" maxlength="64""#,
            r#"<button class="btn approve" id="enroll" type="button">"#,
            r#"<p class="result" id="result" role="status"></p>"#,
        ] {
            assert!(html.contains(hook), "{hook}: {html}");
        }
    }

    #[test]
    fn badges_say_read_only_or_what_can_modify() {
        let read_only = super::read_only_badge().into_string();
        assert!(
            read_only.starts_with(r#"<strong class="badge readonly"><svg "#),
            "{read_only}"
        );
        assert!(
            read_only.ends_with("</svg> Read-only</strong>"),
            "{read_only}"
        );
        let modify = super::can_modify_badge("POST, <PUT>").into_string();
        assert!(
            modify.starts_with(r#"<strong class="badge modify"><svg "#),
            "{modify}"
        );
        assert!(
            modify.ends_with("</svg> Can modify: POST, &lt;PUT&gt;</strong>"),
            "{modify}"
        );
    }

    #[test]
    fn formats_utc_timestamps() {
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_800_000_000), "2027-01-15 08:00:00 UTC");
        assert_eq!(utc(951_825_600), "2000-02-29 12:00:00 UTC");
        assert_eq!(utc(1_709_208_000), "2024-02-29 12:00:00 UTC");
        assert_eq!(utc(4_102_444_799), "2099-12-31 23:59:59 UTC");
        assert_eq!(utc(-1), "1969-12-31 23:59:59 UTC");
    }

    #[test]
    fn labels_granted_windows() {
        assert_eq!(secs_label(900), "15m");
        assert_eq!(secs_label(14_400), "4h");
        assert_eq!(secs_label(901), "901s");
        assert_eq!(secs_label(-5), "-5s");
    }
}
