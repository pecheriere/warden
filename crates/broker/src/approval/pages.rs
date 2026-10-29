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

fn layout(title: &str, with_script: bool, content: &Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " · warden" }
                link rel="stylesheet" href="/static/warden.css";
                @if with_script {
                    script src="/static/warden.js" defer {}
                }
            }
            body {
                nav {
                    a href="/grants" { "Active grants" }
                    a href="/history" { "History" }
                    a href="/enroll" { "Enroll a passkey" }
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
    html! {
        @if modifying.is_empty() {
            strong.readonly { "Read-only" }
        } @else {
            strong.warning { "Can modify: " (modifying.join(", ")) }
        }
    }
}

/// What approving `request` gives access to under `destination`: for a
/// relay target also that the session goes through the warden relay; for an
/// API secret also how its value is written (the secret shown as `…`) and
/// whether a pinned CA replaces the system roots.
fn destination_access(request: &CreateRequest, destination: &Destination) -> Markup {
    match destination {
        Destination::Ssh(target) => html! {
            code { (access_line(request, &target.host, target.port)) }
            @if target.mode == SshMode::Relay { " via the warden relay" }
        },
        Destination::Api(policy) => html! {
            @match super::api_scope(request, policy) {
                Ok(scope) => {
                    (api_access(&policy.grant_for(&scope)))
                    br;
                    (modify_line(&scope))
                }
                Err(message) => bdi { (message) },
            }
            br;
            "value " code { bdi { (policy.format.prefix()) "…" (policy.format.suffix()) } }
            ", pinned CA: " (if policy.ca_pem.is_some() { "yes" } else { "no" })
        },
    }
}

/// What an active grant gives access to.
fn grant_access(grant: &ActiveGrant) -> Markup {
    match &grant.access {
        GrantAccess::Ssh(ssh) => {
            html! { code { (access_line(&grant.request, &ssh.host, ssh.port)) } }
        }
        GrantAccess::Api(api) => html! {
            (api_access(api))
            br;
            @match ApiScope::try_from(api) {
                Ok(scope) => (modify_line(&scope)),
                // A damaged record: the label must not claim read-only.
                Err(_) => strong.warning { "Can modify: unverified scope" },
            }
        },
        GrantAccess::Relay(relay) => html! {
            code { "ssh " bdi { (relay.user) "@" (relay.target) } }
            " via the warden relay"
        },
    }
}

/// The approval page for a pending request.
#[must_use]
pub fn approve(view: &PendingView, now: i64) -> Markup {
    let max = view.destination.max_window();
    let default = view.request.window.min(max);
    let remaining = (view.expires_at - now).max(0);
    let content = html! {
        h1 { "Approve access?" }
        dl {
            dt { "Requested by" }
            dd { bdi { (view.agent) } }
            dt { "Goal" }
            dd { bdi { (view.request.goal) } }
            dt { "Access" }
            dd { (destination_access(&view.request, &view.destination)) }
            dt { "Requested window" }
            dd { (window_label(view.request.window)) }
            dt { "Fingerprint (must match what the agent shows)" }
            dd { code.fingerprint { (view.fingerprint) } }
            dt { "Expires" }
            dd { span #countdown data-remaining=(remaining) { "in " (remaining / 60) " min" } }
        }
        // The script sends this back when the approval begins, binding it to
        // the destination shown above.
        main #approval data-target=(view.destination.digest()) {
            label for="window" { "Grant for " }
            select #window name="window" {
                @for window in WINDOWS.into_iter().filter(|w| *w <= max) {
                    option value=(window_label(window)) selected[window == default] {
                        (window_label(window))
                    }
                }
            }
            div {
                button #approve type="button" { "Approve with passkey" }
                button #deny type="button" { "Deny" }
            }
            p #result role="status" {}
        }
    };
    layout("Approve access", true, &content)
}

/// The request behind a link is unknown, decided or expired. Says nothing
/// about which, so links reveal nothing.
#[must_use]
pub fn not_pending() -> Markup {
    let content = html! {
        h1 { "Nothing to approve" }
        p { "This request is no longer pending: it was decided, expired or never existed." }
    };
    layout("Nothing to approve", false, &content)
}

/// The agent withdrew the request behind a link. Shown only to the owner,
/// who holds the link, so it can say what happened.
#[must_use]
pub fn cancelled() -> Markup {
    let content = html! {
        h1 { "Nothing to approve" }
        p { "Cancelled by the agent." }
    };
    layout("Nothing to approve", false, &content)
}

/// No page at this address.
#[must_use]
pub fn not_found() -> Markup {
    let content = html! {
        h1 { "Not found" }
        p { "There is no page at this address." }
    };
    layout("Not found", false, &content)
}

/// The policy backend could not answer.
#[must_use]
pub fn unavailable(message: &str) -> Markup {
    let content = html! {
        h1 { "Policy unavailable" }
        p { "The request cannot be shown right now: " (message) }
    };
    layout("Policy unavailable", false, &content)
}

/// Something failed on the server; details are in its log.
#[must_use]
pub fn internal_error() -> Markup {
    let content = html! {
        h1 { "Something went wrong" }
        p { "The server logged the details." }
    };
    layout("Error", false, &content)
}

/// Active grants with revoke buttons.
#[must_use]
pub fn grants(grants: &[ActiveGrant], now: i64) -> Markup {
    let content = html! {
        h1 { "Active grants" }
        @if grants.is_empty() {
            p { "No active grants." }
        } @else {
            table {
                thead { tr { th { "Agent" } th { "Access" } th { "Fingerprint" } th { "Ends" } th {} } }
                tbody {
                    @for grant in grants {
                        tr {
                            td { bdi { (grant.agent) } }
                            td { (grant_access(grant)) }
                            td { code { (grant.fingerprint) } }
                            td {
                                (utc(grant.not_after))
                                " (in " (((grant.not_after - now).max(0) + 59) / 60) " min)"
                            }
                            td {
                                button.revoke type="button" data-grant=(grant.grant_id)
                                    title=(grant.grant_id) { "Revoke" }
                                br;
                                small { code { (grant.grant_id) } }
                            }
                        }
                    }
                }
            }
        }
        p #result role="status" {}
    };
    layout("Active grants", true, &content)
}

/// Read-only list of recent requests, newest first.
#[must_use]
pub fn history(entries: &[HistoryEntry]) -> Markup {
    let content = html! {
        h1 { "History" }
        @if entries.is_empty() {
            p { "No requests yet." }
        } @else {
            table {
                thead {
                    tr {
                        th { "Time" } th { "Agent" } th { "Goal" } th { "Access" }
                        th { "Fingerprint" } th { "Status" } th { "Window" }
                    }
                }
                tbody {
                    @for entry in entries {
                        @let subject = match &entry.request.access {
                            Access::Ssh { target, user, .. } => format!("{user}@{target}"),
                            Access::Api { secret, .. } => format!("api:{secret}"),
                        };
                        tr {
                            td { (utc(entry.created_at)) }
                            td { bdi { (entry.agent) } }
                            td { bdi { (entry.request.goal) } }
                            td { code { (subject) } }
                            td { code { (entry.fingerprint) } }
                            td { (entry.status) }
                            td {
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
    layout("History", false, &content)
}

/// The passkey enrollment form.
#[must_use]
pub fn enroll() -> Markup {
    let content = html! {
        h1 { "Enroll a passkey" }
        p { "Run " code { "warden-server enroll" } " on the server and enter the code it prints." }
        main #enrollment {
            p {
                label for="code" { "Enrollment code" } br;
                input #code type="text" autocomplete="one-time-code" autocapitalize="characters"
                    spellcheck="false" maxlength="32";
            }
            p {
                label for="label" { "Name for this passkey" } br;
                input #label type="text" maxlength="64" placeholder="My phone";
            }
            button #enroll type="button" { "Create passkey" }
            p #result role="status" {}
        }
    };
    layout("Enroll a passkey", true, &content)
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
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
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
