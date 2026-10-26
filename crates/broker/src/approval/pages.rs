//! HTML pages of the approval UI, rendered with maud (all text escaped).
//!
//! Text that agents control (goals, agent names) is wrapped in `<bdi>` so
//! bidirectional overrides inside it cannot reorder the surrounding page.
//! Pages carry no inline script; behaviour lives in `/static/warden.js`.

use maud::{DOCTYPE, Markup, html};
use warden_broker_proto::{Access, CreateRequest, Window};

use crate::requests::{ActiveGrant, HistoryEntry, PendingView, window_label};

const STYLE: &str = "\
body{font-family:system-ui,sans-serif;max-width:40rem;margin:0 auto;padding:1rem;line-height:1.4}\
nav a{margin-right:1rem}\
dt{font-weight:600;margin-top:.6rem}dd{margin:0}\
code{word-break:break-all}\
.fingerprint{font-size:1.4rem;letter-spacing:.05em}\
button{font-size:1.1rem;padding:.6rem 1.2rem;margin:.4rem .4rem .4rem 0}\
select,input{font-size:1.1rem;padding:.3rem}\
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ccc;padding:.3rem;text-align:left;vertical-align:top}\
#result{font-weight:600}";

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
                style { (STYLE) }
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
    let Access::Ssh { target, user, .. } = &request.access;
    if host.contains(':') {
        format!("ssh {user}@{target} ([{host}]:{port})")
    } else {
        format!("ssh {user}@{target} ({host}:{port})")
    }
}

/// The approval page for a pending request.
#[must_use]
pub fn approve(view: &PendingView, now: i64) -> Markup {
    let max = view.target.max_window;
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
            dd { code { (access_line(&view.request, &view.target.host, view.target.port)) } }
            dt { "Requested window" }
            dd { (window_label(view.request.window)) }
            dt { "Fingerprint (must match what the agent shows)" }
            dd { code.fingerprint { (view.fingerprint) } }
            dt { "Expires" }
            dd { span #countdown data-remaining=(remaining) { "in " (remaining / 60) " min" } }
        }
        // The script sends this back when the approval begins, binding it to
        // the destination shown above.
        main #approval data-target=(view.target.destination_digest()) {
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
                            td { code { (access_line(&grant.request, &grant.host, grant.port)) } }
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
                        @let Access::Ssh { target, user, .. } = &entry.request.access;
                        tr {
                            td { (utc(entry.created_at)) }
                            td { bdi { (entry.agent) } }
                            td { bdi { (entry.request.goal) } }
                            td { code { (user) "@" (target) } }
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
    use super::{secs_label, utc};

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
