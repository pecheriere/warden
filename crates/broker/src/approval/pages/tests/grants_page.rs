//! The active grants page and its live activity.

use super::super::super::{LiveGrant, LiveProxyCall, LiveRelaySession};
use super::super::grants;
use super::{NOW, active_grants, id, idle, live_grants_fixture};
use crate::requests::LinkHosts;

#[test]
fn the_grants_page_warns_only_while_entries_are_waiting() {
    let quiet = grants(&[], &[], &LinkHosts::default(), NOW, 0).into_string();
    assert!(!quiet.contains("Not in the audit log"), "{quiet}");
    let html = grants(&[], &[], &LinkHosts::default(), NOW, 3).into_string();
    assert!(html.contains("Not in the audit log"), "{html}");
    assert!(html.contains("3 audit log entries"), "{html}");
    assert!(html.contains(r#"role="alert""#), "{html}");
}

#[test]
fn grants_are_cards_with_the_revoke_hook() {
    let active = active_grants();
    let html = grants(&active, &idle(&active), &LinkHosts::default(), NOW, 0).into_string();
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
fn grants_show_live_activity_under_each_grant() {
    let (active, live) = live_grants_fixture();
    let html = grants(&active, &live, &LinkHosts::default(), NOW, 0).into_string();
    let (relay, api, cert) = (id(5), id(4), id(2));
    assert!(
        html.contains(&format!(
            r#"<div class="live-area" data-grant="{relay}" data-kind="relay"><p class="live">2 sessions open</p><ul class="live-list" role="list"><li><span>Session since <time datetime="2027-01-15T07:39:00Z">07:39 UTC</time></span><span><span class="nowrap">1.2 KB to target</span> · <span class="nowrap">3.4 MB from target</span></span><span class="nowrap idle">Idle 12 min</span></li><li><span>Session since <time datetime="2027-01-15T07:58:25Z">07:58 UTC</time></span><span><span class="nowrap">512 B to target</span> · <span class="nowrap">48.2 KB from target</span></span><span class="nowrap idle">Active now</span></li></ul></div>"#
        )),
        "{html}"
    );
    assert!(
        html.contains(&format!(
            r#"<div class="live-area" data-grant="{api}" data-kind="api"><p class="live">1 call in flight</p><ul class="live-list" role="list"><li><code><bdi>POST /v1/devices/switch-01/interfaces/port-24/statistics/history/daily-summary</bdi></code><span>since <time datetime="2027-01-15T07:59:56Z">07:59 UTC</time></span></li></ul></div>"#
        )),
        "{html}"
    );
    assert!(
        html.contains(&format!(
            r#"<div class="live-area" data-grant="{cert}" data-kind="cert"><p class="detail">Certificate issued <time datetime="2027-01-15T07:55:00Z">07:55 UTC</time>, expires <time datetime="2027-01-15T08:30:00Z">08:30 UTC</time>.</p><p class="detail">Certificate logins are not visible to warden, so this does not show whether it was used.</p></div>"#
        )),
        "{html}"
    );
    // The end of each grant is a time the script can localize.
    assert!(
        html.contains(r#"Ends <time datetime="2027-01-15T08:30:00Z">08:30 UTC</time> (in 30 min)"#),
        "{html}"
    );
}

#[test]
fn idle_grants_say_nothing_is_live() {
    let active = active_grants();
    let html = grants(&active, &idle(&active), &LinkHosts::default(), NOW, 0).into_string();
    assert_eq!(
        html.matches(r#"<div class="live-area""#).count(),
        4,
        "{html}"
    );
    assert!(!html.contains(r#"class="live""#), "{html}");
    assert!(
        html.contains(&format!(
            r#"<div class="live-area" data-grant="{}" data-kind="relay"><p class="detail">No sessions open</p></div>"#,
            id(5)
        )),
        "{html}"
    );
    assert_eq!(html.matches("No calls in flight").count(), 2, "{html}");
    // A grant missing from the live entries renders as idle.
    let html = grants(&active, &[], &LinkHosts::default(), NOW, 0).into_string();
    assert_eq!(html.matches("No calls in flight").count(), 2, "{html}");
}

#[test]
fn live_activity_shows_both_counts_and_escapes_the_path() {
    let active = active_grants();
    let live = [LiveGrant {
        grant_id: id(4),
        relay_sessions: vec![LiveRelaySession {
            started_at: NOW,
            bytes_to_target: 0,
            bytes_from_target: 0,
            idle_secs: 0,
        }],
        proxy_calls: vec![
            LiveProxyCall {
                method: "GET",
                path: "/v1/<b>\u{202e}x",
                started_at: NOW,
            },
            LiveProxyCall {
                method: "GET",
                path: "/v1/a",
                started_at: NOW,
            },
        ],
    }];
    let html = grants(&active, &live, &LinkHosts::default(), NOW, 0).into_string();
    assert!(
        html.contains(r#"<p class="live">1 session open · 2 calls in flight</p>"#),
        "{html}"
    );
    assert!(
        html.contains("<code><bdi>GET /v1/&lt;b&gt;\u{202e}x</bdi></code>"),
        "{html}"
    );
}
