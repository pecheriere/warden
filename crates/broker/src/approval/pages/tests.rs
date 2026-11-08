//! Fixtures for the page tests, every page rendered with them, and the tests
//! that name the page module's own items.
//!
//! The fixtures live here, in the parent of the per-page test modules under
//! `tests/`, so every one of those modules can use them without widening their
//! visibility.

mod accessibility;
mod approve_page;
mod format;
mod grants_page;
mod history_page;
mod layout;
mod self_contained;

use http::{HeaderName, Method};
use maud::Markup;
use url::Url;
use warden_broker_proto::{
    Access, AgentName, ApiGrant, CommitSigningGrant, CreateRequest, Fingerprint, Goal, GrantAccess,
    Id, RelayGrant, SecretName, SshGrant, TargetName, UnixUser, Window,
};

use super::super::{LiveGrant, LiveProxyCall, LiveRelaySession};
use super::{
    approve, cancelled, enroll, grants, history, internal_error, not_found, not_pending,
    unavailable,
};
use crate::policy::{ApiSecretPolicy, CommitSigningPolicy, SshMode, SshTarget, ValueFormat};
use crate::requests::{
    ActiveGrant, Destination, HistoryEntry, LinkHosts, PendingEntry, PendingView,
};

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
        session: None,
        link: None,
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
        session: None,
        link: None,
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

fn signing_request() -> CreateRequest {
    CreateRequest {
        goal: goal("Sign my commits on the warden repository"),
        access: Access::CommitSigning {},
        window: Window::D30,
        session: None,
        link: None,
    }
}

fn signing_destination() -> Destination {
    Destination::CommitSigning(CommitSigningPolicy {
        public_key: "ssh-ed25519 AAAA".to_owned(),
        key_fingerprint: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8".to_owned(),
        max_window: Window::D30,
    })
}

fn signing_grants() -> Vec<ActiveGrant> {
    let mut grant = active(
        9,
        signing_request(),
        GrantAccess::CommitSigning(CommitSigningGrant {
            key_fingerprint: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8".to_owned(),
            digest: "0".repeat(64),
        }),
    );
    grant.not_after = NOW + 26 * 86_400;
    vec![grant]
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
        not_before: NOW - 300,
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

/// No activity under any of `grants`.
fn idle(grants: &[ActiveGrant]) -> Vec<LiveGrant<'static>> {
    grants
        .iter()
        .map(|grant| LiveGrant {
            grant_id: grant.grant_id.clone(),
            relay_sessions: Vec::new(),
            proxy_calls: Vec::new(),
        })
        .collect()
}

/// A relay grant with two sessions open, an API grant with a call in
/// flight (a long path, the wrapping case) and a certificate grant.
fn live_grants_fixture() -> (Vec<ActiveGrant>, Vec<LiveGrant<'static>>) {
    let mut all = active_grants();
    let grants = vec![all.remove(3), all.remove(2), all.remove(0)];
    let live = vec![
        LiveGrant {
            grant_id: grants[0].grant_id.clone(),
            relay_sessions: vec![
                LiveRelaySession {
                    started_at: NOW - 1260,
                    bytes_to_target: 1_234,
                    bytes_from_target: 3_456_789,
                    idle_secs: 750,
                },
                LiveRelaySession {
                    started_at: NOW - 95,
                    bytes_to_target: 512,
                    bytes_from_target: 48_200,
                    idle_secs: 2,
                },
            ],
            proxy_calls: Vec::new(),
        },
        LiveGrant {
            grant_id: grants[1].grant_id.clone(),
            relay_sessions: Vec::new(),
            proxy_calls: vec![LiveProxyCall {
                method: "POST",
                path: "/v1/devices/switch-01/interfaces/port-24/statistics/history/daily-summary",
                started_at: NOW - 4,
            }],
        },
        LiveGrant {
            grant_id: grants[2].grant_id.clone(),
            relay_sessions: Vec::new(),
            proxy_calls: Vec::new(),
        },
    ];
    (grants, live)
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

/// A long SSH request, a read-only and a modifying API request, and one
/// whose current policy could not be read.
fn pending_entries() -> Vec<PendingEntry> {
    let entry = |n: u8, agent: AgentName, request, destination| PendingEntry {
        id: id(n),
        agent,
        fingerprint: fingerprint(n),
        request,
        destination,
        expires_at: NOW + 60 * i64::from(n),
    };
    vec![
        entry(
            2,
            long_agent(),
            ssh_request(long_goal(), Window::H1),
            Some(ssh_destination(SshMode::Relay)),
        ),
        entry(
            5,
            agent("build-agent"),
            api_request(goal("Read device status"), &["GET"]),
            Some(api_destination()),
        ),
        entry(
            8,
            agent("build-agent"),
            api_request(goal("Restart switch-01"), &["GET", "POST"]),
            Some(api_destination()),
        ),
        entry(
            9,
            agent("home-agent"),
            ssh_request(goal("Deploy the nightly build"), Window::M30),
            None,
        ),
    ]
}

/// `request` with a session label and a link, as long as they get in practice.
fn stated(mut request: CreateRequest) -> CreateRequest {
    request.session = Some("release-work on the nightly pipeline".parse().unwrap());
    request.link = Some(
        "https://git.example.com/acme/home-lab/pull/1234"
            .parse()
            .unwrap(),
    );
    request
}

/// The list a fixture's links are on.
fn stated_hosts() -> LinkHosts {
    LinkHosts::parse("git.example.com").unwrap()
}

/// The pages that show a session label and a link, one on a host off the list.
fn stated_pages() -> Vec<(&'static str, Markup)> {
    let hosts = stated_hosts();
    let mut request = stated(ssh_request(goal("Deploy the nightly build"), Window::M30));
    let approve_page = approve(
        &pending(
            agent("build-agent"),
            request.clone(),
            ssh_destination(SshMode::Cert),
        ),
        &hosts,
        NOW,
    );
    let mut entries = pending_entries();
    entries.truncate(2);
    entries[0].request = stated(ssh_request(goal("Deploy the nightly build"), Window::H1));
    entries[1].request = stated(api_request(goal("Read device status"), &["GET"]));
    let mut active = active_grants();
    active.truncate(2);
    active[0].request = request.clone();
    active[1].request = stated(api_request(goal("Read device status"), &["GET"]));
    let mut past = history_entries();
    past[1].request = request.clone();
    request.link = Some("https://other.example.org/session".parse().unwrap());
    past[2].request = request.clone();
    let off_list = approve(
        &pending(
            agent("build-agent"),
            request,
            ssh_destination(SshMode::Cert),
        ),
        &hosts,
        NOW,
    );
    vec![
        ("approve-stated", approve_page),
        ("approve-stated-off-list", off_list),
        ("pending-stated", super::pending(&entries, &hosts, NOW)),
        (
            "grants-stated",
            grants(&active, &idle(&active), &hosts, NOW, 0),
        ),
        ("history-stated", history(&past, &hosts)),
    ]
}

/// The pages of a commit signing grant.
fn commit_signing_pages() -> Vec<(&'static str, Markup)> {
    vec![
        (
            "approve-commit-signing",
            approve(
                &pending(
                    agent("build-agent"),
                    signing_request(),
                    signing_destination(),
                ),
                &LinkHosts::default(),
                NOW,
            ),
        ),
        (
            "grants-commit-signing",
            grants(
                &signing_grants(),
                &idle(&signing_grants()),
                &LinkHosts::default(),
                NOW,
                0,
            ),
        ),
        (
            "history-commit-signing",
            history(
                &[HistoryEntry {
                    id: id(9),
                    agent: agent("build-agent"),
                    fingerprint: fingerprint(9),
                    request: signing_request(),
                    status: "approved".to_owned(),
                    created_at: NOW - 600,
                    granted_secs: Some(2_592_000),
                }],
                &LinkHosts::default(),
            ),
        ),
    ]
}

/// Pages showing the longest spelling, five of the longest words: what the
/// layouts must hold without clipping.
fn longest_fingerprint_pages() -> Vec<(&'static str, Markup)> {
    let longest = || Fingerprint::try_from("0522-b233-6c22".to_owned()).unwrap();
    let hosts = LinkHosts::default();
    let mut view = pending(
        agent("build-agent"),
        ssh_request(goal("Deploy the nightly build"), Window::M30),
        ssh_destination(SshMode::Relay),
    );
    view.fingerprint = longest();
    let mut active = active_grants();
    for grant in &mut active {
        grant.fingerprint = longest();
    }
    let mut past = history_entries();
    for entry in &mut past {
        entry.fingerprint = longest();
    }
    let mut waiting = pending_entries();
    for entry in &mut waiting {
        entry.fingerprint = longest();
    }
    vec![
        ("approve-longest-fingerprint", approve(&view, &hosts, NOW)),
        (
            "grants-longest-fingerprint",
            grants(&active, &idle(&active), &hosts, NOW, 0),
        ),
        ("history-longest-fingerprint", history(&past, &hosts)),
        (
            "pending-longest-fingerprint",
            super::pending(&waiting, &hosts, NOW),
        ),
    ]
}

/// Every page with fixture data, named for the screenshot script.
fn pages() -> Vec<(&'static str, Markup)> {
    let long = long_goal();
    // Asks for 4 h of a secret allowed at most 1 h: the capped note shows.
    let mut modify = api_request(long.clone(), &["GET", "POST", "DELETE"]);
    modify.window = Window::H4;
    let active = active_grants();
    let (live_grants, live) = live_grants_fixture();
    vec![
        (
            "approve-ssh-cert",
            approve(
                &pending(
                    long_agent(),
                    ssh_request(long.clone(), Window::H1),
                    ssh_destination(SshMode::Cert),
                ),
                &LinkHosts::default(),
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
                &LinkHosts::default(),
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
                &LinkHosts::default(),
                NOW,
            ),
        ),
        (
            "approve-api-modify",
            approve(
                &pending(long_agent(), modify, api_destination()),
                &LinkHosts::default(),
                NOW,
            ),
        ),
        ("not-pending", not_pending()),
        ("cancelled", cancelled()),
        ("not-found", not_found()),
        ("unavailable", unavailable("The broker is starting up.")),
        ("internal-error", internal_error()),
        (
            "grants-empty",
            grants(&[], &[], &LinkHosts::default(), NOW, 0),
        ),
        (
            "grants-empty-unwritten",
            grants(&[], &[], &LinkHosts::default(), NOW, 2),
        ),
        (
            "grants",
            grants(&active, &idle(&active), &LinkHosts::default(), NOW, 0),
        ),
        (
            "grants-unwritten",
            grants(&active, &idle(&active), &LinkHosts::default(), NOW, 2),
        ),
        (
            "grants-live",
            grants(&live_grants, &live, &LinkHosts::default(), NOW, 0),
        ),
        ("history-empty", history(&[], &LinkHosts::default())),
        (
            "history",
            history(&history_entries(), &LinkHosts::default()),
        ),
        ("enroll", enroll()),
        (
            "pending-empty",
            super::pending(&[], &LinkHosts::default(), NOW),
        ),
        (
            "pending",
            super::pending(&pending_entries(), &LinkHosts::default(), NOW),
        ),
        // The screenshots show the viewport only: these two first.
        (
            "pending-modify-and-outage",
            super::pending(&pending_entries()[2..], &LinkHosts::default(), NOW),
        ),
    ]
    .into_iter()
    .chain(stated_pages())
    .chain(commit_signing_pages())
    .chain(longest_fingerprint_pages())
    .collect()
}

#[test]
fn pending_cards_offer_both_decisions_and_never_guess_at_the_scope() {
    let entries = pending_entries();
    let html = super::pending(&entries, &LinkHosts::default(), NOW).into_string();
    assert_eq!(html.matches("<section class=\"card pending\"").count(), 4);
    assert_eq!(html.matches("Approve…</button>").count(), 4, "{html}");
    assert_eq!(html.matches(">Deny</button>").count(), 4, "{html}");
    for entry in &entries {
        assert!(html.contains(entry.fingerprint.as_str()), "{html}");
        assert!(html.contains(&entry.fingerprint.words()), "{html}");
    }
    assert!(html.contains("<bdi>Restart switch-01</bdi>"), "{html}");
    assert!(html.contains("Can modify: POST"), "{html}");
    // No link to a token, and no form: everything goes through a POST.
    assert!(!html.contains("/approve/"), "{html}");
    assert!(!html.contains("<form"), "{html}");

    // With the policy unreadable the card does not say read-only or not.
    let unread = super::pending(&entries[3..], &LinkHosts::default(), NOW).into_string();
    assert!(unread.contains("could not be read"), "{unread}");
    assert!(!unread.contains("Read-only"), "{unread}");
    assert!(!unread.contains("Can modify"), "{unread}");

    let html = super::pending(&[], &LinkHosts::default(), NOW).into_string();
    assert!(html.contains("Nothing waiting"), "{html}");
    // The empty state refreshes too, and has room for what a denial said.
    assert!(html.contains(r#"data-pending="empty""#), "{html}");
    assert!(html.contains(r#"<p class="result" id="result""#), "{html}");
    assert!(html.contains("/static/warden.js"), "{html}");
    assert_eq!(
        html.matches(r#"<a href="/pending" aria-current="page">"#)
            .count(),
        2,
        "{html}"
    );
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
