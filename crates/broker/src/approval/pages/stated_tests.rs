//! Hostile session labels and links on every page that shows them.

use warden_broker_proto::{
    Access, AgentName, CreateRequest, Fingerprint, Goal, GrantAccess, Id, SessionLabel,
    SessionLink, SshGrant, TargetName, UnixUser, Window,
};

use super::{approve, grants, history, pending};
use crate::policy::{SshMode, SshTarget};
use crate::requests::{
    ActiveGrant, Destination, HistoryEntry, LinkHosts, PendingEntry, PendingView,
};

const NOW: i64 = 1_800_000_000;

/// Valid as a label, and would run if it reached a page as it is.
const HOSTILE_LABEL: &str = "<script>x()</script>\"'><img src=x>&amp;";
/// The same, escaped as a page must show it.
const ESCAPED_LABEL: &str = "&lt;script&gt;x()&lt;/script&gt;&quot;'&gt;&lt;img src=x&gt;&amp;amp;";

fn id() -> Id {
    Id::try_from("0".repeat(32)).unwrap()
}

fn agent() -> AgentName {
    AgentName::try_from("build-agent".to_owned()).unwrap()
}

fn fingerprint() -> Fingerprint {
    Fingerprint::try_from("ab01-cd01-ef01".to_owned()).unwrap()
}

fn target() -> TargetName {
    TargetName::try_from("switch-01".to_owned()).unwrap()
}

fn user() -> UnixUser {
    UnixUser::try_from("deploy".to_owned()).unwrap()
}

fn request(link: &str) -> CreateRequest {
    CreateRequest {
        goal: Goal::try_from("Deploy the nightly build".to_owned()).unwrap(),
        access: Access::Ssh {
            target: target(),
            user: user(),
            public_key: "ssh-ed25519 AAAA".to_owned(),
        },
        window: Window::M15,
        session: Some(SessionLabel::try_from(HOSTILE_LABEL.to_owned()).unwrap()),
        link: Some(SessionLink::try_from(link.to_owned()).unwrap()),
    }
}

fn destination() -> Destination {
    Destination::Ssh(SshTarget {
        name: target(),
        host: "switch-01.lan".to_owned(),
        port: 22,
        mode: SshMode::Cert,
        users: vec![user()],
        max_window: Window::H4,
        host_keys: Vec::new(),
    })
}

/// Each page that shows a label and a link, with `link`.
fn pages(link: &str, hosts: &LinkHosts) -> Vec<(&'static str, String)> {
    let request = request(link);
    let view = PendingView {
        id: id(),
        agent: agent(),
        fingerprint: fingerprint(),
        request: request.clone(),
        destination: destination(),
        expires_at: NOW + 240,
    };
    let entry = PendingEntry {
        id: id(),
        agent: agent(),
        fingerprint: fingerprint(),
        request: request.clone(),
        destination: Some(destination()),
        expires_at: NOW + 240,
    };
    let grant = ActiveGrant {
        grant_id: id(),
        agent: agent(),
        fingerprint: fingerprint(),
        request: request.clone(),
        access: GrantAccess::Ssh(SshGrant {
            certificate: "ssh-ed25519-cert-v01@openssh.com AAAA".to_owned(),
            host: "switch-01.lan".to_owned(),
            port: 22,
            user: user(),
            host_keys: Vec::new(),
        }),
        not_before: NOW - 60,
        not_after: NOW + 1800,
    };
    let past = HistoryEntry {
        id: id(),
        agent: agent(),
        fingerprint: fingerprint(),
        request,
        status: "approved".to_owned(),
        created_at: NOW - 600,
        granted_secs: Some(900),
    };
    vec![
        ("approve", approve(&view, hosts, NOW).into_string()),
        ("pending", pending(&[entry], hosts, NOW).into_string()),
        ("grants", grants(&[grant], &[], hosts, NOW, 0).into_string()),
        ("history", history(&[past], hosts).into_string()),
    ]
}

fn listed() -> LinkHosts {
    LinkHosts::parse("git.example.com").unwrap()
}

/// Tags whose name is `name`, as written in `html`.
fn tags<'a>(html: &'a str, name: &str) -> Vec<&'a str> {
    let open = format!("<{name} ");
    html.match_indices(&open)
        .map(|(at, _)| {
            let rest = &html[at..];
            &rest[..=rest.find('>').unwrap()]
        })
        .collect()
}

#[test]
fn a_hostile_label_is_escaped_on_every_page() {
    for (name, html) in pages("https://git.example.com/a", &listed()) {
        assert!(html.contains(ESCAPED_LABEL), "{name}: {html}");
        assert!(!html.contains("<script>x"), "{name}");
        assert!(!html.contains("<img"), "{name}");
        assert!(
            html.contains(&format!("<bdi>{ESCAPED_LABEL}</bdi>")),
            "{name}: the label must be isolated"
        );
    }
}

#[test]
fn every_page_says_the_agent_stated_it_and_never_that_it_is_verified() {
    for (name, html) in pages("https://git.example.com/a", &listed()) {
        let text = html.to_lowercase();
        assert!(
            text.contains("session stated by the agent")
                || text.contains("session · stated by the agent"),
            "{name}"
        );
        assert!(
            text.contains("link stated by the agent")
                || text.contains("link · stated by the agent"),
            "{name}"
        );
        for claim in ["verified session", "verified link", "confirmed", "trusted"] {
            assert!(!text.contains(claim), "{name} says {claim}");
        }
    }
}

#[test]
fn a_listed_link_goes_to_its_real_host_in_a_new_tab_with_nothing_passed_on() {
    for (name, html) in pages("https://git.example.com/o/r/pull/7", &listed()) {
        let anchors: Vec<&str> = tags(&html, "a")
            .into_iter()
            .filter(|tag| tag.contains("stated-link"))
            .collect();
        assert_eq!(
            anchors,
            [
                r#"<a class="stated-link" href="https://git.example.com/o/r/pull/7" target="_blank" rel="noopener noreferrer">"#
            ],
            "{name}"
        );
        assert!(html.contains("<code>git.example.com</code>"), "{name}");
    }
}

#[test]
fn a_hostile_path_cannot_leave_the_href() {
    for (name, html) in pages(
        "https://git.example.com/\"><script>x()</script>'",
        &listed(),
    ) {
        assert!(!html.contains("<script>x"), "{name}");
        assert!(
            html.contains(r#"href="https://git.example.com/%22%3E%3Cscript%3Ex()%3C/script%3E'""#),
            "{name}: {html}"
        );
    }
}

#[test]
fn a_host_off_the_list_is_named_but_is_not_a_link() {
    let lists = [listed(), LinkHosts::default()];
    for hosts in &lists {
        for (name, html) in pages("https://evil.example.org/phish-path", hosts) {
            assert!(!html.contains("stated-link"), "{name}");
            assert!(!html.contains("href=\"https://evil"), "{name}");
            assert!(
                !html.contains("phish-path"),
                "{name}: only the host is shown"
            );
            assert!(html.contains("<code>evil.example.org</code>"), "{name}");
            assert!(html.contains("not on your list of link hosts"), "{name}");
        }
    }
}

/// The link is in the details, and the decision's buttons follow it only after
/// something else: nothing puts it next to Approve.
#[test]
fn the_link_is_kept_apart_from_approve() {
    let all = pages("https://git.example.com/a", &listed());
    for (name, html) in &all[..2] {
        let link = html.find("stated-link").unwrap();
        let button = html.find("btn approve").unwrap();
        assert!(link < button, "{name}");
        let between = &html[link..button];
        assert!(between.contains("Fingerprint"), "{name}: {between}");
    }
}

#[test]
fn a_request_without_them_shows_neither() {
    let hosts = listed();
    let mut plain = request("https://git.example.com/");
    plain.session = None;
    plain.link = None;
    let view = PendingView {
        id: id(),
        agent: agent(),
        fingerprint: fingerprint(),
        request: plain,
        destination: destination(),
        expires_at: NOW + 240,
    };
    let html = approve(&view, &hosts, NOW).into_string();
    assert!(!html.contains("stated"), "{html}");
}
