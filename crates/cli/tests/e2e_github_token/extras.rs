//! `warden request github --extra-permissions`: what the CLI sends, what it
//! refuses before sending, and what it does once the owner approves.

use std::process::Stdio;

use warden_broker::policy::GithubPermissionPolicy;
use warden_broker::requests::Clock as _;
use warden_broker::testkit::CapturingNotifier;
use warden_broker::testkit::github_app::token_answer;
use warden_broker::testkit::upstream::{Scripted, installation_json};
use warden_broker_proto::Window;
use warden_broker_proto::github_permissions::PermissionSet;
use warden_broker_proto::github_token::{OTHER_PERMISSIONS_PENDING, SENSITIVE_WINDOW};

use super::old_broker::OldBroker;
use super::{
    REPO, REPO_ID, Setup, TOKEN, approve_for, get_grant, offline, script_token, setup, text,
    upstream_calls, wait,
};

const LEGACY: &str = "contents:write,issues:write,metadata:read,pull_requests:write";

fn set(text: &str) -> PermissionSet {
    PermissionSet::parse(text).unwrap()
}

/// The owner allows `extras` on top of the legacy default, and the App's installation
/// holds them (with `more`) as well.
fn allow(s: &Setup, extras: &str, held: &[(&str, &str)]) {
    s.broker
        .backend
        .set_github_permissions(Some(GithubPermissionPolicy {
            default: set(LEGACY),
            allowed_extras: set(extras),
        }));
    let mut all = vec![
        ("contents", "write"),
        ("issues", "write"),
        ("metadata", "read"),
        ("pull_requests", "write"),
    ];
    all.extend_from_slice(held);
    s.upstream
        .answer_github_installation(Some(Scripted::with_body(200, installation_json(&all))));
}

#[tokio::test(flavor = "multi_thread")]
async fn extra_permissions_success_scenario() {
    let s = setup().await;
    allow(
        &s,
        "checks:read,actions:read",
        &[("checks", "read"), ("actions", "read")],
    );
    // A token cut to the default is cached before the extras are approved.
    get_grant(&s).await;
    script_token(&s, TOKEN, (REPO_ID, REPO));
    let first = s
        .machine
        .warden()
        .args(["github", "token", "--repo", REPO])
        .output()
        .unwrap();
    assert_eq!(first.status.code(), Some(0), "{}", text(&first.stderr));
    assert_eq!(text(&first.stdout), format!("{TOKEN}\n"));
    assert!(s.machine.cache().exists());

    let child = s
        .machine
        .warden()
        .args([
            "request",
            "github",
            REPO,
            "--extra-permissions",
            "checks:read,actions:read",
            "--goal",
            "read the CI results",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = CapturingNotifier::token(&s.broker.capture.next().await);
    approve_for(&s, &request, Window::D30, &[(REPO_ID, REPO)], &[]).await;
    let out = wait(child).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("approved: grant"),
        "{}",
        text(&out.stdout)
    );
    assert!(
        !s.machine.cache().exists(),
        "the token minted before the approval is not kept"
    );

    // The next token is minted afresh, with the grant's whole set.
    let wider = "ghs_e2eWider0123456789";
    s.upstream.script_github_token(token_answer(
        wider,
        s.broker.clock.now() + 3600,
        &[(REPO_ID, REPO)],
        &[
            ("actions", "read"),
            ("checks", "read"),
            ("contents", "write"),
            ("issues", "write"),
            ("metadata", "read"),
            ("pull_requests", "write"),
        ],
        "selected",
    ));
    let second = s
        .machine
        .warden()
        .args(["github", "token", "--repo", REPO])
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(0), "{}", text(&second.stderr));
    assert_eq!(text(&second.stdout), format!("{wider}\n"));
    let mint = upstream_calls(&s.upstream)
        .into_iter()
        .rfind(|call| call.path_and_query.ends_with("/access_tokens"))
        .expect("a mint");
    let asked: serde_json::Value = serde_json::from_slice(&mint.body).unwrap();
    assert_eq!(asked["permissions"]["checks"], "read");
    assert_eq!(asked["permissions"]["actions"], "read");
}

#[test]
fn extra_permissions_against_old_broker_says_upgrade() {
    let broker = OldBroker::start();
    let machine = super::Machine::new(&broker.url, format!("wdn_{}", "S".repeat(43)));
    let out = machine
        .warden()
        .args([
            "request",
            "github",
            REPO,
            "--extra-permissions",
            "checks:read",
            "--goal",
            "read the CI results",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let said = text(&out.stderr);
    assert!(
        said.contains("does not support extra GitHub permissions: upgrade the broker"),
        "{said}"
    );
    assert_eq!(
        broker.requests(),
        ["GET /v1/info HTTP/1.1"],
        "nothing but the capability check reached the broker"
    );
}

#[test]
fn bad_extra_permissions_is_usage_error() {
    let machine = offline();
    for bad in [
        "contents:admin",
        "nonsense",
        "checks:read,",
        "checks:read,checks:write",
    ] {
        let out = machine
            .warden()
            .args([
                "request",
                "github",
                REPO,
                "--extra-permissions",
                bad,
                "--goal",
                "read the CI results",
            ])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(64), "{bad}: {}", text(&out.stderr));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sensitive_extra_defaults_to_one_hour_and_a_long_window_is_refused_as_said() {
    let s = setup().await;
    allow(&s, "workflows:write", &[("workflows", "write")]);
    let args = |extra: &'static [&'static str]| {
        let mut cmd = s.machine.warden();
        cmd.args([
            "request",
            "github",
            REPO,
            "--extra-permissions",
            "workflows:write",
            "--goal",
            "update the workflow",
        ])
        .args(extra);
        cmd
    };
    let refused = args(&["--for", "30d"]).output().unwrap();
    assert_eq!(refused.status.code(), Some(1), "{}", text(&refused.stderr));
    assert!(
        text(&refused.stderr).contains(SENSITIVE_WINDOW),
        "{}",
        text(&refused.stderr)
    );

    // No `--for`: the request is for an hour, which the broker takes.
    let child = args(&[])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = CapturingNotifier::token(&s.broker.capture.next().await);
    approve_for(&s, &request, Window::H1, &[(REPO_ID, REPO)], &[]).await;
    let out = wait(child).await;
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_with_other_permissions_pending_is_refused_as_the_broker_says() {
    let s = setup().await;
    allow(&s, "checks:read", &[("checks", "read")]);
    let mut first = s
        .machine
        .warden()
        .args(["request", "github", REPO, "--goal", "push the fix"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = CapturingNotifier::token(&s.broker.capture.next().await);

    let other = s
        .machine
        .warden()
        .args([
            "request",
            "github",
            REPO,
            "--extra-permissions",
            "checks:read",
            "--goal",
            "read the CI results",
        ])
        .output()
        .unwrap();
    assert_eq!(other.status.code(), Some(1), "{}", text(&other.stderr));
    assert!(
        text(&other.stderr).contains(OTHER_PERMISSIONS_PENDING),
        "{}",
        text(&other.stderr)
    );
    first.kill().unwrap();
    first.wait().unwrap();
}
