//! `warden github token --permissions` and `--fresh`: what reaches the broker, what is
//! cached under which key, and what the CLI refuses.

use std::fs;
use std::process::Output;

use warden_broker::requests::Clock as _;
use warden_broker::testkit::github_app::token_answer;
use warden_broker_proto::github_token::PERMISSIONS_NOT_IN_GRANT;

use super::old_broker::OldBroker;
use super::{
    Machine, REPO, REPO_ID, Setup, TOKEN, get_grant, offline, script_token, setup, text,
    upstream_calls,
};

const NARROW: &str = "ghs_e2eNarrow0123456789";
const WIDE: &str = "ghs_e2eWide0123456789";
const KEY: &str = r#""asked":"contents:read,metadata:read""#;

fn token(s: &Setup, args: &[&str]) -> Output {
    s.machine
        .warden()
        .args(["github", "token", "--repo", REPO])
        .args(args)
        .output()
        .unwrap()
}

/// The bodies of the mints GitHub has seen, which are the calls to its token endpoint.
fn mints(s: &Setup) -> Vec<serde_json::Value> {
    upstream_calls(&s.upstream)
        .into_iter()
        .filter(|call| call.path_and_query.ends_with("/access_tokens"))
        .map(|call| serde_json::from_slice(&call.body).unwrap())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn permissions_flag_narrows() {
    let s = setup().await;
    get_grant(&s).await;
    let before = mints(&s).len();

    s.upstream.script_github_token(token_answer(
        NARROW,
        s.broker.clock.now() + 3600,
        &[(REPO_ID, REPO)],
        &[("contents", "read"), ("metadata", "read")],
        "selected",
    ));
    let narrow = token(&s, &["--permissions", "contents:read"]);
    assert_eq!(narrow.status.code(), Some(0), "{}", text(&narrow.stderr));
    assert_eq!(text(&narrow.stdout), format!("{NARROW}\n"));
    let seen = mints(&s);
    assert_eq!(seen.len(), before + 1);
    assert_eq!(seen[before]["permissions"]["contents"], "read");
    assert_eq!(seen[before]["permissions"]["metadata"], "read");
    assert!(seen[before]["permissions"].get("issues").is_none());
    let cached = fs::read_to_string(s.machine.cache()).unwrap();
    assert!(cached.contains(KEY), "cached under the asked key");

    // The same ask is served from the cache.
    let again = token(&s, &["--permissions", "contents:read"]);
    assert_eq!(text(&again.stdout), format!("{NARROW}\n"));
    assert_eq!(mints(&s).len(), before + 1, "no second mint");

    // A plain token is the whole grant's: it does not get the narrowed one.
    script_token(&s, WIDE, (REPO_ID, REPO));
    let plain = token(&s, &[]);
    assert_eq!(plain.status.code(), Some(0), "{}", text(&plain.stderr));
    assert_eq!(text(&plain.stdout), format!("{WIDE}\n"));
    let seen = mints(&s);
    assert_eq!(seen.len(), before + 2);
    assert_eq!(seen[before + 1]["permissions"]["issues"], "write");
    let cached = fs::read_to_string(s.machine.cache()).unwrap();
    assert!(cached.contains(KEY) && cached.contains(r#""asked":"full""#));
}

#[test]
fn permissions_flag_against_old_broker_says_upgrade() {
    let broker = OldBroker::start();
    let machine = Machine::new(&broker.url, format!("wdn_{}", "S".repeat(43)));
    let out = machine
        .warden()
        .args([
            "github",
            "token",
            "--repo",
            REPO,
            "--permissions",
            "contents:read",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "");
    assert!(
        text(&out.stderr).contains("upgrade the broker"),
        "{}",
        text(&out.stderr)
    );
    assert!(
        broker
            .requests()
            .iter()
            .all(|line| line.starts_with("GET /v1/info")),
        "nothing but the capability check reached the broker"
    );
}

#[test]
fn bad_permissions_flag_is_usage_error() {
    let machine = offline();
    for bad in [
        "contents:admin",
        "nonsense",
        "checks:read,",
        "checks:read,checks:write",
    ] {
        let out = machine
            .warden()
            .args(["github", "token", "--repo", REPO, "--permissions", bad])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(64), "{bad}: {}", text(&out.stderr));
        assert_eq!(text(&out.stdout), "");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn permissions_outside_grant_prints_refusal() {
    let s = setup().await;
    get_grant(&s).await;
    let out = token(&s, &["--permissions", "checks:read"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(text(&out.stdout), "");
    let said = text(&out.stderr);
    assert!(
        said.contains(&format!("{PERMISSIONS_NOT_IN_GRANT}checks:read")),
        "the refusal and the name it carries are printed"
    );
    assert!(!s.machine.cache().exists(), "nothing was cached");
}

#[tokio::test(flavor = "multi_thread")]
async fn fresh_mints_again() {
    let s = setup().await;
    get_grant(&s).await;
    script_token(&s, TOKEN, (REPO_ID, REPO));
    let first = token(&s, &[]);
    assert_eq!(text(&first.stdout), format!("{TOKEN}\n"));
    let before = mints(&s).len();

    script_token(&s, WIDE, (REPO_ID, REPO));
    let fresh = token(&s, &["--fresh"]);
    assert_eq!(fresh.status.code(), Some(0), "{}", text(&fresh.stderr));
    assert_eq!(text(&fresh.stdout), format!("{WIDE}\n"));
    assert_eq!(mints(&s).len(), before + 1, "a mint despite the cache");

    // The new token replaced the old one in the cache.
    let after = token(&s, &[]);
    assert_eq!(text(&after.stdout), format!("{WIDE}\n"));
    assert_eq!(mints(&s).len(), before + 1);
}
