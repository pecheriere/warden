use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use warden_broker_proto::Window;
use warden_broker_proto::offers::{
    ApiSecretOffer, Availability, GithubOffer, GithubTokenStatus, OfferPart, Offers, ReleaseStatus,
    RepositoryOffer, SshModeName, SshTargetOffer,
};
use zeroize::Zeroizing;

use super::template::Section;
use super::{
    BROKER_ERROR, NOT_SET_UP, OFFERS_TIMEOUT, REFUSED, Setup, TIMED_OUT, UNREACHABLE, UNUSABLE,
    brief_offers, kept, output, setup_from,
};
use crate::client::{Auth, Client};

/// Words only the GitHub, signing, release, SSH and API sections hold.
const GITHUB: &str = "### GitHub, if this machine uses warden for it";
const SIGNING: &str = "### Commits, if this machine signs through warden";
const RELEASE: &str = "### Releases, if the person asked you to make one";
const SSH: &str = "warden request ssh <target>";
const API: &str = "warden request api <secret>";
/// Words only the brief section holds.
const BRIEF: &str = "Run `warden prime` before your first request";

fn empty() -> Offers {
    Offers {
        ssh_targets: Vec::new(),
        api_secrets: Vec::new(),
        github: GithubOffer {
            configured: false,
            max_window: None,
        },
        commit_signing: Availability { available: false },
        releases: Availability { available: false },
        unavailable: Vec::new(),
    }
}

fn target(name: &str, user: &str) -> SshTargetOffer {
    SshTargetOffer {
        name: name.parse().unwrap(),
        users: vec![user.parse().unwrap()],
        max_window: Window::H1,
        mode: SshModeName::Cert,
        destination: None,
    }
}

fn repository() -> RepositoryOffer {
    RepositoryOffer {
        repository: "example-org/example-repo".parse().unwrap(),
        github_token: GithubTokenStatus::Covered,
        commit_signing: true,
        release: ReleaseStatus::NoKey,
    }
}

/// A broker that answers the offers routes and records the path of every call.
struct Fake {
    url: url::Url,
    paths: Arc<Mutex<Vec<String>>>,
}

async fn broker(offers: Option<&Offers>, repository: Option<&RepositoryOffer>) -> Fake {
    let offers = offers.map(|o| serde_json::to_string(o).unwrap());
    let repository = repository.map(|r| serde_json::to_string(r).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = url::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    let paths = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&paths);
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let mut buf = [0_u8; 4096];
            let n = conn.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();
            let path = request.split(' ').nth(1).unwrap_or_default().to_owned();
            let body = if path == "/v1/offers" {
                offers.clone()
            } else if path.starts_with("/v1/offers/repository/") {
                repository.clone()
            } else {
                None
            };
            seen.lock().unwrap().push(path);
            let (status, body) = body.map_or((404, String::new()), |b| (200, b));
            let resp = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = conn.write_all(resp.as_bytes()).await;
        }
    });
    Fake { url, paths }
}

fn ready(url: &url::Url) -> Setup {
    let key = Zeroizing::new(format!("wdn_{}", "S".repeat(43)));
    Setup::Ready(Client::new(url, Auth::Bearer(key)).unwrap())
}

/// A git checkout whose origin is the GitHub repository `example-org/example-repo`.
fn github_checkout() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for args in [
        &["init", "--quiet"][..],
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example-org/example-repo.git",
        ],
    ] {
        let status = Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "{args:?}");
    }
    dir
}

async fn prime(setup: Setup, dir: Option<&Path>, brief: bool) -> String {
    output(setup, dir, brief, OFFERS_TIMEOUT).await
}

#[tokio::test]
async fn prime_keeps_sections_offered() {
    let mut offers = empty();
    offers.ssh_targets = vec![target("web-01", "deploy")];
    offers.commit_signing = Availability { available: true };
    let fake = broker(Some(&offers), None).await;
    let text = prime(ready(&fake.url), None, false).await;
    assert!(text.contains(SSH), "{text}");
    assert!(text.contains(SIGNING), "{text}");
    assert!(!text.contains(GITHUB), "{text}");
    assert!(!text.contains(RELEASE), "{text}");
    assert!(!text.contains(API), "{text}");
    assert!(!text.contains(BRIEF), "{text}");
    assert!(
        text.contains("SSH targets:\n  web-01: users deploy"),
        "{text}"
    );
    assert!(text.contains("Commit signing: available"), "{text}");
    assert!(!text.contains(UNREACHABLE), "{text}");
}

#[tokio::test]
async fn prime_includes_repository_answer_in_github_checkout() {
    let mut offers = empty();
    offers.github = GithubOffer {
        configured: true,
        max_window: None,
    };
    let fake = broker(Some(&offers), Some(&repository())).await;
    let checkout = github_checkout();
    let text = prime(ready(&fake.url), Some(checkout.path()), false).await;
    assert!(text.contains(GITHUB), "{text}");
    assert!(
        text.contains("This repository (example-org/example-repo):"),
        "{text}"
    );
    assert!(
        text.contains("  Releases: no release signing key names it"),
        "{text}"
    );
    assert_eq!(
        *fake.paths.lock().unwrap(),
        [
            "/v1/offers",
            "/v1/offers/repository/example-org/example-repo"
        ]
    );
}

#[tokio::test]
async fn brief_does_not_ask_about_repository() {
    let fake = broker(Some(&empty()), Some(&repository())).await;
    let checkout = github_checkout();
    let text = prime(ready(&fake.url), Some(checkout.path()), true).await;
    assert!(text.contains(BRIEF), "{text}");
    assert!(!text.contains("This repository"), "{text}");
    assert_eq!(*fake.paths.lock().unwrap(), ["/v1/offers"]);
}

#[tokio::test]
async fn brief_is_short() {
    let mut offers = empty();
    offers.ssh_targets = vec![target("web-01", "deploy"), target("switch-01", "admin")];
    offers.api_secrets = vec![ApiSecretOffer {
        name: "home-api".parse().unwrap(),
        origin: Some("https://home-api.example.internal".to_owned()),
        methods: vec!["GET".to_owned()],
        path_prefix: "/api/".to_owned(),
        max_window: Window::M30,
    }];
    offers.github = GithubOffer {
        configured: true,
        max_window: Some(Window::D30),
    };
    let fake = broker(Some(&offers), None).await;
    let text = prime(ready(&fake.url), None, true).await;
    assert!(text.lines().count() <= 15, "{text}");
    assert!(
        text.contains("\nSSH: web-01 (deploy), switch-01 (admin)\n"),
        "{text}"
    );
    assert!(text.contains("\nAPI: home-api\n"), "{text}");
    assert!(text.contains("\nGitHub tokens: on\n"), "{text}");
    assert!(!text.contains("Commit signing"), "{text}");
    assert!(!text.contains("example.internal"), "{text}");
    assert!(text.contains("never look for another way in"), "{text}");
    assert!(!text.contains(SSH), "{text}");
}

/// The rules for every kind of access, as printed without the broker's answer.
fn assert_all_rules(text: &str) {
    for words in [SSH, API, SIGNING, GITHUB, RELEASE] {
        assert!(text.contains(words), "{words}: {text}");
    }
    assert!(!text.contains(BRIEF), "{text}");
}

#[tokio::test]
async fn broker_unreachable_prints_rules_and_exits_0() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = url::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    drop(listener);
    let text = prime(ready(&url), None, false).await;
    assert_all_rules(&text);
    assert!(text.contains(&format!("\n{UNREACHABLE}\n")), "{text}");
    assert!(UNREACHABLE.contains("cannot be reached") && UNREACHABLE.contains("warden doctor"));
    assert!(text.contains("warden doctor"), "{text}");
    let brief = prime(ready(&url), None, true).await;
    assert!(brief.contains(BRIEF), "{brief}");
    assert!(brief.contains(&format!("\n{UNREACHABLE}\n")), "{brief}");
}

#[tokio::test]
async fn broker_hangs_returns_within_timeout() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = url::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    // Accepts every connection and keeps it open without ever answering.
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((conn, _)) = listener.accept().await {
            held.push(conn);
        }
    });
    // A short limit keeps the test quick; the command finishing at all is the check.
    let text = output(ready(&url), None, false, Duration::from_millis(100)).await;
    assert_all_rules(&text);
    assert!(text.contains(&format!("\n{TIMED_OUT}\n")), "{text}");
    assert!(TIMED_OUT.contains("within 3 s") && TIMED_OUT.contains("warden doctor"));
}

/// A broker that answers every call with `status` and `body`.
async fn answering(status: u16, body: &'static str) -> url::Url {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = url::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let mut buf = [0_u8; 4096];
            let _ = conn.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = conn.write_all(resp.as_bytes()).await;
        }
    });
    url
}

#[tokio::test]
async fn each_failure_has_its_own_line() {
    for (status, body, line) in [
        (503, r#"{"error":"backend unavailable"}"#, BROKER_ERROR),
        (500, "", BROKER_ERROR),
        (401, r#"{"error":"unauthorized"}"#, REFUSED),
        (200, r#"{"ssh_targets":"no"}"#, REFUSED),
    ] {
        let url = answering(status, body).await;
        let text = prime(ready(&url), None, false).await;
        assert_all_rules(&text);
        assert!(text.contains(&format!("\n{line}\n")), "{status}: {text}");
        assert!(!text.contains(UNREACHABLE), "{status}: {text}");
    }
    assert!(BROKER_ERROR.contains("cannot read its policy now"));
    assert!(REFUSED.contains("refused this agent's call or gave an answer this CLI cannot read"));
}

#[test]
fn an_unknown_unavailable_part_keeps_every_section() {
    let mut offers = empty();
    offers.unavailable = vec![OfferPart::Unknown];
    assert_eq!(kept(&offers), Section::ALL.into());
    assert_eq!(brief_offers(&offers), "Other offers: could not be read");
}

#[tokio::test]
async fn old_broker_prints_rules_and_too_old_line() {
    let fake = broker(None, None).await;
    let text = prime(ready(&fake.url), None, false).await;
    assert_all_rules(&text);
    assert!(text.contains("\nwarden: this broker is too old"), "{text}");
    assert!(text.contains(env!("CARGO_PKG_VERSION")), "{text}");
}

#[tokio::test]
async fn not_set_up_prints_one_line_and_exits_0() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("warden").join("config.toml");
    assert!(matches!(setup_from(Ok(path.clone())), Setup::NotSetUp));
    for brief in [false, true] {
        let text = prime(setup_from(Ok(path.clone())), None, brief).await;
        assert_eq!(text, format!("{NOT_SET_UP}\n"));
        assert!(text.contains("not set up"), "{text}");
    }

    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "not toml at all [").unwrap();
    assert!(matches!(setup_from(Ok(path.clone())), Setup::Unusable));
    let text = prime(setup_from(Ok(path)), None, false).await;
    assert_all_rules(&text);
    assert!(text.contains(&format!("\n{UNUSABLE}\n")), "{text}");
}
