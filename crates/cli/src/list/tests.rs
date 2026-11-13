use std::path::Path;
use std::process::Command;

use warden_broker_proto::Window;
use warden_broker_proto::offers::{
    ApiSecretOffer, Availability, Destination, GithubOffer, GithubTokenStatus, OfferPart, Offers,
    ReleaseStatus, RepositoryOffer, SshModeName, SshTargetOffer,
};
use zeroize::Zeroizing;

use super::{Fetched, Repository, checkout_repository, fetch, json_output, render, run};
use crate::client::{Auth, Client, OffersError, read_offer};
use crate::{EXIT_ERROR, EXIT_USAGE, Exit};

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

fn target(name: &str, destination: Option<Destination>) -> SshTargetOffer {
    SshTargetOffer {
        name: name.parse().unwrap(),
        users: vec!["deploy".parse().unwrap(), "admin".parse().unwrap()],
        max_window: Window::H1,
        mode: SshModeName::Cert,
        destination,
    }
}

fn repository(token: GithubTokenStatus, release: ReleaseStatus) -> RepositoryOffer {
    RepositoryOffer {
        repository: "example-org/example-repo".parse().unwrap(),
        github_token: token,
        commit_signing: true,
        release,
    }
}

#[test]
fn render_full_and_name_items() {
    let mut offers = empty();
    offers.ssh_targets = vec![
        target(
            "web-01",
            Some(Destination {
                host: "web-01.example.internal".to_owned(),
                port: 22,
            }),
        ),
        target("switch-01", None),
        SshTargetOffer {
            mode: SshModeName::Relay,
            ..target("relay-01", None)
        },
    ];
    offers.api_secrets = vec![
        ApiSecretOffer {
            name: "home-api".parse().unwrap(),
            origin: Some("https://home-api.example.internal".to_owned()),
            methods: vec!["GET".to_owned(), "HEAD".to_owned()],
            path_prefix: "/api/".to_owned(),
            max_window: Window::M30,
        },
        ApiSecretOffer {
            name: "hidden-origin".parse().unwrap(),
            origin: None,
            methods: vec!["GET".to_owned()],
            path_prefix: "/".to_owned(),
            max_window: Window::M15,
        },
    ];
    offers.github = GithubOffer {
        configured: true,
        max_window: Some(Window::D30),
    };
    offers.commit_signing = Availability { available: true };
    offers.releases = Availability { available: true };
    assert_eq!(
        render(&offers, None),
        "SSH targets:\n\
         \x20 web-01: users deploy, admin, up to 1h, cert, web-01.example.internal:22\n\
         \x20 switch-01: users deploy, admin, up to 1h, cert\n\
         \x20 relay-01: users deploy, admin, up to 1h, relay\n\
         API secrets:\n\
         \x20 home-api: GET, HEAD under /api/, up to 30m, https://home-api.example.internal\n\
         \x20 hidden-origin: GET under /, up to 15m\n\
         GitHub tokens: available, up to 30d\n\
         Commit signing: available\n\
         Releases: available\n"
    );
}

#[test]
fn render_leaves_out_empty_sections() {
    let mut offers = empty();
    offers.commit_signing = Availability { available: true };
    assert_eq!(render(&offers, None), "Commit signing: available\n");
    assert_eq!(
        render(&empty(), None),
        "The broker offers this agent nothing.\n"
    );
}

#[test]
fn render_marks_unavailable_parts() {
    let mut offers = empty();
    offers.unavailable = vec![OfferPart::ApiSecrets, OfferPart::Releases];
    offers.ssh_targets = vec![target("switch-01", None)];
    let text = render(&offers, None);
    assert!(text.contains("API secrets: could not be read\n"), "{text}");
    assert!(text.contains("Releases: could not be read\n"), "{text}");
    assert!(text.contains("SSH targets:\n"), "{text}");
    assert!(!text.contains("GitHub tokens"), "{text}");
    assert!(!text.contains("Other offers"), "{text}");
}

#[test]
fn render_unknown_values() {
    let mut offers = empty();
    offers.unavailable = vec![OfferPart::Unknown];
    let mut newer = target("switch-01", None);
    newer.mode = SshModeName::Unknown;
    offers.ssh_targets = vec![newer];
    let text = render(&offers, None);
    assert!(
        text.contains("  switch-01: users deploy, admin, up to 1h, unknown\n"),
        "{text}"
    );
    assert!(text.contains("Other offers: could not be read\n"), "{text}");
}

#[test]
fn render_unreadable_repository() {
    let repo = Repository::Unreadable("example-org/example-repo".parse().unwrap());
    let text = render(&empty(), Some(&repo));
    assert_eq!(
        text,
        "This repository (example-org/example-repo): could not be read\n"
    );
}

#[test]
fn render_repository_section() {
    let cases = [
        (GithubTokenStatus::Covered, "the GitHub App covers it"),
        (
            GithubTokenStatus::NotCovered,
            "the GitHub App does not cover it",
        ),
        (
            GithubTokenStatus::NotConfigured,
            "no GitHub App is configured",
        ),
        (GithubTokenStatus::Unavailable, "could not be read"),
        (GithubTokenStatus::Unknown, "could not be read"),
    ];
    for (status, words) in cases {
        let repo = Repository::Offer(repository(status, ReleaseStatus::Ready));
        let text = render(&empty(), Some(&repo));
        assert!(
            text.starts_with("This repository (example-org/example-repo):\n"),
            "{text}"
        );
        assert!(
            text.contains(&format!("  GitHub tokens: {words}\n")),
            "{text}"
        );
        assert!(text.contains("  Commit signing: available\n"), "{text}");
    }
    let cases = [
        (ReleaseStatus::Ready, "ready"),
        (ReleaseStatus::NoKey, "no release signing key names it"),
        (ReleaseStatus::NoReleaseApp, "no release App is configured"),
        (ReleaseStatus::Unavailable, "could not be read"),
        (ReleaseStatus::Unknown, "could not be read"),
    ];
    for (status, words) in cases {
        let repo = Repository::Offer(repository(GithubTokenStatus::Covered, status));
        let text = render(&empty(), Some(&repo));
        assert!(text.contains(&format!("  Releases: {words}\n")), "{text}");
    }
}

#[test]
fn render_makes_broker_text_safe_to_print() {
    let mut offers = empty();
    offers.ssh_targets = vec![target(
        "web-01",
        Some(Destination {
            host: "host\u{1b}[2J\n".to_owned(),
            port: 22,
        }),
    )];
    offers.api_secrets = vec![ApiSecretOffer {
        name: "home-api".parse().unwrap(),
        origin: Some("https://x\u{1b}]0;t\u{7}".to_owned()),
        methods: vec!["GE\rT".to_owned()],
        path_prefix: "/\u{202e}a".to_owned(),
        max_window: Window::M15,
    }];
    let text = render(&offers, None);
    assert!(
        !text
            .chars()
            .any(|c| c != '\n' && (c.is_control() || c == '\u{202e}')),
        "{text:?}"
    );
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "{args:?}");
}

#[test]
fn no_repository_section_outside_github_checkout() {
    let plain = tempfile::tempdir().unwrap();
    assert_eq!(checkout_repository(plain.path()), None);

    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "--quiet"]);
    assert_eq!(checkout_repository(repo.path()), None);

    git(
        repo.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://git.example.internal/a/b.git",
        ],
    );
    assert_eq!(checkout_repository(repo.path()), None);

    git(
        repo.path(),
        &[
            "remote",
            "set-url",
            "origin",
            "git@github.com:example-org/example-repo.git",
        ],
    );
    assert_eq!(
        checkout_repository(repo.path()),
        Some("example-org/example-repo".parse().unwrap())
    );
}

/// A broker that answers every request with `status` and `body`.
async fn answering(status: u16, body: &'static str) -> url::Url {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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
    url::Url::parse(&format!("http://{addr}/")).unwrap()
}

fn client(url: &url::Url) -> Client {
    let key = Zeroizing::new(format!("wdn_{}", "S".repeat(43)));
    Client::new(url, Auth::Bearer(key)).unwrap()
}

#[tokio::test]
async fn old_broker_exits_1_with_upgrade_hint() {
    let old = client(&answering(404, "").await);
    let error = fetch(&old, None).await.unwrap_err();
    let exit = error.downcast_ref::<Exit>().unwrap();
    assert_eq!(exit.code, EXIT_ERROR);
    assert!(exit.message.contains("too old"), "{}", exit.message);
    assert!(
        exit.message.contains("upgrade it to at least"),
        "{}",
        exit.message
    );

    let refused = client(&answering(401, r#"{"error":"agent revoked"}"#).await);
    let error = fetch(&refused, None).await.unwrap_err();
    assert_eq!(error.downcast_ref::<Exit>().unwrap().code, EXIT_ERROR);
}

#[tokio::test]
async fn bad_repo_flag_exits_64() {
    for bad in ["nonsense", "https://example.com/a/b", "a/b/c"] {
        let error = run(false, Some(bad.to_owned())).await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<Exit>().unwrap().code,
            EXIT_USAGE,
            "{bad}"
        );
    }
}

#[test]
fn json_prints_the_bodies_as_received() {
    let offers = serde_json::json!({ "ssh_targets": [], "newer": { "x": 1 } });
    let none = json_output(&Fetched {
        offers: offers.clone(),
        repository: None,
    });
    assert_eq!(none["offers"], offers);
    assert!(none["repository"].is_null());
    let repo = serde_json::json!({ "github_token": "suspended", "newer": true });
    let some = json_output(&Fetched {
        offers: offers.clone(),
        repository: Some(Ok(repo.clone())),
    });
    assert_eq!(some["repository"], repo);
    let failed = json_output(&Fetched {
        offers,
        repository: Some(Err(OffersError::Broker("broker error (503)".to_owned()))),
    });
    assert!(failed["repository"].is_null());
}

/// A broker that answers `GET /v1/offers` with `offers` and every other call with `status`.
async fn offers_then(offers: &'static str, status: u16) -> url::Url {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let mut buf = [0_u8; 4096];
            let n = conn.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();
            let (status, body) = if request.starts_with("GET /v1/offers ") {
                (200, offers)
            } else {
                (status, r#"{"error":"backend unavailable"}"#)
            };
            let resp = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                 content-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = conn.write_all(resp.as_bytes()).await;
        }
    });
    url::Url::parse(&format!("http://{addr}/")).unwrap()
}

const EMPTY_OFFERS: &str = r#"{"ssh_targets":[],"api_secrets":[],"github":{"configured":false,"max_window":null},
    "commit_signing":{"available":false},"releases":{"available":false},"unavailable":[]}"#;

#[tokio::test]
async fn a_failed_repository_call_is_not_an_error() {
    let repo = "example-org/example-repo".parse().unwrap();
    for status in [500, 503, 401] {
        let broker = client(&offers_then(EMPTY_OFFERS, status).await);
        let fetched = fetch(&broker, Some(&repo)).await.unwrap();
        assert_eq!(read_offer::<Offers>(&fetched.offers), Ok(empty()));
        assert!(matches!(fetched.repository, Some(Err(_))), "{status}");
    }
}

#[tokio::test]
async fn a_5xx_from_the_offers_call_is_a_broker_error() {
    let broker = client(&answering(503, r#"{"error":"backend unavailable"}"#).await);
    let error = broker.offers().await.unwrap_err();
    assert!(matches!(error, OffersError::Broker(_)), "{error:?}");
    let error = fetch(&broker, None).await.unwrap_err();
    assert_eq!(error.downcast_ref::<Exit>().unwrap().code, EXIT_ERROR);
}

#[tokio::test]
async fn client_reads_both_offers_routes() {
    let offers = client(
        &answering(
            200,
            r#"{"ssh_targets":[],"api_secrets":[],"github":{"configured":false,"max_window":null},
                "commit_signing":{"available":false},"releases":{"available":false},
                "unavailable":[]}"#,
        )
        .await,
    );
    let body = offers.offers().await.unwrap().unwrap();
    assert_eq!(read_offer::<Offers>(&body), Ok(empty()));
    let repo = "example-org/example-repo".parse().unwrap();
    let answer = client(
        &answering(
            200,
            r#"{"repository":"example-org/example-repo","github_token":"not_covered",
                "commit_signing":false,"release":"no_key"}"#,
        )
        .await,
    );
    let mut expected = repository(GithubTokenStatus::NotCovered, ReleaseStatus::NoKey);
    expected.commit_signing = false;
    let body = answer.repository_offer(&repo).await.unwrap().unwrap();
    assert_eq!(read_offer::<RepositoryOffer>(&body), Ok(expected));
    let old = client(&answering(404, "").await);
    assert_eq!(old.repository_offer(&repo).await, Ok(None));
}
