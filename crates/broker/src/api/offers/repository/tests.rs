use axum::http::StatusCode;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use warden_broker_proto::offers::{GithubTokenStatus, ReleaseStatus, RepositoryOffer};
use warden_broker_proto::release::RepoName;

use crate::github_app::GithubApi;
use crate::policy::{ReleaseAppKey, ReleaseSigningKey};
use crate::requests::Clock as _;
use crate::testkit::github_app::{RSA2048_PKCS8, token_answer};
use crate::testkit::upstream::{HttpsUpstream, Scripted};
use crate::testkit::{TestBroker, github_app_key};

const REPO: &str = "example-org/example-repo";
const PATH: &str = "/v1/offers/repository/example-org/example-repo";
const RESOLVE_TOKEN: &str = "ghs_resolve_0123456789abcdef";

fn api_of(upstream: &HttpsUpstream) -> GithubApi {
    GithubApi::pinned(
        upstream.origin().parse().unwrap(),
        upstream.origin().parse().unwrap(),
        upstream.ca_pem().as_bytes().to_vec(),
    )
}

/// A broker holding the test App and talking to a fake GitHub, with an enrolled
/// agent whose key is returned.
async fn on_fake() -> (TestBroker, String, HttpsUpstream) {
    let upstream = HttpsUpstream::start().await;
    let broker = TestBroker::with_github_api(api_of(&upstream)).await;
    broker.backend.set_github_app(Some(github_app_key().0));
    let key = broker.add_agent("bot").await;
    (broker, key, upstream)
}

/// GitHub's answer when the installation reaches `name`.
fn resolved(broker: &TestBroker, name: &str) -> Scripted {
    token_answer(
        RESOLVE_TOKEN,
        broker.clock.now() + 3600,
        &[(1001, name)],
        &[("metadata", "read")],
        "selected",
    )
}

/// How many token requests the fake GitHub has received.
fn github_calls(upstream: &HttpsUpstream) -> usize {
    upstream
        .received()
        .iter()
        .filter(|r| r.path_and_query.ends_with("/access_tokens"))
        .count()
}

async fn ask(broker: &TestBroker, key: &str) -> RepositoryOffer {
    let resp = broker.api_get(key, PATH).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    serde_json::from_str(&resp.body).unwrap()
}

fn signing(repository: &str) -> ReleaseSigningKey {
    ReleaseSigningKey::for_tests(
        repository,
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap(),
        None,
        false,
    )
}

fn release_app() -> ReleaseAppKey {
    ReleaseAppKey::new(
        "987654".to_owned(),
        std::str::from_utf8(RSA2048_PKCS8).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn needs_an_agent() {
    let (broker, _, upstream) = on_fake().await;
    let resp = broker.api_get("wdn_nope", PATH).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED);
    assert_eq!(github_calls(&upstream), 0);
}

#[tokio::test]
async fn invalid_name_is_refused() {
    let (broker, key, upstream) = on_fake().await;
    for path in [
        "/v1/offers/repository/Example..Org/x",
        "/v1/offers/repository/example-org/..",
        "/v1/offers/repository/example-org/a%2Fb",
    ] {
        let resp = broker.api_get(&key, path).await;
        assert_eq!(
            resp.status,
            StatusCode::BAD_REQUEST,
            "{path}: {}",
            resp.body
        );
        assert!(resp.json()["error"].is_string(), "{}", resp.body);
    }
    assert_eq!(github_calls(&upstream), 0);
    assert_eq!(broker.backend.github_app_reads(), 0);
}

#[tokio::test]
async fn covered_repository() {
    let (broker, key, upstream) = on_fake().await;
    upstream.script_github_token(resolved(&broker, REPO));

    let got = ask(&broker, &key).await;

    assert_eq!(
        got,
        RepositoryOffer {
            repository: RepoName::try_from(REPO.to_owned()).unwrap(),
            github_token: GithubTokenStatus::Covered,
            commit_signing: true,
            release: ReleaseStatus::NoKey,
        }
    );
    // The broker asked for a metadata-only token for the bare name.
    let calls = upstream.received();
    let body: serde_json::Value = serde_json::from_slice(&calls[0].body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"permissions": {"metadata": "read"}, "repositories": ["example-repo"]})
    );
}

#[tokio::test]
async fn not_covered_repository() {
    let (broker, key, upstream) = on_fake().await;
    // GitHub's answer for a repository outside the installation.
    upstream.script_github_token(Scripted::with_body(422, r#"{"message":"There is at least one repository that does not exist or is not accessible to the parent installation."}"#));
    assert_eq!(
        ask(&broker, &key).await.github_token,
        GithubTokenStatus::NotCovered
    );

    // A name the installation reaches only under another owner is not covered
    // either: GitHub takes bare names within the installation's account.
    let (broker, key, upstream) = on_fake().await;
    upstream.script_github_token(resolved(&broker, "other-org/example-repo"));
    assert_eq!(
        ask(&broker, &key).await.github_token,
        GithubTokenStatus::NotCovered
    );
}

#[tokio::test]
async fn github_unreachable_is_unavailable_and_not_cached() {
    let (broker, key, upstream) = on_fake().await;
    // A server error (nothing scripted answers 500), a rate limit, the App's own
    // login refused, an installation GitHub does not know: none says the
    // repository is outside the installation.
    let refusals = [
        None,
        Some(Scripted::with_body(
            403,
            r#"{"message":"API rate limit exceeded"}"#,
        )),
        Some(Scripted::with_body(401, r#"{"message":"Bad credentials"}"#)),
        Some(Scripted::with_body(404, r#"{"message":"Not Found"}"#)),
    ];
    for (i, refusal) in refusals.into_iter().enumerate() {
        if let Some(refusal) = refusal {
            upstream.script_github_token(refusal);
        }
        let got = ask(&broker, &key).await;
        assert_eq!(got.github_token, GithubTokenStatus::Unavailable, "{i}");
        // Not kept: each question goes to GitHub again.
        assert_eq!(github_calls(&upstream), i + 1);
    }
    upstream.script_github_token(resolved(&broker, REPO));
    assert_eq!(
        ask(&broker, &key).await.github_token,
        GithubTokenStatus::Covered
    );

    // GitHub not answering at all.
    let gone = HttpsUpstream::start().await;
    let api = api_of(&gone);
    drop(gone);
    let broker = TestBroker::with_github_api(api).await;
    broker.backend.set_github_app(Some(github_app_key().0));
    let key = broker.add_agent("bot").await;
    assert_eq!(
        ask(&broker, &key).await.github_token,
        GithubTokenStatus::Unavailable
    );
}

#[tokio::test]
async fn no_app_is_not_configured() {
    let (broker, key, upstream) = on_fake().await;
    broker.backend.set_github_app(None);
    assert_eq!(
        ask(&broker, &key).await.github_token,
        GithubTokenStatus::NotConfigured
    );
    assert_eq!(github_calls(&upstream), 0);
}

#[tokio::test]
async fn unreadable_app_is_unavailable() {
    let (broker, key, upstream) = on_fake().await;
    broker
        .backend
        .set_github_app_outage(Some("connect down at 192.0.2.99"));
    let resp = broker.api_get(&key, PATH).await;
    assert!(!resp.body.contains("192.0.2.99"), "{}", resp.body);
    let got: RepositoryOffer = serde_json::from_str(&resp.body).unwrap();
    assert_eq!(got.github_token, GithubTokenStatus::Unavailable);
    assert_eq!(github_calls(&upstream), 0);
}

#[tokio::test]
async fn release_ready() {
    let (broker, key, upstream) = on_fake().await;
    broker.backend.add_release_key(signing(REPO));
    broker.backend.set_release_app(Some(release_app()));
    upstream.script_github_token(resolved(&broker, REPO));
    assert_eq!(ask(&broker, &key).await.release, ReleaseStatus::Ready);
}

#[tokio::test]
async fn release_no_key() {
    let (broker, key, upstream) = on_fake().await;
    // A key for another repository is no key for this one.
    broker
        .backend
        .add_release_key(signing("example-org/other-repo"));
    broker.backend.set_release_app(Some(release_app()));
    upstream.script_github_token(resolved(&broker, REPO));
    assert_eq!(ask(&broker, &key).await.release, ReleaseStatus::NoKey);
}

#[tokio::test]
async fn release_no_release_app() {
    let (broker, key, upstream) = on_fake().await;
    broker.backend.add_release_key(signing(REPO));
    upstream.script_github_token(resolved(&broker, REPO));
    assert_eq!(
        ask(&broker, &key).await.release,
        ReleaseStatus::NoReleaseApp
    );
}

#[tokio::test]
async fn release_unreadable_is_unavailable_and_not_cached() {
    let (broker, key, upstream) = on_fake().await;
    broker.backend.add_release_key(signing(REPO));
    broker
        .backend
        .set_release_app_outage(Some("connect down at 192.0.2.99"));
    upstream.script_github_token(resolved(&broker, REPO));
    assert_eq!(ask(&broker, &key).await.release, ReleaseStatus::Unavailable);

    broker.backend.set_release_app_outage(None);
    broker.backend.set_release_app(Some(release_app()));
    upstream.script_github_token(resolved(&broker, REPO));
    assert_eq!(ask(&broker, &key).await.release, ReleaseStatus::Ready);
    assert_eq!(github_calls(&upstream), 2);
}

#[tokio::test]
async fn unreadable_commit_signing_is_backend_unavailable() {
    let (broker, key, upstream) = on_fake().await;
    broker
        .backend
        .set_commit_signing_outage(Some("connect down at 192.0.2.99"));
    upstream.script_github_token(resolved(&broker, REPO));
    let resp = broker.api_get(&key, PATH).await;
    assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.json()["error"], crate::requests::BACKEND_UNAVAILABLE);
    assert!(!resp.body.contains("192.0.2.99"), "{}", resp.body);
}

#[tokio::test]
async fn second_call_within_ttl_makes_no_github_call() {
    let (broker, key, upstream) = on_fake().await;
    upstream.script_github_token(resolved(&broker, REPO));
    let first = ask(&broker, &key).await;
    assert_eq!(github_calls(&upstream), 1);

    broker.clock.advance(299);
    assert_eq!(ask(&broker, &key).await, first);
    assert_eq!(github_calls(&upstream), 1);

    broker.clock.advance(1);
    upstream.script_github_token(Scripted::with_body(422, "{}"));
    assert_eq!(
        ask(&broker, &key).await.github_token,
        GithubTokenStatus::NotCovered
    );
    assert_eq!(github_calls(&upstream), 2);
}

#[tokio::test]
async fn no_token_in_response() {
    let (broker, key, upstream) = on_fake().await;
    upstream.script_github_token(resolved(&broker, REPO));
    let resp = broker.api_get(&key, PATH).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    assert!(!resp.body.contains(RESOLVE_TOKEN), "{}", resp.body);
    assert!(!resp.body.contains("ghs_"), "{}", resp.body);
    assert!(!resp.body.contains("1001"), "{}", resp.body);
}

#[tokio::test]
async fn asking_writes_no_audit_entry() {
    let (broker, key, upstream) = on_fake().await;
    let before = broker.audit_types();
    upstream.script_github_token(resolved(&broker, REPO));
    ask(&broker, &key).await;
    assert_eq!(broker.audit_types(), before);
}
