use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::Value;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use warden_broker_proto::Window;
use warden_broker_proto::offers::{OfferPart, Offers, SshModeName};
use zeroize::Zeroizing;

use crate::config::LocalSettings;
use crate::policy::local::LocalBackend;
use crate::policy::{ApiSecretPolicy, Listing, ReleaseAppKey, ReleaseSigningKey, SshTarget};
use crate::policy::{RelayCredential, SshMode};
use crate::testkit::github_app::RSA2048_PKCS8;
use crate::testkit::{FakeBackend, TestBroker, github_app_key};

const BACKEND_DOWN: &str = "connect down at 192.0.2.99";

async fn broker() -> (TestBroker, String) {
    let broker = TestBroker::new().await;
    let key = broker.add_agent("bot").await;
    (broker, key)
}

async fn offers(broker: &TestBroker, key: &str) -> Offers {
    let resp = broker.api_get(key, "/v1/offers").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    serde_json::from_str(&resp.body).unwrap()
}

fn target(name: &str, listing: Listing) -> SshTarget {
    let mut t = FakeBackend::pi_target();
    t.name = name.to_owned().try_into().unwrap();
    t.listing = listing;
    t
}

fn secret(name: &str, listing: Listing) -> ApiSecretPolicy {
    let mut s = FakeBackend::example_api_secret();
    s.name = name.to_owned().try_into().unwrap();
    s.listing = listing;
    s
}

#[tokio::test]
async fn offers_need_an_agent() {
    let (broker, _) = broker().await;
    let grants = broker.api_get("wdn_nope", "/v1/grants").await;
    let offers = broker.api_get("wdn_nope", "/v1/offers").await;
    assert_eq!(grants.status, StatusCode::UNAUTHORIZED);
    assert_eq!(offers.status, grants.status);
    assert_eq!(offers.body, grants.body);
}

#[tokio::test]
async fn full_name_hidden_invalid() {
    let (broker, key) = broker().await;
    // `pi` is the fake backend's own target, listed in full.
    for (name, listing) in [
        ("name", Listing::Name),
        ("hidden", Listing::Hidden),
        ("invalid", Listing::Invalid),
    ] {
        broker.backend.set_target(target(name, listing));
    }
    for (name, listing) in [
        ("full", Listing::Full),
        ("name", Listing::Name),
        ("hidden", Listing::Hidden),
        ("invalid", Listing::Invalid),
    ] {
        broker
            .backend
            .set_api_secret(secret(name, listing), "value");
    }

    let got = offers(&broker, &key).await;

    let targets: Vec<_> = got.ssh_targets.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(targets.len(), 2);
    for expected in ["pi", "name"] {
        assert!(targets.contains(&expected), "{targets:?}");
    }
    let by_name = |n: &str| {
        got.ssh_targets
            .iter()
            .find(|t| t.name.as_str() == n)
            .unwrap()
    };
    let full = by_name("pi");
    let destination = full.destination.as_ref().unwrap();
    assert_eq!(destination.host, "192.0.2.10");
    assert_eq!(destination.port, 22);
    assert_eq!(full.mode, SshModeName::Cert);
    assert_eq!(full.max_window, Window::H1);
    assert_eq!(full.users.len(), 2);
    assert!(by_name("name").destination.is_none());

    assert_eq!(got.api_secrets.len(), 2);
    let secret_named = |n: &str| {
        got.api_secrets
            .iter()
            .find(|s| s.name.as_str() == n)
            .unwrap()
    };
    let full = secret_named("full");
    assert_eq!(full.origin.as_deref(), Some("https://api.example.com"));
    assert_eq!(full.methods, ["GET"]);
    assert_eq!(full.path_prefix, "/");
    assert_eq!(full.max_window, Window::H1);
    assert!(secret_named("name").origin.is_none());
    assert_eq!(got.unavailable.len(), 0);
}

#[tokio::test]
async fn relay_target_shows_destination_when_full() {
    let (broker, key) = broker().await;
    broker.backend.set_relay_target(
        FakeBackend::relay_target(),
        RelayCredential::Password(Zeroizing::new("onward-password".to_owned())),
    );
    let got = offers(&broker, &key).await;
    let nas = got
        .ssh_targets
        .iter()
        .find(|t| t.name.as_str() == "nas")
        .unwrap();
    assert_eq!(nas.mode, SshModeName::Relay);
    let destination = nas.destination.as_ref().unwrap();
    assert_eq!(
        (destination.host.as_str(), destination.port),
        ("192.0.2.20", 22)
    );
}

#[tokio::test]
async fn github_and_signing_flags() {
    let (broker, key) = broker().await;
    let got = offers(&broker, &key).await;
    assert!(!got.github.configured);
    assert!(got.github.max_window.is_none());
    assert!(got.commit_signing.available);
    assert!(!got.releases.available);

    broker.backend.set_github_app(Some(github_app_key().0));
    broker.backend.set_commit_signing_key(None);
    let got = offers(&broker, &key).await;
    assert!(got.github.configured);
    assert_eq!(got.github.max_window, Some(Window::GITHUB_TOKEN_DEFAULT));
    assert!(!got.commit_signing.available);

    // A release needs a signing key and a release App.
    let signing = || {
        ReleaseSigningKey::for_tests(
            "example-org/example-repo",
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap(),
            None,
            false,
        )
    };
    let release_app = || {
        ReleaseAppKey::new(
            "987654".to_owned(),
            std::str::from_utf8(RSA2048_PKCS8).unwrap(),
        )
        .unwrap()
    };
    broker.backend.set_release_app(Some(release_app()));
    assert!(!offers(&broker, &key).await.releases.available);
    broker.backend.set_release_app(None);
    broker.backend.add_release_key(signing());
    assert!(!offers(&broker, &key).await.releases.available);
    broker.backend.set_release_app(Some(release_app()));
    assert!(offers(&broker, &key).await.releases.available);
    broker.backend.replace_release_keys(signing());
    broker.backend.set_release_app(None);
    assert!(!offers(&broker, &key).await.releases.available);
}

#[tokio::test]
async fn github_window_follows_the_configured_maximum() {
    let broker = TestBroker::with_github_token_max(Window::H1).await;
    let key = broker.add_agent("bot").await;
    broker.backend.set_github_app(Some(github_app_key().0));
    assert_eq!(
        offers(&broker, &key).await.github.max_window,
        Some(Window::H1)
    );
}

#[tokio::test]
async fn partial_failure_names_the_part() {
    let (broker, key) = broker().await;
    broker
        .backend
        .set_api_secret(FakeBackend::example_api_secret(), "value");
    broker.backend.set_api_outage(Some(BACKEND_DOWN));

    let got = offers(&broker, &key).await;

    assert_eq!(got.unavailable, [OfferPart::ApiSecrets]);
    assert_eq!(got.api_secrets.len(), 0);
    assert_eq!(got.ssh_targets.len(), 1);
    assert!(got.commit_signing.available);
}

#[tokio::test]
async fn a_failed_release_read_makes_releases_unavailable() {
    let (broker, key) = broker().await;
    broker.backend.set_release_app_outage(Some(BACKEND_DOWN));
    let got = offers(&broker, &key).await;
    assert_eq!(got.unavailable, [OfferPart::Releases]);
    assert!(!got.releases.available);
}

#[tokio::test]
async fn all_unavailable_is_backend_unavailable() {
    let (broker, key) = broker().await;
    broker.backend.set_target_outage(Some(BACKEND_DOWN));
    broker.backend.set_api_outage(Some(BACKEND_DOWN));
    broker.backend.set_github_app_outage(Some(BACKEND_DOWN));
    broker.backend.set_commit_signing_outage(Some(BACKEND_DOWN));
    broker
        .backend
        .set_release_signing_outage(Some(BACKEND_DOWN));

    let resp = broker.api_get(&key, "/v1/offers").await;

    assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.json()["error"], crate::requests::BACKEND_UNAVAILABLE);
    assert!(!resp.body.contains("192.0.2.99"), "{}", resp.body);
}

#[tokio::test]
async fn the_stores_parts_failing_together_is_backend_unavailable() {
    let (broker, key) = broker().await;
    broker.backend.set_target_outage(Some(BACKEND_DOWN));
    broker.backend.set_api_outage(Some(BACKEND_DOWN));
    broker.backend.set_commit_signing_outage(Some(BACKEND_DOWN));

    let resp = broker.api_get(&key, "/v1/offers").await;

    assert_eq!(resp.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(resp.json()["error"], crate::requests::BACKEND_UNAVAILABLE);
}

#[tokio::test]
async fn two_of_the_stores_parts_failing_names_both() {
    let (broker, key) = broker().await;
    broker.backend.set_target_outage(Some(BACKEND_DOWN));
    broker.backend.set_commit_signing_outage(Some(BACKEND_DOWN));

    let got = offers(&broker, &key).await;

    assert_eq!(
        got.unavailable,
        [OfferPart::SshTargets, OfferPart::CommitSigning]
    );
}

#[tokio::test]
async fn an_unreadable_local_policy_is_backend_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let settings = LocalSettings {
        policy_file: dir.path().join("missing-policy.toml"),
        secrets_dir: dir.path().join("missing-secrets"),
    };
    let broker =
        TestBroker::with_secret_backend(Arc::new(LocalBackend::unaudited(&settings))).await;
    let key = broker.add_agent("bot").await;

    let resp = broker.api_get(&key, "/v1/offers").await;

    assert_eq!(
        resp.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        resp.body
    );
    assert_eq!(resp.json()["error"], crate::requests::BACKEND_UNAVAILABLE);
}

#[tokio::test]
async fn no_secret_in_response() {
    let (broker, key) = broker().await;
    broker.backend.set_relay_target(
        FakeBackend::relay_target(),
        RelayCredential::Password(Zeroizing::new("onward-password-7f3a".to_owned())),
    );
    broker
        .backend
        .set_api_secret(FakeBackend::example_api_secret(), "api-secret-value-9c1d");
    broker.backend.set_github_app(Some(github_app_key().0));

    let resp = broker.api_get(&key, "/v1/offers").await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);

    let mut forbidden = vec![
        "onward-password-7f3a".to_owned(),
        "api-secret-value-9c1d".to_owned(),
        "PRIVATE".to_owned(),
    ];
    for name in ["pi", "nas"] {
        let line = broker.backend.target(name).host_keys[0]
            .to_openssh()
            .unwrap();
        forbidden.push(line.split_whitespace().nth(1).unwrap().to_owned());
    }
    for needle in &forbidden {
        assert!(
            !resp.body.contains(needle),
            "{needle} leaked: {}",
            resp.body
        );
    }
    let parsed: Value = resp.json();
    for (list, allowed) in [
        (
            "ssh_targets",
            &["name", "users", "max_window", "mode", "destination"][..],
        ),
        (
            "api_secrets",
            &["name", "origin", "methods", "path_prefix", "max_window"][..],
        ),
    ] {
        let entries = parsed[list].as_array().unwrap();
        assert!(!entries.is_empty(), "{list}");
        for entry in entries {
            for key in entry.as_object().unwrap().keys() {
                assert!(allowed.contains(&key.as_str()), "{list}: {key}");
            }
        }
    }
    assert_eq!(broker.backend.target("nas").mode, SshMode::Relay);
}

#[tokio::test]
async fn listing_writes_no_audit_entry() {
    let (broker, key) = broker().await;
    let before = broker.audit_types();
    offers(&broker, &key).await;
    offers(&broker, &key).await;
    assert_eq!(broker.audit_types(), before);
}

#[tokio::test]
async fn creates_no_request_and_notifies_no_one() {
    let (broker, key) = broker().await;
    offers(&broker, &key).await;
    let pending = broker.api_get(&key, "/v1/requests").await;
    assert_eq!(
        pending.json().as_array().unwrap().len(),
        0,
        "{}",
        pending.body
    );
    assert_eq!(broker.capture.rung().len(), 0);
}
