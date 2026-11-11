use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::StatusCode;
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use warden_broker_proto::release::RepoName;

use super::{GithubError, ReleaseClient, installation_for, release_token};
use crate::github_app::GithubApi;
use crate::policy::ReleaseAppKey;
use crate::testkit::github_app::{RSA2048_PKCS8, RSA2048_PUBLIC_DER};
use crate::testkit::github_release::{INSTALLATION_ID, TOKEN, TOKEN_EXPIRES_AT};
use crate::testkit::upstream::{HttpsUpstream, Scripted};

/// 2026-11-08T12:00:00Z.
const NOW: i64 = 1_794_139_200;
const APP_ID: &str = "987654";
/// Text a failing GitHub might say; it must never show up in an error.
const MARKER: &str = "marker-github-said-this";

fn repo() -> RepoName {
    "example-owner/example-repo".to_owned().try_into().unwrap()
}

fn app() -> ReleaseAppKey {
    ReleaseAppKey::new(
        APP_ID.to_owned(),
        std::str::from_utf8(RSA2048_PKCS8).unwrap(),
    )
    .unwrap()
}

/// A fake GitHub with the release App installed on [`repo`], and a client for it.
async fn github() -> (HttpsUpstream, GithubApi) {
    let upstream = HttpsUpstream::start().await;
    upstream.github_release().install(&repo());
    let origin: url::Url = upstream.origin().parse().unwrap();
    let api = GithubApi::pinned(
        origin.clone(),
        origin,
        upstream.ca_pem().as_bytes().to_vec(),
    );
    (upstream, api)
}

fn decode(part: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(part).unwrap()
}

/// A token answer with these permissions.
fn token_answer(permissions: &Value, expires_at: &str) -> Scripted {
    Scripted::with_body(
        201,
        json!({"token": TOKEN, "expires_at": expires_at, "permissions": permissions}).to_string(),
    )
}

#[tokio::test]
async fn installation_lookup_uses_app_jwt() {
    let (upstream, api) = github().await;
    let id = installation_for(&api, &app(), &repo(), NOW).await.unwrap();
    assert_eq!(id, INSTALLATION_ID);

    let calls = upstream.github_release().record();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].method, "GET");
    assert_eq!(
        calls[0].path_and_query,
        "/repos/example-owner/example-repo/installation"
    );
    assert_eq!(calls[0].headers["accept-encoding"], "identity");
    let authorization = calls[0].headers["authorization"].to_str().unwrap();
    let jwt = authorization.strip_prefix("Bearer ").unwrap();
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, RSA2048_PUBLIC_DER)
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &decode(parts[2]),
        )
        .unwrap();
    let claims: Value = serde_json::from_slice(&decode(parts[1])).unwrap();
    assert_eq!(claims["iss"], APP_ID);
    assert_eq!(claims["iat"], NOW - 60);
    assert_eq!(claims["exp"], NOW + 540);
}

#[tokio::test]
async fn installation_lookup_of_an_uninstalled_repository_is_not_found() {
    let (_upstream, api) = github().await;
    let other: RepoName = "example-owner/other-repo".to_owned().try_into().unwrap();
    let err = installation_for(&api, &app(), &other, NOW)
        .await
        .unwrap_err();
    assert_eq!(err, GithubError::NotFound);
}

#[tokio::test]
async fn release_token_is_limited_to_the_repository() {
    let (upstream, api) = github().await;
    let token = release_token(&api, &app(), INSTALLATION_ID, &repo(), NOW)
        .await
        .unwrap();
    assert_eq!(token.token.expose_secret(), TOKEN);
    assert_eq!(
        token.expires_at,
        TOKEN_EXPIRES_AT
            .parse::<jiff::Timestamp>()
            .unwrap()
            .as_second()
    );

    let calls = upstream.github_release().record();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].method, "POST");
    assert_eq!(
        calls[0].path_and_query,
        format!("/app/installations/{INSTALLATION_ID}/access_tokens")
    );
    assert_eq!(
        String::from_utf8(calls[0].body.clone()).unwrap(),
        r#"{"repositories":["example-repo"],"permissions":{"contents":"write","metadata":"read"}}"#
    );
    assert_eq!(calls[0].headers["content-type"], "application/json");
    assert_eq!(calls[0].headers["accept-encoding"], "identity");
}

#[tokio::test]
async fn release_token_refuses_wider_permissions() {
    let (upstream, api) = github().await;
    for permissions in [
        json!({"contents": "write", "metadata": "read", "administration": "write"}),
        json!({"contents": "write"}),
        json!({"contents": "write", "metadata": "write"}),
        json!({}),
    ] {
        upstream
            .github_release()
            .answer_everything_with(token_answer(&permissions, TOKEN_EXPIRES_AT));
        let err = release_token(&api, &app(), INSTALLATION_ID, &repo(), NOW)
            .await
            .unwrap_err();
        assert_eq!(err, GithubError::Unreadable, "{permissions}");
    }
}

#[tokio::test]
async fn release_token_refuses_an_expiry_that_is_not_credible() {
    let (upstream, api) = github().await;
    let exact = json!({"contents": "write", "metadata": "read"});
    for expires_at in ["2026-11-08T12:00:00Z", "2026-11-08T14:00:01Z", "soon"] {
        upstream
            .github_release()
            .answer_everything_with(token_answer(&exact, expires_at));
        let err = release_token(&api, &app(), INSTALLATION_ID, &repo(), NOW)
            .await
            .unwrap_err();
        assert_eq!(err, GithubError::Unreadable, "{expires_at}");
    }
    upstream
        .github_release()
        .answer_everything_with(token_answer(&exact, "2026-11-08T14:00:00Z"));
    assert!(
        release_token(&api, &app(), INSTALLATION_ID, &repo(), NOW)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn refuses_encoded_answers() {
    let (upstream, api) = github().await;
    upstream.github_release().answer_everything_with(
        Scripted::with_body(200, json!({"id": 1}).to_string()).header("content-encoding", "gzip"),
    );
    let err = installation_for(&api, &app(), &repo(), NOW)
        .await
        .unwrap_err();
    assert_eq!(err, GithubError::Unreadable);
}

#[tokio::test]
async fn refuses_oversized_answers() {
    let (upstream, api) = github().await;
    let padding = "a".repeat(64 * 1024);
    let body = json!({"id": 1, "padding": padding}).to_string();
    for scripted in [
        Scripted::with_body(200, body.clone()),
        Scripted::with_body(200, body).chunked(),
    ] {
        upstream.github_release().answer_everything_with(scripted);
        let err = installation_for(&api, &app(), &repo(), NOW)
            .await
            .unwrap_err();
        assert_eq!(err, GithubError::Unreadable);
    }
}

#[tokio::test]
async fn errors_carry_no_github_text() {
    let (upstream, api) = github().await;
    upstream
        .github_release()
        .answer_everything_with(Scripted::with_body(
            500,
            format!("{{\"message\":\"{MARKER}\"}}"),
        ));
    let err = installation_for(&api, &app(), &repo(), NOW)
        .await
        .unwrap_err();
    assert_eq!(err, GithubError::Refused(StatusCode::INTERNAL_SERVER_ERROR));
    assert!(!err.to_string().contains(MARKER));
    assert!(!format!("{err:?}").contains(MARKER));
}

#[tokio::test]
async fn an_untrusted_github_is_unreachable() {
    let upstream = HttpsUpstream::start().await;
    let other = HttpsUpstream::start().await;
    upstream.github_release().install(&repo());
    let origin: url::Url = upstream.origin().parse().unwrap();
    let api = GithubApi::pinned(origin.clone(), origin, other.ca_pem().as_bytes().to_vec());
    let err = installation_for(&api, &app(), &repo(), NOW)
        .await
        .unwrap_err();
    assert_eq!(err, GithubError::Unreachable);
    assert!(upstream.github_release().record().is_empty());
}

#[tokio::test]
async fn connect_finds_the_installation_then_mints_for_the_repository() {
    let (upstream, api) = github().await;
    let app = app();
    let client = ReleaseClient::connect(&api, &app, &repo(), NOW)
        .await
        .unwrap();
    assert!(client.repo().matches(&repo()));
    assert_eq!(client.expires_at(), NOW + 3600);
    let calls: Vec<String> = upstream
        .github_release()
        .record()
        .into_iter()
        .map(|call| format!("{} {}", call.method, call.path_and_query))
        .collect();
    assert_eq!(
        calls,
        [
            "GET /repos/example-owner/example-repo/installation".to_owned(),
            format!("POST /app/installations/{INSTALLATION_ID}/access_tokens"),
        ]
    );
    assert!(!format!("{client:?}").contains(TOKEN));
}

#[tokio::test]
async fn connect_stops_when_the_app_is_not_installed() {
    let (upstream, api) = github().await;
    let other: RepoName = "example-owner/other-repo".to_owned().try_into().unwrap();
    let err = ReleaseClient::connect(&api, &app(), &other, NOW)
        .await
        .unwrap_err();
    assert_eq!(err, GithubError::NotFound);
    assert_eq!(upstream.github_release().record().len(), 1);
}

#[test]
fn error_messages_are_fixed() {
    for (err, text) in [
        (GithubError::Unreachable, "GitHub could not be reached"),
        (
            GithubError::Refused(StatusCode::FORBIDDEN),
            "GitHub refused the request",
        ),
        (
            GithubError::NotFound,
            "GitHub does not have what was asked for",
        ),
        (
            GithubError::Unreadable,
            "GitHub's answer was not understood",
        ),
    ] {
        assert_eq!(err.to_string(), text);
    }
}
