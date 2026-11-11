use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use warden_broker_proto::github_token::PERMISSIONS;

use super::{GithubApi, InstallationToken, MintError, jwt, mint};
use crate::testkit::github_app::{APP_ID, INSTALLATION_ID, github_app_key};
use crate::testkit::upstream::{Gate, HttpsUpstream, Scripted};

/// 2026-11-08T12:00:00Z.
const NOW: i64 = 1_794_139_200;
const EXPIRES_AT: &str = "2026-11-08T13:00:00Z";
const EXPIRES_AT_EPOCH: i64 = NOW + 3600;

async fn upstream() -> (HttpsUpstream, GithubApi) {
    let upstream = HttpsUpstream::start().await;
    let api = GithubApi::pinned(
        upstream.origin().parse().unwrap(),
        upstream.origin().parse().unwrap(),
        upstream.ca_pem().as_bytes().to_vec(),
    );
    (upstream, api)
}

fn created(token: &str, expires_at: &str) -> Scripted {
    Scripted::with_body(
        201,
        json!({"token": token, "expires_at": expires_at}).to_string(),
    )
}

async fn mint_with(scripted: Scripted) -> Result<InstallationToken, MintError> {
    let (upstream, api) = upstream().await;
    upstream.script_github_token(scripted);
    mint(&api, &github_app_key().0, NOW).await
}

/// The error of a mint that must fail.
async fn refused(scripted: Scripted) -> MintError {
    mint_with(scripted).await.unwrap_err()
}

fn decode(part: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(part).unwrap()
}

fn verify(token: &str, public: &[u8]) {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public)
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &decode(parts[2]),
        )
        .unwrap();
}

#[test]
fn jwt_verifies_with_public_key_and_has_claims() {
    let (key, public) = github_app_key();
    let token = jwt(&key, NOW).unwrap();
    verify(&token, &public);
    assert!(!token.contains(['=', '+', '/']));
    let parts: Vec<&str> = token.split('.').collect();
    let header: Value = serde_json::from_slice(&decode(parts[0])).unwrap();
    assert_eq!(header, json!({"alg": "RS256", "typ": "JWT"}));
    let claims: Value = serde_json::from_slice(&decode(parts[1])).unwrap();
    assert_eq!(claims["iat"], NOW - 60);
    assert_eq!(claims["exp"], NOW + 540);
    assert_eq!(claims["iss"], APP_ID);
}

#[tokio::test]
async fn mint_sends_fixed_permissions_and_headers() {
    let (upstream, api) = upstream().await;
    upstream.script_github_token(created("ghs_test", EXPIRES_AT));
    let (key, public) = github_app_key();
    mint(&api, &key, NOW).await.unwrap();
    let received = upstream.received();
    assert_eq!(received.len(), 1);
    let request = &received[0];
    assert_eq!(request.method, "POST");
    assert_eq!(
        request.path_and_query,
        format!("/app/installations/{INSTALLATION_ID}/access_tokens")
    );
    let header = |name: &str| request.headers.get(name).unwrap().to_str().unwrap();
    verify(
        header("authorization").strip_prefix("Bearer ").unwrap(),
        &public,
    );
    assert_eq!(header("accept"), "application/vnd.github+json");
    assert_eq!(header("x-github-api-version"), "2022-11-28");
    assert!(header("user-agent").starts_with("warden-broker/"));
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    let expected: serde_json::Map<String, Value> = PERMISSIONS
        .iter()
        .map(|(name, level)| ((*name).to_owned(), json!(level)))
        .collect();
    assert_eq!(body, json!({ "permissions": expected }));
}

#[tokio::test]
async fn mint_parses_token_and_expiry() {
    let minted = mint_with(created("ghs_test", EXPIRES_AT)).await.unwrap();
    assert_eq!(minted.token.expose_secret(), "ghs_test");
    assert_eq!(minted.expires_at, EXPIRES_AT_EPOCH);
    assert!(!format!("{minted:?}").contains("ghs_test"));
}

#[tokio::test]
async fn mint_refuses_non_201_without_echo() {
    let err = refused(Scripted::with_body(401, "SECRET-ECHO")).await;
    assert_eq!(err, MintError::Refused(401));
    assert!(!err.to_string().contains("SECRET-ECHO"));
    assert!(!format!("{err:?}").contains("SECRET-ECHO"));
}

#[tokio::test]
async fn mint_refuses_redirect() {
    let scripted =
        Scripted::with_body(302, "moved").header("location", "https://elsewhere.example/");
    assert_eq!(refused(scripted).await, MintError::Refused(302));
}

#[tokio::test]
async fn mint_refuses_gzip() {
    let scripted = created("ghs_test", EXPIRES_AT).header("content-encoding", "gzip");
    assert_eq!(refused(scripted).await, MintError::Compressed);
}

#[tokio::test]
async fn mint_refuses_oversize() {
    let scripted = Scripted::with_body(201, vec![b' '; 64 * 1024 + 1]);
    assert_eq!(refused(scripted).await, MintError::TooLarge);
}

#[tokio::test]
async fn mint_refuses_oversize_without_a_length() {
    // No Content-Length: the cap is applied while the chunks come in.
    let scripted = Scripted::with_body(201, vec![b' '; 64 * 1024 + 1]).chunked();
    assert_eq!(refused(scripted).await, MintError::TooLarge);
    // Exactly the cap, in chunks, is read whole (and then parsed).
    let mut body = json!({"token": "ghs_test", "expires_at": EXPIRES_AT})
        .to_string()
        .into_bytes();
    body.resize(64 * 1024, b' ');
    let minted = mint_with(Scripted::with_body(201, body).chunked())
        .await
        .unwrap();
    assert_eq!(minted.token.expose_secret(), "ghs_test");
}

#[tokio::test]
async fn mint_refuses_malformed_answers() {
    for body in [
        "not json".to_owned(),
        json!({"expires_at": EXPIRES_AT}).to_string(),
        json!({"token": "", "expires_at": EXPIRES_AT}).to_string(),
        json!({"token": "ghs_test"}).to_string(),
    ] {
        assert_eq!(
            refused(Scripted::with_body(201, body.clone())).await,
            MintError::Malformed,
            "{body}"
        );
    }
}

#[tokio::test]
async fn mint_refuses_bad_expiry() {
    assert_eq!(
        refused(created("ghs_test", "tomorrow")).await,
        MintError::Malformed
    );
}

#[tokio::test]
async fn mint_refuses_expired_or_far_future() {
    for expires_at in [
        "2026-11-08T12:00:00Z",
        "2026-11-08T11:00:00Z",
        "2026-11-08T14:00:01Z",
    ] {
        assert_eq!(
            refused(created("ghs_test", expires_at)).await,
            MintError::Malformed,
            "{expires_at}"
        );
    }
    assert!(
        mint_with(created("ghs_test", "2026-11-08T14:00:00Z"))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn mint_fails_closed_when_upstream_is_untrusted() {
    let upstream = HttpsUpstream::start().await;
    let other = HttpsUpstream::start().await;
    let api = GithubApi::pinned(
        upstream.origin().parse().unwrap(),
        upstream.origin().parse().unwrap(),
        other.ca_pem().as_bytes().to_vec(),
    );
    let err = mint(&api, &github_app_key().0, NOW).await.unwrap_err();
    assert_eq!(err, MintError::Unreachable);
    assert!(upstream.received().is_empty());
}

#[tokio::test]
async fn mint_waits_for_a_held_answer() {
    let (upstream, api) = upstream().await;
    let gate = Gate::new();
    upstream.script_github_token(created("ghs_test", EXPIRES_AT).held_by(&gate));
    let call = tokio::spawn(async move { mint(&api, &github_app_key().0, NOW).await });
    upstream.wait_for_github_token_calls(1).await;
    assert!(!call.is_finished());
    gate.open();
    assert!(call.await.unwrap().is_ok());
}

#[test]
fn mint_error_messages_are_fixed() {
    for (err, text) in [
        (MintError::Key, "the GitHub App key could not sign"),
        (MintError::Unreachable, "GitHub could not be reached"),
        (MintError::Refused(401), "GitHub refused the request"),
        (MintError::Malformed, "GitHub's answer was not understood"),
        (MintError::TooLarge, "GitHub's answer was too large"),
        (MintError::Compressed, "GitHub's answer was compressed"),
    ] {
        assert_eq!(err.to_string(), text);
    }
}
