use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};
use warden_broker_proto::github_token::PERMISSIONS;
use warden_broker_proto::release::RepoName;

use super::{
    GithubApi, InstallationToken, MintError, ResolvedRepository, current_names, jwt, mint, resolve,
};
use crate::testkit::github_app::{APP_ID, INSTALLATION_ID, github_app_key, token_answer};
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

const REPO_ID: u64 = 1001;
const REPO: &str = "example-owner/example-repo";

fn asked_permissions() -> Vec<(&'static str, &'static str)> {
    PERMISSIONS.to_vec()
}

/// A good answer for [`REPO_ID`], expiring at `expires_at` (Unix seconds).
fn created_at(token: &str, expires_at: i64) -> Scripted {
    token_answer(
        token,
        expires_at,
        &[(REPO_ID, REPO)],
        &asked_permissions(),
        "selected",
    )
}

fn created(token: &str, expires_at: &str) -> Scripted {
    let epoch = expires_at
        .parse::<jiff::Timestamp>()
        .expect("a test expiry is a valid timestamp")
        .as_second();
    created_at(token, epoch)
}

/// A body with the shape of an answer, but not what `created` makes.
fn answer_body(token: &str, expires_at: &str, extra: &Value) -> Scripted {
    let mut body = json!({"token": token, "expires_at": expires_at});
    body.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    Scripted::with_body(201, body.to_string())
}

async fn mint_with(scripted: Scripted) -> Result<InstallationToken, MintError> {
    let (upstream, api) = upstream().await;
    upstream.script_github_token(scripted);
    mint(&api, &github_app_key().0, REPO_ID, NOW).await
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
async fn mint_names_one_repository_id_with_fixed_permissions_and_headers() {
    let (upstream, api) = upstream().await;
    upstream.script_github_token(created("ghs_test", EXPIRES_AT));
    let (key, public) = github_app_key();
    mint(&api, &key, REPO_ID, NOW).await.unwrap();
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
    assert_eq!(
        body,
        json!({ "permissions": expected, "repository_ids": [1001] })
    );
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
    let mut body = json!({
        "token": "ghs_test",
        "expires_at": EXPIRES_AT,
        "repository_selection": "selected",
        "repositories": [{"id": REPO_ID, "full_name": REPO}],
        "permissions": expected_permissions(),
    })
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
        refused(answer_body(
            "ghs_test",
            "tomorrow",
            &json!({"repositories": [{"id": REPO_ID, "full_name": REPO}],
                    "permissions": expected_permissions(),
                    "repository_selection": "selected"}),
        ))
        .await,
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
    let err = mint(&api, &github_app_key().0, REPO_ID, NOW)
        .await
        .unwrap_err();
    assert_eq!(err, MintError::Unreachable);
    assert!(upstream.received().is_empty());
}

#[tokio::test]
async fn mint_waits_for_a_held_answer() {
    let (upstream, api) = upstream().await;
    let gate = Gate::new();
    upstream.script_github_token(created("ghs_test", EXPIRES_AT).held_by(&gate));
    let call = tokio::spawn(async move { mint(&api, &github_app_key().0, REPO_ID, NOW).await });
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
        (
            MintError::NotAccessible,
            "GitHub says the App cannot reach that repository",
        ),
        (
            MintError::WrongScope,
            "GitHub's token was not limited as asked",
        ),
    ] {
        assert_eq!(err.to_string(), text);
    }
}

fn expected_permissions() -> Value {
    PERMISSIONS
        .iter()
        .map(|(name, level)| ((*name).to_owned(), json!(level)))
        .collect::<serde_json::Map<_, _>>()
        .into()
}

fn name(value: &str) -> RepoName {
    RepoName::try_from(value.to_owned()).unwrap()
}

fn resolved(id: u64, value: &str) -> ResolvedRepository {
    ResolvedRepository {
        id,
        name: name(value),
    }
}

const METADATA: [(&str, &str); 1] = [("metadata", "read")];

fn answer(repositories: &[(u64, &str)], permissions: &[(&str, &str)], selection: &str) -> Scripted {
    token_answer("ghs_test", NOW + 3600, repositories, permissions, selection)
}

#[tokio::test]
async fn mint_refuses_other_repository() {
    let scripted = answer(
        &[(1002, "example-owner/homebrew-tap")],
        &asked_permissions(),
        "selected",
    );
    assert_eq!(refused(scripted).await, MintError::WrongScope);
}

#[tokio::test]
async fn mint_refuses_two_repositories() {
    let scripted = answer(
        &[(REPO_ID, REPO), (1002, "example-owner/homebrew-tap")],
        &asked_permissions(),
        "selected",
    );
    assert_eq!(refused(scripted).await, MintError::WrongScope);
}

#[tokio::test]
async fn mint_refuses_missing_repositories() {
    let none = answer(&[], &asked_permissions(), "selected");
    assert_eq!(refused(none).await, MintError::WrongScope);
    let absent = answer_body(
        "ghs_test",
        EXPIRES_AT,
        &json!({"permissions": expected_permissions(), "repository_selection": "selected"}),
    );
    assert_eq!(refused(absent).await, MintError::WrongScope);
}

#[tokio::test]
async fn mint_refuses_wider_permissions() {
    let mut extra = asked_permissions();
    extra.push(("administration", "write"));
    let mut higher: Vec<_> = asked_permissions()
        .into_iter()
        .filter(|(name, _)| *name != "contents")
        .collect();
    higher.push(("contents", "admin"));
    let mut unknown = asked_permissions();
    unknown.push(("contents", "bogus"));
    for permissions in [extra, higher, unknown] {
        let scripted = answer(&[(REPO_ID, REPO)], &permissions, "selected");
        assert_eq!(
            refused(scripted).await,
            MintError::WrongScope,
            "{permissions:?}"
        );
    }
}

#[tokio::test]
async fn mint_accepts_lower_permissions() {
    let scripted = answer(&[(REPO_ID, REPO)], &METADATA, "selected");
    assert!(mint_with(scripted).await.is_ok());
}

#[tokio::test]
async fn mint_refuses_selection_all() {
    let scripted = answer(&[(REPO_ID, REPO)], &asked_permissions(), "all");
    assert_eq!(refused(scripted).await, MintError::WrongScope);
}

#[tokio::test]
async fn mint_maps_inaccessible_status_without_echo() {
    let err = refused(Scripted::with_body(422, "SECRET-ECHO")).await;
    assert_eq!(err, MintError::NotAccessible);
    assert!(!format!("{err:?} {err}").contains("SECRET-ECHO"));
}

#[tokio::test]
async fn resolve_sends_bare_names_and_metadata_only() {
    let (upstream, api) = upstream().await;
    upstream.script_github_token(answer(
        &[(REPO_ID, REPO), (1002, "example-owner/homebrew-tap")],
        &METADATA,
        "selected",
    ));
    let names = [name(REPO), name("example-owner/homebrew-tap")];
    resolve(&api, &github_app_key().0, &names, NOW)
        .await
        .unwrap();
    let received = upstream.received();
    assert_eq!(received.len(), 1);
    let body: Value = serde_json::from_slice(&received[0].body).unwrap();
    assert_eq!(
        body,
        json!({
            "permissions": {"metadata": "read"},
            "repositories": ["example-repo", "homebrew-tap"],
        })
    );
}

async fn resolve_with(
    names: &[&str],
    scripted: Scripted,
) -> Result<Vec<ResolvedRepository>, MintError> {
    let (upstream, api) = upstream().await;
    upstream.script_github_token(scripted);
    let names: Vec<RepoName> = names.iter().map(|n| name(n)).collect();
    resolve(&api, &github_app_key().0, &names, NOW).await
}

#[tokio::test]
async fn resolve_returns_ids_and_github_case() {
    let scripted = answer(
        &[(1002, "Example-Owner/Homebrew-Tap"), (REPO_ID, REPO)],
        &METADATA,
        "selected",
    );
    let found = resolve_with(&[REPO, "example-owner/homebrew-tap"], scripted)
        .await
        .unwrap();
    assert_eq!(
        found,
        vec![
            resolved(REPO_ID, REPO),
            resolved(1002, "Example-Owner/Homebrew-Tap"),
        ]
    );
    assert_eq!(found[1].name.to_string(), "Example-Owner/Homebrew-Tap");
}

#[tokio::test]
async fn resolve_refuses_other_owner() {
    let scripted = answer(&[(REPO_ID, REPO)], &METADATA, "selected");
    let err = resolve_with(&["other-owner/example-repo"], scripted)
        .await
        .unwrap_err();
    assert_eq!(err, MintError::WrongScope);
}

#[tokio::test]
async fn resolve_refuses_missing_or_extra_entry() {
    let both = [REPO, "example-owner/homebrew-tap"];
    let missing = answer(&[(REPO_ID, REPO)], &METADATA, "selected");
    assert_eq!(
        resolve_with(&both, missing).await.unwrap_err(),
        MintError::WrongScope
    );
    let extra = answer(
        &[(REPO_ID, REPO), (1002, "example-owner/homebrew-tap")],
        &METADATA,
        "selected",
    );
    assert_eq!(
        resolve_with(&[REPO], extra).await.unwrap_err(),
        MintError::WrongScope
    );
    let twice = answer(&[(REPO_ID, REPO), (REPO_ID, REPO)], &METADATA, "selected");
    assert_eq!(
        resolve_with(&[REPO], twice).await.unwrap_err(),
        MintError::WrongScope
    );
}

#[tokio::test]
async fn resolve_refuses_more_than_metadata() {
    let scripted = answer(&[(REPO_ID, REPO)], &asked_permissions(), "selected");
    assert_eq!(
        resolve_with(&[REPO], scripted).await.unwrap_err(),
        MintError::WrongScope
    );
}

#[tokio::test]
async fn resolve_maps_inaccessible_status() {
    let err = resolve_with(&[REPO], Scripted::with_body(422, "{}"))
        .await
        .unwrap_err();
    assert_eq!(err, MintError::NotAccessible);
}

#[tokio::test]
async fn current_names_returns_new_name_for_id() {
    let (upstream, api) = upstream().await;
    upstream.script_github_token(answer(
        &[(REPO_ID, "example-owner/renamed-repo")],
        &METADATA,
        "selected",
    ));
    let found = current_names(&api, &github_app_key().0, &[REPO_ID], NOW)
        .await
        .unwrap();
    assert_eq!(found, vec![resolved(REPO_ID, "example-owner/renamed-repo")]);
    let body: Value = serde_json::from_slice(&upstream.received()[0].body).unwrap();
    assert_eq!(
        body,
        json!({"permissions": {"metadata": "read"}, "repository_ids": [1001]})
    );
}

#[tokio::test]
async fn current_names_refuses_other_ids() {
    let (upstream, api) = upstream().await;
    upstream.script_github_token(answer(
        &[(1002, "example-owner/homebrew-tap")],
        &METADATA,
        "selected",
    ));
    let err = current_names(&api, &github_app_key().0, &[REPO_ID], NOW)
        .await
        .unwrap_err();
    assert_eq!(err, MintError::WrongScope);
}

#[tokio::test]
async fn errors_carry_no_github_text() {
    const MARKER: &str = "MARKER-FROM-GITHUB";
    let bodies = [
        json!({"token": "ghs_test", "expires_at": EXPIRES_AT, "message": MARKER,
               "repository_selection": MARKER,
               "repositories": [{"id": 5, "full_name": MARKER}],
               "permissions": {MARKER: MARKER}}),
        json!({"token": MARKER, "expires_at": MARKER}),
        json!({"token": "ghs_test", "expires_at": EXPIRES_AT,
               "repository_selection": "selected",
               "repositories": [{"id": REPO_ID, "full_name": MARKER}],
               "permissions": {"metadata": "read"}}),
    ];
    // Whether `mint` and `resolve` must refuse each body. `mint` ignores names, so
    // the third body is only a refusal for `resolve`.
    let must_fail = [(true, true), (true, true), (false, true)];
    for (body, (mint_fails, resolve_fails)) in bodies.into_iter().zip(must_fail) {
        let minted = mint_with(Scripted::with_body(201, body.to_string())).await;
        let resolved = resolve_with(&[REPO], Scripted::with_body(201, body.to_string())).await;
        assert_eq!(minted.is_err(), mint_fails, "{body}");
        assert_eq!(resolved.is_err(), resolve_fails, "{body}");
        for err in [minted.err(), resolved.err()].into_iter().flatten() {
            assert!(!format!("{err:?} {err}").contains(MARKER), "{err:?}");
        }
    }
}

#[tokio::test]
async fn mint_refuses_missing_permissions() {
    let absent = answer_body(
        "ghs_test",
        EXPIRES_AT,
        &json!({"repositories": [{"id": REPO_ID, "full_name": REPO}],
                "repository_selection": "selected"}),
    );
    assert_eq!(refused(absent).await, MintError::Malformed);
}

#[tokio::test]
async fn mint_refuses_missing_selection() {
    let absent = answer_body(
        "ghs_test",
        EXPIRES_AT,
        &json!({"repositories": [{"id": REPO_ID, "full_name": REPO}],
                "permissions": expected_permissions()}),
    );
    assert_eq!(refused(absent).await, MintError::WrongScope);
}
