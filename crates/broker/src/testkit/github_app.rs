//! A fixed GitHub App key for tests: generated once with `openssl`, committed under
//! `github_app/` and named `throwaway-test-only`. It protects nothing.

use crate::policy::GithubAppKey;
use crate::testkit::upstream::Scripted;

/// The App id of [`github_app_key`].
pub const APP_ID: &str = "123456";

/// The installation id of [`github_app_key`].
pub const INSTALLATION_ID: u64 = 7_654_321;

/// A 2048-bit RSA key as PKCS#1 PEM.
pub const RSA2048_PKCS1: &[u8] = include_bytes!("github_app/throwaway-test-only-rsa2048-pkcs1.pem");
/// The same key as PKCS#8 PEM.
pub const RSA2048_PKCS8: &[u8] = include_bytes!("github_app/throwaway-test-only-rsa2048-pkcs8.pem");
/// The same key, encrypted with a passphrase, as PKCS#8 PEM.
pub const RSA2048_ENCRYPTED: &[u8] =
    include_bytes!("github_app/throwaway-test-only-rsa2048-encrypted-pkcs8.pem");
/// Another 2048-bit RSA key, encrypted the legacy way: PKCS#1 PEM with
/// `Proc-Type: 4,ENCRYPTED`.
pub const RSA2048_ENCRYPTED_PKCS1: &[u8] =
    include_bytes!("github_app/throwaway-test-only-rsa2048-encrypted-pkcs1.pem");
/// A 1024-bit RSA key, too short to accept.
pub const RSA1024_PKCS8: &[u8] = include_bytes!("github_app/throwaway-test-only-rsa1024-pkcs8.pem");
/// An ECDSA P-256 key.
pub const EC_P256_PKCS8: &[u8] = include_bytes!("github_app/throwaway-test-only-ec-p256-pkcs8.pem");
/// An Ed25519 key.
pub const ED25519_PKCS8: &[u8] = include_bytes!("github_app/throwaway-test-only-ed25519-pkcs8.pem");
/// The public half of the 2048-bit key, as a PKCS#1 `RSAPublicKey` DER, to verify
/// signatures with.
pub const RSA2048_PUBLIC_DER: &[u8] =
    include_bytes!("github_app/throwaway-test-only-rsa2048-public.der");

/// The fixed test App, and its public key for verifying what it signs.
///
/// # Panics
/// Never, unless the committed fixture is damaged.
#[must_use]
pub fn github_app_key() -> (GithubAppKey, Vec<u8>) {
    let key = GithubAppKey::new(APP_ID.to_owned(), INSTALLATION_ID, RSA2048_PKCS8)
        .expect("the committed test key loads");
    (key, RSA2048_PUBLIC_DER.to_vec())
}

/// GitHub's `201` for a token request: the token, when it expires, the
/// repositories it covers as `(id, full_name)`, its permissions and its
/// `repository_selection`.
///
/// # Panics
/// If `expires_at` is not a time a timestamp can hold.
#[must_use]
pub fn token_answer(
    token: &str,
    expires_at: i64,
    repositories: &[(u64, &str)],
    permissions: &[(&str, &str)],
    selection: &str,
) -> Scripted {
    let expires = jiff::Timestamp::from_second(expires_at).expect("a representable time");
    let permissions: serde_json::Map<String, serde_json::Value> = permissions
        .iter()
        .map(|(name, level)| ((*name).to_owned(), serde_json::json!(level)))
        .collect();
    let repositories: Vec<serde_json::Value> = repositories
        .iter()
        .map(|(id, name)| serde_json::json!({"id": id, "full_name": name}))
        .collect();
    Scripted::with_body(
        201,
        serde_json::json!({
            "token": token,
            "expires_at": expires.to_string(),
            "permissions": permissions,
            "repository_selection": selection,
            "repositories": repositories,
        })
        .to_string(),
    )
}

/// GitHub's `201` for a mint that went as asked: a token for `repositories`
/// (`(id, full_name)`) with the permissions an agent's token carries, ending at
/// `expires_at`.
///
/// # Panics
/// If `expires_at` is not a time a timestamp can hold.
#[must_use]
pub fn minted_answer(token: &str, expires_at: i64, repositories: &[(u64, &str)]) -> Scripted {
    token_answer(
        token,
        expires_at,
        repositories,
        &warden_broker_proto::github_token::PERMISSIONS,
        "selected",
    )
}
