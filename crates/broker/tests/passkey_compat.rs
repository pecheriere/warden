//! Passkeys enrolled on an older broker must keep approving after an upgrade:
//! losing them would lock the owner out.
//!
//! `fixtures/throwaway-test-only-passkeys-webauthn-rs-0.5.5.json` holds rows
//! of the `passkeys` table exactly as a broker on `webauthn-rs` 0.5.5 wrote
//! them, through the real enrollment and approval routes, with the private
//! keys of the throwaway authenticators that made them. Never regenerate the
//! file with a newer library: its age is the point. The one-off generator is
//! in commit 22eb498 of pull request #140.
//!
//! The authenticator here is deliberately independent of `webauthn-rs` and of
//! `webauthn-authenticator-rs`: it writes the JSON that `warden.js` posts and
//! signs with `p256` and `rsa`, so a library upgrade cannot change what it
//! sends. Each test goes through the real approval routes.

use std::time::Duration;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::SigningKey as P256SigningKey;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::pkcs8::DecodePrivateKey as _;
use rsa::signature::{SignatureEncoding as _, Signer as _};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use warden_broker::testkit::{TEST_ORIGIN, TestBroker};
use warden_broker_proto::{AgentName, Id, RequestStatus, Window};
use webauthn_rs::prelude::Passkey;

const FIXTURE: &str = include_str!("fixtures/throwaway-test-only-passkeys-webauthn-rs-0.5.5.json");

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;

/// The relying party id of [`TEST_ORIGIN`].
const RP_ID: &str = "warden.test";

#[derive(Debug, Deserialize)]
struct Fixture {
    webauthn_rs: String,
    passkeys: Vec<StoredPasskey>,
}

/// One row of the `passkeys` table, and the authenticator that owns it.
#[derive(Debug, Clone, Deserialize)]
struct StoredPasskey {
    /// What kind of authenticator this credential stands for.
    shape: String,
    id: String,
    label: String,
    credential: String,
    created_at: i64,
    counter: i64,
    /// `ES256` or `RS256`.
    algorithm: String,
    /// The private key: a P-256 scalar, or RSA PKCS#8 DER.
    signing_key_hex: String,
    backup_eligible: bool,
    backup_state: bool,
}

impl StoredPasskey {
    fn parsed(&self) -> Value {
        serde_json::from_str(&self.credential).unwrap()
    }

    fn cred_id(&self) -> String {
        self.parsed()["cred"]["cred_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// Whether this authenticator counts signatures, or always reports 0 as
    /// platform passkeys do.
    fn counts(&self) -> bool {
        self.counter > 0
    }

    fn flags(&self) -> u8 {
        let mut flags = FLAG_UP | FLAG_UV;
        if self.backup_eligible {
            flags |= FLAG_BE;
        }
        if self.backup_state {
            flags |= FLAG_BS;
        }
        flags
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let key = hex::decode(&self.signing_key_hex).unwrap();
        match self.algorithm.as_str() {
            "ES256" => {
                let key = P256SigningKey::from_slice(&key).unwrap();
                let signature: p256::ecdsa::Signature =
                    p256::ecdsa::signature::Signer::sign(&key, message);
                let (r, s) = signature.split_bytes();
                der_signature(r.as_ref(), s.as_ref())
            }
            "RS256" => {
                let key = RsaPrivateKey::from_pkcs8_der(&key).unwrap();
                RsaSigningKey::<Sha256>::new(key).sign(message).to_vec()
            }
            other => panic!("unknown algorithm {other}"),
        }
    }
}

/// An ASN.1 DER `ECDSA-Sig-Value`, as authenticators send.
fn der_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    fn integer(bytes: &[u8]) -> Vec<u8> {
        let first = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let bytes = &bytes[first..];
        let mut out = vec![0x02];
        if bytes[0] & 0x80 == 0 {
            out.push(u8::try_from(bytes.len()).unwrap());
        } else {
            out.push(u8::try_from(bytes.len() + 1).unwrap());
            out.push(0);
        }
        out.extend_from_slice(bytes);
        out
    }
    let mut body = integer(r);
    body.extend(integer(s));
    let mut out = vec![0x30, u8::try_from(body.len()).unwrap()];
    out.extend(body);
    out
}

fn fixture() -> Fixture {
    let fixture: Fixture = serde_json::from_str(FIXTURE).unwrap();
    assert_eq!(fixture.webauthn_rs, "0.5.5");
    fixture
}

fn by_shape(shape: &str) -> StoredPasskey {
    fixture()
        .passkeys
        .into_iter()
        .find(|passkey| passkey.shape == shape)
        .unwrap()
}

/// What an assertion gets wrong, if anything.
#[derive(Debug, Clone, Copy, Default)]
struct Assertion<'a> {
    counter: Option<u32>,
    origin: Option<&'a str>,
    rp_id: Option<&'a str>,
    challenge: Option<&'a str>,
    ceremony_type: Option<&'a str>,
    flags: Option<u8>,
    signed_by: Option<&'a StoredPasskey>,
    flip_signature_bit: bool,
}

/// The JSON `warden.js` posts for an assertion by `passkey`.
fn assertion(passkey: &StoredPasskey, options: &Value, how: Assertion<'_>) -> Value {
    let challenge = how
        .challenge
        .or_else(|| options["publicKey"]["challenge"].as_str())
        .unwrap();
    let client_data = json!({
        "type": how.ceremony_type.unwrap_or("webauthn.get"),
        "challenge": challenge,
        "origin": how.origin.unwrap_or(TEST_ORIGIN),
        "crossOrigin": false,
    })
    .to_string();
    let counter = how.counter.unwrap_or(if passkey.counts() {
        u32::try_from(passkey.counter + 1).unwrap()
    } else {
        0
    });
    let mut authenticator_data = Sha256::digest(how.rp_id.unwrap_or(RP_ID)).to_vec();
    authenticator_data.push(how.flags.unwrap_or_else(|| passkey.flags()));
    authenticator_data.extend_from_slice(&counter.to_be_bytes());
    let mut message = authenticator_data.clone();
    message.extend_from_slice(&Sha256::digest(&client_data));
    let mut signature = how.signed_by.unwrap_or(passkey).sign(&message);
    if how.flip_signature_bit {
        *signature.last_mut().unwrap() ^= 1;
    }
    let cred_id = passkey.cred_id();
    json!({
        "id": cred_id,
        "rawId": cred_id,
        "type": "public-key",
        "response": {
            "authenticatorData": URL_SAFE_NO_PAD.encode(authenticator_data),
            "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data),
            "signature": URL_SAFE_NO_PAD.encode(signature),
            "userHandle": URL_SAFE_NO_PAD.encode(b"warden-owner-key"),
        },
        "extensions": {},
    })
}

/// A fresh broker on the current library whose database holds exactly `rows`,
/// byte for byte.
async fn broker_holding(rows: &[StoredPasskey]) -> TestBroker {
    let broker = TestBroker::new().await;
    broker.add_agent("bot").await;
    for row in rows {
        sqlx::query(
            "INSERT INTO passkeys (id, label, credential, created_at, counter) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&row.id)
        .bind(&row.label)
        .bind(&row.credential)
        .bind(row.created_at)
        .bind(row.counter)
        .execute(&broker.state().pool)
        .await
        .unwrap();
    }
    broker
}

async fn request(broker: &TestBroker) -> (Id, String) {
    let (created, token) = broker
        .create_request("bot", TestBroker::pi_request("compat check", Window::M30))
        .await;
    (created.id, token)
}

async fn status(broker: &TestBroker, id: &Id) -> RequestStatus {
    broker
        .state()
        .requests
        .status(
            &AgentName::try_from("bot".to_owned()).unwrap(),
            id,
            Duration::ZERO,
        )
        .await
        .unwrap()
}

/// `(credential, counter)` of passkey `id` as stored now.
async fn row(broker: &TestBroker, id: &str) -> (String, i64) {
    let row = sqlx::query("SELECT credential, counter FROM passkeys WHERE id = ?")
        .bind(id)
        .fetch_one(&broker.state().pool)
        .await
        .unwrap();
    (row.get("credential"), row.get("counter"))
}

async fn grant_count(broker: &TestBroker) -> i64 {
    sqlx::query("SELECT COUNT(*) FROM grants")
        .fetch_one(&broker.state().pool)
        .await
        .unwrap()
        .get(0)
}

/// Begin an approval, answer it as `passkey` would and post it.
async fn approve(
    broker: &TestBroker,
    token: &str,
    passkey: &StoredPasskey,
    how: Assertion<'_>,
) -> warden_broker::testkit::TestResponse {
    let begin = broker.begin_approval(token, Window::M30).await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
    let begin = begin.json();
    let credential = assertion(passkey, &begin["options"], how);
    broker
        .post_json(
            &format!("/approve/{token}/finish"),
            &json!({"ceremony": begin["ceremony"], "credential": credential}),
        )
        .await
}

#[test]
fn fixture_covers_every_shape_warden_can_store() {
    let passkeys = fixture().passkeys;
    let shapes: Vec<&str> = passkeys.iter().map(|p| p.shape.as_str()).collect();
    assert_eq!(
        shapes,
        [
            "es256-synced-never-used",
            "es256-synced-used",
            "es256-hardware-used",
            "rs256-windows-hello",
            "es256-packed-self-attestation",
            "es256-packed-x5c-attestation",
        ]
    );
    let algorithms = |alg: &str| passkeys.iter().filter(|p| p.algorithm == alg).count();
    assert_eq!(algorithms("ES256"), 5);
    assert_eq!(algorithms("RS256"), 1);
}

#[test]
fn stored_credentials_load_and_lose_nothing_when_written_back() {
    for stored in fixture().passkeys {
        let passkey: Passkey = serde_json::from_str(&stored.credential)
            .unwrap_or_else(|error| panic!("{}: {error}", stored.shape));
        assert_eq!(
            URL_SAFE_NO_PAD.encode::<&[u8]>(passkey.cred_id().as_ref()),
            stored.cred_id(),
            "{}",
            stored.shape
        );
        let written: Value = serde_json::to_value(&passkey).unwrap();
        assert_eq!(written, stored.parsed(), "{}", stored.shape);
    }
}

/// Migration 0004 and enrollment both read the counter from this JSON path.
#[test]
fn counter_stays_where_the_counter_column_reads_it() {
    for stored in fixture().passkeys {
        assert_eq!(
            stored.parsed()["cred"]["counter"].as_i64(),
            Some(stored.counter),
            "{}",
            stored.shape
        );
    }
}

#[tokio::test]
async fn every_stored_credential_completes_real_approvals() {
    for stored in fixture().passkeys {
        let broker = broker_holding(std::slice::from_ref(&stored)).await;
        let (id, token) = request(&broker).await;

        let begin = broker.begin_approval(&token, Window::M30).await;
        assert_eq!(
            begin.status,
            StatusCode::OK,
            "{}: {}",
            stored.shape,
            begin.body
        );
        let public_key = &begin.json()["options"]["publicKey"];
        assert_eq!(public_key["rpId"], RP_ID, "{}", stored.shape);
        assert_eq!(
            public_key["userVerification"], "required",
            "{}",
            stored.shape
        );
        assert_eq!(
            public_key["allowCredentials"][0]["id"].as_str(),
            Some(stored.cred_id().as_str()),
            "{}",
            stored.shape
        );

        let done = approve(&broker, &token, &stored, Assertion::default()).await;
        assert_eq!(
            done.status,
            StatusCode::OK,
            "{}: {}",
            stored.shape,
            done.body
        );
        assert!(
            matches!(status(&broker, &id).await, RequestStatus::Approved(_)),
            "{}",
            stored.shape
        );
        assert_eq!(grant_count(&broker).await, 1, "{}", stored.shape);

        // The approval rewrote the row with the current library. It must
        // still load and approve, with the counter raised.
        let (credential, counter) = row(&broker, &stored.id).await;
        let expected = if stored.counts() {
            stored.counter + 1
        } else {
            0
        };
        assert_eq!(counter, expected, "{}", stored.shape);
        let rewritten = StoredPasskey {
            credential,
            counter,
            ..stored.clone()
        };
        assert_eq!(
            rewritten.parsed()["cred"]["counter"].as_i64(),
            Some(expected),
            "{}",
            stored.shape
        );
        let (again, token) = request(&broker).await;
        let done = approve(&broker, &token, &rewritten, Assertion::default()).await;
        assert_eq!(
            done.status,
            StatusCode::OK,
            "{}: {}",
            stored.shape,
            done.body
        );
        assert!(matches!(
            status(&broker, &again).await,
            RequestStatus::Approved(_)
        ));
    }
}

#[tokio::test]
async fn all_stored_credentials_work_side_by_side() {
    let passkeys = fixture().passkeys;
    let broker = broker_holding(&passkeys).await;
    for stored in &passkeys {
        let (id, token) = request(&broker).await;
        let begin = broker.begin_approval(&token, Window::M30).await;
        let allowed = begin.json()["options"]["publicKey"]["allowCredentials"].clone();
        assert_eq!(allowed.as_array().unwrap().len(), passkeys.len());
        let done = approve(&broker, &token, stored, Assertion::default()).await;
        assert_eq!(
            done.status,
            StatusCode::OK,
            "{}: {}",
            stored.shape,
            done.body
        );
        assert!(matches!(
            status(&broker, &id).await,
            RequestStatus::Approved(_)
        ));
    }
}

/// `how` must not approve anything, and must leave the stored passkey alone.
async fn refused(stored: &StoredPasskey, why: &str, how: Assertion<'_>) {
    let broker = broker_holding(std::slice::from_ref(stored)).await;
    let (id, token) = request(&broker).await;
    let done = approve(&broker, &token, stored, how).await;
    assert_ne!(done.status, StatusCode::OK, "{}: {why}", stored.shape);
    assert!(
        matches!(status(&broker, &id).await, RequestStatus::Pending),
        "{}: {why}",
        stored.shape
    );
    assert_eq!(grant_count(&broker).await, 0, "{}: {why}", stored.shape);
    assert_eq!(
        row(&broker, &stored.id).await,
        (stored.credential.clone(), stored.counter),
        "{}: {why}",
        stored.shape
    );
}

/// The checks must still hold for stored credentials, for each kind of key.
#[tokio::test]
async fn stored_credentials_refuse_bad_assertions() {
    let es256 = by_shape("es256-hardware-used");
    let rs256 = by_shape("rs256-windows-hello");
    let other = by_shape("es256-synced-used");
    let no_uv = FLAG_UP;
    for stored in [&es256, &rs256] {
        let flipped = Assertion {
            flip_signature_bit: true,
            ..Assertion::default()
        };
        refused(stored, "altered signature", flipped).await;
        let wrong_key = Assertion {
            signed_by: Some(&other),
            ..Assertion::default()
        };
        refused(stored, "signed by another key", wrong_key).await;
        let wrong_origin = Assertion {
            origin: Some("https://evil.example"),
            ..Assertion::default()
        };
        refused(stored, "wrong origin", wrong_origin).await;
        let subdomain = Assertion {
            origin: Some("https://sub.warden.test"),
            ..Assertion::default()
        };
        refused(stored, "subdomain origin", subdomain).await;
        let wrong_rp = Assertion {
            rp_id: Some("evil.example"),
            ..Assertion::default()
        };
        refused(stored, "wrong RP id", wrong_rp).await;
        let wrong_challenge = Assertion {
            challenge: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ..Assertion::default()
        };
        refused(stored, "wrong challenge", wrong_challenge).await;
        let wrong_type = Assertion {
            ceremony_type: Some("webauthn.create"),
            ..Assertion::default()
        };
        refused(stored, "wrong ceremony type", wrong_type).await;
        let unverified = Assertion {
            flags: Some(no_uv),
            ..Assertion::default()
        };
        refused(stored, "no user verification", unverified).await;
    }
}

#[tokio::test]
async fn stored_credentials_refuse_counter_rollback() {
    for stored in [
        by_shape("es256-hardware-used"),
        by_shape("rs256-windows-hello"),
    ] {
        assert!(stored.counts(), "{}", stored.shape);
        for counter in [stored.counter, stored.counter - 1, 0] {
            let broker = broker_holding(std::slice::from_ref(&stored)).await;
            let (id, token) = request(&broker).await;
            let how = Assertion {
                counter: Some(u32::try_from(counter).unwrap()),
                ..Assertion::default()
            };
            let done = approve(&broker, &token, &stored, how).await;
            assert_ne!(done.status, StatusCode::OK, "{}: {counter}", stored.shape);
            assert!(matches!(status(&broker, &id).await, RequestStatus::Pending));
            assert_eq!(grant_count(&broker).await, 0);
            assert_eq!(
                row(&broker, &stored.id).await,
                (stored.credential.clone(), stored.counter)
            );
            assert!(
                broker
                    .audit_types()
                    .contains(&"passkey_counter_regressed".to_owned()),
                "{}: {counter}",
                stored.shape
            );
        }
    }
}
