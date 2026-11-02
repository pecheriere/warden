//! One-off generator of the fixture `passkey_compat.rs` reads. Run on
//! webauthn-rs 0.5.5 only, then deleted: see that file.

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p256::ecdsa::SigningKey as P256SigningKey;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::pkcs8::DecodePrivateKey as _;
use rsa::signature::{SignatureEncoding as _, Signer as _};
use rsa::traits::PublicKeyParts as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use warden_broker::testkit::{TEST_ORIGIN, TestBroker};
use warden_broker_proto::Window;

const RP_ID: &str = "warden.test";
const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;
const ED: u8 = 0x80;

/// Just enough CBOR.
enum Cbor {
    Int(i64),
    Bytes(Vec<u8>),
    Text(&'static str),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
}

fn head(major: u8, length: u64, out: &mut Vec<u8>) {
    let major = major << 5;
    if length < 24 {
        out.push(major | u8::try_from(length).unwrap());
    } else if length < 256 {
        out.push(major | 24);
        out.push(u8::try_from(length).unwrap());
    } else {
        out.push(major | 25);
        out.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
    }
}

impl Cbor {
    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Int(i) if *i >= 0 => head(0, i.unsigned_abs(), out),
            Self::Int(i) => head(1, i.unsigned_abs() - 1, out),
            Self::Bytes(b) => {
                head(2, b.len() as u64, out);
                out.extend_from_slice(b);
            }
            Self::Text(t) => {
                head(3, t.len() as u64, out);
                out.extend_from_slice(t.as_bytes());
            }
            Self::Array(a) => {
                head(4, a.len() as u64, out);
                for item in a {
                    item.write(out);
                }
            }
            Self::Map(m) => {
                head(5, m.len() as u64, out);
                for (k, v) in m {
                    k.write(out);
                    v.write(out);
                }
            }
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }
}

#[derive(Clone)]
enum Key {
    Es256(Vec<u8>),
    Rs256(Vec<u8>),
}

impl Key {
    fn alg(&self) -> &'static str {
        match self {
            Self::Es256(_) => "ES256",
            Self::Rs256(_) => "RS256",
        }
    }

    fn cose(&self) -> Cbor {
        match self {
            Self::Es256(scalar) => {
                let key = P256SigningKey::from_slice(scalar).unwrap();
                let point = key.verifying_key().to_sec1_point(false);
                Cbor::Map(vec![
                    (Cbor::Int(1), Cbor::Int(2)),
                    (Cbor::Int(3), Cbor::Int(-7)),
                    (Cbor::Int(-1), Cbor::Int(1)),
                    (Cbor::Int(-2), Cbor::Bytes(point.x().unwrap().to_vec())),
                    (Cbor::Int(-3), Cbor::Bytes(point.y().unwrap().to_vec())),
                ])
            }
            Self::Rs256(der) => {
                let key = RsaPrivateKey::from_pkcs8_der(der).unwrap();
                Cbor::Map(vec![
                    (Cbor::Int(1), Cbor::Int(3)),
                    (Cbor::Int(3), Cbor::Int(-257)),
                    (Cbor::Int(-1), Cbor::Bytes(key.n_bytes().to_vec())),
                    (Cbor::Int(-2), Cbor::Bytes(key.e_bytes().to_vec())),
                ])
            }
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Es256(scalar) => es256(scalar, message),
            Self::Rs256(der) => {
                let key = RsaPrivateKey::from_pkcs8_der(der).unwrap();
                RsaSigningKey::<Sha256>::new(key).sign(message).to_vec()
            }
        }
    }

    fn hex(&self) -> String {
        match self {
            Self::Es256(k) | Self::Rs256(k) => hex::encode(k),
        }
    }
}

fn es256(scalar: &[u8], message: &[u8]) -> Vec<u8> {
    let key = P256SigningKey::from_slice(scalar).unwrap();
    let signature: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(&key, message);
    let (r, s) = signature.split_bytes();
    der_signature(r.as_ref(), s.as_ref())
}

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

fn fresh_es256() -> Key {
    let mut scalar = [0_u8; 32];
    getrandom::fill(&mut scalar).unwrap();
    P256SigningKey::from_slice(&scalar).unwrap();
    Key::Es256(scalar.to_vec())
}

/// What the attestation statement holds.
enum Att<'a> {
    None,
    PackedSelf,
    PackedX5c { cert: &'a [u8], key: &'a [u8] },
}

struct Authenticator<'a> {
    shape: &'static str,
    key: Key,
    enroll_flags: u8,
    enroll_counter: u32,
    transports: Value,
    cred_protect: Option<i64>,
    att: Att<'a>,
    /// Approve once on this library, with these flags and this counter, so
    /// that the row is what `update_credential` writes.
    use_once: Option<(u8, u32)>,
}

async fn enroll(broker: &TestBroker, a: &Authenticator<'_>) -> Vec<u8> {
    let code = broker.enrollment_code().await;
    let begin = broker
        .post_json("/enroll/begin", &json!({"code": code, "label": a.shape}))
        .await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
    let begin = begin.json();
    let challenge = begin["options"]["publicKey"]["challenge"].as_str().unwrap();
    let client_data = json!({
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": TEST_ORIGIN,
        "crossOrigin": false,
    })
    .to_string();

    let mut cred_id = vec![0_u8; 32];
    getrandom::fill(&mut cred_id).unwrap();

    let mut auth = Sha256::digest(RP_ID).to_vec();
    let extension_flag = if a.cred_protect.is_some() { ED } else { 0 };
    auth.push(a.enroll_flags | AT | extension_flag);
    auth.extend_from_slice(&a.enroll_counter.to_be_bytes());
    auth.extend_from_slice(&[0_u8; 16]);
    auth.extend_from_slice(&u16::try_from(cred_id.len()).unwrap().to_be_bytes());
    auth.extend_from_slice(&cred_id);
    auth.extend(a.key.cose().bytes());
    if let Some(policy) = a.cred_protect {
        auth.extend(Cbor::Map(vec![(Cbor::Text("credProtect"), Cbor::Int(policy))]).bytes());
    }

    let mut message = auth.clone();
    message.extend_from_slice(&Sha256::digest(&client_data));
    let (fmt, statement) = match a.att {
        Att::None => ("none", Cbor::Map(Vec::new())),
        Att::PackedSelf => (
            "packed",
            Cbor::Map(vec![
                (Cbor::Text("alg"), Cbor::Int(-7)),
                (Cbor::Text("sig"), Cbor::Bytes(a.key.sign(&message))),
            ]),
        ),
        Att::PackedX5c { cert, key } => (
            "packed",
            Cbor::Map(vec![
                (Cbor::Text("alg"), Cbor::Int(-7)),
                (Cbor::Text("sig"), Cbor::Bytes(es256(key, &message))),
                (
                    Cbor::Text("x5c"),
                    Cbor::Array(vec![Cbor::Bytes(cert.to_vec())]),
                ),
            ]),
        ),
    };
    let object = Cbor::Map(vec![
        (Cbor::Text("fmt"), Cbor::Text(fmt)),
        (Cbor::Text("attStmt"), statement),
        (Cbor::Text("authData"), Cbor::Bytes(auth)),
    ])
    .bytes();

    let id = URL_SAFE_NO_PAD.encode(&cred_id);
    let credential = json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "response": {
            "attestationObject": URL_SAFE_NO_PAD.encode(object),
            "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data),
            "transports": a.transports,
        },
        "extensions": {"credProps": {"rk": true}},
    });
    let finish = broker
        .post_json(
            "/enroll/finish",
            &json!({"ceremony": begin["ceremony"], "credential": credential}),
        )
        .await;
    assert_eq!(
        finish.status,
        StatusCode::OK,
        "{}: {}",
        a.shape,
        finish.body
    );
    cred_id
}

async fn approve_once(broker: &TestBroker, a: &Authenticator<'_>, cred_id: &[u8]) {
    let Some((flags, counter)) = a.use_once else {
        return;
    };
    let (_, token) = broker
        .create_request("bot", TestBroker::pi_request("fixture", Window::M30))
        .await;
    let begin = broker.begin_approval(&token, Window::M30).await;
    assert_eq!(begin.status, StatusCode::OK, "{}", begin.body);
    let begin = begin.json();
    let client_data = json!({
        "type": "webauthn.get",
        "challenge": begin["options"]["publicKey"]["challenge"],
        "origin": TEST_ORIGIN,
        "crossOrigin": false,
    })
    .to_string();
    let mut auth = Sha256::digest(RP_ID).to_vec();
    auth.push(flags);
    auth.extend_from_slice(&counter.to_be_bytes());
    let mut message = auth.clone();
    message.extend_from_slice(&Sha256::digest(&client_data));
    let id = URL_SAFE_NO_PAD.encode(cred_id);
    let credential = json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "response": {
            "authenticatorData": URL_SAFE_NO_PAD.encode(auth),
            "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data),
            "signature": URL_SAFE_NO_PAD.encode(a.key.sign(&message)),
            "userHandle": URL_SAFE_NO_PAD.encode(b"warden-owner-key"),
        },
        "extensions": {},
    });
    let done = broker
        .post_json(
            &format!("/approve/{token}/finish"),
            &json!({"ceremony": begin["ceremony"], "credential": credential}),
        )
        .await;
    assert_eq!(done.status, StatusCode::OK, "{}: {}", a.shape, done.body);
}

#[tokio::test]
#[ignore = "writes the fixture; run once on webauthn-rs 0.5.5"]
async fn generate() {
    let dir = std::env::var("PASSKEY_FIXTURE_DIR").unwrap();
    let dir = std::path::Path::new(&dir);
    let cert = std::fs::read(dir.join("att.der")).unwrap();
    let attestation_key = hex::decode(
        std::fs::read_to_string(dir.join("att.scalar"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    let pem = include_str!("fixtures/throwaway-test-only-rsa-pkcs8.key");
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let rsa_der = STANDARD.decode(body).unwrap();

    let authenticators = vec![
        // A phone or a password manager: synced, never counts.
        Authenticator {
            shape: "es256-synced-never-used",
            key: fresh_es256(),
            enroll_flags: UP | UV | BE | BS,
            enroll_counter: 0,
            transports: json!(["hybrid", "internal"]),
            cred_protect: None,
            att: Att::None,
            use_once: None,
        },
        // Backed up only after enrollment, as a phone may be.
        Authenticator {
            shape: "es256-synced-used",
            key: fresh_es256(),
            enroll_flags: UP | UV | BE,
            enroll_counter: 0,
            transports: json!(["internal"]),
            cred_protect: None,
            att: Att::None,
            use_once: Some((UP | UV | BE | BS, 0)),
        },
        // A hardware key: device-bound, counts, honours credProtect.
        Authenticator {
            shape: "es256-hardware-used",
            key: fresh_es256(),
            enroll_flags: UP | UV,
            enroll_counter: 7,
            transports: json!(["nfc", "usb"]),
            cred_protect: Some(3),
            att: Att::None,
            use_once: Some((UP | UV, 8)),
        },
        // RS256, as older Windows Hello and TPM authenticators use.
        Authenticator {
            shape: "rs256-windows-hello",
            key: Key::Rs256(rsa_der),
            enroll_flags: UP | UV,
            enroll_counter: 3,
            transports: json!(["internal"]),
            cred_protect: None,
            att: Att::None,
            use_once: None,
        },
        // Clients that do not strip attestation although warden asks for none.
        Authenticator {
            shape: "es256-packed-self-attestation",
            key: fresh_es256(),
            enroll_flags: UP | UV,
            enroll_counter: 0,
            transports: json!(["usb"]),
            cred_protect: None,
            att: Att::PackedSelf,
            use_once: None,
        },
        Authenticator {
            shape: "es256-packed-x5c-attestation",
            key: fresh_es256(),
            enroll_flags: UP | UV,
            enroll_counter: 1,
            transports: json!(["usb"]),
            cred_protect: Some(3),
            att: Att::PackedX5c {
                cert: &cert,
                key: &attestation_key,
            },
            use_once: None,
        },
    ];

    let mut passkeys = Vec::new();
    for a in &authenticators {
        let broker = TestBroker::new().await;
        broker.add_agent("bot").await;
        let cred_id = enroll(&broker, a).await;
        approve_once(&broker, a, &cred_id).await;
        let row = sqlx::query("SELECT id, label, credential, created_at, counter FROM passkeys")
            .fetch_one(&broker.state().pool)
            .await
            .unwrap();
        let credential: String = row.get("credential");
        let parsed: Value = serde_json::from_str(&credential).unwrap();
        let (backup_eligible, backup_state) = (
            parsed["cred"]["backup_eligible"].as_bool().unwrap(),
            parsed["cred"]["backup_state"].as_bool().unwrap(),
        );
        passkeys.push(json!({
            "shape": a.shape,
            "id": row.get::<String, _>("id"),
            "label": row.get::<String, _>("label"),
            "credential": credential,
            "created_at": row.get::<i64, _>("created_at"),
            "counter": row.get::<i64, _>("counter"),
            "algorithm": a.key.alg(),
            "signing_key_hex": a.key.hex(),
            "backup_eligible": backup_eligible,
            "backup_state": backup_state,
        }));
    }
    let fixture = json!({
        "comment": "Throwaway test data. Rows of the passkeys table as a broker on \
                    webauthn-rs 0.5.5 wrote them through its real routes, with the private \
                    keys of the test authenticators. Never regenerate with a newer library.",
        "webauthn_rs": "0.5.5",
        "passkeys": passkeys,
    });
    let out = dir.join("fixture.json");
    std::fs::write(out, serde_json::to_string_pretty(&fixture).unwrap() + "\n").unwrap();
}
