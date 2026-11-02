//! A `Warden-Signature` value: its base64, the SSHSIG blob inside and the
//! signature check, run before the signer is trusted.
//!
//! Input: the first byte picks the form of the rest. Even: the bytes of the
//! blob, base64-encoded here so mutations reach the SSHSIG decoder. Odd: the
//! header value as sent.

#![no_main]

use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use ssh_key::PublicKey;
use warden_broker::signed::fuzzing::signature_accepted;

/// The protocol's published test vectors; the key protects nothing.
const VECTORS: &str = include_str!("../../crates/proto/tests/fixtures/signing-v1.json");

struct Fixture {
    ed25519: PublicKey,
    p256: PublicKey,
    message: String,
    signature: String,
}

fn key(value: &Value) -> Option<PublicKey> {
    PublicKey::from_openssh(value.as_str()?).ok()
}

fn load() -> Option<Fixture> {
    let vectors: Value = serde_json::from_str(VECTORS).ok()?;
    let vector = &vectors["vectors"][0];
    Some(Fixture {
        ed25519: key(&vectors["public_key"])?,
        p256: key(&vectors["ecdsa_p256"]["public_key"])?,
        message: vector["message"].as_str()?.to_owned(),
        signature: vector["signature"].as_str()?.to_owned(),
    })
}

/// The vector, checked to be accepted, so that the property below cannot hold
/// only because nothing is ever accepted.
static FIXTURE: LazyLock<Option<Fixture>> = LazyLock::new(|| {
    load().filter(|fixture| {
        signature_accepted(
            &fixture.signature,
            &fixture.ed25519,
            fixture.message.as_bytes(),
        )
    })
});

fuzz_target!(|data: &[u8]| {
    let Some(fixture) = FIXTURE.as_ref() else {
        panic!("the test vector no longer verifies");
    };
    let Some((form, rest)) = data.split_first() else {
        return;
    };
    let value = if form % 2 == 0 {
        STANDARD.encode(rest)
    } else {
        let Ok(value) = std::str::from_utf8(rest) else {
            return;
        };
        value.to_owned()
    };
    let message = fixture.message.as_bytes();

    // Without the private key no new Ed25519 signature can be made, and an
    // accepted one has a single encoding: only the vector itself may pass.
    if signature_accepted(&value, &fixture.ed25519, message) {
        assert_eq!(value, fixture.signature);
    }
    // ECDSA signatures are malleable, so a second encoding would not be a bug;
    // this only exercises the P-256 path.
    let _accepted = signature_accepted(&value, &fixture.p256, message);
});
