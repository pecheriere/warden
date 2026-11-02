//! Public key lines agents submit at enrollment and login: the key-type policy
//! and the SSH public key parser under it.
//!
//! Input: the first byte picks the form of the rest. `0` to `3`: a line with
//! that key type and the rest as its base64 blob, so mutations reach the wire
//! format decoder. Otherwise: the line as sent.

#![no_main]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use libfuzzer_sys::fuzz_target;
use warden_broker::agents::AgentPublicKey;
use warden_broker_proto::signing::{PUBLISHED_TEST_KEYS, SigningKeyError, SigningPublicKey};

const TYPES: [&str; 4] = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ssh-rsa",
];

fn check_accepted(line: &str, key: &SigningPublicKey) {
    let openssh = key.openssh();
    assert!(!PUBLISHED_TEST_KEYS.contains(&openssh));
    assert!(!line.trim().chars().any(char::is_control));
    // Normalised: the type and the blob, with no comment or stray text.
    let mut words = openssh.split(' ');
    assert!(matches!(
        words.next(),
        Some("ssh-ed25519" | "ecdsa-sha2-nistp256")
    ));
    assert!(words.next().is_some_and(|blob| !blob.is_empty()));
    assert_eq!(words.next(), None);
    let Ok(again) = SigningPublicKey::parse(openssh) else {
        panic!("a normalised key parses");
    };
    assert_eq!(&again, key);
    assert!(key.fingerprint().starts_with("SHA256:"));
    let Ok(agent) = AgentPublicKey::parse(line) else {
        panic!("the broker and the shared policy disagree");
    };
    assert_eq!(agent.openssh(), openssh);
    assert_eq!(agent.fingerprint(), key.fingerprint());
}

fn check_line(line: &str) {
    match SigningPublicKey::parse(line) {
        Ok(key) => check_accepted(line, &key),
        Err(refusal) => {
            // The one refusal that repeats input: it is short and printable.
            if let SigningKeyError::Unsupported(shown) = &refusal {
                assert!(shown.len() <= 64);
                assert!(shown.bytes().all(|b| b.is_ascii_graphic()));
            }
            assert!(AgentPublicKey::parse(line).is_err());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((form, rest)) = data.split_first() else {
        return;
    };
    if let Some(kind) = TYPES.get(usize::from(*form)) {
        check_line(&format!("{kind} {}", STANDARD.encode(rest)));
    } else if let Ok(line) = std::str::from_utf8(rest) {
        check_line(line);
    }
});
