//! The validated types agents send: names, identifiers, goals and the
//! `CreateRequest` JSON body. Each must accept exactly what its documentation
//! says, and deserializing must not get past the check.
//!
//! Input: the text to validate, also read as a JSON body.

#![no_main]

use libfuzzer_sys::fuzz_target;
use warden_broker_proto::signing::{Audience, Nonce};
use warden_broker_proto::{
    Access, AgentName, CreateRequest, Fingerprint, Goal, Id, SecretName, TargetName, UnixUser,
    Window, fingerprint, is_read_only, modifying_methods,
};

/// `^[a-z0-9][a-z0-9-]{0,31}$`
fn is_resource_name(s: &str) -> bool {
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    (1..=32).contains(&s.len())
        && s.bytes().next().is_some_and(alnum)
        && s.bytes().all(|b| alnum(b) || b == b'-')
}

/// `^[a-z_][a-z0-9_-]{0,31}$`
fn is_unix_user(s: &str) -> bool {
    let head = |b: u8| b.is_ascii_lowercase() || b == b'_';
    (1..=32).contains(&s.len())
        && s.bytes().next().is_some_and(head)
        && s.bytes()
            .all(|b| head(b) || b.is_ascii_digit() || b == b'-')
}

fn is_hex32(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `xxxx-xxxx-xxxx`
fn is_fingerprint(s: &str) -> bool {
    s.len() == 14
        && s.bytes().enumerate().all(|(i, b)| {
            if i == 4 || i == 9 {
                b == b'-'
            } else {
                matches!(b, b'0'..=b'9' | b'a'..=b'f')
            }
        })
}

/// A JSON string decodes to the same result as `TryFrom`.
macro_rules! check_json {
    ($ty:ty, $text:expr, $parsed:expr) => {{
        if let Ok(json) = serde_json::to_string($text) {
            let decoded = serde_json::from_str::<$ty>(&json);
            assert_eq!(decoded.ok(), $parsed.ok());
        }
    }};
}

/// The check, through both ways in: `TryFrom` and deserialization. What is
/// accepted is kept as it was sent.
macro_rules! check_exact {
    ($ty:ty, $spec:expr, $text:expr) => {{
        let text: &str = $text;
        let parsed = <$ty>::try_from(text.to_owned());
        assert_eq!(parsed.is_ok(), $spec(text), "{}: {text:?}", stringify!($ty));
        if let Ok(parsed) = &parsed {
            assert_eq!(parsed.as_str(), text);
        }
        check_json!($ty, text, parsed);
    }};
}

/// Invisible format characters a goal may never hold: a subset of category Cf,
/// listed here so the check does not use the code's Unicode tables.
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{ad}' | '\u{600}'..='\u{605}' | '\u{61c}' | '\u{6dd}' | '\u{70f}' | '\u{180e}'
        | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206f}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}'
        | '\u{e0001}' | '\u{e0020}'..='\u{e007f}')
}

fn check_goal(text: &str) {
    let parsed = Goal::try_from(text.to_owned());
    let trimmed = text.trim();
    if let Ok(goal) = &parsed {
        let stored = goal.as_str();
        assert_eq!(stored, trimmed);
        assert!((1..=500).contains(&stored.chars().count()));
        assert!(!stored.chars().any(|c| c.is_control() || is_invisible(c)));
    } else {
        // Plain text of an allowed length is never refused.
        assert!(
            trimmed.is_empty()
                || trimmed.chars().count() > 500
                || !trimmed.chars().all(|c| c.is_ascii_graphic() || c == ' '),
            "{text:?}"
        );
    }
    check_json!(Goal, text, parsed);
}

fn check_window(text: &str) {
    let listed = matches!(text, "15m" | "30m" | "1h" | "4h");
    assert_eq!(text.parse::<Window>().is_ok(), listed, "{text:?}");
}

/// A body that parses survives a round trip, can be fingerprinted and has
/// consistent method warnings.
fn check_request(data: &[u8]) {
    let Ok(request) = serde_json::from_slice::<CreateRequest>(data) else {
        return;
    };
    let Ok(json) = serde_json::to_vec(&request) else {
        panic!("wire types always serialize");
    };
    let Ok(again) = serde_json::from_slice::<CreateRequest>(&json) else {
        panic!("a serialized request parses");
    };
    assert_eq!(again, request);
    let Ok(agent) = AgentName::try_from("build-agent".to_owned()) else {
        panic!("the fixed agent name is valid");
    };
    let digest = fingerprint(&agent, &request);
    assert!(is_fingerprint(digest.as_str()));
    assert_eq!(fingerprint(&agent, &again), digest);
    if let Access::Api {
        methods: Some(methods),
        ..
    } = &request.access
    {
        assert_eq!(is_read_only(methods), modifying_methods(methods).is_empty());
    }
}

fuzz_target!(|data: &[u8]| {
    check_request(data);
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    check_exact!(AgentName, is_resource_name, text);
    check_exact!(TargetName, is_resource_name, text);
    check_exact!(SecretName, is_resource_name, text);
    check_exact!(UnixUser, is_unix_user, text);
    check_exact!(Id, is_hex32, text);
    check_exact!(Nonce, is_hex32, text);
    check_exact!(Audience, is_hex32, text);
    check_exact!(Fingerprint, is_fingerprint, text);
    check_goal(text);
    check_window(text);
});
