//! The `Warden-*` headers of a signed request, parsed before the agent is
//! authenticated, and the canonical message built from them.
//!
//! Input: fields split on `0xFF`: agent, timestamp, nonce, signature, extra
//! header name, extra header value, method, target.

#![no_main]

use http::{HeaderMap, HeaderName, HeaderValue};
use libfuzzer_sys::fuzz_target;
use warden_broker::signed::{fuzzing, has_signing_headers};
use warden_broker_proto::AgentName;
use warden_broker_proto::signing::{
    AGENT_HEADER, Audience, MAX_TARGET_LEN, NONCE_HEADER, Nonce, SIGNATURE_HEADER,
    SignedRequestParts, TIMESTAMP_HEADER, canonical_message, parse_timestamp,
};
use warden_fuzz::{fields, text};

const AUDIENCE: &str = "40ad20029e94984d193159667b296d8a";
const NONCE: &str = "ee517b64804ef8916b8386eeaa436de0";
const SIGNING_HEADERS: [&str; 4] = [
    AGENT_HEADER,
    TIMESTAMP_HEADER,
    NONCE_HEADER,
    SIGNATURE_HEADER,
];

/// The timestamp spelling the protocol allows, checked without its parser.
fn canonical_timestamp(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
        && value
            .parse::<i128>()
            .is_ok_and(|n| n <= i128::from(i64::MAX))
}

fn check_parsed_headers(headers: &HeaderMap) {
    let Some((agent, timestamp, nonce)) = fuzzing::parse_headers(headers) else {
        return;
    };
    assert!(has_signing_headers(headers));
    assert!(!headers.contains_key("authorization"));
    for name in SIGNING_HEADERS {
        assert_eq!(headers.get_all(name).iter().count(), 1, "{name}");
    }
    assert!(headers.keys().all(|name| {
        !name.as_str().starts_with("warden-")
            || SIGNING_HEADERS
                .iter()
                .any(|known| name.as_str().eq_ignore_ascii_case(known))
    }));
    let value = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    // What was parsed is what was sent, byte for byte: the signature covers it.
    assert_eq!(value(AGENT_HEADER), Some(agent.as_str()));
    assert_eq!(value(NONCE_HEADER), Some(nonce.as_str()));
    assert_eq!(
        value(TIMESTAMP_HEADER),
        Some(timestamp.to_string().as_str())
    );
}

fn check_timestamp(value: &str) {
    match parse_timestamp(value) {
        Ok(parsed) => {
            assert!(canonical_timestamp(value));
            assert_eq!(parsed.to_string(), value);
        }
        Err(_) => assert!(!canonical_timestamp(value)),
    }
}

/// No field can forge a line of the signed message: an accepted one always
/// gives the same eight lines, with each field in its own.
fn check_canonical_message(agent: &AgentName, method: &str, target: &str, timestamp: i64) {
    let (Ok(audience), Ok(nonce)) = (
        Audience::try_from(AUDIENCE.to_owned()),
        Nonce::try_from(NONCE.to_owned()),
    ) else {
        panic!("the fixed audience and nonce are valid");
    };
    let message = canonical_message(&SignedRequestParts {
        audience: &audience,
        agent,
        method,
        target,
        timestamp,
        nonce: &nonce,
        body_sha256: [0xab; 32],
    });
    let Ok(message) = message else {
        return;
    };
    assert!(timestamp >= 0);
    assert!(!method.is_empty() && method.bytes().all(|b| b.is_ascii_graphic()));
    assert!(target.starts_with('/') && target.len() <= MAX_TARGET_LEN);
    assert!(target.bytes().all(|b| b.is_ascii_graphic() && b != b'#'));
    let body = "ab".repeat(32);
    let expected = format!(
        "warden-request-v1\naudience:{AUDIENCE}\nagent:{agent}\nmethod:{method}\n\
         target:{target}\ntimestamp:{timestamp}\nnonce:{NONCE}\nbody-sha256:{body}\n"
    );
    assert_eq!(message, expected);
    assert_eq!(message.matches('\n').count(), 8);
}

fuzz_target!(|data: &[u8]| {
    let [
        agent,
        timestamp,
        nonce,
        signature,
        name,
        value,
        method,
        target,
    ] = fields::<8>(data);

    let mut headers = HeaderMap::new();
    for (header, field) in SIGNING_HEADERS
        .into_iter()
        .zip([agent, timestamp, nonce, signature])
    {
        // An empty field stands for a missing header.
        if !field.is_empty()
            && let (Ok(header), Ok(field)) = (
                HeaderName::from_bytes(header.as_bytes()),
                HeaderValue::from_bytes(field),
            )
        {
            headers.append(header, field);
        }
    }
    if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name), HeaderValue::from_bytes(value)) {
        headers.append(name, value);
    }
    check_parsed_headers(&headers);

    check_timestamp(text(timestamp));
    let parsed = parse_timestamp(text(timestamp)).unwrap_or(-1);
    let agent = AgentName::try_from(text(agent).to_owned())
        .or_else(|_| AgentName::try_from("build-agent".to_owned()));
    if let Ok(agent) = agent {
        check_canonical_message(&agent, text(method), text(target), parsed);
    }
});
