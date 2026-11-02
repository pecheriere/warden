//! Redaction of what an upstream echoes back. The property tests in
//! `redact.rs` use ASCII secrets of 12 to 40 bytes at one position. This adds
//! any UTF-8 secret, however short, several placements next to arbitrary bytes
//! that can overlap it, more spellings, base64 at any alignment with arbitrary
//! neighbours, and the header names and values of a whole response.
//!
//! The property: an occurrence of the secret, in any form `redact` documents,
//! never survives, wherever it is placed and however its bytes are spelled, and
//! nothing but occurrences is removed. Redaction matches contiguous occurrences
//! by design, so a secret with other bytes inserted into it is out of scope.
//!
//! Input: fields split on `0xFF`: secret, spelling choices, and three pieces of
//! surrounding data.

#![no_main]

use base64::Engine as _;
use base64::engine::GeneralPurpose;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use libfuzzer_sys::fuzz_target;
use warden_broker::proxy::redact::{MARKER, redact_name};
use warden_broker::proxy::{Needles, Upstream, redact, redact_response};
use warden_fuzz::{contains, fields, text};

const ENGINES: [&GeneralPurpose; 4] = [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD];

/// Shortest value whose base64 is matched at every alignment: shorter ones may
/// leave fewer than 8 fully determined characters.
const MIN_ALIGNED: usize = 12;

/// `form` with each byte written in a spelling the choices pick. Written from
/// the list in `redact`'s documentation, not from its code.
fn spell(form: &[u8], choices: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, &b) in form.iter().enumerate() {
        let choice = choices.get(i).copied().unwrap_or(0);
        let printable = (b' '..=b'~').contains(&b);
        let piece = match choice % 12 {
            1 => format!("%{b:02X}").into_bytes(),
            2 => format!("%{b:02x}").into_bytes(),
            3 => format!("\\u00{b:02x}").into_bytes(),
            4 => format!("\\u00{b:02X}").into_bytes(),
            5 if b == b' ' => b"+".to_vec(),
            6 if matches!(b, b'/' | b'"' | b'\\') => vec![b'\\', b],
            7 if b == b'&' => b"&amp;".to_vec(),
            7 if b == b'"' => b"&quot;".to_vec(),
            7 if b == b'<' => b"&lt;".to_vec(),
            7 if b == b'>' => b"&gt;".to_vec(),
            7 if b == b'\'' => b"&apos;".to_vec(),
            8 if printable => format!("&#{b};").into_bytes(),
            9 if printable => format!("&#x{b:x};").into_bytes(),
            10 if printable => format!("&#X{b:02X};").into_bytes(),
            // Leading zeros, up to the limit of 7 digits.
            11 if printable => format!("&#{b:07};").into_bytes(),
            _ => vec![b],
        };
        out.extend_from_slice(&piece);
    }
    out
}

/// The pieces of `out` around the markers.
fn segments(out: &[u8]) -> Vec<&[u8]> {
    let mut pieces = Vec::new();
    let mut start = 0;
    let mut at = 0;
    while at + MARKER.len() <= out.len() {
        if out[at..].starts_with(MARKER) {
            pieces.push(&out[start..at]);
            at += MARKER.len();
            start = at;
        } else {
            at += 1;
        }
    }
    pieces.push(&out[start..]);
    pieces
}

/// Nothing is left that matches, and what is left is the data's own bytes in
/// their original order: redaction removes, and invents nothing.
fn check_output(data: &[u8], out: &[u8], count: u32, needles: &Needles) {
    if count == 0 {
        assert_eq!(out, data);
    }
    let mut from = 0;
    for piece in segments(out) {
        assert_eq!(redact(piece, needles).1, 0, "an occurrence survived");
        if piece.is_empty() {
            continue;
        }
        let Some(found) = data[from..]
            .windows(piece.len())
            .position(|window| window == piece)
        else {
            panic!("the output holds bytes the data did not");
        };
        from += found + piece.len();
    }
}

/// The secret, spelled per byte, between arbitrary data, more than once.
fn check_placements(forms: &[Vec<u8>], choices: &[u8], around: [&[u8]; 3], needles: &Needles) {
    let [before, between, after] = around;
    for form in forms {
        let spelled = spell(form, choices);
        let data = [before, &spelled, between, &spelled, after].concat();
        let (out, count) = redact(&data, needles);
        assert!(count >= 1, "not redacted");
        assert!(contains(&out, MARKER));
        for piece in segments(&out) {
            assert!(!contains(piece, form), "the base form survived");
            assert!(!contains(piece, &spelled), "the spelled form survived");
        }
        check_output(&data, &out, count, needles);
    }
}

/// Inside a larger base64 blob, at any alignment and next to any bytes, no
/// byte of the value can be decoded from what is left around the markers.
fn check_aligned(value: &[u8], around: [&[u8]; 3], needles: &Needles) {
    if value.len() < MIN_ALIGNED {
        return;
    }
    let [lead, _, trail] = around;
    let blob = [lead, value, trail].concat();
    for engine in ENGINES {
        let encoded = engine.encode(&blob).into_bytes();
        let (out, count) = redact(&encoded, needles);
        assert!(count >= 1, "not redacted in a blob");
        // Base64 has no `[`, so every marker here is one redaction wrote.
        let pieces = segments(&out);
        let (Some(first), Some(last)) = (pieces.first(), pieces.last()) else {
            panic!("segments always returns a piece");
        };
        let head_bytes = first.len() * 6 / 8;
        let tail_first_byte = ((encoded.len() - last.len()) * 6).div_ceil(8);
        assert!(head_bytes <= lead.len(), "a decodable prefix survived");
        assert!(
            tail_first_byte >= lead.len() + value.len(),
            "a decodable suffix survived"
        );
    }
}

/// A whole response: no header name, header value or body keeps the secret.
fn check_response(secret: &str, spelled: &[u8], data: &[u8], needles: &Needles) {
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_bytes(spelled) {
        headers.append("x-echo", value);
    }
    if let Ok(value) = HeaderValue::from_bytes(data) {
        headers.append("x-data", value);
    }
    if let Ok(name) = HeaderName::from_bytes(secret.as_bytes()) {
        assert!(redact_name(name.as_str().as_bytes(), needles).1 >= 1);
        headers.append(name, HeaderValue::from_static("x"));
    }
    let upstream = Upstream {
        status: StatusCode::OK,
        headers,
        body: [data, spelled, data].concat(),
    };
    let response = redact_response(&upstream, needles);
    assert!(response.redactions >= 1, "the body held the secret");
    let raw = secret.as_bytes();
    // Header values go through a lossy UTF-8 conversion after redaction, which
    // can write U+FFFD itself; that is not the secret surviving.
    let lossy_can_match = secret.contains(char::REPLACEMENT_CHARACTER);
    for (name, value) in &response.headers {
        assert!(
            !contains(name.as_bytes(), secret.to_ascii_lowercase().as_bytes()),
            "a header name kept the secret"
        );
        for piece in segments(value.as_bytes()) {
            assert!(lossy_can_match || !contains(piece, raw), "a value kept it");
        }
    }
    let Ok(body) = STANDARD.decode(&response.body_b64) else {
        panic!("the body is valid base64");
    };
    for piece in segments(&body) {
        assert!(!contains(piece, raw), "the body kept the secret");
    }
}

fuzz_target!(|data: &[u8]| {
    let [secret, choices, before, between, after] = fields::<5>(data);
    let secret = text(secret);
    if secret.is_empty() {
        return;
    }
    let around = [before, between, after];
    let header = format!("Bearer {secret}");
    let needles = Needles::new(secret, &header);

    // Data with or without the secret: the invariants hold either way.
    let plain = [before, between, after].concat();
    let (out, count) = redact(&plain, &needles);
    check_output(&plain, &out, count, &needles);

    for value in [secret, header.as_str()] {
        let mut forms = vec![value.as_bytes().to_vec()];
        forms.extend(ENGINES.iter().map(|e| e.encode(value).into_bytes()));
        check_placements(&forms, choices, around, &needles);
        check_aligned(value.as_bytes(), around, &needles);
    }
    check_response(secret, &spell(secret.as_bytes(), choices), &plain, &needles);
});
