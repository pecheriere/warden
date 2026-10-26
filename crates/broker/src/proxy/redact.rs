//! Removing an API secret from upstream responses, in the encodings an
//! echoing server is likely to use.

use std::fmt;

use base64::Engine as _;
use base64::engine::GeneralPurpose;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

/// What every redacted region is replaced with.
pub const MARKER: &[u8] = b"[REDACTED]";

/// Shortest aligned base64 needle kept; shorter ones would match unrelated
/// base64 text too often.
const MIN_MIDDLE: usize = 8;

/// Most digits accepted in an HTML numeric character reference (leading
/// zeros included, as in `&#039;`).
const MAX_ENTITY_DIGITS: usize = 7;

/// The secret and the injected header value in the forms a response may
/// carry them, matched byte by byte with per-byte escapes (see [`redact`]).
///
/// The base forms of each value are:
/// - the value itself;
/// - its base64 in the standard and URL-safe alphabets, padded and unpadded;
/// - for each of the three byte positions the value can start at inside a
///   3-byte group of a larger base64-encoded blob, in both alphabets, every
///   base64 character fully determined by the value's bytes (dropped when
///   shorter than 8 characters). Only the one character on each side that
///   mixes value bits with neighbouring bytes is left: at most 4 bits of
///   the value per side (2 or 4 bits at the start, 2 or 4 at the end,
///   depending on alignment and length).
///
/// Wiped on drop; never printed.
pub struct Needles {
    list: Vec<Zeroizing<Vec<u8>>>,
}

impl Needles {
    /// The needles for `secret` and the header value built from it. Empty
    /// values are skipped. Each buffer is allocated once at its final size
    /// (`Engine::encode` sizes its output up front), so no reallocation
    /// leaves an unwiped copy behind.
    #[must_use]
    pub fn new(secret: &str, header_value: &str) -> Self {
        let mut list = Vec::new();
        for value in [secret, header_value] {
            let bytes = value.as_bytes();
            if bytes.is_empty() {
                continue;
            }
            list.push(Zeroizing::new(bytes.to_vec()));
            for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
                list.push(encode(engine, bytes));
            }
            for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
                for position in 0..3 {
                    if let Some(aligned) = aligned_base64(engine, bytes, position)
                        && aligned.len() >= MIN_MIDDLE
                    {
                        list.push(aligned);
                    }
                }
            }
        }
        // Equal needles end up adjacent and are dropped (and wiped) by
        // `dedup`.
        list.sort_unstable_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        list.dedup();
        Self { list }
    }

    /// The length of the longest occurrence of any needle at the start of
    /// `data`.
    fn longest_at(&self, data: &[u8], scratch: &mut Scratch) -> Option<usize> {
        self.list
            .iter()
            .filter_map(|needle| match_len(needle, data, scratch))
            .max()
    }
}

fn encode(engine: &GeneralPurpose, bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(engine.encode(bytes).into_bytes())
}

/// The base64 characters fully determined by `bytes` when they start at
/// byte `position` (0, 1 or 2) of a 3-byte group in a larger blob.
///
/// A group `b0 b1 b2` encodes as `c0 c1 c2 c3`, where `c0` holds 6 bits of
/// `b0`, `c1` 2 of `b0` and 4 of `b1`, `c2` 4 of `b1` and 2 of `b2`, and
/// `c3` 6 of `b2`. So at the head, starting at `b1` keeps `c2 c3` and
/// starting at `b2` keeps `c3`; at the tail, ending after `b0` keeps `c0`
/// and ending after `b1` keeps `c0 c1`. The value is placed in a zero-filled
/// buffer of whole groups, encoded, and the mixed characters cut off.
fn aligned_base64(
    engine: &GeneralPurpose,
    bytes: &[u8],
    position: usize,
) -> Option<Zeroizing<Vec<u8>>> {
    let end = position + bytes.len();
    let mut blob = Zeroizing::new(vec![0; end.div_ceil(3) * 3]);
    blob.get_mut(position..end)?.copy_from_slice(bytes);
    let chars = encode(engine, &blob);
    let head = if position == 0 { 0 } else { position + 1 };
    let tail = match end % 3 {
        0 => 0,
        rest => 4 - rest,
    };
    let kept = chars.get(head..chars.len().checked_sub(tail)?)?;
    Some(Zeroizing::new(kept.to_vec()))
}

impl fmt::Debug for Needles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Needles({} redacted)", self.list.len())
    }
}

/// Reused state sets of the matcher, so matching allocates only while the
/// sets grow.
#[derive(Default)]
struct Scratch {
    current: Vec<usize>,
    next: Vec<usize>,
}

/// Whether `rest` starts with a spelling of needle byte `b`, and in how
/// many bytes, for each accepted form (see [`redact`] for the list).
fn spellings(b: u8, rest: &[u8]) -> [Option<usize>; 6] {
    let first = rest.first().copied();
    let json_short = match (b, rest.get(..2)) {
        (b'/', Some(b"\\/")) | (b'"', Some(b"\\\"")) | (b'\\', Some(b"\\\\")) => Some(2),
        _ => None,
    };
    [
        (first == Some(b) || (b == b' ' && first == Some(b'+'))).then_some(1),
        (first == Some(b'%') && hex_byte(rest.get(1..3)) == Some(b)).then_some(3),
        json_short,
        (rest.starts_with(b"\\u00") && hex_byte(rest.get(4..6)) == Some(b)).then_some(6),
        html_named(b, rest),
        html_numeric(b, rest),
    ]
}

/// `&amp;`, `&quot;`, `&lt;`, `&gt;` or `&apos;` for the byte they name.
fn html_named(b: u8, rest: &[u8]) -> Option<usize> {
    let name: &[u8] = match b {
        b'&' => b"&amp;",
        b'"' => b"&quot;",
        b'<' => b"&lt;",
        b'>' => b"&gt;",
        b'\'' => b"&apos;",
        _ => return None,
    };
    rest.starts_with(name).then_some(name.len())
}

/// `&#NN;` (decimal) or `&#xHH;` / `&#XHH;` (hex, either case) for a
/// printable ASCII byte, with up to [`MAX_ENTITY_DIGITS`] digits.
fn html_numeric(b: u8, rest: &[u8]) -> Option<usize> {
    if !(b' '..=b'~').contains(&b) {
        return None;
    }
    let body = rest.strip_prefix(b"&#")?;
    let (radix, marker_len) = match body.first() {
        Some(b'x' | b'X') => (16, 1),
        _ => (10, 0),
    };
    let digits = body.get(marker_len..)?;
    let count = digits
        .iter()
        .take(MAX_ENTITY_DIGITS)
        .take_while(|d| char::from(**d).is_digit(radix))
        .count();
    if count == 0 || digits.get(count) != Some(&b';') {
        return None;
    }
    let value = digits[..count]
        .iter()
        .filter_map(|d| char::from(*d).to_digit(radix))
        .fold(0u32, |acc, d| acc * radix + d);
    (value == u32::from(b)).then_some(2 + marker_len + count + 1)
}

/// The byte two hex digits (either case) stand for.
fn hex_byte(digits: Option<&[u8]>) -> Option<u8> {
    let &[hi, lo] = digits? else {
        return None;
    };
    let value = |d: u8| {
        char::from(d)
            .to_digit(16)
            .and_then(|v| u8::try_from(v).ok())
    };
    Some(value(hi)? << 4 | value(lo)?)
}

/// The length of the longest spelling of `needle` at the start of `data`,
/// where each needle byte may be written in any form [`spellings`] accepts.
///
/// Forms can overlap (a needle `%` is both itself and the start of `%25`),
/// so this tracks every data offset reachable after each needle byte, a set
/// that stays tiny in practice. An offset whose first byte cannot start any
/// spelling of the needle's first byte is rejected in O(1).
fn match_len(needle: &[u8], data: &[u8], scratch: &mut Scratch) -> Option<usize> {
    let (&first, _) = needle.split_first()?;
    if spellings(first, data).iter().all(Option::is_none) {
        return None;
    }
    scratch.current.clear();
    scratch.current.push(0);
    for &b in needle {
        scratch.next.clear();
        for &at in &scratch.current {
            let rest = data.get(at..).unwrap_or_default();
            scratch
                .next
                .extend(spellings(b, rest).into_iter().flatten().map(|len| at + len));
        }
        if scratch.next.is_empty() {
            return None;
        }
        scratch.next.sort_unstable();
        scratch.next.dedup();
        std::mem::swap(&mut scratch.current, &mut scratch.next);
    }
    scratch.current.last().copied()
}

/// `data` with every occurrence of every needle replaced by [`MARKER`], and
/// the number of markers written.
///
/// Needles are the base forms listed on [`Needles`]: the raw secret and
/// header value, their base64 (standard and URL-safe, padded and unpadded)
/// and their alignment-independent base64 inside a larger blob. Each needle
/// byte may appear in any of these spellings, mixed freely within one
/// occurrence, and nothing else:
/// - the byte itself;
/// - percent-encoded `%hh`, hex in either case;
/// - `+` for a space;
/// - JSON `\/` for `/`, `\"` for `"`, `\\` for `\`, and `\u00hh` (hex in
///   either case) for any byte;
/// - HTML `&amp;`, `&quot;`, `&lt;`, `&gt;`, `&apos;` for the byte they name,
///   and `&#NN;` / `&#xHH;` (hex in either case, up to 7 digits) for any
///   printable ASCII byte.
///
/// Every byte covered by any occurrence of any needle is removed: occurrences
/// that overlap (a needle inside a longer one, or a periodic secret
/// overlapping itself) merge into one region and one marker, so no tail of a
/// secret survives a shorter match. Occurrences that only touch stay
/// separate regions.
///
/// Cost: for each offset and needle, an O(1) first-byte check; only offsets
/// that pass it walk the needle, so a response is scanned in
/// O(len × needles) plus O(needle length) per candidate offset. With about
/// twenty needles of a few dozen bytes, 1 MiB is a few tens of millions of
/// cheap steps at worst.
#[must_use]
pub fn redact(data: &[u8], needles: &Needles) -> (Vec<u8>, u32) {
    let mut out = Vec::with_capacity(data.len());
    let mut count = 0u32;
    let mut copied = 0;
    let mut region: Option<(usize, usize)> = None;
    let mut scratch = Scratch::default();
    let mut close = |out: &mut Vec<u8>, (start, end): (usize, usize)| {
        out.extend_from_slice(&data[copied..start]);
        out.extend_from_slice(MARKER);
        copied = end;
        count = count.saturating_add(1);
    };
    for at in 0..data.len() {
        let Some(len) = needles.longest_at(&data[at..], &mut scratch) else {
            continue;
        };
        let end = at + len;
        region = match region {
            Some((start, region_end)) if at < region_end => Some((start, region_end.max(end))),
            Some(done) => {
                close(&mut out, done);
                Some((at, end))
            }
            None => Some((at, end)),
        };
    }
    if let Some(done) = region {
        close(&mut out, done);
    }
    out.extend_from_slice(&data[copied..]);
    (out, count)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    use proptest::collection::vec;
    use proptest::prelude::{
        ProptestConfig, any, prop_assert, prop_assert_eq, prop_assume, proptest,
    };

    use super::{MARKER, Needles, redact};

    /// Has `/`, space, `<>&~` raw, and `+`, `/`, `=` in its standard base64.
    const SECRET: &str = "s3cr3t/t0ken+with=odd&chars ~<>?~~>?>";

    /// Has the characters JSON and HTML escape by name: `"`, `\`, `'`, `<`,
    /// `&`, `>`, `/`.
    const QUOTED: &str = "abc\"def\\ghij12'<&>/ x";

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Every encoding the response may carry, computed independently of the
    /// implementation.
    fn encodings(value: &str) -> Vec<String> {
        let upper = utf8_percent_encode(value, NON_ALPHANUMERIC).to_string();
        let lower = lowercase_hex(&upper);
        let form: String = url::form_urlencoded::byte_serialize(value.as_bytes()).collect();
        vec![
            value.to_owned(),
            STANDARD.encode(value),
            STANDARD_NO_PAD.encode(value),
            URL_SAFE.encode(value),
            URL_SAFE_NO_PAD.encode(value),
            lower,
            upper,
            lowercase_hex(&form),
            form,
        ]
    }

    fn lowercase_hex(encoded: &str) -> String {
        let mut out = String::with_capacity(encoded.len());
        let mut hex_left = 0;
        for c in encoded.chars() {
            if hex_left > 0 {
                out.push(c.to_ascii_lowercase());
                hex_left -= 1;
            } else {
                if c == '%' {
                    hex_left = 2;
                }
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn redact_raw_base64_variants_and_percent() {
        let header = format!("Bearer {SECRET}");
        let needles = Needles::new(SECRET, &header);
        for value in [SECRET, header.as_str()] {
            for enc in encodings(value) {
                let data = format!("before {enc} after");
                let (out, count) = redact(data.as_bytes(), &needles);
                assert_eq!(
                    out,
                    [b"before ".as_slice(), MARKER, b" after"].concat(),
                    "{enc}"
                );
                assert_eq!(count, 1, "{enc}");
            }
        }
        // Encoding only the reserved characters (as URL builders do) is
        // caught as well.
        let reserved_only = SECRET
            .replace('/', "%2F")
            .replace('+', "%2B")
            .replace('=', "%3D")
            .replace('&', "%26")
            .replace(' ', "%20");
        let (out, count) = redact(reserved_only.as_bytes(), &needles);
        assert_eq!((out.as_slice(), count), (MARKER, 1));
    }

    /// The base forms: raw, and base64 in both alphabets, padded or not.
    fn base_forms(value: &str) -> Vec<String> {
        vec![
            value.to_owned(),
            STANDARD.encode(value),
            STANDARD_NO_PAD.encode(value),
            URL_SAFE.encode(value),
            URL_SAFE_NO_PAD.encode(value),
        ]
    }

    /// `form` with each byte written as `choices[i] % 7` picks: raw, `%HH`,
    /// `%hh`, `\u00hh`, a named escape (`+` for space, JSON `\/ \" \\`, HTML
    /// `&amp; &lt; &gt; &#39;`; `\u00HH` otherwise), `&#NN;` or `&#xHH;`.
    fn encode_per_byte(form: &[u8], choices: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, &b) in form.iter().enumerate() {
            let piece = match choices.get(i).copied().unwrap_or(0) % 7 {
                0 => vec![b],
                1 => format!("%{b:02X}").into_bytes(),
                2 => format!("%{b:02x}").into_bytes(),
                3 => format!("\\u00{b:02x}").into_bytes(),
                4 => match b {
                    b' ' => b"+".to_vec(),
                    b'/' => b"\\/".to_vec(),
                    b'"' => b"\\\"".to_vec(),
                    b'\\' => b"\\\\".to_vec(),
                    b'&' => b"&amp;".to_vec(),
                    b'<' => b"&lt;".to_vec(),
                    b'>' => b"&gt;".to_vec(),
                    b'\'' => b"&#39;".to_vec(),
                    _ => format!("\\u00{b:02X}").into_bytes(),
                },
                5 => format!("&#{b};").into_bytes(),
                _ => format!("&#x{b:X};").into_bytes(),
            };
            out.extend_from_slice(&piece);
        }
        out
    }

    fn assert_redacted_once(needles: &Needles, enc: &[u8]) {
        let data = [b"before ".as_slice(), enc, b" after"].concat();
        let (out, count) = redact(&data, needles);
        assert_eq!(
            out,
            [b"before ".as_slice(), MARKER, b" after"].concat(),
            "{}",
            String::from_utf8_lossy(enc)
        );
        assert_eq!(count, 1, "{}", String::from_utf8_lossy(enc));
    }

    #[test]
    fn redact_json_escaped_slash_and_unicode_forms() {
        let header = format!("Bearer {SECRET}");
        let needles = Needles::new(SECRET, &header);
        for value in [SECRET, header.as_str()] {
            for form in base_forms(value) {
                // PHP json_encode: `/` as `\/`.
                assert_redacted_once(&needles, form.replace('/', "\\/").as_bytes());
                // Go encoding/json: `<`, `>`, `&` (and `+` in some
                // encoders) as `\u00hh`, either hex case.
                let go = form
                    .replace('<', "\\u003c")
                    .replace('>', "\\u003E")
                    .replace('&', "\\u0026")
                    .replace('+', "\\u002b");
                assert_redacted_once(&needles, go.as_bytes());
            }
        }
        // `"` as `\"` and `\` as `\\` (every JSON encoder).
        let header = format!("Bearer {QUOTED}");
        let needles = Needles::new(QUOTED, &header);
        for value in [QUOTED, header.as_str()] {
            let json = value.replace('\\', "\\\\").replace('"', "\\\"");
            assert_redacted_once(&needles, json.as_bytes());
            assert_redacted_once(&needles, json.replace('/', "\\/").as_bytes());
        }
    }

    /// `value` with every byte written by `spell`.
    fn per_byte(value: &str, spell: fn(u8) -> String) -> String {
        let mut out = String::new();
        for b in value.bytes() {
            out.push_str(&spell(b));
        }
        out
    }

    #[test]
    fn redact_html_entity_forms() {
        let header = format!("Bearer {QUOTED}");
        let needles = Needles::new(QUOTED, &header);
        for value in [QUOTED, header.as_str()] {
            // `&` first, so the other entities are not escaped again.
            let named = value
                .replace('&', "&amp;")
                .replace('"', "&quot;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('\'', "&#39;");
            let apos = value.replace('\'', "&apos;").replace('"', "&#034;");
            let decimal = per_byte(value, |b| format!("&#{b};"));
            let hex_lower = per_byte(value, |b| format!("&#x{b:x};"));
            let hex_upper = per_byte(value, |b| format!("&#X{b:02X};"));
            for enc in [named, apos, decimal, hex_lower, hex_upper] {
                assert_redacted_once(&needles, enc.as_bytes());
            }
        }
    }

    #[test]
    fn redact_mixed_case_and_plus_percent_forms() {
        let header = format!("Bearer {SECRET}");
        let needles = Needles::new(SECRET, &header);
        // Mixed hex case within one value, `~` both raw and encoded, space
        // as `+`.
        let mixed = SECRET
            .replace('/', "%2f")
            .replace('+', "%2B")
            .replace('=', "%3d")
            .replace('&', "%26")
            .replace(' ', "+")
            .replace('<', "%3C")
            .replace('>', "%3e");
        assert_redacted_once(&needles, mixed.as_bytes());
        let tilde = SECRET.replace('~', "%7E").replace(' ', "%20");
        assert_redacted_once(&needles, tilde.as_bytes());
        let header_form = header.replace(' ', "+").replace('/', "%2F");
        assert_redacted_once(&needles, header_form.as_bytes());
    }

    #[test]
    fn redact_percent_encoded_base64() {
        let header = format!("Bearer {SECRET}");
        let needles = Needles::new(SECRET, &header);
        for value in [SECRET, header.as_str()] {
            let b64 = STANDARD.encode(value);
            for (plus, slash, eq) in [("%2B", "%2F", "%3D"), ("%2b", "%2f", "%3d")] {
                let enc = b64.replace('+', plus).replace('/', slash).replace('=', eq);
                assert_redacted_once(&needles, enc.as_bytes());
            }
        }
    }

    /// After redacting a base64 blob that embeds the value at every byte
    /// alignment, with and without trailing bytes and padding, no byte of
    /// the value can be decoded from the characters left on either side of
    /// the marker: those characters determine only bytes outside the value.
    #[test]
    fn redact_base64_at_any_alignment() {
        let header = format!("Bearer {SECRET}");
        let needles = Needles::new(SECRET, &header);
        for value in [SECRET, header.as_str()] {
            for lead in 0..6 {
                for trail in 0..4 {
                    let blob = [
                        vec![b'{'; lead],
                        value.as_bytes().to_vec(),
                        vec![b'}'; trail],
                    ]
                    .concat();
                    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
                        let encoded = engine.encode(&blob);
                        let data = format!("token={encoded}").into_bytes();
                        let (out, count) = redact(&data, &needles);
                        let ctx = format!("lead {lead} trail {trail}: {encoded}");
                        assert_eq!(count, 1, "{ctx}");
                        let start = out.windows(MARKER.len()).position(|w| w == MARKER).unwrap();
                        let end = data.len() - (out.len() - start - MARKER.len());
                        assert!(start >= "token=".len(), "{ctx}");
                        // Characters kept before the marker, and the index of
                        // the first one kept after it, in `encoded`.
                        let (head_chars, tail_from) = (start - 6, end - 6);
                        // Bytes of the blob fully determined by them.
                        let head_bytes = head_chars * 6 / 8;
                        let tail_first_byte = (tail_from * 6).div_ceil(8);
                        assert!(head_bytes <= lead, "decodable secret prefix: {ctx}");
                        assert!(
                            tail_first_byte >= lead + value.len(),
                            "decodable secret suffix: {ctx}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn redact_counts_occurrences() {
        let needles = Needles::new(SECRET, &format!("Bearer {SECRET}"));
        let data = format!(
            "{SECRET}{SECRET} x Bearer {SECRET} y {} z {SECRET}",
            STANDARD.encode(SECRET)
        );
        let (out, count) = redact(data.as_bytes(), &needles);
        // Adjacent copies are two regions; the header value covers its
        // secret, so it is one region.
        assert_eq!(count, 5);
        let expected = [
            MARKER, MARKER, b" x ", MARKER, b" y ", MARKER, b" z ", MARKER,
        ]
        .concat();
        assert_eq!(out, expected);

        let (out, count) = redact(b"nothing here", &needles);
        assert_eq!((out.as_slice(), count), (b"nothing here".as_slice(), 0));
        let (out, count) = redact(b"", &needles);
        assert_eq!((out.as_slice(), count), (b"".as_slice(), 0));
    }

    #[test]
    fn redact_overlapping_occurrences_leave_no_part() {
        // A periodic secret overlaps itself; no tail of it may survive.
        let needles = Needles::new("abababababab", "Bearer abababababab");
        let (out, count) = redact(b"x abababababababab y", &needles);
        assert_eq!(out, [b"x ".as_slice(), MARKER, b" y"].concat());
        assert_eq!(count, 1);
    }

    #[test]
    fn needles_debug_hides_values() {
        let needles = Needles::new(SECRET, "Bearer x");
        let shown = format!("{needles:?}");
        assert!(!shown.contains("s3cr3t"));
        assert!(shown.starts_with("Needles("));
    }

    proptest! {
        #![proptest_config(ProptestConfig::default())]

        #[test]
        fn redact_never_changes_data_without_secret(
            secret in "[A-Za-z0-9!$&'()*+,./:;=?@_~ \"\\\\-]{12,40}",
            data in vec(any::<u8>(), 0..512),
        ) {
            let header = format!("Bearer {secret}");
            let needles = Needles::new(&secret, &header);
            for value in [secret.as_str(), header.as_str()] {
                for enc in encodings(value) {
                    prop_assume!(!contains(&data, enc.as_bytes()));
                }
            }
            let (out, count) = redact(&data, &needles);
            prop_assert_eq!(out, data);
            prop_assert_eq!(count, 0);
        }

        #[test]
        fn redact_removes_secret_anywhere(
            secret in "[A-Za-z0-9!$&'()*+,./:;=?@_~ \"\\\\-]{12,40}",
            prefix in vec(any::<u8>(), 0..64),
            suffix in vec(any::<u8>(), 0..64),
        ) {
            let header = format!("Bearer {secret}");
            let needles = Needles::new(&secret, &header);
            for value in [secret.as_str(), header.as_str()] {
                for enc in encodings(value) {
                    let data = [prefix.as_slice(), enc.as_bytes(), suffix.as_slice()].concat();
                    let (out, count) = redact(&data, &needles);
                    prop_assert!(count >= 1);
                    prop_assert!(!contains(&out, enc.as_bytes()));
                    prop_assert!(!contains(&out, secret.as_bytes()));
                    prop_assert!(contains(&out, MARKER));
                }
            }
        }

        #[test]
        fn redact_removes_per_byte_mixed_encodings(
            secret in "[A-Za-z0-9!$&'()*+,./:;=?@_~ <>\"\\\\-]{12,40}",
            choices in vec(any::<u8>(), 64..=64),
            prefix in vec(any::<u8>(), 0..32),
            suffix in vec(any::<u8>(), 0..32),
        ) {
            let header = format!("Bearer {secret}");
            let needles = Needles::new(&secret, &header);
            for value in [secret.as_str(), header.as_str()] {
                for form in base_forms(value) {
                    let enc = encode_per_byte(form.as_bytes(), &choices);
                    let data = [prefix.as_slice(), &enc, suffix.as_slice()].concat();
                    let (out, count) = redact(&data, &needles);
                    prop_assert!(count >= 1);
                    prop_assert!(!contains(&out, &enc));
                    prop_assert!(!contains(&out, secret.as_bytes()));
                }
            }
        }
    }
}
