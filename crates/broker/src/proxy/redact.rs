//! Removing an API secret from upstream responses, in the encodings an
//! echoing server is likely to use.

use std::fmt;

use base64::Engine as _;
use base64::engine::GeneralPurpose;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

/// What every redacted region is replaced with.
pub const MARKER: &[u8] = b"[REDACTED]";

/// Shortest base64 middle part kept as a needle; shorter ones would match
/// unrelated base64 text too often.
const MIN_MIDDLE: usize = 8;

/// The secret and the injected header value in the forms a response may
/// carry them, matched byte by byte with per-byte escapes (see [`redact`]).
///
/// The base forms of each value are: the value itself; its base64 in the
/// standard and URL-safe alphabets, padded and unpadded; and, for each of the
/// three byte alignments the value can have inside a larger base64-encoded
/// blob, the base64 characters that encode only the value's bytes (dropped
/// when shorter than 8 characters). Wiped on drop; never printed.
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
                for offset in 0..3 {
                    // Skip to the first byte that starts a 3-byte group of
                    // the blob, and keep whole groups only: their characters
                    // depend on nothing but the value.
                    let skip = (3 - offset) % 3;
                    let Some(rest) = bytes.get(skip..) else {
                        continue;
                    };
                    let middle = encode(engine, &rest[..rest.len() / 3 * 3]);
                    if middle.len() >= MIN_MIDDLE {
                        list.push(middle);
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

/// Whether `data[at..]` spells needle byte `b`, and in how many bytes, in
/// each of the accepted forms: the byte itself (or `+` for a space), `%hh`,
/// `\/` for `/`, and `\u00hh` (hex in either case).
fn spellings(b: u8, rest: &[u8]) -> [Option<usize>; 4] {
    let first = rest.first().copied();
    [
        (first == Some(b) || (b == b' ' && first == Some(b'+'))).then_some(1),
        (first == Some(b'%') && hex_byte(rest.get(1..3)) == Some(b)).then_some(3),
        (b == b'/' && rest.starts_with(b"\\/")).then_some(2),
        (rest.starts_with(b"\\u00") && hex_byte(rest.get(4..6)) == Some(b)).then_some(6),
    ]
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
/// Each needle byte may appear as itself, as `%hh` (hex in either case), as
/// `+` for a space, as `\/` for `/` and as `\u00hh`, mixed freely within one
/// occurrence: this covers percent-encoding by any encoder, form encoding,
/// JSON escaping and percent-encoded base64.
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
    use base64::engine::GeneralPurpose;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    use proptest::collection::vec;
    use proptest::prelude::{
        ProptestConfig, any, prop_assert, prop_assert_eq, prop_assume, proptest,
    };

    use super::{MARKER, Needles, redact};

    /// Has `/`, space, `<>&~` raw, and `+`, `/`, `=` in its standard base64.
    const SECRET: &str = "s3cr3t/t0ken+with=odd&chars ~<>?~~>?>";

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

    /// `form` with each byte written as `choices[i] % 5` picks: raw, `%HH`,
    /// `%hh`, `\u00hh`, or `+`/`\/` for space/slash (`\u00HH` otherwise).
    fn encode_per_byte(form: &[u8], choices: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, &b) in form.iter().enumerate() {
            let piece = match choices.get(i).copied().unwrap_or(0) % 5 {
                0 => vec![b],
                1 => format!("%{b:02X}").into_bytes(),
                2 => format!("%{b:02x}").into_bytes(),
                3 => format!("\\u00{b:02x}").into_bytes(),
                _ => match b {
                    b' ' => b"+".to_vec(),
                    b'/' => b"\\/".to_vec(),
                    _ => format!("\\u00{b:02X}").into_bytes(),
                },
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

    /// The base64 characters that encode only `value`'s bytes when it sits
    /// at byte offset `offset` (mod 3) of a larger blob.
    fn aligned_middle(value: &[u8], offset: usize, engine: &GeneralPurpose) -> String {
        let skip = (3 - offset % 3) % 3;
        let whole = (value.len() - skip) / 3 * 3;
        engine.encode(&value[skip..skip + whole])
    }

    #[test]
    fn redact_base64_at_any_alignment() {
        let header = format!("Bearer {SECRET}");
        let needles = Needles::new(SECRET, &header);
        for value in [SECRET, header.as_str()] {
            for lead in 0..7 {
                let blob = [vec![b'{'; lead], value.as_bytes().to_vec(), b"}".to_vec()].concat();
                for (engine, plain) in
                    [(&STANDARD, &STANDARD_NO_PAD), (&URL_SAFE, &URL_SAFE_NO_PAD)]
                {
                    let data = format!("token={}", engine.encode(&blob));
                    let (out, count) = redact(data.as_bytes(), &needles);
                    let middle = aligned_middle(value.as_bytes(), lead, plain);
                    assert!(count >= 1, "{lead} {data}");
                    assert!(!contains(&out, middle.as_bytes()), "{lead} {data}");
                    assert!(out.starts_with(b"token="));
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
            secret in "[A-Za-z0-9!$&'()*+,./:;=?@_~ -]{12,40}",
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
            secret in "[A-Za-z0-9!$&'()*+,./:;=?@_~ -]{12,40}",
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
            secret in "[A-Za-z0-9!$&'()*+,./:;=?@_~ <>-]{12,40}",
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
