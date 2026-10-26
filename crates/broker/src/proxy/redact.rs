//! Removing an API secret from upstream responses, in the encodings an
//! echoing server is likely to use.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use percent_encoding::{AsciiSet, CONTROLS, NON_ALPHANUMERIC, utf8_percent_encode};
use url::form_urlencoded::byte_serialize;
use zeroize::Zeroizing;

/// What every redacted region is replaced with.
pub const MARKER: &[u8] = b"[REDACTED]";

/// The byte strings to remove from a response: the secret and the injected
/// header value, each raw, in base64 (standard and URL-safe alphabets,
/// padded and unpadded), percent-encoded (upper- and lowercase hex) and
/// form-encoded. Longest first; wiped on drop; never printed.
pub struct Needles {
    list: Vec<Zeroizing<Vec<u8>>>,
}

/// The WHATWG URL "component percent-encode set" (what `encodeURIComponent`
/// style encoders produce): only reserved characters are encoded.
const COMPONENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'=')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'|')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b',');

impl Needles {
    /// The needles for `secret` and the header value built from it. Empty
    /// values are skipped. Every buffer is sized before it is filled, so no
    /// reallocation leaves an unwiped copy behind.
    #[must_use]
    pub fn new(secret: &str, header_value: &str) -> Self {
        let mut list = Vec::new();
        for value in [secret, header_value] {
            if value.is_empty() {
                continue;
            }
            list.push(Zeroizing::new(value.as_bytes().to_vec()));
            for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
                // `encode` writes into one buffer of the exact final size.
                list.push(Zeroizing::new(engine.encode(value).into_bytes()));
            }
            for set in [NON_ALPHANUMERIC, COMPONENT] {
                let upper = gather(value.len(), utf8_percent_encode(value, set));
                list.push(lowercase_hex(&upper));
                list.push(upper);
            }
            let form = gather(value.len(), byte_serialize(value.as_bytes()));
            list.push(lowercase_hex(&form));
            list.push(form);
        }
        // Longest first; equal needles end up adjacent and are dropped
        // (and wiped) by `dedup`.
        list.sort_unstable_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        list.dedup();
        Self { list }
    }

    /// The length of the longest needle that `data` starts with.
    fn longest_at(&self, data: &[u8]) -> Option<usize> {
        self.list
            .iter()
            .find(|needle| data.starts_with(needle.as_slice()))
            .map(|needle| needle.len())
    }
}

/// Concatenate percent-encoded chunks of a `len`-byte input into a buffer
/// sized for the worst case (every byte as `%XX`).
fn gather<'a>(len: usize, chunks: impl Iterator<Item = &'a str>) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(len.saturating_mul(3)));
    for chunk in chunks {
        out.extend_from_slice(chunk.as_bytes());
    }
    out
}

/// `encoded` with the two hex digits after every `%` in lowercase.
fn lowercase_hex(encoded: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(encoded.to_vec());
    let mut i = 0;
    while i < out.len() {
        if out[i] == b'%' {
            for digit in out.iter_mut().skip(i + 1).take(2) {
                digit.make_ascii_lowercase();
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    out
}

impl fmt::Debug for Needles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Needles({} redacted)", self.list.len())
    }
}

/// `data` with every occurrence of every needle replaced by [`MARKER`], and
/// the number of markers written.
///
/// Every byte covered by any occurrence of any needle is removed, whichever
/// needle matched first: occurrences that overlap (a needle inside a longer
/// one, or a periodic secret overlapping itself) merge into one region and
/// one marker, so no tail of a secret survives a shorter match. Occurrences
/// that only touch stay separate regions.
#[must_use]
pub fn redact(data: &[u8], needles: &Needles) -> (Vec<u8>, u32) {
    let mut out = Vec::with_capacity(data.len());
    let mut count = 0u32;
    let mut copied = 0;
    let mut region: Option<(usize, usize)> = None;
    let mut close = |out: &mut Vec<u8>, (start, end): (usize, usize)| {
        out.extend_from_slice(&data[copied..start]);
        out.extend_from_slice(MARKER);
        copied = end;
        count = count.saturating_add(1);
    };
    for at in 0..data.len() {
        let Some(len) = needles.longest_at(&data[at..]) else {
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

    const SECRET: &str = "s3cr3t/t0ken+with=odd&chars ~";

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
    }
}
