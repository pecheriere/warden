//! Free text cut to a bound before it goes into an audit entry.
//!
//! The log is append-only and never rotated, so the size of every entry must be
//! bounded for the per-day bounds of the threat model to hold. Messages whose
//! length an agent, a request or an upstream answer sets (a refusal, an error) are
//! cut here where their entry is built; [`MAX_LINE_BYTES`](super::MAX_LINE_BYTES)
//! is only the last resort.

/// Longest text recorded, in bytes as the log writes it: JSON-escaped, so that a
/// control character counts for the 6 bytes of its `\u00XX` escape. The marker
/// [`TRUNCATED`] comes on top.
const MAX_TEXT_BYTES: usize = 512;

/// Appended to text that was cut to [`MAX_TEXT_BYTES`].
const TRUNCATED: &str = " (truncated)";

/// `text` as recorded: whole if it takes at most [`MAX_TEXT_BYTES`] once
/// JSON-escaped, otherwise cut on a character boundary to that much and marked
/// with [`TRUNCATED`]. The longest result takes `MAX_TEXT_BYTES + TRUNCATED.len()`
/// bytes in the log.
pub(crate) fn bounded_text(mut text: String) -> String {
    let mut written = 0_usize;
    let cut = text.char_indices().find_map(|(at, c)| {
        written = written.saturating_add(escaped_len(c));
        (written > MAX_TEXT_BYTES).then_some(at)
    });
    if let Some(at) = cut {
        text.truncate(at);
        text.push_str(TRUNCATED);
    }
    text
}

/// The bytes `c` takes inside a JSON string as `serde_json` writes it: a short
/// escape for `"`, `\` and five control characters, `\u00XX` for the other
/// control characters below U+0020, and its UTF-8 bytes otherwise.
const fn escaped_len(c: char) -> usize {
    match c {
        '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
        '\u{0}'..='\u{1f}' => 6,
        _ => c.len_utf8(),
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_TEXT_BYTES, TRUNCATED, bounded_text, escaped_len};

    /// Bytes `text` takes in the log, without the quotes around it.
    fn written(text: &str) -> usize {
        serde_json::to_string(text).unwrap().len() - 2
    }

    #[test]
    fn escaped_len_matches_serde_json() {
        let samples = (0..=0x80_u32)
            .chain([0x7ff, 0x800, 0x2028, 0xffff, 0x1_0000, 0x10_ffff])
            .filter_map(char::from_u32);
        for c in samples {
            assert_eq!(escaped_len(c), written(&c.to_string()), "{c:?}");
        }
    }

    #[test]
    fn text_within_the_bound_is_kept_whole() {
        assert_eq!(bounded_text("ok".to_owned()), "ok");
        let fits = "a".repeat(MAX_TEXT_BYTES);
        assert_eq!(bounded_text(fits.clone()), fits);
        let escaped = "\u{1}".repeat(MAX_TEXT_BYTES / 6);
        assert_eq!(bounded_text(escaped.clone()), escaped);
    }

    #[test]
    fn longer_text_is_cut_on_a_character_boundary_and_marked() {
        let cut = bounded_text("a".repeat(MAX_TEXT_BYTES + 1));
        assert_eq!(cut, format!("{}{TRUNCATED}", "a".repeat(MAX_TEXT_BYTES)));
        // A two-byte character straddling the bound is dropped whole.
        let straddling = format!("{}é", "a".repeat(MAX_TEXT_BYTES - 1));
        assert_eq!(
            bounded_text(straddling),
            format!("{}{TRUNCATED}", "a".repeat(MAX_TEXT_BYTES - 1))
        );
    }

    #[test]
    fn the_bound_counts_json_escapes() {
        for c in ['\u{1}', '"', '\\', '\n', 'é', '😀'] {
            let text = c.to_string().repeat(MAX_TEXT_BYTES);
            let cut = bounded_text(text);
            let kept = cut.strip_suffix(TRUNCATED).expect("marked");
            let size = written(kept);
            assert!(size <= MAX_TEXT_BYTES, "{c:?}: {size}");
            assert!(size + escaped_len(c) > MAX_TEXT_BYTES, "{c:?}: cut early");
            assert!(written(&cut) <= MAX_TEXT_BYTES + TRUNCATED.len());
        }
    }
}
