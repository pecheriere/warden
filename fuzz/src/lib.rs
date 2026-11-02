//! Helpers shared by the fuzz targets in `fuzz_targets/`.

/// Separates the fields of a structured fuzz input. `0xFF` never occurs in
/// UTF-8, so a text field can hold any text.
pub const SEPARATOR: u8 = 0xFF;

/// Split `data` into exactly `N` fields on [`SEPARATOR`]. Missing fields are
/// empty; anything after the last separator belongs to the last field.
#[must_use]
pub fn fields<const N: usize>(data: &[u8]) -> [&[u8]; N] {
    let mut out: [&[u8]; N] = [&[]; N];
    for (field, part) in out.iter_mut().zip(data.splitn(N, |&b| b == SEPARATOR)) {
        *field = part;
    }
    out
}

/// A field as text; the empty string if it is not UTF-8.
#[must_use]
pub fn text(field: &[u8]) -> &str {
    std::str::from_utf8(field).unwrap_or_default()
}

/// Whether `haystack` contains `needle`. An empty needle never counts.
#[must_use]
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}
