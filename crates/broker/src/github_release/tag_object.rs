//! Rebuilding the bytes of a tag object from what GitHub's API reports about it.
//!
//! GitHub's `GET /git/tags/{sha}` gives a tag's fields, not the object. The
//! object is what its id is the hash of, so a rebuilt one is only used when its
//! SHA-1 is the id GitHub named: whatever the rebuild gets wrong (the tagger's
//! time zone, an encoding) shows up as a different hash, and the bytes are
//! dropped instead of trusted.

use std::fmt::Write as _;

use serde::Deserialize;
use sha1::{Digest as _, Sha1};

/// The fields of a tag object as `GET /git/tags/{sha}` reports them.
#[derive(Debug, Deserialize)]
pub struct GitTagResponse {
    /// The tag object's id.
    pub sha: String,
    /// The tag's name.
    pub tag: String,
    /// The message, which for a signed tag ends with the signature block.
    pub message: String,
    /// Who tagged, and when. Old tags may have none.
    pub tagger: Option<Tagger>,
    /// What the tag points at.
    pub object: TaggedObject,
}

/// A tag's `tagger` line.
#[derive(Debug, Deserialize)]
pub struct Tagger {
    /// The name.
    pub name: String,
    /// The email address.
    pub email: String,
    /// The time, ISO 8601. Its UTC offset is not kept.
    pub date: String,
}

/// What a tag points at.
#[derive(Debug, Deserialize)]
pub struct TaggedObject {
    /// The object's id.
    pub sha: String,
    /// `commit`, `tree`, `blob` or `tag`.
    #[serde(rename = "type")]
    pub kind: String,
}

/// The tag object `tag` describes, with the tagger's time in UTC (`+0000`), or
/// `None` when a field cannot be written into one: an unknown object type, a
/// date that is not a timestamp, or a name, email or tag with a line break.
///
/// Whether the bytes are the object `tag.sha` names is for the caller to say, by comparing the SHA-1 of the bytes.
#[must_use]
pub fn rebuild(tag: &GitTagResponse) -> Option<Vec<u8>> {
    if !matches!(tag.object.kind.as_str(), "commit" | "tree" | "blob" | "tag") {
        return None;
    }
    let mut text = format!(
        "object {}\ntype {}\ntag {}\n",
        tag.object.sha, tag.object.kind, tag.tag
    );
    let mut single_lines = vec![&tag.object.sha, &tag.tag];
    if let Some(tagger) = &tag.tagger {
        let when = tagger.date.parse::<jiff::Timestamp>().ok()?.as_second();
        writeln!(
            text,
            "tagger {} <{}> {when} +0000",
            tagger.name, tagger.email
        )
        .ok()?;
        single_lines.extend([&tagger.name, &tagger.email]);
    }
    if single_lines.iter().any(|field| field.contains('\n')) {
        return None;
    }
    Some(format!("{text}\n{}", tag.message).into_bytes())
}

/// The id Git gives a tag object with these bytes: the SHA-1 of `tag <length>`,
/// a NUL and the bytes, in hexadecimal.
#[must_use]
pub fn object_id(raw: &[u8]) -> String {
    hex::encode(
        Sha1::new()
            .chain_update(format!("tag {}\0", raw.len()).as_bytes())
            .chain_update(raw)
            .finalize(),
    )
}
