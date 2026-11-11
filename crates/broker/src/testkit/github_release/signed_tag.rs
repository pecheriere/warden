//! Tag objects as Git writes them, for tests of what the broker checks in a tag
//! that already exists.

use ssh_key::{HashAlg, LineEnding, PrivateKey};

/// An annotated tag object for `tag` on `commit`, tagged by `Release Bot` at
/// `seconds` (UTC), with the SSH signature of `key` in `namespace` at the end of
/// its message, as `git tag -s` writes it.
///
/// # Panics
/// If the signature cannot be made or armored.
#[must_use]
pub fn signed_tag_object(
    key: &PrivateKey,
    namespace: &str,
    tag: &str,
    commit: &str,
    seconds: i64,
) -> Vec<u8> {
    let mut object = unsigned_tag_object(tag, commit, seconds);
    let signature = crate::test_keys::sign(key, namespace, HashAlg::Sha512, &object)
        .to_pem(LineEnding::LF)
        .expect("armored signature");
    object.extend_from_slice(signature.as_bytes());
    object
}

/// The same tag with no signature.
#[must_use]
pub fn unsigned_tag_object(tag: &str, commit: &str, seconds: i64) -> Vec<u8> {
    format!(
        "object {commit}\ntype commit\ntag {tag}\ntagger Release Bot <release@example.com> {seconds} +0000\n\n{tag}\n"
    )
    .into_bytes()
}
