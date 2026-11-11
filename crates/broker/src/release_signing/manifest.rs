//! The manifest of a release: what the agent may ask the broker to sign, and its
//! signature.

use std::collections::HashSet;

use ssh_key::{HashAlg, LineEnding};
use warden_broker_proto::release::MAX_MANIFEST_BYTES;

use crate::commit_signing::SignFailed;
use crate::policy::ReleaseSigningKey;

/// Why a manifest was refused. The messages name the rule and never quote the
/// manifest, so that nothing the agent sent is echoed into an error or the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ManifestError {
    /// The name is not the one the grant covers.
    #[error("the manifest's name is not the one the grant covers")]
    WrongName,
    /// There are no lines.
    #[error("the manifest is empty")]
    Empty,
    /// More than 64 KiB.
    #[error("the manifest is larger than 64 KiB")]
    TooLarge,
    /// Not UTF-8 text.
    #[error("the manifest is not UTF-8 text")]
    NotUtf8,
    /// The last line has no line feed.
    #[error("the manifest does not end with a line feed")]
    MissingFinalNewline,
    /// A carriage return anywhere.
    #[error("the manifest has a carriage return; lines end with a line feed only")]
    CarriageReturn,
    /// A line is not a digest, two spaces and a name.
    #[error("line {line} is not 64 lowercase hex digits, two spaces and a name")]
    BadLine {
        /// The line, counted from 1.
        line: usize,
    },
    /// A name is neither a file name nor an image reference at the release's version.
    #[error(
        "line {line} names neither a plain file name nor an image reference tagged with the release's version"
    )]
    BadName {
        /// The line, counted from 1.
        line: usize,
    },
    /// A name already seen on an earlier line.
    #[error("line {line} repeats a name")]
    DuplicateName {
        /// The line, counted from 1.
        line: usize,
    },
}

/// Length of a SHA-256 digest in hexadecimal.
const DIGEST_LEN: usize = 64;

/// Check that `bytes` is the manifest the grant covers: named `expected_name`, as
/// asked for in `name`, and made of lines `<64 lowercase hex>  <name>` that each
/// end with a line feed. A name is a plain file name (`[A-Za-z0-9._+-]+`, not `.`
/// or `..`) or an image reference `<registry>/<path>:<version>` with lowercase
/// `[a-z0-9._-]` segments, where the tag is exactly `version`. No name appears
/// twice, and there is at least one line.
///
/// # Errors
/// [`ManifestError`], whose message names the rule and a line number only.
pub fn check(
    expected_name: &str,
    version: &str,
    name: &str,
    bytes: &[u8],
) -> Result<(), ManifestError> {
    if name != expected_name {
        return Err(ManifestError::WrongName);
    }
    if bytes.is_empty() {
        return Err(ManifestError::Empty);
    }
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ManifestError::NotUtf8)?;
    if text.contains('\r') {
        return Err(ManifestError::CarriageReturn);
    }
    let lines = text
        .strip_suffix('\n')
        .ok_or(ManifestError::MissingFinalNewline)?;
    let mut seen = HashSet::new();
    for (index, line) in lines.split('\n').enumerate() {
        let line_number = index + 1;
        let entry = line
            .get(..DIGEST_LEN)
            .filter(|digest| digest.bytes().all(is_lower_hex))
            .and_then(|_| line.get(DIGEST_LEN..))
            .and_then(|rest| rest.strip_prefix("  "))
            .filter(|entry| !entry.is_empty())
            .ok_or(ManifestError::BadLine { line: line_number })?;
        if !is_file_name(entry) && !is_image_reference(entry, version) {
            return Err(ManifestError::BadName { line: line_number });
        }
        if !seen.insert(entry) {
            return Err(ManifestError::DuplicateName { line: line_number });
        }
    }
    Ok(())
}

const fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || matches!(b, b'a'..=b'f')
}

/// `^[A-Za-z0-9._+-]+$`, and not `.` or `..`.
fn is_file_name(name: &str) -> bool {
    !matches!(name, "" | "." | "..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// `<registry>/<path>:<version>`: at least two `/`-separated segments of lowercase
/// `[a-z0-9._-]`, none empty, `.` or `..`, then `:` and exactly `version`.
fn is_image_reference(name: &str, version: &str) -> bool {
    let Some((path, tag)) = name.rsplit_once(':') else {
        return false;
    };
    if tag != version {
        return false;
    }
    let mut segments = 0_usize;
    for segment in path.split('/') {
        segments += 1;
        let valid = !matches!(segment, "" | "." | "..")
            && segment.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            });
        if !valid {
            return false;
        }
    }
    segments >= 2
}

/// Sign `bytes` in `namespace` with SHA-512. The armored signature, with LF line
/// ends, is what `ssh-keygen -Y sign` would write.
///
/// # Errors
/// [`SignFailed`], which says nothing about the key.
pub fn sign_manifest(
    key: &ReleaseSigningKey,
    namespace: &str,
    bytes: &[u8],
) -> Result<String, SignFailed> {
    key.private_key()
        .sign(namespace, HashAlg::Sha512, bytes)
        .and_then(|signature| signature.to_pem(LineEnding::LF))
        .map_err(|_| SignFailed)
}
