//! The annotated tag object of a release, as Git writes it, and its signature.

use ssh_key::{HashAlg, LineEnding};
use warden_broker_proto::release::{CommitId, ReleaseTag};

use crate::commit_signing::SignFailed;
use crate::github_release::tag_object;
use crate::policy::{ReleaseSigningKey, TAG_NAMESPACE};

/// The bytes Git signs for an annotated tag on `commit`: the headers, a blank
/// line and `message` with a final newline. `time` is seconds since the Unix
/// epoch, written in UTC.
#[must_use]
pub fn tag_payload(
    commit: &CommitId,
    tag: &ReleaseTag,
    tagger_name: &str,
    tagger_email: &str,
    time: i64,
    message: &str,
) -> Vec<u8> {
    format!(
        "object {commit}\ntype commit\ntag {tag}\ntagger {tagger_name} <{tagger_email}> {time} +0000\n\n{message}\n",
        commit = commit.as_str(),
        tag = tag.as_str(),
    )
    .into_bytes()
}

/// Sign `payload` in the `git` namespace with SHA-512. The armored signature, with
/// LF line ends, follows the payload in the tag object.
///
/// # Errors
/// [`SignFailed`], which says nothing about the key.
pub fn sign_tag(key: &ReleaseSigningKey, payload: &[u8]) -> Result<String, SignFailed> {
    key.private_key()
        .sign(TAG_NAMESPACE, HashAlg::Sha512, payload)
        .and_then(|signature| signature.to_pem(LineEnding::LF))
        .map_err(|_| SignFailed)
}

/// The id Git gives the tag object `payload` followed by `signature`.
#[must_use]
pub fn tag_object_id(payload: &[u8], signature: &str) -> String {
    let mut object = payload.to_vec();
    object.extend_from_slice(signature.as_bytes());
    tag_object::object_id(&object)
}
