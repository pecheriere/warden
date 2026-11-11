//! Signing what a release grant covers: the tag object. Nothing here decides
//! whether to sign: see `api::release`.
//!
//! This is kept apart from [`crate::commit_signing`] by design. The commit
//! signing key signs commits an agent wrote, under its own grant; the release
//! key signs a tag and a manifest the owner approved on their phone, and
//! release verifiers trust that key alone. Sharing code or keys would let a
//! mistake in the check of a commit produce a signature those verifiers trust.
//! Only the unit error [`crate::commit_signing::SignFailed`] is shared, because
//! it says nothing about a key.
//!
//! The key types, [`crate::policy::ReleaseSigningKey`] and
//! [`crate::policy::ManifestSpec`], live in `policy::release_signing`, next to
//! how they are read from the vault.

mod tag;

pub use self::tag::{sign_tag, tag_object_id, tag_payload};

#[cfg(test)]
mod tests;
