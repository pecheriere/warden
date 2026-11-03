//! Signing a commit: the SSH signature over a payload that parsed as a commit,
//! and the id git gives the commit once that signature is in it. Nothing here
//! decides whether to sign: see `api::commit_signing`.
//!
//! The key is held by the [`CommitSigningKey`] only while this runs, and no error
//! says anything about it. Commit and tag signing are kept apart by design: this
//! key signs commits only, and tag signing would come with its own grant and its
//! own key, so that a mistake in the check of a commit could not produce a
//! signature that release verifiers trust.

use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use ssh_key::{HashAlg, LineEnding};
use warden_broker_proto::commit_signing::NAMESPACE;

use crate::policy::CommitSigningKey;

pub mod payload;

use self::payload::{ObjectFormat, ParsedCommit};

/// A signature, and the commit it makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCommit {
    /// The armored signature, as `ssh-keygen -Y sign` writes it.
    pub signature: String,
    /// The id git gives the commit with this signature.
    pub commit: String,
}

/// Why a commit could not be signed. Never says anything about the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("signing the commit failed")]
pub struct SignFailed;

/// Sign `payload`, which must be what `parsed` was parsed from, in the `git`
/// namespace.
///
/// # Errors
/// [`SignFailed`].
pub fn sign(
    key: &CommitSigningKey,
    payload: &[u8],
    parsed: &ParsedCommit,
) -> Result<SignedCommit, SignFailed> {
    let signature = key
        .private_key()
        .sign(NAMESPACE, HashAlg::Sha512, payload)
        .and_then(|signature| signature.to_pem(LineEnding::LF))
        .map_err(|_| SignFailed)?;
    let commit = signed_commit_id(payload, parsed, &signature);
    Ok(SignedCommit { signature, commit })
}

/// The id of the commit git writes from `payload` and `signature`: the signature
/// goes in a header at the end of the headers, each of its lines after a space,
/// and the id hashes the object that makes.
fn signed_commit_id(payload: &[u8], parsed: &ParsedCommit, signature: &str) -> String {
    let (headers, rest) = payload.split_at(parsed.end_of_headers);
    let mut object = headers.to_vec();
    object.extend_from_slice(parsed.format.signature_header().as_bytes());
    for line in signature.split_inclusive('\n') {
        object.push(b' ');
        object.extend_from_slice(line.as_bytes());
    }
    object.extend_from_slice(rest);
    let header = format!("commit {}\0", object.len());
    match parsed.format {
        ObjectFormat::Sha1 => hex::encode(
            Sha1::new()
                .chain_update(header.as_bytes())
                .chain_update(&object)
                .finalize(),
        ),
        ObjectFormat::Sha256 => hex::encode(
            Sha256::new()
                .chain_update(header.as_bytes())
                .chain_update(&object)
                .finalize(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey};

    use super::{payload, sign};
    use crate::policy::CommitSigningKey;

    #[test]
    fn signatures_verify_in_the_git_namespace_only() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let public = key.public_key().clone();
        let body = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
            author A <a@example.com> 1 +0000\ncommitter A <a@example.com> 1 +0000\n\nm\n";
        let parsed = payload::parse(body).unwrap();
        let signed = sign(&CommitSigningKey::new(key).unwrap(), body, &parsed).unwrap();
        assert!(
            signed
                .signature
                .starts_with("-----BEGIN SSH SIGNATURE-----\n")
        );
        assert!(signed.signature.ends_with("-----END SSH SIGNATURE-----\n"));
        assert_eq!(signed.commit.len(), 40);
        let parsed_sig: ssh_key::SshSig = signed.signature.parse().unwrap();
        assert!(public.verify("git", body, &parsed_sig).is_ok());
        assert!(public.verify("file", body, &parsed_sig).is_err());
    }
}
