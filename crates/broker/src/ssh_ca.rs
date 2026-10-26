//! SSH certificate issuance: signs short-lived user certificates with the CA key.

use ssh_key::certificate::{Builder, CertType};
use ssh_key::rand_core::{OsRng, RngCore};
use ssh_key::{Algorithm, Certificate, PublicKey};
use thiserror::Error;
use warden_broker_proto::{AgentName, Id, TargetName, UnixUser};

/// Seconds a certificate is backdated to tolerate clock skew with the target.
const BACKDATE_SECS: i64 = 60;

/// Everything needed to issue one certificate.
#[derive(Debug)]
pub struct IssueInput<'a> {
    /// Agent the grant belongs to.
    pub agent: &'a AgentName,
    /// Grant the certificate is issued for.
    pub grant_id: &'a Id,
    /// Target the grant was approved for; part of the principal.
    pub target: &'a TargetName,
    /// Unix user the certificate is valid for; part of the principal.
    pub user: &'a UnixUser,
    /// The agent's ephemeral subject key.
    pub public_key: &'a PublicKey,
    /// Current time, Unix seconds.
    pub now: i64,
    /// Expiry of the certificate, Unix seconds.
    pub not_after: i64,
}

/// Why a certificate could not be issued.
#[derive(Debug, Error)]
pub enum CaError {
    /// The subject key is not Ed25519.
    #[error("subject key is {0}, but only Ed25519 keys are accepted")]
    UnsupportedSubjectKey(String),
    /// The requested expiry is not in the future.
    #[error("certificate expiry {not_after} is not after the current time {now}")]
    NotInFuture {
        /// Current time, Unix seconds.
        now: i64,
        /// Requested expiry, Unix seconds.
        not_after: i64,
    },
    /// Building or signing the certificate failed.
    #[error("signing the certificate failed: {0}")]
    Sign(#[from] ssh_key::Error),
}

/// The certificate's only principal: `warden:<target>:<user>`.
///
/// Scoping the principal to the target means a host accepts the certificate
/// only if it maps this exact string to the account (`AuthorizedPrincipalsFile`
/// or a `cert-authority,principals=` option), so an approval for one target is
/// useless on every other host that trusts the same CA. Both parts are
/// validated names that cannot contain `:` or `,`.
#[must_use]
pub fn principal(target: &TargetName, user: &UnixUser) -> String {
    format!("warden:{target}:{user}")
}

/// Issue a user certificate for `input.public_key`, signed by `ca`.
///
/// # Errors
/// [`CaError::UnsupportedSubjectKey`] for a non-Ed25519 subject key,
/// [`CaError::NotInFuture`] if `not_after <= now`, and [`CaError::Sign`] if
/// the certificate cannot be built or signed.
pub fn issue(ca: &crate::policy::CaKey, input: &IssueInput<'_>) -> Result<Certificate, CaError> {
    if input.public_key.algorithm() != Algorithm::Ed25519 {
        return Err(CaError::UnsupportedSubjectKey(
            input.public_key.algorithm().to_string(),
        ));
    }
    if input.not_after <= input.now {
        return Err(CaError::NotInFuture {
            now: input.now,
            not_after: input.not_after,
        });
    }
    // A negative expiry cannot be encoded; treat it as already past.
    let valid_before = u64::try_from(input.not_after).map_err(|_| CaError::NotInFuture {
        now: input.now,
        not_after: input.not_after,
    })?;
    // Saturating, never negative; `valid_after < valid_before` since `now < not_after`.
    let valid_after = u64::try_from(input.now.saturating_sub(BACKDATE_SECS).max(0)).unwrap_or(0);

    let mut builder = Builder::new_with_random_nonce(
        &mut OsRng,
        input.public_key.key_data().clone(),
        valid_after,
        valid_before,
    )?;
    builder
        .serial(OsRng.next_u64())?
        .cert_type(CertType::User)?
        .key_id(format!("warden:{}:{}", input.agent, input.grant_id))?
        .valid_principal(principal(input.target, input.user))?
        .extension("permit-pty", "")?;
    Ok(builder.sign(ca.private_key())?)
}

#[cfg(test)]
mod tests {
    use ssh_key::{Algorithm, PrivateKey};

    use super::*;
    use crate::policy::CaKey;

    const NOW: i64 = 1_800_000_000;

    struct Fixture {
        ca: CaKey,
        agent: AgentName,
        grant: Id,
        target: TargetName,
        user: UnixUser,
        subject: PublicKey,
    }

    impl Fixture {
        fn new() -> Self {
            let ca =
                CaKey::new(PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()).unwrap();
            Self {
                ca,
                agent: AgentName::try_from("bot-laptop".to_owned()).unwrap(),
                grant: Id::random(),
                target: TargetName::try_from("pi".to_owned()).unwrap(),
                user: UnixUser::try_from("alice".to_owned()).unwrap(),
                subject: PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
                    .unwrap()
                    .public_key()
                    .clone(),
            }
        }

        fn issue(&self, now: i64, not_after: i64) -> Result<Certificate, CaError> {
            issue(
                &self.ca,
                &IssueInput {
                    agent: &self.agent,
                    grant_id: &self.grant,
                    target: &self.target,
                    user: &self.user,
                    public_key: &self.subject,
                    now,
                    not_after,
                },
            )
        }
    }

    #[test]
    fn cert_has_single_principal_and_key_id() {
        let f = Fixture::new();
        let cert = f.issue(NOW, NOW + 1800).unwrap();
        assert_eq!(cert.valid_principals(), ["warden:pi:alice"]);
        assert_eq!(cert.cert_type(), CertType::User);
        assert_eq!(
            cert.key_id(),
            format!("warden:bot-laptop:{}", f.grant.as_str())
        );
        assert_eq!(cert.public_key(), f.subject.key_data());
    }

    #[test]
    fn cert_valid_after_is_backdated_60s() {
        let f = Fixture::new();
        let cert = f.issue(NOW, NOW + 1800).unwrap();
        assert_eq!(cert.valid_after(), u64::try_from(NOW - 60).unwrap());
    }

    #[test]
    fn cert_valid_after_never_negative() {
        let f = Fixture::new();
        assert_eq!(f.issue(10, 100).unwrap().valid_after(), 0);
        assert_eq!(f.issue(-5, 100).unwrap().valid_after(), 0);
        assert_eq!(f.issue(i64::MIN, 100).unwrap().valid_after(), 0);
    }

    #[test]
    fn cert_valid_before_is_not_after() {
        let f = Fixture::new();
        let cert = f.issue(NOW, NOW + 1800).unwrap();
        assert_eq!(cert.valid_before(), u64::try_from(NOW + 1800).unwrap());
    }

    #[test]
    fn cert_only_permit_pty() {
        let f = Fixture::new();
        let cert = f.issue(NOW, NOW + 1800).unwrap();
        let extensions: Vec<_> = cert.extensions().iter().collect();
        assert_eq!(extensions.len(), 1);
        assert_eq!(extensions[0].0, "permit-pty");
        assert!(cert.critical_options().is_empty());
    }

    #[test]
    fn cert_serials_are_random() {
        let f = Fixture::new();
        let a = f.issue(NOW, NOW + 1800).unwrap();
        let b = f.issue(NOW, NOW + 1800).unwrap();
        assert_ne!(a.serial(), b.serial());
    }

    #[test]
    fn cert_verifies_against_ca_public_key() {
        let f = Fixture::new();
        let cert = f.issue(NOW, NOW + 1800).unwrap();
        let fingerprint = f.ca.public_key().fingerprint(ssh_key::HashAlg::Sha256);
        cert.validate_at(u64::try_from(NOW).unwrap(), &[fingerprint])
            .unwrap();
        let other = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let wrong = other.public_key().fingerprint(ssh_key::HashAlg::Sha256);
        assert!(
            cert.validate_at(u64::try_from(NOW).unwrap(), &[wrong])
                .is_err()
        );
        // Outside the window the certificate no longer validates.
        let fingerprint = f.ca.public_key().fingerprint(ssh_key::HashAlg::Sha256);
        assert!(
            cert.validate_at(u64::try_from(NOW + 1800).unwrap(), &[fingerprint])
                .is_err()
        );
    }

    #[test]
    fn rejects_non_ed25519_subject() {
        let mut f = Fixture::new();
        f.subject = PublicKey::from_openssh(
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg= test",
        )
        .unwrap();
        let err = f.issue(NOW, NOW + 1800).unwrap_err();
        assert!(matches!(err, CaError::UnsupportedSubjectKey(_)));
        assert!(err.to_string().contains("Ed25519"));
    }

    #[test]
    fn rejects_expiry_not_in_the_future() {
        let f = Fixture::new();
        assert!(matches!(
            f.issue(NOW, NOW),
            Err(CaError::NotInFuture { .. })
        ));
        assert!(matches!(
            f.issue(NOW, NOW - 1),
            Err(CaError::NotInFuture { .. })
        ));
    }
}
