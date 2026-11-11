//! Release signing items and the release App item, read from 1Password Connect.

use warden_broker_proto::release::RepoName;

use super::{
    KeyItem, KeyItemError, OnePasswordConnect, RELEASE_APP_TAG, RELEASE_SIGNING_TAG, check_id,
};
use crate::policy::release_app::parse_item as parse_release_app;
use crate::policy::release_signing::parse_item as parse_release_signing;
use crate::policy::{PolicyError, ReleaseAppKey, ReleaseSigningKey, SecretBackend, check_distinct};

impl OnePasswordConnect {
    /// Every release signing item, each parsed, and all of them checked to be kept
    /// apart from one another, from the commit signing key and from the SSH CA key.
    /// One unusable item fails the lot: which repository it was meant for cannot be
    /// trusted.
    ///
    /// # Errors
    /// [`PolicyError::ReleaseKey`] naming the item or repositories at fault, or
    /// [`PolicyError::Unavailable`].
    pub async fn release_signing_keys(&self) -> Result<Vec<ReleaseSigningKey>, PolicyError> {
        let mut keys = Vec::new();
        for summary in self.tagged(RELEASE_SIGNING_TAG).await? {
            check_id(&summary.id)?;
            let body = self.vault_bytes(&["items", &summary.id]).await?;
            // Never interpolate the serde error: it can quote a field value.
            let item: KeyItem = serde_json::from_slice(&body).map_err(|_| {
                PolicyError::ReleaseKey(format!(
                    "item \"{}\": unreadable release signing item",
                    summary.title
                ))
            })?;
            drop(body);
            keys.push(
                parse_release_signing(&summary.title, &item.fields)
                    .map_err(PolicyError::ReleaseKey)?,
            );
        }
        let commit_signing = match self.commit_signing_key().await {
            Ok(key) => Some(key),
            Err(PolicyError::NoCommitSigningKey) => None,
            Err(PolicyError::CommitSigningKey(_)) => {
                return Err(PolicyError::ReleaseKey(
                    "the commit signing key cannot be read, so nothing says the release keys are different keys; fix it first".to_owned(),
                ));
            }
            Err(e) => return Err(e),
        };
        let ca = if self.has_ssh_ca().await? {
            match self.ssh_ca().await {
                Ok(ca) => Some(ca),
                Err(PolicyError::Ca(_)) => {
                    return Err(PolicyError::ReleaseKey(
                        "the SSH CA cannot be read, so nothing says the release keys are different keys; fix the CA first".to_owned(),
                    ));
                }
                Err(e) => return Err(e),
            }
        } else {
            None
        };
        check_distinct(
            &keys,
            commit_signing.as_ref(),
            ca.as_ref().map(crate::policy::CaKey::public_key),
        )
        .map_err(PolicyError::ReleaseKey)?;
        Ok(keys)
    }

    /// The release signing key of `repository`, once every item has been checked.
    pub(super) async fn release_signing_for(
        &self,
        repository: &RepoName,
    ) -> Result<ReleaseSigningKey, PolicyError> {
        self.release_signing_keys()
            .await?
            .into_iter()
            .find(|key| key.repository().matches(repository))
            .ok_or(PolicyError::NoReleaseKey)
    }

    pub(super) async fn release_app_key(&self) -> Result<ReleaseAppKey, PolicyError> {
        match self
            .tagged_item(RELEASE_APP_TAG, "release GitHub App")
            .await
        {
            Ok((title, item)) => {
                parse_release_app(&title, &item.fields).map_err(PolicyError::ReleaseApp)
            }
            Err(KeyItemError::Absent) => Err(PolicyError::NoReleaseApp),
            Err(KeyItemError::Unusable(reason)) => Err(PolicyError::ReleaseApp(reason)),
            Err(KeyItemError::Backend(e)) => Err(e),
        }
    }
}
