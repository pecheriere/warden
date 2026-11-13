//! Every target and API secret item, for the offers listing.

use warden_broker_proto::{SecretName, TargetName};

use super::{API_TAG, OnePasswordConnect, TARGET_TAG};
use crate::policy::{ApiSecretPolicy, PolicyError, SshTarget};

/// What to do with the outcome of reading one item for the listing: keep the
/// value, leave the item out (logged by its title only), or fail the listing.
fn kept<T>(title: &str, result: Result<T, PolicyError>) -> Result<Option<T>, PolicyError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(PolicyError::Unavailable(detail)) => Err(PolicyError::Unavailable(detail)),
        Err(_) => {
            tracing::warn!(item = %title, "item left out of the listing");
            Ok(None)
        }
    }
}

impl OnePasswordConnect {
    /// Every valid SSH target item, in name order. An item with an invalid
    /// title, a title another item shares, or content that fails validation is
    /// left out.
    ///
    /// # Errors
    /// [`PolicyError::Unavailable`].
    pub(super) async fn listed_targets(&self) -> Result<Vec<SshTarget>, PolicyError> {
        let mut targets = Vec::new();
        for summary in self.tagged(TARGET_TAG).await? {
            let Ok(name) = TargetName::try_from(summary.title.clone()) else {
                tracing::warn!(item = %summary.title, "item left out of the listing");
                continue;
            };
            let read = self.target_item(&name).await.map(|(target, _)| target);
            targets.extend(kept(&summary.title, read)?);
        }
        targets.sort_by(|a, b| a.name.as_str().cmp(b.name.as_str()));
        Ok(targets)
    }

    /// Every valid API secret item, in name order, under the same rules.
    ///
    /// # Errors
    /// [`PolicyError::Unavailable`].
    pub(super) async fn listed_api_secrets(&self) -> Result<Vec<ApiSecretPolicy>, PolicyError> {
        let mut secrets = Vec::new();
        for summary in self.tagged(API_TAG).await? {
            let Ok(name) = SecretName::try_from(summary.title.clone()) else {
                tracing::warn!(item = %summary.title, "item left out of the listing");
                continue;
            };
            let read = self.api_item(&name).await.map(|(policy, _)| policy);
            secrets.extend(kept(&summary.title, read)?);
        }
        secrets.sort_by(|a, b| a.name.as_str().cmp(b.name.as_str()));
        Ok(secrets)
    }
}
