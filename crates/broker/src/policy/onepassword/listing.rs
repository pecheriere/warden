//! Every target and API secret item, for the offers listing.
//!
//! Each listing reads the vault's item list once, then each item's body once by
//! its id: never the list again per item.

use std::collections::BTreeMap;

use warden_broker_proto::{SecretName, TargetName};

use super::{API_TAG, ItemSummary, OnePasswordConnect, TARGET_TAG};
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

/// The summaries whose title no other summary shares, in title order. An item
/// whose title another item shares is left out, logged by its title only, as
/// reading it by name would refuse it.
fn uniquely_titled(summaries: Vec<ItemSummary>) -> Vec<ItemSummary> {
    let mut by_title: BTreeMap<String, Vec<ItemSummary>> = BTreeMap::new();
    for summary in summaries {
        by_title
            .entry(summary.title.clone())
            .or_default()
            .push(summary);
    }
    by_title
        .into_iter()
        .filter_map(|(title, mut same)| {
            if same.len() == 1 {
                same.pop()
            } else {
                tracing::warn!(item = %title, "item left out of the listing");
                None
            }
        })
        .collect()
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
        for summary in uniquely_titled(self.tagged(TARGET_TAG).await?) {
            let Ok(name) = TargetName::try_from(summary.title.clone()) else {
                tracing::warn!(item = %summary.title, "item left out of the listing");
                continue;
            };
            let read = self
                .read_target_item(&name, &summary.id)
                .await
                .map(|(target, _)| target);
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
        for summary in uniquely_titled(self.tagged(API_TAG).await?) {
            let Ok(name) = SecretName::try_from(summary.title.clone()) else {
                tracing::warn!(item = %summary.title, "item left out of the listing");
                continue;
            };
            let read = self
                .read_api_item(&name, &summary.id)
                .await
                .map(|(policy, _)| policy);
            secrets.extend(kept(&summary.title, read)?);
        }
        secrets.sort_by(|a, b| a.name.as_str().cmp(b.name.as_str()));
        Ok(secrets)
    }
}
