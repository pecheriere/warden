//! Every target and API secret entry of the policy file, for the offers listing.

use warden_broker_proto::{SecretName, TargetName};

use super::Files;
use crate::policy::{ApiSecretPolicy, PolicyError, SshTarget};

impl Files {
    /// Every target entry that parses, in name order. One that does not is left
    /// out and logged by name: the startup probe refuses a policy file with such
    /// an entry, so this only happens when the file changed since.
    pub(super) fn listed_targets(&self) -> Result<Vec<SshTarget>, PolicyError> {
        let policy = self.policy()?;
        let mut targets = Vec::new();
        for (key, entry) in &policy.targets {
            let parsed = TargetName::try_from(key.clone())
                .map_err(|_| ())
                .and_then(|name| self.parse_target(&name, entry).map_err(|_| ()));
            if let Ok((target, _credential)) = parsed {
                targets.push(target);
            } else {
                tracing::warn!(item = %key, "item left out of the listing");
            }
        }
        Ok(targets)
    }

    /// Every API secret entry that parses, in name order, under the same rules.
    pub(super) fn listed_api_secrets(&self) -> Result<Vec<ApiSecretPolicy>, PolicyError> {
        let policy = self.policy()?;
        let mut secrets = Vec::new();
        for (key, entry) in &policy.api_secrets {
            let parsed = SecretName::try_from(key.clone())
                .map_err(|_| ())
                .and_then(|name| self.parse_api(&name, entry).map_err(|_| ()));
            if let Ok((policy, _value)) = parsed {
                secrets.push(policy);
            } else {
                tracing::warn!(item = %key, "item left out of the listing");
            }
        }
        Ok(secrets)
    }
}
