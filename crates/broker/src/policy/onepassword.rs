//! [`SecretBackend`] backed by a 1Password Connect server.

use std::time::Duration;

use async_trait::async_trait;
use http::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use ssh_key::PrivateKey;
use tokio::sync::Mutex;
use url::Url;
use warden_broker_proto::{SecretName, TargetName};
use zeroize::Zeroizing;

use super::{
    ApiSecretPolicy, CaKey, CommitSigningKey, PolicyError, RelayCredential, SecretBackend,
    SecretValue, SshTarget, not_a_relay_target,
};

const TARGET_TAG: &str = "warden:ssh-target";
const CA_TAG: &str = "warden:ssh-ca";

/// Tag of the item holding the commit signing key. Its own item, because a tag
/// signing key would be another one: see `crate::commit_signing`.
const COMMIT_SIGNING_TAG: &str = "warden:commit-signing";
const API_TAG: &str = "warden:api-secret";
const MIN_CREDENTIAL_CHARS: usize = 12;
const CA_FIELD_ID: &str = "private_key";
const TIMEOUT: Duration = Duration::from_secs(5);

mod items;
mod probe;

use items::invalid;
pub(crate) use items::parse_host_port;
pub(super) use items::{
    ApiItem, ItemUrl, SecretField, TargetItem, parse_api_secret, parse_private_key, parse_target,
};
pub use probe::{CaProbe, VaultProbe};

#[derive(Deserialize)]
struct Vault {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct ItemSummary {
    id: String,
    title: String,
    #[serde(default)]
    tags: Vec<String>,
}

/// Why [`OnePasswordConnect::tagged_key`] found no key.
enum KeyItemError {
    /// No item has the tag.
    Absent,
    /// The item cannot be used. Never quotes it.
    Unusable(String),
    /// Connect could not answer.
    Backend(PolicyError),
}

/// The CA item, decoded so that no private-key text lives in a plain `String`.
#[derive(Deserialize)]
struct CaItem {
    #[serde(default)]
    fields: Vec<SecretField>,
}

/// Reads policy from a 1Password Connect server. Items are fetched on every
/// call; only the vault id is cached, and it is resolved again when Connect
/// stops knowing it (the vault was recreated).
pub struct OnePasswordConnect {
    client: reqwest::Client,
    base: Url,
    token: SecretString,
    vault: String,
    /// The resolved vault id. The lock is held while resolving, so concurrent
    /// callers share one lookup (single flight).
    vault_id: Mutex<Option<String>>,
}

impl OnePasswordConnect {
    /// Create a client for `vault` on the Connect server at `url`.
    ///
    /// # Panics
    /// If the TLS backend cannot be initialised, which only happens on a
    /// broken platform configuration.
    #[must_use]
    pub fn new(url: Url, token: SecretString, vault: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            // The bearer token must never follow a redirect to another host.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client with static configuration");
        Self {
            client,
            base: url,
            token,
            vault,
            vault_id: Mutex::new(None),
        }
    }

    async fn get<T: DeserializeOwned>(
        &self,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<T, PolicyError> {
        let body = self.get_bytes(segments, query).await?;
        // Never interpolate the serde error itself: it can quote a field value.
        serde_json::from_slice(&body).map_err(|e| unreadable(&e))
    }

    /// GET and return the raw body in memory that is wiped on drop.
    async fn get_bytes(
        &self,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<Zeroizing<Vec<u8>>, PolicyError> {
        self.get_found(segments, query).await?.ok_or_else(|| {
            PolicyError::Unavailable(format!(
                "1Password Connect returned HTTP {}",
                StatusCode::NOT_FOUND
            ))
        })
    }

    /// The URL of an API path on the Connect server.
    fn url(&self, segments: &[&str], query: &[(&str, &str)]) -> Result<Url, PolicyError> {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|()| PolicyError::Unavailable("Connect URL cannot be a base".into()))?
            .pop_if_empty()
            .extend(segments);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        Ok(url)
    }

    /// Like [`Self::get_bytes`], but `Ok(None)` for a 404, so that callers
    /// can tell "not found" from a failure.
    async fn get_found(
        &self,
        segments: &[&str],
        query: &[(&str, &str)],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, PolicyError> {
        let url = self.url(segments, query)?;
        let mut response = self
            .client
            .get(url)
            .bearer_auth(self.token.expose_secret())
            .send()
            .await
            // Strip the URL; the error text is the only thing we surface.
            .map_err(|e| {
                PolicyError::Unavailable(format!(
                    "1Password Connect request failed: {}",
                    e.without_url()
                ))
            })?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(PolicyError::Unavailable(format!(
                "1Password Connect returned HTTP {status}"
            )));
        }
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|e| {
            PolicyError::Unavailable(format!(
                "1Password Connect response was cut short: {}",
                e.without_url()
            ))
        })? {
            body.extend_from_slice(&chunk);
        }
        Ok(Some(body))
    }

    /// The cached vault id, resolved by name on first use.
    async fn vault_id(&self) -> Result<String, PolicyError> {
        let mut cached = self.vault_id.lock().await;
        if let Some(id) = cached.as_ref() {
            return Ok(id.clone());
        }
        let id = self.resolve_vault().await?;
        *cached = Some(id.clone());
        Ok(id)
    }

    /// Resolve the vault again after Connect answered 404 for `stale`.
    /// Returns the current id, which equals `stale` when the vault still has
    /// it (the 404 was for something else). Callers that saw the same stale
    /// id queue on the lock; the first one resolves and the rest find the
    /// new id already cached. A vault that no longer resolves clears the
    /// cache and fails.
    async fn refresh_vault_id(&self, stale: &str) -> Result<String, PolicyError> {
        let mut cached = self.vault_id.lock().await;
        if let Some(id) = cached.as_ref().filter(|id| id.as_str() != stale) {
            return Ok(id.clone());
        }
        *cached = None;
        let id = self.resolve_vault().await?;
        *cached = Some(id.clone());
        Ok(id)
    }

    /// A name with a quote or backslash cannot go into a Connect filter.
    fn vault_name_is_usable(&self) -> bool {
        !self.vault.contains(['"', '\\'])
    }

    fn vault_filter(&self) -> String {
        format!("name eq \"{}\"", self.vault)
    }

    async fn resolve_vault(&self) -> Result<String, PolicyError> {
        if !self.vault_name_is_usable() {
            return Err(PolicyError::Unavailable(
                "vault name contains unsupported characters".into(),
            ));
        }
        let filter = self.vault_filter();
        let vaults: Vec<Vault> = self.get(&["v1", "vaults"], &[("filter", &filter)]).await?;
        let vault = vaults
            .into_iter()
            .find(|v| v.name == self.vault)
            .ok_or_else(|| {
                PolicyError::Unavailable(format!("vault \"{}\" not found", self.vault))
            })?;
        check_id(&vault.id)?;
        Ok(vault.id)
    }

    /// GET `/v1/vaults/{vault}/{tail…}`. On a 404 the vault id is resolved
    /// again; if the vault has a new id the request is repeated once with it.
    /// Otherwise (same id, or a second 404) the 404 is reported as it is, so
    /// a vault that is truly gone fails closed without a retry loop.
    async fn vault_bytes(&self, tail: &[&str]) -> Result<Zeroizing<Vec<u8>>, PolicyError> {
        let mut vault_id = self.vault_id().await?;
        for retry in [true, false] {
            let mut segments = vec!["v1", "vaults", vault_id.as_str()];
            segments.extend_from_slice(tail);
            if let Some(body) = self.get_found(&segments, &[]).await? {
                return Ok(body);
            }
            if !retry {
                break;
            }
            let current = self.refresh_vault_id(&vault_id).await?;
            if current == vault_id {
                break;
            }
            vault_id = current;
        }
        Err(PolicyError::Unavailable(format!(
            "1Password Connect returned HTTP {}",
            StatusCode::NOT_FOUND
        )))
    }

    /// [`Self::vault_bytes`], decoded. Never interpolates the serde error: it
    /// can quote a field value.
    async fn vault_get<T: DeserializeOwned>(&self, tail: &[&str]) -> Result<T, PolicyError> {
        let body = self.vault_bytes(tail).await?;
        serde_json::from_slice(&body).map_err(|e| unreadable(&e))
    }

    /// The title and private key of the one item tagged `tag`; `what` names the
    /// item in messages, none of which quote it.
    async fn tagged_key(
        &self,
        tag: &str,
        what: &str,
    ) -> Result<(String, PrivateKey), KeyItemError> {
        let mut items = self.tagged(tag).await.map_err(KeyItemError::Backend)?;
        let summary = match items.len() {
            0 => return Err(KeyItemError::Absent),
            1 => items.remove(0),
            n => {
                return Err(KeyItemError::Unusable(format!(
                    "{n} items are tagged \"{tag}\"; exactly one is required"
                )));
            }
        };
        let unusable =
            |reason: &str| KeyItemError::Unusable(format!("item \"{}\": {reason}", summary.title));
        check_id(&summary.id).map_err(KeyItemError::Backend)?;
        let body = self
            .vault_bytes(&["items", &summary.id])
            .await
            .map_err(KeyItemError::Backend)?;
        // Never interpolate the serde error: it can quote a field value.
        let item: CaItem = serde_json::from_slice(&body)
            .map_err(|_| unusable(&format!("unreadable {what} item")))?;
        drop(body);
        let text = item
            .fields
            .iter()
            .find(|f| f.id == CA_FIELD_ID)
            .and_then(|f| f.value.as_deref().map(String::as_str))
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| {
                unusable(&format!(
                    "field with id \"{CA_FIELD_ID}\" is missing or empty"
                ))
            })?;
        let key = parse_private_key(text).ok_or_else(|| {
            unusable("the private key is not a readable OpenSSH or PKCS#8 Ed25519 key")
        })?;
        Ok((summary.title.clone(), key))
    }

    /// Summaries of all items in the vault carrying `tag`.
    async fn tagged(&self, tag: &str) -> Result<Vec<ItemSummary>, PolicyError> {
        let items: Vec<ItemSummary> = self.vault_get(&["items"]).await?;
        Ok(items
            .into_iter()
            .filter(|i| i.tags.iter().any(|t| t == tag))
            .collect())
    }

    /// The one item tagged `tag` and titled `title`; `Ok(None)` if there is
    /// none, [`PolicyError::Invalid`] if there are several.
    async fn tagged_titled(
        &self,
        tag: &str,
        title: &str,
        what: &str,
    ) -> Result<Option<ItemSummary>, PolicyError> {
        let mut matches: Vec<ItemSummary> = self
            .tagged(tag)
            .await?
            .into_iter()
            .filter(|i| i.title == title)
            .collect();
        match matches.len() {
            0 => Ok(None),
            1 => Ok(Some(matches.remove(0))),
            _ => Err(invalid(
                title,
                "title",
                &format!("more than one item is tagged as {what} with this title"),
            )),
        }
    }

    /// Fetch and validate the API secret item `name`. The body and the
    /// credential stay in `Zeroizing` buffers throughout.
    async fn api_item(
        &self,
        name: &SecretName,
    ) -> Result<(ApiSecretPolicy, SecretValue), PolicyError> {
        let summary = self
            .tagged_titled(API_TAG, name.as_str(), "an API secret")
            .await?
            .ok_or_else(|| PolicyError::UnknownSecret(name.as_str().to_owned()))?;
        check_id(&summary.id)?;
        let body = self.vault_bytes(&["items", &summary.id]).await?;
        // Never interpolate the serde error: it can quote the credential.
        let item: ApiItem = serde_json::from_slice(&body).map_err(|_| {
            PolicyError::Unavailable(format!(
                "1Password Connect sent an unreadable item for API secret \"{name}\""
            ))
        })?;
        drop(body);
        parse_api_secret(name, &item)
    }

    /// Fetch and validate the SSH target item `name`. The body and any
    /// relay credential stay in `Zeroizing` buffers throughout.
    async fn target_item(
        &self,
        name: &TargetName,
    ) -> Result<(SshTarget, Option<RelayCredential>), PolicyError> {
        let summary = self
            .tagged_titled(TARGET_TAG, name.as_str(), "a target")
            .await?
            .ok_or_else(|| PolicyError::NotFound(name.as_str().to_owned()))?;
        check_id(&summary.id)?;
        let body = self.vault_bytes(&["items", &summary.id]).await?;
        // Never interpolate the serde error: it can quote the credential.
        let item: TargetItem = serde_json::from_slice(&body).map_err(|_| {
            PolicyError::Unavailable(format!(
                "1Password Connect sent an unreadable item for target \"{name}\""
            ))
        })?;
        drop(body);
        parse_target(name, &item)
    }
}

/// The error for a response that is not the JSON we expect. Only the position
/// and class of the serde error are used: its text can quote a field value.
fn unreadable(e: &serde_json::Error) -> PolicyError {
    PolicyError::Unavailable(format!(
        "1Password Connect sent an unreadable response ({:?} error at line {}, column {})",
        e.classify(),
        e.line(),
        e.column()
    ))
}

/// Connect ids are 26 lowercase alphanumerics; refuse anything that could
/// alter the request path.
fn check_id(id: &str) -> Result<(), PolicyError> {
    if !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric()) {
        Ok(())
    } else {
        Err(PolicyError::Unavailable(
            "1Password Connect sent a malformed id".into(),
        ))
    }
}

#[async_trait]
impl SecretBackend for OnePasswordConnect {
    async fn ssh_target(&self, name: &TargetName) -> Result<SshTarget, PolicyError> {
        self.target_item(name)
            .await
            .map(|(target, _credential)| target)
    }

    async fn relay_target_with_credential(
        &self,
        name: &TargetName,
    ) -> Result<(SshTarget, RelayCredential), PolicyError> {
        match self.target_item(name).await? {
            (target, Some(credential)) => Ok((target, credential)),
            (_, None) => Err(not_a_relay_target(name.as_str())),
        }
    }

    async fn ssh_ca(&self) -> Result<CaKey, PolicyError> {
        let (title, key) = match self.tagged_key(CA_TAG, "CA").await {
            Ok(found) => found,
            Err(KeyItemError::Absent) => {
                return Err(PolicyError::Ca(format!("no item is tagged \"{CA_TAG}\"")));
            }
            Err(KeyItemError::Unusable(reason)) => return Err(PolicyError::Ca(reason)),
            Err(KeyItemError::Backend(e)) => return Err(e),
        };
        CaKey::new(key).map_err(|e| match e {
            PolicyError::Ca(reason) => PolicyError::Ca(format!("item \"{title}\": {reason}")),
            other => other,
        })
    }

    async fn has_ssh_ca(&self) -> Result<bool, PolicyError> {
        Ok(!self.tagged(CA_TAG).await?.is_empty())
    }

    async fn has_commit_signing_key(&self) -> Result<bool, PolicyError> {
        Ok(!self.tagged(COMMIT_SIGNING_TAG).await?.is_empty())
    }

    async fn commit_signing_key(&self) -> Result<CommitSigningKey, PolicyError> {
        let (title, key) = match self.tagged_key(COMMIT_SIGNING_TAG, "commit signing").await {
            Ok(found) => found,
            Err(KeyItemError::Absent) => return Err(PolicyError::NoCommitSigningKey),
            Err(KeyItemError::Unusable(reason)) => {
                return Err(PolicyError::CommitSigningKey(reason));
            }
            Err(KeyItemError::Backend(e)) => return Err(e),
        };
        CommitSigningKey::new(key).map_err(|e| match e {
            PolicyError::CommitSigningKey(reason) => {
                PolicyError::CommitSigningKey(format!("item \"{title}\": {reason}"))
            }
            other => other,
        })
    }

    async fn api_secret(&self, name: &SecretName) -> Result<ApiSecretPolicy, PolicyError> {
        self.api_item(name).await.map(|(policy, _value)| policy)
    }

    async fn api_secret_with_value(
        &self,
        name: &SecretName,
    ) -> Result<(ApiSecretPolicy, SecretValue), PolicyError> {
        self.api_item(name).await
    }
}
