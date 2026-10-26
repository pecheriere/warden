//! Home Assistant webhook notifier.

use async_trait::async_trait;
use serde_json::json;

use super::{Doorbell, Notifier, NotifyError, check_status, http_client};
use crate::config::SecretUrl;

/// Posts `{"title","message","url"}` to a Home Assistant webhook trigger.
/// The webhook id is a secret, so the URL is redacted and redirects are off.
#[derive(Debug)]
pub struct HaWebhook {
    url: SecretUrl,
    client: reqwest::Client,
}

impl HaWebhook {
    /// Create a notifier for `url`.
    ///
    /// # Errors
    /// Returns [`NotifyError`] if the HTTP client cannot be built.
    pub fn new(url: SecretUrl) -> Result<Self, NotifyError> {
        let client = http_client().map_err(|e| NotifyError::request("ha", e))?;
        Ok(Self { url, client })
    }
}

#[async_trait]
impl Notifier for HaWebhook {
    fn name(&self) -> &'static str {
        "ha"
    }

    async fn ring(&self, d: &Doorbell) -> Result<(), NotifyError> {
        let resp = self
            .client
            .post(self.url.expose_url().clone())
            .json(&json!({
                "title": d.title,
                "message": d.message,
                "url": d.url.as_str(),
            }))
            .send()
            .await
            .map_err(|e| NotifyError::request("ha", e))?;
        check_status("ha", &resp)
    }
}
