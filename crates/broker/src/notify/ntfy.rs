//! ntfy notifier.

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use secrecy::{ExposeSecret, SecretString};
use url::Url;

use super::{ChannelKind, Doorbell, Notifier, NotifyError, check_status, http_client};

/// The notifier's name in logs and errors: its `WARDEN_NOTIFY` name.
const NAME: &str = ChannelKind::Ntfy.name();

/// Publishes to an ntfy topic: the message is the body, the title and click
/// target travel as headers, priority is high and the tag is `lock`.
#[derive(Debug)]
pub struct Ntfy {
    topic_url: Url,
    token: Option<SecretString>,
    client: reqwest::Client,
}

impl Ntfy {
    /// Create a notifier for the topic at `topic_url`, with an optional bearer
    /// token.
    ///
    /// # Errors
    /// Returns [`NotifyError`] if the HTTP client cannot be built.
    pub fn new(topic_url: Url, token: Option<SecretString>) -> Result<Self, NotifyError> {
        let client = http_client().map_err(|e| NotifyError::request(NAME, e))?;
        Ok(Self {
            topic_url,
            token,
            client,
        })
    }
}

/// HTTP header values are ASCII. ntfy decodes RFC 2047 encoded-words, so a
/// title with other characters is sent as `=?UTF-8?B?...?=`.
fn header_text(s: &str) -> String {
    if s.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
        s.to_owned()
    } else {
        format!("=?UTF-8?B?{}?=", STANDARD.encode(s))
    }
}

#[async_trait]
impl Notifier for Ntfy {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn ring(&self, d: &Doorbell) -> Result<&'static str, NotifyError> {
        let mut req = self
            .client
            .post(self.topic_url.clone())
            .header("Title", header_text(&d.title))
            .header("Click", d.url.as_str())
            .header("Priority", "high")
            .header("Tags", "lock")
            .body(d.message.clone());
        if let Some(token) = &self.token {
            req = req.bearer_auth(token.expose_secret());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| NotifyError::request(NAME, e))?;
        check_status(NAME, &resp)?;
        Ok(NAME)
    }
}
