//! Out-of-band notifications that tell the owner a request needs approval.
//!
//! Notifications carry the agent, target, a truncated goal and the approval
//! link, never secrets. [`Fallback`] tries the configured channels in order
//! and stops at the first that accepts; the channels are chosen by
//! [`ChannelSettings`].

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use url::Url;
use warden_broker_proto::{AgentName, CreateRequest};

mod channels;
mod ha;
mod ntfy;

pub use channels::{ChannelKind, ChannelSettings, parse_channels};
pub use ha::HaWebhook;
pub use ntfy::Ntfy;

/// Longest goal, in characters, sent in a notification.
const GOAL_LIMIT: usize = 200;

/// How long [`Fallback`] waits for each notifier.
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// Connect timeout for notifier HTTP clients.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// A notification asking the owner to approve a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Doorbell {
    /// Short headline.
    pub title: String,
    /// Body text.
    pub message: String,
    /// Approval page the owner should open.
    pub url: Url,
}

/// Why a notification could not be delivered. Never contains a URL, so secret
/// webhook ids cannot leak through error text.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum NotifyError {
    /// The HTTP request failed before a response arrived.
    #[error("{notifier} request failed: {reason}")]
    Request {
        /// Notifier name.
        notifier: &'static str,
        /// Transport error with the URL stripped.
        reason: String,
    },
    /// The server answered with a non-2xx status.
    #[error("{notifier} returned HTTP {status}")]
    Status {
        /// Notifier name.
        notifier: &'static str,
        /// HTTP status code.
        status: u16,
    },
    /// The notifier did not answer in time.
    #[error("{notifier} timed out after {} s", .after.as_secs())]
    Timeout {
        /// Notifier name.
        notifier: &'static str,
        /// The limit that was exceeded.
        after: Duration,
    },
    /// Every configured notifier failed, in priority order.
    #[error("all notifiers failed: {}", join(.0))]
    AllFailed(Vec<NotifyError>),
}

fn join(failures: &[NotifyError]) -> String {
    failures
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

impl NotifyError {
    pub(crate) fn request(notifier: &'static str, err: reqwest::Error) -> Self {
        Self::Request {
            notifier,
            reason: err.without_url().to_string(),
        }
    }
}

/// Delivers a [`Doorbell`] to the owner.
#[async_trait]
pub trait Notifier: Send + Sync + 'static {
    /// Short stable name, used in errors and logs.
    fn name(&self) -> &'static str;

    /// Deliver the notification.
    ///
    /// # Errors
    /// Returns [`NotifyError`] when delivery fails.
    async fn ring(&self, d: &Doorbell) -> Result<(), NotifyError>;
}

/// Tries its notifiers in priority order and stops at the first that
/// accepts; each gets 5 s.
pub struct Fallback {
    channels: Vec<Arc<dyn Notifier>>,
    timeout: Duration,
}

impl Fallback {
    /// Build a chain that tries `primary`, then each of `fallbacks` in order,
    /// with the standard 5 s per-notifier timeout.
    #[must_use]
    pub fn new(primary: Arc<dyn Notifier>, fallbacks: Vec<Arc<dyn Notifier>>) -> Self {
        let mut channels = vec![primary];
        channels.extend(fallbacks);
        Self {
            channels,
            timeout: NOTIFY_TIMEOUT,
        }
    }

    async fn ring_one(&self, n: &Arc<dyn Notifier>, d: &Doorbell) -> Result<(), NotifyError> {
        tokio::time::timeout(self.timeout, n.ring(d))
            .await
            .unwrap_or(Err(NotifyError::Timeout {
                notifier: n.name(),
                after: self.timeout,
            }))
    }
}

#[async_trait]
impl Notifier for Fallback {
    fn name(&self) -> &'static str {
        "fallback"
    }

    async fn ring(&self, d: &Doorbell) -> Result<(), NotifyError> {
        let mut failures = Vec::new();
        for (i, n) in self.channels.iter().enumerate() {
            match self.ring_one(n, d).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if let Some(next) = self.channels.get(i + 1) {
                        tracing::warn!(
                            notifier = n.name(),
                            next = next.name(),
                            error = %e,
                            "notifier failed, trying the next one"
                        );
                    }
                    failures.push(e);
                }
            }
        }
        match <[NotifyError; 1]>::try_from(failures) {
            Ok([only]) => Err(only),
            Err(failures) => Err(NotifyError::AllFailed(failures)),
        }
    }
}

/// Build the owner notification for a new request; `subject` says what it
/// is for (`ssh user@target`, or an API scope's [`subject`](crate::policy::ApiScope::subject)).
#[must_use]
pub fn doorbell(agent: &AgentName, subject: &str, req: &CreateRequest, url: Url) -> Doorbell {
    Doorbell {
        title: format!("warden: {agent} wants {subject}"),
        message: truncate_goal(req.goal.as_str()),
        url,
    }
}

fn truncate_goal(goal: &str) -> String {
    match goal.char_indices().nth(GOAL_LIMIT) {
        None => goal.to_owned(),
        Some((cut, _)) => format!("{}…", &goal[..cut]),
    }
}

pub(crate) fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(NOTIFY_TIMEOUT)
        .build()
}

pub(crate) fn check_status(
    notifier: &'static str,
    resp: &reqwest::Response,
) -> Result<(), NotifyError> {
    let status = resp.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(NotifyError::Status {
            notifier,
            status: status.as_u16(),
        })
    }
}
