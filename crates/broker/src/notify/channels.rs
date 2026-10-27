//! The compile-time registry of notification channels.
//!
//! [`ChannelKind`] names the built-in channels, [`ChannelSettings`] holds one
//! channel's validated settings, parsed from `WARDEN_NOTIFY_<KIND>_*`, and
//! [`ChannelSettings::build`] turns them into a [`Notifier`]. `WARDEN_NOTIFY`
//! lists the enabled channels in priority order; see `docs/notifications.md`.
//!
//! The registry is an enum rather than a map of boxed constructors: adding a
//! channel is a new variant, and the compiler then points at every `match`
//! that must handle it (name, variables, parsing, building), so a channel
//! cannot be half-registered.

use std::sync::Arc;

use secrecy::SecretString;
use url::Url;

use super::{HaWebhook, Notifier, NotifyError, Ntfy};
use crate::config::{ConfigError, SecretUrl};

/// The variable that lists the enabled channels.
const LIST_VAR: &str = "WARDEN_NOTIFY";

/// Longest unknown channel name echoed back in an error.
const NAME_ECHO_LIMIT: usize = 32;

/// Variables of the removed fixed Home Assistant / ntfy wiring and what
/// replaces each. Setting one is a startup error, not a silent no-op.
const REMOVED: [(&str, &str); 3] = [
    (
        "WARDEN_HA_WEBHOOK_URL",
        "set WARDEN_NOTIFY=homeassistant and WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL",
    ),
    (
        "WARDEN_NTFY_URL",
        "set WARDEN_NOTIFY=ntfy and WARDEN_NOTIFY_NTFY_URL",
    ),
    ("WARDEN_NTFY_TOKEN", "use WARDEN_NOTIFY_NTFY_TOKEN"),
];

const HA_WEBHOOK_URL: &str = "WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL";
const NTFY_URL: &str = "WARDEN_NOTIFY_NTFY_URL";
const NTFY_TOKEN: &str = "WARDEN_NOTIFY_NTFY_TOKEN";

/// A built-in notification channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKind {
    /// A Home Assistant webhook (`homeassistant`).
    HomeAssistant,
    /// An ntfy topic (`ntfy`).
    Ntfy,
}

impl ChannelKind {
    /// Every built-in channel.
    pub const ALL: [Self; 2] = [Self::HomeAssistant, Self::Ntfy];

    /// The name used in `WARDEN_NOTIFY`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::HomeAssistant => "homeassistant",
            Self::Ntfy => "ntfy",
        }
    }

    /// The channel called `name` in `WARDEN_NOTIFY`, if there is one.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }

    /// Every `WARDEN_NOTIFY_<KIND>_*` variable the channel reads.
    const fn variables(self) -> &'static [&'static str] {
        match self {
            Self::HomeAssistant => &[HA_WEBHOOK_URL],
            Self::Ntfy => &[NTFY_URL, NTFY_TOKEN],
        }
    }
}

/// One channel's validated settings. `Debug` never shows a secret: the
/// webhook URL and the token are redacted types.
#[derive(Debug, Clone)]
pub enum ChannelSettings {
    /// A Home Assistant webhook.
    HomeAssistant {
        /// The webhook URL; its id is a secret.
        webhook_url: SecretUrl,
    },
    /// An ntfy topic.
    Ntfy {
        /// The topic URL.
        url: Url,
        /// Optional bearer token.
        token: Option<SecretString>,
    },
}

impl ChannelSettings {
    /// Which channel these settings belong to.
    #[must_use]
    pub const fn kind(&self) -> ChannelKind {
        match self {
            Self::HomeAssistant { .. } => ChannelKind::HomeAssistant,
            Self::Ntfy { .. } => ChannelKind::Ntfy,
        }
    }

    /// Create the notifier for these settings.
    ///
    /// # Errors
    /// Returns [`NotifyError`] if the notifier's HTTP client cannot be built.
    pub fn build(&self) -> Result<Arc<dyn Notifier>, NotifyError> {
        Ok(match self {
            Self::HomeAssistant { webhook_url } => Arc::new(HaWebhook::new(webhook_url.clone())?),
            Self::Ntfy { url, token } => Arc::new(Ntfy::new(url.clone(), token.clone())?),
        })
    }

    /// Parse the settings of `kind` from its variables.
    fn parse(
        kind: ChannelKind,
        get: &impl Fn(&'static str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        let required = |var: &'static str| get(var).ok_or(ConfigError::Missing(var));
        match kind {
            ChannelKind::HomeAssistant => Ok(Self::HomeAssistant {
                webhook_url: SecretUrl::new(parse_url(HA_WEBHOOK_URL, &required(HA_WEBHOOK_URL)?)?),
            }),
            ChannelKind::Ntfy => Ok(Self::Ntfy {
                url: parse_url(NTFY_URL, &required(NTFY_URL)?)?,
                token: get(NTFY_TOKEN).map(SecretString::from),
            }),
        }
    }
}

fn parse_url(var: &'static str, value: &str) -> Result<Url, ConfigError> {
    Url::parse(value).map_err(|_| ConfigError::Invalid {
        var,
        reason: "not a valid URL",
    })
}

/// Read the enabled channels, in priority order, from `WARDEN_NOTIFY` and the
/// per-channel variables.
///
/// # Errors
///
/// [`ConfigError`] when a removed variable is set, the list is empty, names an
/// unknown or repeated channel, a listed channel lacks a setting, or a
/// setting of an unlisted channel is present.
pub fn parse_channels(
    get: &impl Fn(&'static str) -> Option<String>,
) -> Result<Vec<ChannelSettings>, ConfigError> {
    for (var, replacement) in REMOVED {
        if get(var).is_some() {
            return Err(ConfigError::Removed { var, replacement });
        }
    }
    let list = get(LIST_VAR).ok_or(ConfigError::NoChannels)?;
    let mut kinds: Vec<ChannelKind> = Vec::new();
    for entry in list.split(',').map(str::trim) {
        if entry.is_empty() {
            return Err(ConfigError::Invalid {
                var: LIST_VAR,
                reason: "contains an empty channel name",
            });
        }
        let kind = ChannelKind::parse(entry).ok_or_else(|| ConfigError::UnknownChannel {
            name: entry.chars().take(NAME_ECHO_LIMIT).collect(),
        })?;
        if kinds.contains(&kind) {
            return Err(ConfigError::DuplicateChannel(kind.name()));
        }
        kinds.push(kind);
    }
    // A setting for a channel that is not listed is most likely a forgotten
    // or mistyped list entry; fail rather than silently ignore it.
    for kind in ChannelKind::ALL.iter().filter(|k| !kinds.contains(k)) {
        if let Some(var) = kind.variables().iter().find(|v| get(v).is_some()) {
            return Err(ConfigError::Invalid {
                var,
                reason: "set but the channel is not listed in WARDEN_NOTIFY",
            });
        }
    }
    kinds
        .into_iter()
        .map(|kind| ChannelSettings::parse(kind, get))
        .collect()
}
