//! The hook's signals and the per-signal settings from the `[hook]` table.
//!
//! An invalid table never turns protection off: it yields the defaults and a
//! short note naming the bad key or value.

use std::fmt::Write as _;

/// One kind of warden-bypassing action the hook can detect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Signal {
    /// A command reaching a host that warden covers over SSH.
    CoveredSsh,
    /// A command calling an API that warden covers.
    CoveredApi,
    /// A command using the owner's SSH key.
    OwnerSshKey,
    /// A command reading a secret store such as `op`.
    SecretStore,
    /// A command reading a token warden holds.
    TokenRead,
    /// A command reaching a host warden does not cover.
    UncoveredHost,
    /// A command using the owner's GitHub login.
    OwnerGithub,
}

impl Signal {
    /// Every signal, in the order the settings document them.
    pub const ALL: [Signal; 7] = [
        Signal::CoveredSsh,
        Signal::CoveredApi,
        Signal::OwnerSshKey,
        Signal::SecretStore,
        Signal::TokenRead,
        Signal::UncoveredHost,
        Signal::OwnerGithub,
    ];

    /// The signal's name in the `[hook]` table.
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Signal::CoveredSsh => "covered-ssh",
            Signal::CoveredApi => "covered-api",
            Signal::OwnerSshKey => "owner-ssh-key",
            Signal::SecretStore => "secret-store",
            Signal::TokenRead => "token-read",
            Signal::UncoveredHost => "uncovered-host",
            Signal::OwnerGithub => "owner-github",
        }
    }

    fn index(self) -> usize {
        match self {
            Signal::CoveredSsh => 0,
            Signal::CoveredApi => 1,
            Signal::OwnerSshKey => 2,
            Signal::SecretStore => 3,
            Signal::TokenRead => 4,
            Signal::UncoveredHost => 5,
            Signal::OwnerGithub => 6,
        }
    }

    fn default_setting(self) -> Setting {
        match self {
            Signal::CoveredSsh | Signal::CoveredApi => Setting::Block,
            Signal::OwnerSshKey | Signal::SecretStore | Signal::TokenRead => Setting::Ask,
            Signal::UncoveredHost | Signal::OwnerGithub => Setting::Warn,
        }
    }

    fn from_key(key: &str) -> Option<Signal> {
        Signal::ALL.into_iter().find(|s| s.key() == key)
    }
}

/// What the hook does when a signal fires. Ordered from weakest to strongest,
/// so the strongest of several settings is their `max`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Setting {
    /// Ignore the signal.
    Off,
    /// Let the command run and tell the agent.
    Warn,
    /// Ask the user before the command runs.
    Ask,
    /// Refuse the command.
    Block,
}

impl Setting {
    fn parse(value: &str) -> Option<Setting> {
        match value {
            "off" => Some(Setting::Off),
            "warn" => Some(Setting::Warn),
            "ask" => Some(Setting::Ask),
            "block" => Some(Setting::Block),
            _ => None,
        }
    }
}

/// The setting of every signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    values: [Setting; 7],
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            values: Signal::ALL.map(Signal::default_setting),
        }
    }
}

/// Quote a bad key only when it looks like a signal name: at most 32 of
/// `[a-z-]`. Anything else could be a secret pasted into the wrong place, so
/// the note does not echo it.
fn unknown_key_detail(key: &str) -> String {
    if key.len() <= 32 && key.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
        format!("{key}: unknown key")
    } else {
        "an unknown key".to_owned()
    }
}

/// Name a bad value only when it looks like a setting name: at most 12 ASCII
/// lowercase letters. Anything else is not echoed.
fn unknown_value_detail(signal: Signal, value: &str) -> String {
    if value.len() <= 12 && value.chars().all(|c| c.is_ascii_lowercase()) {
        format!("{}: unknown value {value}", signal.key())
    } else {
        format!("{}: unknown value", signal.key())
    }
}

fn note(detail: &str) -> String {
    let mut s = String::from("invalid [hook] setting ");
    // Writing to a String cannot fail.
    let _ = write!(s, "{detail}; using the defaults");
    s
}

impl Settings {
    /// The setting of `signal`.
    #[must_use]
    pub fn get(&self, signal: Signal) -> Setting {
        self.values[signal.index()]
    }

    /// Read the `[hook]` table. Any invalid key or value gives all defaults
    /// and a note naming it, never a weaker setting.
    #[must_use]
    pub fn from_table(table: Option<&toml::Table>) -> (Settings, Option<String>) {
        let Some(table) = table else {
            return (Settings::default(), None);
        };
        let mut settings = Settings::default();
        for (key, value) in table {
            let Some(signal) = Signal::from_key(key) else {
                return (Settings::default(), Some(note(&unknown_key_detail(key))));
            };
            let Some(text) = value.as_str() else {
                return (
                    Settings::default(),
                    Some(note(&format!("{}: must be a string", signal.key()))),
                );
            };
            let Some(setting) = Setting::parse(text) else {
                return (
                    Settings::default(),
                    Some(note(&unknown_value_detail(signal, text))),
                );
            };
            settings.values[signal.index()] = setting;
        }
        (settings, None)
    }
}

#[cfg(test)]
mod tests;
