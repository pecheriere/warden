//! The access window: how long a grant lasts.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ParseError;

/// Access window length. The windows up to 4 hours are for SSH and API access;
/// the windows in days are for commit signing only, and neither parsing a
/// policy's `max_window` nor a target's or secret's limit can ever admit one
/// (see [`Window::commit_signing`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Window {
    /// 15 minutes.
    #[serde(rename = "15m")]
    M15,
    /// 30 minutes.
    #[serde(rename = "30m")]
    M30,
    /// 1 hour.
    #[serde(rename = "1h")]
    H1,
    /// 4 hours.
    #[serde(rename = "4h")]
    H4,
    /// 1 day: commit signing only.
    #[serde(rename = "1d")]
    D1,
    /// 7 days: commit signing only.
    #[serde(rename = "7d")]
    D7,
    /// 30 days: commit signing only.
    #[serde(rename = "30d")]
    D30,
    /// 90 days: commit signing only.
    #[serde(rename = "90d")]
    D90,
}

impl Window {
    /// Length of the window in seconds.
    #[must_use]
    pub const fn secs(self) -> u64 {
        match self {
            Self::M15 => 900,
            Self::M30 => 1800,
            Self::H1 => 3600,
            Self::H4 => 14400,
            Self::D1 => 86_400,
            Self::D7 => 604_800,
            Self::D30 => 2_592_000,
            Self::D90 => 7_776_000,
        }
    }

    /// The windows a commit signing grant may have, shortest first.
    pub const COMMIT_SIGNING: [Self; 4] = [Self::D1, Self::D7, Self::D30, Self::D90];

    /// The default window of a commit signing grant.
    pub const COMMIT_SIGNING_DEFAULT: Self = Self::D30;

    /// Whether this is one of the windows of a commit signing grant.
    #[must_use]
    pub const fn is_commit_signing(self) -> bool {
        matches!(self, Self::D1 | Self::D7 | Self::D30 | Self::D90)
    }

    /// Parse a commit signing window: `1d`, `7d`, `30d` or `90d`. Kept apart from
    /// [`FromStr`], which every policy's `max_window` goes through, so that no
    /// target or secret can be given a window this long.
    ///
    /// # Errors
    /// If `s` is anything else.
    pub fn commit_signing(s: &str) -> Result<Self, ParseError> {
        match s {
            "1d" => Ok(Self::D1),
            "7d" => Ok(Self::D7),
            "30d" => Ok(Self::D30),
            "90d" => Ok(Self::D90),
            _ => Err(ParseError::new("window", "must be one of 1d, 7d, 30d, 90d")),
        }
    }

    /// The window as written on the wire and on the command line, such as `15m`.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::M15 => "15m",
            Self::M30 => "30m",
            Self::H1 => "1h",
            Self::H4 => "4h",
            Self::D1 => "1d",
            Self::D7 => "7d",
            Self::D30 => "30d",
            Self::D90 => "90d",
        }
    }
}

/// Covers the windows of SSH and API access only: see [`Window::commit_signing`].
impl FromStr for Window {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "15m" => Ok(Self::M15),
            "30m" => Ok(Self::M30),
            "1h" => Ok(Self::H1),
            "4h" => Ok(Self::H4),
            _ => Err(ParseError::new("window", "must be one of 15m, 30m, 1h, 4h")),
        }
    }
}
