//! The `list` field of a target or API secret item: whether `warden list`
//! shows the item and how much of it.
//!
//! It decides listing only, never access: a hidden item can still be requested.

/// How much of an item `warden list` shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listing {
    /// The item, what may be requested of it, and where it points.
    Full,
    /// The item and what may be requested of it (users, longest window and
    /// mode, or methods, path prefix and longest window), not where it points.
    Name,
    /// Nothing.
    Hidden,
    /// The field holds something else. Listed as [`Listing::Hidden`] would be:
    /// the local backend refuses such a policy file instead.
    Invalid,
}

impl Listing {
    /// From the item's `list` field: absent or blank is `Full`; `full`,
    /// `name` and `hidden` (case-sensitive, trimmed) are themselves; anything
    /// else is `Invalid`.
    #[must_use]
    pub fn parse(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            None | Some("" | "full") => Self::Full,
            Some("name") => Self::Name,
            Some("hidden") => Self::Hidden,
            Some(_) => Self::Invalid,
        }
    }

    /// Whether `warden list` shows the item at all (`Full` or `Name`).
    #[must_use]
    pub const fn is_listed(self) -> bool {
        matches!(self, Self::Full | Self::Name)
    }

    /// Whether it shows where the item points (`Full` only).
    #[must_use]
    pub const fn shows_destination(self) -> bool {
        matches!(self, Self::Full)
    }
}

#[cfg(test)]
mod tests {
    use super::Listing;

    #[test]
    fn missing_or_blank_is_full() {
        for value in [None, Some(""), Some("  ")] {
            assert_eq!(Listing::parse(value), Listing::Full, "{value:?}");
        }
    }

    #[test]
    fn known_values_trimmed() {
        assert_eq!(Listing::parse(Some(" name ")), Listing::Name);
        assert_eq!(Listing::parse(Some("hidden\n")), Listing::Hidden);
        assert_eq!(Listing::parse(Some("full")), Listing::Full);
    }

    #[test]
    fn anything_else_is_invalid() {
        for value in ["Full", "yes", "visible"] {
            assert_eq!(Listing::parse(Some(value)), Listing::Invalid, "{value}");
        }
    }

    #[test]
    fn only_full_and_name_are_listed() {
        assert!(Listing::Full.is_listed());
        assert!(Listing::Name.is_listed());
        assert!(!Listing::Hidden.is_listed());
        assert!(!Listing::Invalid.is_listed());
    }

    #[test]
    fn only_full_shows_destination() {
        assert!(Listing::Full.shows_destination());
        assert!(!Listing::Name.shows_destination());
        assert!(!Listing::Hidden.shows_destination());
        assert!(!Listing::Invalid.shows_destination());
    }
}
