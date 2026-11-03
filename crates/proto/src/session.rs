//! What a request may say about where it came from: a session label and a link.
//!
//! Both are the agent's own claim. Sessions of one agent share its key, so any of
//! them can state any label, and the page behind a link is the agent's too. They
//! help the owner read a request and prove nothing.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use unicode_properties::{GeneralCategory, UnicodeGeneralCategory as _};
use url::{Host, Url};

use super::{ParseError, check_free_text};

/// Longest session label, in characters.
const LABEL_MAX: usize = 64;

/// Longest link, in bytes, as given and as normalized.
const LINK_MAX: usize = 256;

/// The one scheme a link may have, spelled as it must be.
const SCHEME: &str = "https://";

/// The name a session states for itself: 1 to 64 characters after trimming
/// Unicode whitespace, with the checks of a [`Goal`](super::Goal), and no line or
/// paragraph separators, so that it stays one line wherever it is shown. The
/// stored value is trimmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionLabel(String);

impl TryFrom<String> for SessionLabel {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        const WHAT: &str = "session label";
        let trimmed = value.trim();
        let chars = trimmed.chars().count();
        if chars == 0 || chars > LABEL_MAX {
            return Err(ParseError::new(WHAT, "must be 1 to 64 characters"));
        }
        check_free_text(WHAT, trimmed)?;
        if trimmed.chars().any(|c| {
            matches!(
                c.general_category(),
                GeneralCategory::LineSeparator | GeneralCategory::ParagraphSeparator
            )
        }) {
            return Err(ParseError::new(WHAT, "must be one line"));
        }
        Ok(Self(trimmed.to_owned()))
    }
}
string_newtype!(SessionLabel);

/// A link to where a request came from, in the form a browser would resolve it
/// to: `https://<host>/<path>`, at most 256 bytes.
///
/// Everything that could make the host read differently from where the link goes
/// is refused, not cleaned up: another scheme, anything in the authority but the
/// name (user, password, port, percent-encoding), non-ASCII (so an international
/// name must be given as `xn--`, which is how it is shown), an IP address in any
/// spelling, characters a URL parser drops or reads as a slash. So are a query and a
/// fragment, the usual places for a token and for a redirect's destination.
///
/// Whether a host may be linked to is the owner's setting, which the broker checks:
/// this type says only that the link is what it looks like. Errors never quote the
/// value, which could hold a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionLink(String);

impl TryFrom<String> for SessionLink {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        const WHAT: &str = "link";
        const LENGTH: &str = "must be 1 to 256 characters";
        let raw = value.trim();
        if raw.is_empty() || raw.len() > LINK_MAX {
            return Err(ParseError::new(WHAT, LENGTH));
        }
        let Some(rest) = raw.strip_prefix(SCHEME) else {
            return Err(ParseError::new(WHAT, "must start with https://"));
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(end);
        if authority.is_empty()
            || !authority
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(ParseError::new(
                WHAT,
                "must name a host, with no user, password or port",
            ));
        }
        if path.bytes().any(|b| !b.is_ascii_graphic() || b == b'\\') {
            return Err(ParseError::new(
                WHAT,
                "must be printable ASCII with no backslash",
            ));
        }
        if path.contains(['?', '#']) {
            return Err(ParseError::new(WHAT, "must not have a query or a fragment"));
        }
        let url = Url::parse(raw).map_err(|_| ParseError::new(WHAT, "is not a valid URL"))?;
        let named = matches!(url.host(), Some(Host::Domain(name))
            if name.split('.').all(|label| !label.is_empty()));
        if !named {
            return Err(ParseError::new(
                WHAT,
                "must name a host by its full name, not an IP address",
            ));
        }
        let normalized: String = url.into();
        if normalized.len() > LINK_MAX {
            return Err(ParseError::new(WHAT, LENGTH));
        }
        Ok(Self(normalized))
    }
}
string_newtype!(SessionLink);

impl SessionLink {
    /// What follows the scheme: the host, then the path from its `/`.
    fn parts(&self) -> (&str, &str) {
        let rest = self.0.strip_prefix(SCHEME).unwrap_or(&self.0);
        rest.split_at(rest.find('/').unwrap_or(rest.len()))
    }

    /// The host the link really goes to, lowercase.
    #[must_use]
    pub fn host(&self) -> &str {
        self.parts().0
    }

    /// The path, from its `/`, percent-encoded where needed.
    #[must_use]
    pub fn path(&self) -> &str {
        self.parts().1
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionLabel, SessionLink};

    fn label(text: &str) -> Result<SessionLabel, String> {
        SessionLabel::try_from(text.to_owned()).map_err(|e| e.to_string())
    }

    fn link(text: &str) -> Result<SessionLink, String> {
        SessionLink::try_from(text.to_owned()).map_err(|e| e.to_string())
    }

    #[test]
    fn a_label_is_a_short_single_line() {
        assert_eq!(label("  release-work ").unwrap().as_str(), "release-work");
        assert!(label(&"é".repeat(64)).is_ok());
        assert!(label(&"é".repeat(65)).is_err());
        assert!(label("").is_err());
        assert!(label("   ").is_err());
        assert!(serde_json::from_str::<SessionLabel>("\"\"").is_err());
    }

    #[test]
    fn a_label_refuses_what_could_change_how_it_reads() {
        for bad in [
            "a\nb",
            "a\rb",
            "a\tb",
            "a\u{0}b",
            "a\u{7f}b",
            "a\u{85}b",
            "a\u{2028}b",
            "a\u{2029}b",
            "a\u{202E}b",
            "a\u{2066}b",
            "a\u{200B}b",
            "a\u{FEFF}b",
            "a\u{AD}b",
            "\u{E0041}tag",
        ] {
            assert!(label(bad).is_err(), "accepted {bad:?}");
        }
        // Text that looks like markup is the pages' job to escape.
        assert!(label("<script>alert(1)</script>").is_ok());
    }

    #[test]
    fn a_link_is_normalized_and_splits_into_host_and_path() {
        let plain = link("https://Sessions.Example.com").unwrap();
        assert_eq!(plain.as_str(), "https://sessions.example.com/");
        assert_eq!(plain.host(), "sessions.example.com");
        assert_eq!(plain.path(), "/");
        let deep = link(" https://git.example.com/o/r/pull/1/../2 ").unwrap();
        assert_eq!(deep.as_str(), "https://git.example.com/o/r/pull/2");
        assert_eq!(deep.path(), "/o/r/pull/2");
        // Markup characters cannot survive in the path as they are.
        let markup = link("https://git.example.com/\"><script>").unwrap();
        assert_eq!(
            markup.as_str(),
            "https://git.example.com/%22%3E%3Cscript%3E"
        );
        assert_eq!(
            markup,
            serde_json::from_str(&serde_json::to_string(&markup).unwrap()).unwrap()
        );
    }

    #[test]
    fn a_link_refuses_tricks_with_its_host() {
        for bad in [
            // Other schemes, and other spellings of this one.
            "http://example.com/",
            "javascript:alert(1)",
            "data:text/html,x",
            "file:///etc/passwd",
            "HTTPS://example.com/",
            "https:example.com/",
            "https:/example.com/",
            "//example.com/",
            "example.com",
            // Slashes a parser would skip or read differently.
            "https:///example.com/",
            "https://\\example.com/",
            "https://good.example\\@evil.example/",
            "https://good.example/\\evil",
            // Userinfo, also empty, and credentials.
            "https://user@example.com/",
            "https://user:hunter2@example.com/",
            "https://@example.com/",
            "https://good.example@evil.example/",
            "https://good.example%2f@evil.example/",
            // Ports, also the default one.
            "https://example.com:443/",
            "https://example.com:8443/",
            "https://example.com:/",
            // IP addresses in any spelling.
            "https://192.0.2.1/",
            "https://2130706433/",
            "https://0x7f.1/",
            "https://127.1/",
            "https://[2001:db8::1]/",
            // International and confusable names, percent-encoded names.
            "https://exämple.com/",
            "https://example。com/",
            "https://ex%61mple.com/",
            "https://аpple.com/",
            "https://xn--/",
            // Empty labels.
            "https://example.com./",
            "https://example..com/",
            "https://./",
            "https://",
            "https:///",
        ] {
            assert!(link(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_link_refuses_queries_fragments_and_what_a_parser_would_drop() {
        for bad in [
            "https://example.com/?token=hunter2",
            "https://example.com?next=https://evil.example/",
            "https://example.com/a?b",
            "https://example.com/#access_token=hunter2",
            "https://example.com#x",
            "https://exa\tmple.com/",
            "https://exa\nmple.com/",
            "https://example.com/a\tb",
            "https://example.com/a\nb",
            "https://example.com/a b",
            "https://example.com/é",
            "https://example.com/\u{202E}gnp",
            "https://example.com/\u{200B}",
        ] {
            assert!(link(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_link_cannot_be_too_long_as_given_or_once_normalized() {
        let base = "https://example.com/";
        assert!(link(&format!("{base}{}", "a".repeat(256 - base.len()))).is_ok());
        assert!(link(&format!("{base}{}", "a".repeat(257 - base.len()))).is_err());
        assert!(link(&format!("https://{}.com/", "a".repeat(100_000))).is_err());
        // Short as given, over the limit once `<` becomes `%3C`.
        assert!(link(&format!("{base}{}", "<".repeat(200))).is_err());
    }

    #[test]
    fn refusals_do_not_quote_the_value() {
        for bad in [
            "https://user:hunter2@example.com/",
            "http://hunter2.example.com/",
            "https://example.com/?hunter2",
            "https://example.com/hunter2 x",
        ] {
            let message = link(bad).unwrap_err();
            assert!(!message.contains("hunter2"), "{message}");
        }
    }
}
