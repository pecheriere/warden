//! The owner's list of hosts a request may link to.

use std::collections::BTreeSet;
use std::sync::Arc;

use warden_broker_proto::SessionLink;

use super::RequestError;

/// Most hosts the list may hold: it is a short list of places the owner knows.
const MAX_HOSTS: usize = 64;

/// The hosts a request may link to, matched exactly: `WARDEN_REQUEST_LINK_HOSTS`.
/// Empty by default, and then no request may carry a link. A subdomain of a listed
/// host is another host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkHosts(Arc<BTreeSet<String>>);

impl LinkHosts {
    /// Parse the setting: host names separated by commas, blank for none. Each must
    /// be what [`SessionLink::host`] would give, or differ from it in case only: no
    /// scheme, path, port or wildcard, and an international name as `xn--`.
    ///
    /// # Errors
    /// Why the setting is refused.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        if value.trim().is_empty() {
            return Ok(Self::default());
        }
        let mut hosts = BTreeSet::new();
        for entry in value.split(',') {
            let host = entry.trim().to_ascii_lowercase();
            let link = SessionLink::try_from(format!("https://{host}/"))
                .map_err(|_| "must be host names separated by commas, nothing else")?;
            if host.is_empty() || link.host() != host {
                return Err("must be host names separated by commas, nothing else");
            }
            hosts.insert(host);
        }
        if hosts.len() > MAX_HOSTS {
            return Err("must list at most 64 hosts");
        }
        Ok(Self(Arc::new(hosts)))
    }

    /// Whether `link` goes to a listed host.
    #[must_use]
    pub fn allows(&self, link: &SessionLink) -> bool {
        self.0.contains(link.host())
    }

    /// Whether a request may carry `link`.
    ///
    /// # Errors
    /// [`RequestError::Rejected`] saying what to tell the agent, which does not
    /// reveal the list.
    pub(super) fn check(&self, link: Option<&SessionLink>) -> Result<(), RequestError> {
        match link {
            Some(link) if !self.allows(link) => Err(RequestError::Rejected(format!(
                "link refused: this broker does not accept links to {}. Nothing was stored and \
                 the owner was not asked. Make the request again without --link",
                link.host()
            ))),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use warden_broker_proto::SessionLink;

    use super::LinkHosts;

    fn link(text: &str) -> SessionLink {
        SessionLink::try_from(text.to_owned()).unwrap()
    }

    #[test]
    fn nothing_is_allowed_by_default() {
        for hosts in [LinkHosts::default(), LinkHosts::parse("  ").unwrap()] {
            assert!(!hosts.allows(&link("https://git.example.com/")));
            assert!(
                hosts
                    .check(Some(&link("https://git.example.com/")))
                    .is_err()
            );
            assert!(hosts.check(None).is_ok());
        }
    }

    #[test]
    fn hosts_match_exactly() {
        let hosts = LinkHosts::parse(" Git.Example.com ,sessions.example.org").unwrap();
        assert!(hosts.allows(&link("https://git.example.com/o/r/pull/1")));
        assert!(hosts.allows(&link("https://GIT.example.com")));
        assert!(hosts.allows(&link("https://sessions.example.org/s")));
        for other in [
            "https://example.com/",
            "https://evil.git.example.com/",
            "https://git.example.com.evil.example/",
            "https://notgit.example.com/",
            "https://git.example.org/",
        ] {
            assert!(!hosts.allows(&link(other)), "{other}");
        }
    }

    #[test]
    fn the_setting_takes_host_names_and_nothing_else() {
        for bad in [
            "https://git.example.com",
            "git.example.com/",
            "git.example.com/path",
            "git.example.com:443",
            "*.example.com",
            ".example.com",
            "example.com.",
            "192.0.2.1",
            "[2001:db8::1]",
            "user@example.com",
            "exämple.com",
            "a.example.com,,b.example.com",
            "a.example.com,",
            "a b.example.com",
        ] {
            assert!(LinkHosts::parse(bad).is_err(), "accepted {bad:?}");
        }
        let many = (0..65)
            .map(|n| format!("h{n}.example.com"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(LinkHosts::parse(&many).is_err());
    }

    #[test]
    fn a_refusal_names_the_host_and_keeps_the_list_to_itself() {
        let hosts = LinkHosts::parse("git.example.com").unwrap();
        let message = hosts
            .check(Some(&link("https://evil.example.org/secret-path")))
            .unwrap_err()
            .to_string();
        assert!(message.contains("evil.example.org"), "{message}");
        assert!(!message.contains("secret-path"), "{message}");
        assert!(!message.contains("git.example.com"), "{message}");
    }
}
