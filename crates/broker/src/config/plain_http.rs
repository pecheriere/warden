//! Which service URLs may use plain `http`.
//!
//! The Connect token, a webhook id and an ntfy token all travel with their
//! request, so a plain `http` URL sends them in clear to whatever the path
//! crosses. That is an accepted choice on a network warden shares only with
//! the service, and nothing else is: a typo or a remote host would expose them
//! with no sign of it. So `http` is accepted when the URL plainly stays on a
//! local or private network, and otherwise only for a variable listed in
//! [`ALLOW_PLAIN_HTTP`].
//!
//! This reads the URL as written. It resolves no name, so a name that looks
//! local and resolves elsewhere is not caught.

use std::net::{Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

use super::{BackendSettings, CONNECT_URL, Config, ConfigError};
use crate::notify::ChannelKind;

/// The variable listing the URL settings that may use plain `http` to any host.
pub const ALLOW_PLAIN_HTTP: &str = "WARDEN_ALLOW_PLAIN_HTTP";

/// Name suffixes that stay on a local or private network. `.localhost`, `.local`
/// and `.home.arpa` are reserved for this (RFC 6761, 6762, 8375), and so is
/// `.internal` (ICANN). `.lan` is not delegated, and is what home routers commonly
/// hand out. `.ts.net` is not here: it is publicly delegated, and only this host
/// being on that tailnet would keep such a name off the public internet.
const LOCAL_SUFFIXES: [&str; 5] = [".localhost", ".local", ".home.arpa", ".internal", ".lan"];

/// How a service URL's traffic travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlTransport {
    /// `https`.
    Tls,
    /// Plain `http` to a host that is clearly local or private.
    PlainLocal,
    /// Plain `http` to any other host.
    PlainRemote,
}

impl UrlTransport {
    /// How `url` travels, from the URL alone.
    #[must_use]
    pub fn of(url: &Url) -> Self {
        if url.scheme() == "https" {
            Self::Tls
        } else if url.host().is_some_and(|host| is_local_host(&host)) {
            Self::PlainLocal
        } else {
            Self::PlainRemote
        }
    }
}

fn is_local_host(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(name) => is_local_name(name),
        Host::Ipv4(ip) => is_local_ipv4(*ip),
        Host::Ipv6(ip) => is_local_ipv6(*ip),
    }
}

/// A name without a dot can only be local: a Docker service or an `/etc/hosts`
/// entry. With a final dot it is absolute, which makes it a top-level domain,
/// unless it is `localhost`.
fn is_local_name(name: &str) -> bool {
    let has_local_suffix = |name: &str| LOCAL_SUFFIXES.iter().any(|s| name.ends_with(s));
    match name.strip_suffix('.') {
        Some(absolute) => absolute == "localhost" || has_local_suffix(absolute),
        None => !name.contains('.') || has_local_suffix(name),
    }
}

/// Loopback, RFC 1918, link-local, or the shared range (RFC 6598). That range
/// holds tailnet addresses and is also carrier NAT, and an address in it may not
/// belong to this host's tailnet: it is accepted without that being checked.
fn is_local_ipv4(ip: Ipv4Addr) -> bool {
    let [first, second, ..] = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || (first == 100 && second & 0b1100_0000 == 64)
}

/// Loopback, unique local (which holds tailnet addresses), link-local, or an
/// IPv4 address written as IPv6.
fn is_local_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.to_ipv4_mapped().is_some_and(is_local_ipv4)
}

/// The URL settings [`ALLOW_PLAIN_HTTP`] may list.
fn url_variables() -> impl Iterator<Item = &'static str> {
    ChannelKind::ALL
        .into_iter()
        .map(ChannelKind::url_variable)
        .chain([CONNECT_URL])
}

/// The variables that [`ALLOW_PLAIN_HTTP`] lists.
#[derive(Debug, Default)]
pub struct AllowedPlainHttp(Vec<&'static str>);

impl AllowedPlainHttp {
    /// Read [`ALLOW_PLAIN_HTTP`]. An entry that names no URL setting, or one
    /// that is unset, is refused: it would not do what the owner believes.
    /// A value is never echoed, in case a URL was pasted here.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] naming [`ALLOW_PLAIN_HTTP`].
    pub fn read(lookup: &impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let invalid = |reason| ConfigError::Invalid {
            var: ALLOW_PLAIN_HTTP,
            reason,
        };
        let is_set = |var: &str| lookup(var).is_some_and(|v| !v.trim().is_empty());
        let Some(list) = lookup(ALLOW_PLAIN_HTTP).filter(|v| !v.trim().is_empty()) else {
            return Ok(Self::default());
        };
        let mut allowed = Vec::new();
        for entry in list.split(',').map(str::trim) {
            let var = url_variables().find(|var| *var == entry).ok_or(invalid(
                "must list only WARDEN_OP_CONNECT_URL, \
                 WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL or WARDEN_NOTIFY_NTFY_URL",
            ))?;
            if !is_set(var) {
                return Err(invalid("lists a URL setting that is not set"));
            }
            allowed.push(var);
        }
        Ok(Self(allowed))
    }
}

/// Parse the service URL in the variable `var`: `https`, or plain `http` where
/// that is accepted. The value is never echoed: it can hold a secret.
///
/// # Errors
///
/// [`ConfigError::Invalid`] naming `var`, or [`ALLOW_PLAIN_HTTP`] when it lists
/// a variable that does not need it, so that a forgotten entry cannot later let
/// a mistyped URL through.
pub fn parse_service_url(
    var: &'static str,
    value: &str,
    allowed: &AllowedPlainHttp,
) -> Result<Url, ConfigError> {
    let invalid = |reason| ConfigError::Invalid { var, reason };
    let url = Url::parse(value).map_err(|_| invalid("not a valid URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(invalid("must be an https or http URL"));
    }
    let listed = allowed.0.contains(&var);
    match UrlTransport::of(&url) {
        UrlTransport::PlainRemote if !listed => Err(invalid(
            "plain http to a host that is not clearly local or private sends secrets in clear; \
             use https, or list this variable in WARDEN_ALLOW_PLAIN_HTTP (docs/upgrading.md)",
        )),
        UrlTransport::Tls | UrlTransport::PlainLocal if listed => Err(ConfigError::Invalid {
            var: ALLOW_PLAIN_HTTP,
            reason: "lists a URL setting that does not need it: it is https, or clearly local \
                     or private",
        }),
        _ => Ok(url),
    }
}

impl Config {
    /// Each configured service URL that uses plain `http`: its variable, and
    /// how it travels. Variables only, because a URL can hold a secret.
    #[must_use]
    pub fn plain_http_urls(&self) -> Vec<(&'static str, UrlTransport)> {
        let connect = match &self.backend {
            BackendSettings::OnePassword(connect) => Some((CONNECT_URL, &connect.url)),
            BackendSettings::Local(_) => None,
        };
        connect
            .into_iter()
            .chain(
                self.notify
                    .iter()
                    .map(|channel| (channel.kind().url_variable(), channel.url())),
            )
            .map(|(var, url)| (var, UrlTransport::of(url)))
            .filter(|(_, transport)| *transport != UrlTransport::Tls)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::{ALLOW_PLAIN_HTTP, AllowedPlainHttp, UrlTransport, parse_service_url};
    use crate::config::{CONNECT_URL, ConfigError};

    const NTFY_URL: &str = "WARDEN_NOTIFY_NTFY_URL";
    const REMOTE: &str = "http://connect.example.com:8080";

    fn transport(url: &str) -> UrlTransport {
        UrlTransport::of(&Url::parse(url).unwrap())
    }

    /// The Connect URL set to `REMOTE`, and the opt-in set to `list`.
    fn allowed(list: &str) -> Result<AllowedPlainHttp, ConfigError> {
        AllowedPlainHttp::read(&|var: &str| match var {
            ALLOW_PLAIN_HTTP => Some(list.to_owned()),
            CONNECT_URL => Some(REMOTE.to_owned()),
            _ => None,
        })
    }

    #[test]
    fn https_is_tls_whatever_the_host() {
        for url in ["https://8.8.8.8/", "https://ntfy.example.com/topic"] {
            assert_eq!(transport(url), UrlTransport::Tls, "{url}");
        }
    }

    #[test]
    fn local_and_private_hosts_are_recognized() {
        for url in [
            "http://127.0.0.1:8080",
            "http://127.1:8080",
            "http://10.1.2.3",
            "http://172.16.0.1",
            "http://172.31.251.11:8080",
            "http://192.168.1.2:8123/api/webhook/id",
            "http://169.254.0.1",
            "http://100.64.0.1",
            "http://100.127.255.254",
            "http://[::1]:8080",
            "http://[fd7a:115c:a1e0::1]",
            "http://[fe80::1]",
            "http://[::ffff:192.168.1.2]",
            "http://localhost:8080",
            "http://localhost.:8080",
            "http://connect:8080",
            "http://op-connect-api:8080",
            "http://CONNECT:8080",
            "http://foo.localhost",
            "http://homeassistant.local:8123/api/webhook/id",
            "http://homeassistant.local.:8123",
            "http://ha.home.arpa",
            "http://connect.internal",
            "http://ha.lan",
        ] {
            assert_eq!(transport(url), UrlTransport::PlainLocal, "{url}");
        }
    }

    #[test]
    fn other_hosts_are_remote() {
        for url in [
            "http://8.8.8.8",
            "http://192.0.2.1:8080",
            "http://198.51.100.7",
            "http://172.32.0.1",
            "http://172.15.0.1",
            "http://100.63.0.1",
            "http://100.128.0.1",
            "http://0.0.0.0",
            "http://[::]",
            "http://[2001:db8::1]",
            "http://[::ffff:8.8.8.8]",
            "http://ntfy.sh/topic",
            "http://connect.example.com",
            "http://connect.",
            "http://local.example.com",
            "http://example.local.evil.example",
            "http://mylan.example",
            "http://xlocalhost.example",
            "http://ts.net",
            "http://warden-connect.example.ts.net",
            "http://warden-connect.example.ts.net.",
            "http://home.arpa",
            "http://notlocal.example",
            "http://example-ts.net",
        ] {
            assert_eq!(transport(url), UrlTransport::PlainRemote, "{url}");
        }
    }

    #[test]
    fn remote_plain_http_is_refused_without_echoing_the_url() {
        let err = parse_service_url(CONNECT_URL, REMOTE, &AllowedPlainHttp::default()).unwrap_err();
        let ConfigError::Invalid { var, reason } = &err else {
            panic!("{err}");
        };
        assert_eq!(*var, CONNECT_URL);
        assert!(reason.contains(ALLOW_PLAIN_HTTP), "{reason}");
        assert!(!err.to_string().contains("connect.example.com"), "{err}");
    }

    /// A tailnet name can be another tailnet's, or a public Funnel host, so it
    /// takes the opt-in, and the refusal says so.
    #[test]
    fn a_ts_net_name_over_plain_http_needs_the_opt_in() {
        const TAILNET_NAME: &str = "http://warden-connect.example.ts.net";
        let err =
            parse_service_url(CONNECT_URL, TAILNET_NAME, &AllowedPlainHttp::default()).unwrap_err();
        assert!(err.to_string().contains(ALLOW_PLAIN_HTTP), "{err}");
        let allowed = allowed(CONNECT_URL).unwrap();
        assert!(parse_service_url(CONNECT_URL, TAILNET_NAME, &allowed).is_ok());
        assert!(
            parse_service_url(
                CONNECT_URL,
                "https://warden-connect.example.ts.net",
                &AllowedPlainHttp::default()
            )
            .is_ok()
        );
    }

    #[test]
    fn listing_the_variable_allows_remote_plain_http_for_it_alone() {
        let allowed = allowed(CONNECT_URL).unwrap();
        assert!(parse_service_url(CONNECT_URL, REMOTE, &allowed).is_ok());
        assert!(parse_service_url(NTFY_URL, "http://ntfy.example.com/t", &allowed).is_err());
    }

    #[test]
    fn local_plain_http_and_https_need_no_listing() {
        let none = AllowedPlainHttp::default();
        for url in ["http://172.31.251.11:8080", "https://connect.example.com"] {
            assert!(parse_service_url(CONNECT_URL, url, &none).is_ok(), "{url}");
        }
    }

    /// A leftover entry would quietly let a later typo through.
    #[test]
    fn listing_a_variable_that_does_not_need_it_is_refused() {
        let allowed = allowed(CONNECT_URL).unwrap();
        for url in ["http://172.31.251.11:8080", "https://connect.example.com"] {
            let err = parse_service_url(CONNECT_URL, url, &allowed).unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigError::Invalid {
                        var: ALLOW_PLAIN_HTTP,
                        ..
                    }
                ),
                "{url}: {err}"
            );
        }
    }

    #[test]
    fn other_schemes_are_refused() {
        for url in [
            "ftp://connect.internal/",
            "file:///etc/passwd",
            "connect:8080",
        ] {
            let err =
                parse_service_url(CONNECT_URL, url, &AllowedPlainHttp::default()).unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigError::Invalid {
                        var: CONNECT_URL,
                        ..
                    }
                ),
                "{url}: {err}"
            );
        }
    }

    #[test]
    fn a_bad_opt_in_list_is_refused_without_echoing_it() {
        for list in [
            "WARDEN_DB_PATH",
            "http://connect.example.com",
            "WARDEN_OP_CONNECT_URL,",
            "WARDEN_NOTIFY_NTFY_URL",
        ] {
            let err = allowed(list).unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigError::Invalid {
                        var: ALLOW_PLAIN_HTTP,
                        ..
                    }
                ),
                "{list}: {err}"
            );
            assert!(!err.to_string().contains("connect.example.com"), "{err}");
        }
    }

    #[test]
    fn a_blank_opt_in_list_allows_nothing() {
        let blank = allowed(" ").unwrap();
        assert!(parse_service_url(CONNECT_URL, REMOTE, &blank).is_err());
    }
}
