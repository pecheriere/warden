//! Server configuration, read from environment variables.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use secrecy::SecretString;
use url::Url;

use crate::policy::onepassword::parse_host_port;
use crate::proxy::ProxyLimits;

/// Largest value accepted for `WARDEN_RELAY_MAX_SESSIONS`: each session
/// holds two SSH connections and their buffers.
const MAX_RELAY_SESSIONS_CAP: usize = 1024;

/// Largest value accepted for `WARDEN_PROXY_MAX_RESPONSE_BYTES`: a response
/// is held in memory whole (and base64-encoded once more for the agent), so
/// the cap bounds what one call can make the broker allocate.
const MAX_PROXY_RESPONSE_CAP: usize = 64 * 1024 * 1024;

/// A configuration variable is missing or invalid. The message names it.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// A required variable is unset or empty.
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    /// A variable has an unusable value (the value itself is never echoed).
    #[error("invalid environment variable {var}: {reason}")]
    Invalid {
        /// Variable name.
        var: &'static str,
        /// Why the value was rejected.
        reason: &'static str,
    },
    /// Neither notifier is configured.
    #[error("at least one notifier is required: set WARDEN_HA_WEBHOOK_URL or WARDEN_NTFY_URL")]
    NoNotifier,
}

/// A URL that embeds a secret (for example a webhook id). Redacted in
/// `Debug` and `Display`; use [`SecretUrl::expose_url`] to read it.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretUrl(Url);

impl SecretUrl {
    /// Wrap a URL.
    #[must_use]
    pub const fn new(url: Url) -> Self {
        Self(url)
    }

    /// The underlying URL; handle with care.
    #[must_use]
    pub const fn expose_url(&self) -> &Url {
        &self.0
    }
}

impl fmt::Debug for SecretUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretUrl(<redacted>)")
    }
}

impl fmt::Display for SecretUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Parse a `WARDEN_PUBLIC_URL` value: a bare https origin with a domain
/// name, since it is the `WebAuthn` relying party and the approval UI is served
/// at its root.
///
/// # Errors
///
/// [`ConfigError::Invalid`] naming `WARDEN_PUBLIC_URL`.
pub fn parse_public_url(value: &str) -> Result<Url, ConfigError> {
    let invalid = |reason| ConfigError::Invalid {
        var: "WARDEN_PUBLIC_URL",
        reason,
    };
    let url = Url::parse(value).map_err(|_| invalid("not a valid URL"))?;
    if url.scheme() != "https" {
        return Err(invalid("must be an https URL"));
    }
    if url.domain().is_none() {
        return Err(invalid("must name a host by domain, not an IP address"));
    }
    if url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid(
            "must be a bare origin (no path, query, fragment or credentials)",
        ));
    }
    Ok(url)
}

/// Where agents reach the SSH relay: a host name or IP address and a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAddress {
    /// Host name or IP address, without brackets.
    pub host: String,
    /// TCP port.
    pub port: u16,
}

/// Parse a `WARDEN_RELAY_PUBLIC_ADDR` value: `host:port` or `[ipv6]:port`,
/// the port required.
///
/// # Errors
///
/// [`ConfigError::Invalid`] naming `WARDEN_RELAY_PUBLIC_ADDR`.
pub fn parse_relay_address(value: &str) -> Result<RelayAddress, ConfigError> {
    let invalid = |reason| ConfigError::Invalid {
        var: "WARDEN_RELAY_PUBLIC_ADDR",
        reason,
    };
    match parse_host_port(value.trim()).map_err(invalid)? {
        (host, Some(port)) => Ok(RelayAddress { host, port }),
        (_, None) => Err(invalid("must name a port (host:port)")),
    }
}

/// The SSH relay's settings.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// `WARDEN_RELAY_LISTEN`, default `127.0.0.1:2222`.
    pub listen: SocketAddr,
    /// `WARDEN_RELAY_PUBLIC_ADDR`: where agents connect to the relay. Unset
    /// means the relay is off and requests for relay targets are refused.
    pub public_addr: Option<RelayAddress>,
    /// `WARDEN_RELAY_HOST_KEY_PATH`, default `/data/relay_host_ed25519`:
    /// the relay's Ed25519 host key, created on first use.
    pub host_key_path: PathBuf,
    /// `WARDEN_RELAY_MAX_SESSIONS`, default 16: relayed sessions open at
    /// once, across all grants.
    pub max_sessions: usize,
}

/// Full server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// `WARDEN_DB_PATH`.
    pub db_path: PathBuf,
    /// `WARDEN_AUDIT_PATH`.
    pub audit_path: PathBuf,
    /// `WARDEN_API_LISTEN`, default `127.0.0.1:8080`.
    pub api_listen: SocketAddr,
    /// `WARDEN_APPROVAL_LISTEN`, default `127.0.0.1:8081`.
    pub approval_listen: SocketAddr,
    /// `WARDEN_PUBLIC_URL`, https only.
    pub public_url: Url,
    /// `WARDEN_OWNER_LOGIN`.
    pub owner_login: String,
    /// `WARDEN_OP_CONNECT_URL`.
    pub connect_url: Url,
    /// `WARDEN_OP_CONNECT_TOKEN`.
    pub connect_token: SecretString,
    /// `WARDEN_OP_VAULT`, default `Warden`.
    pub vault: String,
    /// `WARDEN_HA_WEBHOOK_URL`.
    pub ha_webhook_url: Option<SecretUrl>,
    /// `WARDEN_NTFY_URL`.
    pub ntfy_url: Option<Url>,
    /// `WARDEN_NTFY_TOKEN`.
    pub ntfy_token: Option<SecretString>,
    /// Limits of proxied API calls; `WARDEN_PROXY_MAX_RESPONSE_BYTES` sets
    /// the response size (default 1 MiB, at most 64 MiB).
    pub proxy: ProxyLimits,
    /// The SSH relay.
    pub relay: RelayConfig,
}

impl Config {
    /// Read the configuration from the process environment.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the first missing or invalid variable.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|var| std::env::var(var).ok())
    }

    /// Read the configuration through `lookup` (variable name to value).
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the first missing or invalid variable.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |var: &'static str| lookup(var).filter(|v| !v.trim().is_empty());
        let required = |var: &'static str| get(var).ok_or(ConfigError::Missing(var));
        let url = |var: &'static str, value: &str| {
            Url::parse(value).map_err(|_| ConfigError::Invalid {
                var,
                reason: "not a valid URL",
            })
        };
        let addr = |var: &'static str, default: &str| {
            get(var)
                .unwrap_or_else(|| default.to_owned())
                .parse::<SocketAddr>()
                .map_err(|_| ConfigError::Invalid {
                    var,
                    reason: "not a valid socket address (host:port)",
                })
        };

        let public_url = parse_public_url(&required("WARDEN_PUBLIC_URL")?)?;
        let connect_url = url("WARDEN_OP_CONNECT_URL", &required("WARDEN_OP_CONNECT_URL")?)?;
        let ha_webhook_url = get("WARDEN_HA_WEBHOOK_URL")
            .map(|v| url("WARDEN_HA_WEBHOOK_URL", &v).map(SecretUrl::new))
            .transpose()?;
        let ntfy_url = get("WARDEN_NTFY_URL")
            .map(|v| url("WARDEN_NTFY_URL", &v))
            .transpose()?;
        if ha_webhook_url.is_none() && ntfy_url.is_none() {
            return Err(ConfigError::NoNotifier);
        }
        let ntfy_token = get("WARDEN_NTFY_TOKEN").map(SecretString::from);
        if ntfy_token.is_some() && ntfy_url.is_none() {
            // A token with nowhere to go is a misconfiguration, most likely a
            // mistyped or forgotten URL; fail rather than silently ignore it.
            return Err(ConfigError::Invalid {
                var: "WARDEN_NTFY_TOKEN",
                reason: "set while WARDEN_NTFY_URL is unset",
            });
        }

        let mut proxy = ProxyLimits::default();
        if let Some(raw) = get("WARDEN_PROXY_MAX_RESPONSE_BYTES") {
            proxy.max_response_bytes = raw
                .trim()
                .parse::<usize>()
                .ok()
                .filter(|n| (1..=MAX_PROXY_RESPONSE_CAP).contains(n))
                .ok_or(ConfigError::Invalid {
                    var: "WARDEN_PROXY_MAX_RESPONSE_BYTES",
                    reason: "must be a whole number of bytes from 1 to 67108864",
                })?;
        }

        let relay = RelayConfig {
            listen: addr("WARDEN_RELAY_LISTEN", "127.0.0.1:2222")?,
            public_addr: get("WARDEN_RELAY_PUBLIC_ADDR")
                .map(|v| parse_relay_address(&v))
                .transpose()?,
            host_key_path: get("WARDEN_RELAY_HOST_KEY_PATH")
                .unwrap_or_else(|| "/data/relay_host_ed25519".to_owned())
                .into(),
            max_sessions: match get("WARDEN_RELAY_MAX_SESSIONS") {
                None => 16,
                Some(raw) => raw
                    .trim()
                    .parse::<usize>()
                    .ok()
                    .filter(|n| (1..=MAX_RELAY_SESSIONS_CAP).contains(n))
                    .ok_or(ConfigError::Invalid {
                        var: "WARDEN_RELAY_MAX_SESSIONS",
                        reason: "must be a whole number from 1 to 1024",
                    })?,
            },
        };

        Ok(Self {
            db_path: required("WARDEN_DB_PATH")?.into(),
            audit_path: required("WARDEN_AUDIT_PATH")?.into(),
            api_listen: addr("WARDEN_API_LISTEN", "127.0.0.1:8080")?,
            approval_listen: addr("WARDEN_APPROVAL_LISTEN", "127.0.0.1:8081")?,
            public_url,
            owner_login: required("WARDEN_OWNER_LOGIN")?,
            connect_url,
            connect_token: SecretString::from(required("WARDEN_OP_CONNECT_TOKEN")?),
            vault: get("WARDEN_OP_VAULT").unwrap_or_else(|| "Warden".to_owned()),
            ha_webhook_url,
            ntfy_url,
            ntfy_token,
            proxy,
            relay,
        })
    }
}
