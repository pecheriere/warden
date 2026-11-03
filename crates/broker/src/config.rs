//! Server configuration, read from environment variables.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read as _};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path, PathBuf};

use secrecy::SecretString;
use url::Url;
use warden_broker_proto::Window;
use zeroize::Zeroizing;

use crate::notify::{ChannelKind, ChannelList, parse_channels};
use crate::policy::onepassword::parse_host_port;
use crate::proxy::ProxyLimits;
use crate::requests::{LinkHosts, RequestLimits};
use crate::signed::BodyReadTimeout;

mod plain_http;

pub use plain_http::{ALLOW_PLAIN_HTTP, AllowedPlainHttp, UrlTransport, parse_service_url};

/// Largest value accepted for `WARDEN_RELAY_MAX_SESSIONS`: each session
/// holds two SSH connections and their buffers.
const MAX_RELAY_SESSIONS_CAP: usize = 1024;

/// Largest value accepted for `WARDEN_PROXY_MAX_RESPONSE_BYTES`: a response
/// is held in memory whole (and base64-encoded once more for the agent), so
/// the cap bounds what one call can make the broker allocate.
const MAX_PROXY_RESPONSE_CAP: usize = 64 * 1024 * 1024;

/// Largest value accepted for `WARDEN_PROXY_MAX_CALLS_PER_AGENT`.
const MAX_PROXY_CALLS_PER_AGENT_CAP: usize = 64;

/// Largest value accepted for `WARDEN_PROXY_MAX_CALLS`: each call holds up to
/// two response-sized buffers while it runs.
const MAX_PROXY_CALLS_CAP: usize = 256;

/// The Connect token's variable and the one naming a file that holds it.
const CONNECT_TOKEN_VARIABLES: (&str, &str) =
    ("WARDEN_OP_CONNECT_TOKEN", "WARDEN_OP_CONNECT_TOKEN_FILE");

/// Largest secret file accepted, in bytes. Far above any token or URL; it
/// keeps a wrong path from being read into memory whole.
const MAX_SECRET_FILE_BYTES: u16 = 32 * 1024;

/// The Connect API's URL variable.
const CONNECT_URL: &str = "WARDEN_OP_CONNECT_URL";

/// The variables only the 1Password backend reads.
const ONE_PASSWORD_VARIABLES: [&str; 4] = [
    CONNECT_TOKEN_VARIABLES.0,
    CONNECT_TOKEN_VARIABLES.1,
    CONNECT_URL,
    "WARDEN_OP_VAULT",
];

/// The local backend's policy file variable.
const LOCAL_POLICY_FILE: &str = "WARDEN_LOCAL_POLICY_FILE";

/// The local backend's secrets directory variable.
const LOCAL_SECRETS_DIR: &str = "WARDEN_LOCAL_SECRETS_DIR";

/// `WARDEN_SECRET_BACKEND`'s value for 1Password.
const ONE_PASSWORD_BACKEND: &str = "1password";

/// `WARDEN_SECRET_BACKEND`'s value for local files.
const LOCAL_BACKEND: &str = "local";

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
    /// A `*_FILE` variable names a file that cannot be read. Neither the path
    /// nor anything in the file is echoed.
    #[error("cannot read the file named by {var}: {kind}")]
    SecretFile {
        /// The `*_FILE` variable.
        var: &'static str,
        /// Why reading failed.
        kind: io::ErrorKind,
    },
    /// `WARDEN_NOTIFY` is unset or empty.
    #[error(
        "WARDEN_NOTIFY must list at least one notification channel in priority order ({}), \
         for example WARDEN_NOTIFY={}",
        ChannelKind::known(),
        ChannelKind::known().replace(", ", ",")
    )]
    NoChannels,
    /// `WARDEN_NOTIFY` names a channel that does not exist.
    #[error(
        "WARDEN_NOTIFY names {} (known: {})",
        .name.as_ref().map_or_else(|| "an unknown channel name".to_owned(), |n| format!("unknown channel {n:?}")),
        ChannelKind::known()
    )]
    UnknownChannel {
        /// The name, only when it looks like a plain channel name (a pasted
        /// URL or token is never echoed).
        name: Option<String>,
    },
    /// `WARDEN_NOTIFY` names a channel with upper-case letters.
    #[error("WARDEN_NOTIFY: channel names are lowercase: {}", ChannelKind::known())]
    UppercaseChannel,
    /// `WARDEN_NOTIFY` names a channel twice.
    #[error("WARDEN_NOTIFY lists channel {0} twice")]
    DuplicateChannel(&'static str),
    /// A variable of the removed fixed notifier wiring is set.
    #[error("{var} is no longer supported: {replacement}")]
    Removed {
        /// The removed variable.
        var: &'static str,
        /// What to set instead.
        replacement: &'static str,
    },
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

/// Where the audience file is when `WARDEN_AUDIENCE_PATH` is not set.
pub const DEFAULT_AUDIENCE_PATH: &str = "/data/audience";

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

/// How to reach 1Password Connect.
#[derive(Debug, Clone)]
pub struct ConnectSettings {
    /// `WARDEN_OP_CONNECT_URL`.
    pub url: Url,
    /// `WARDEN_OP_CONNECT_TOKEN`.
    pub token: SecretString,
    /// `WARDEN_OP_VAULT`, default `Warden`.
    pub vault: String,
}

/// Where the local backend reads its files. Both paths are absolute, without
/// `..`; whether they are safe to read is decided each time they are read.
#[derive(Debug, Clone)]
pub struct LocalSettings {
    /// `WARDEN_LOCAL_POLICY_FILE`: targets and API secrets, in TOML.
    pub policy_file: PathBuf,
    /// `WARDEN_LOCAL_SECRETS_DIR`: the only directory secrets are read from.
    pub secrets_dir: PathBuf,
}

/// Where targets, API secrets and the SSH CA key come from.
#[derive(Debug, Clone)]
pub enum BackendSettings {
    /// A 1Password vault through Connect: the recommended backend.
    OnePassword(ConnectSettings),
    /// Files on the broker's host. Weaker: see `docs/local-backend.md`.
    Local(LocalSettings),
}

impl BackendSettings {
    /// The `WARDEN_SECRET_BACKEND` spelling of this backend.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::OnePassword(_) => ONE_PASSWORD_BACKEND,
            Self::Local(_) => LOCAL_BACKEND,
        }
    }
}

/// Full server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// `WARDEN_DB_PATH`.
    pub db_path: PathBuf,
    /// `WARDEN_AUDIT_PATH`.
    pub audit_path: PathBuf,
    /// `WARDEN_AUDIENCE_PATH`, default `/data/audience`: the file holding
    /// the broker's audience id, created on first start and never changed.
    pub audience_path: PathBuf,
    /// `WARDEN_API_LISTEN`, default `127.0.0.1:8080`.
    pub api_listen: SocketAddr,
    /// `WARDEN_APPROVAL_LISTEN`, default `127.0.0.1:8081`.
    pub approval_listen: SocketAddr,
    /// `WARDEN_PUBLIC_URL`, https only.
    pub public_url: Url,
    /// `WARDEN_OWNER_LOGIN`.
    pub owner_login: String,
    /// `WARDEN_SECRET_BACKEND` and the settings of the backend it names.
    pub backend: BackendSettings,
    /// The enabled notification channels in priority order: `WARDEN_NOTIFY`
    /// and the `WARDEN_NOTIFY_<KIND>_*` settings. Never empty.
    pub notify: ChannelList,
    /// Limits of proxied API calls; `WARDEN_PROXY_MAX_RESPONSE_BYTES` sets
    /// the response size (default 1 MiB, at most 64 MiB),
    /// `WARDEN_PROXY_MAX_CALLS_PER_AGENT` (default 4, 1 to 64) and
    /// `WARDEN_PROXY_MAX_CALLS` (default 16, 1 to 256, at least the
    /// per-agent limit) the calls in flight at once.
    pub proxy: ProxyLimits,
    /// How many requests each agent may make;
    /// `WARDEN_REQUEST_MAX_PENDING_PER_AGENT` (default 5, 1 to 256),
    /// `WARDEN_REQUEST_MAX_NEW_PER_AGENT` (default 10, 1 to 1024, at least the
    /// pending limit) and `WARDEN_REQUEST_LIMIT_WINDOW_SECS` (default 600, 60
    /// to 3600).
    pub requests: RequestLimits,
    /// `WARDEN_COMMIT_SIGNING_MAX_WINDOW`, default `30d`: the longest commit
    /// signing grant the server allows, `1d`, `7d`, `30d` or `90d`.
    pub commit_signing_max_window: Window,
    /// `WARDEN_COMMIT_SIGNING_MAX_PER_DAY`, default 5000, 1 to 1000000: signatures per
    /// commit signing grant per UTC day.
    pub commit_signing_max_per_day: u32,
    /// `WARDEN_REQUEST_LINK_HOSTS`: the hosts a request may link to. Unset, no
    /// request may carry a link.
    pub link_hosts: LinkHosts,
    /// The SSH relay.
    pub relay: RelayConfig,
    /// How long the body of a signed request may take to arrive. Not set
    /// from the environment: always [`BodyReadTimeout::default`]; tests
    /// shorten it.
    pub body_read_timeout: BodyReadTimeout,
}

/// Whether `WARDEN_SECRET_BACKEND` asks for the local backend. Unset means
/// 1Password: every deployment from before the setting exists keeps working,
/// and nothing ever falls through to the weaker backend. So the local backend's
/// settings without the explicit choice are refused, and so are one backend's
/// settings under the other: either could mean the owner believes secrets are
/// somewhere they are not.
fn wants_local_backend(lookup: &impl Fn(&str) -> Option<String>) -> Result<bool, ConfigError> {
    const VAR: &str = "WARDEN_SECRET_BACKEND";
    let is_set = |var: &&&'static str| lookup(var).is_some_and(|v| !v.trim().is_empty());
    let local = match lookup(VAR).filter(|v| !v.trim().is_empty()).as_deref() {
        None | Some(ONE_PASSWORD_BACKEND) => false,
        Some(LOCAL_BACKEND) => true,
        Some(_) => {
            return Err(ConfigError::Invalid {
                var: VAR,
                reason: "must be 1password or local",
            });
        }
    };
    let (other, reason) = if local {
        (
            &ONE_PASSWORD_VARIABLES[..],
            "set, but WARDEN_SECRET_BACKEND is local",
        )
    } else {
        (
            &[LOCAL_POLICY_FILE, LOCAL_SECRETS_DIR][..],
            "set, but WARDEN_SECRET_BACKEND is not local",
        )
    };
    match other.iter().find(is_set) {
        Some(var) => Err(ConfigError::Invalid { var, reason }),
        None => Ok(local),
    }
}

/// A path for the local backend: absolute and without `..`.
fn local_path(var: &'static str, value: &str) -> Result<PathBuf, ConfigError> {
    let path = Path::new(value);
    if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        return Err(ConfigError::Invalid {
            var,
            reason: "must be an absolute path without ..",
        });
    }
    Ok(path.to_owned())
}

/// The proxy's limits from the environment, defaults where unset.
fn proxy_limits(get: &impl Fn(&'static str) -> Option<String>) -> Result<ProxyLimits, ConfigError> {
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
    if let Some(raw) = get("WARDEN_PROXY_MAX_CALLS_PER_AGENT") {
        proxy.max_calls_per_agent = raw
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=MAX_PROXY_CALLS_PER_AGENT_CAP).contains(n))
            .ok_or(ConfigError::Invalid {
                var: "WARDEN_PROXY_MAX_CALLS_PER_AGENT",
                reason: "must be a whole number from 1 to 64",
            })?;
    }
    if let Some(raw) = get("WARDEN_PROXY_MAX_CALLS") {
        proxy.max_calls = raw
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=MAX_PROXY_CALLS_CAP).contains(n))
            .ok_or(ConfigError::Invalid {
                var: "WARDEN_PROXY_MAX_CALLS",
                reason: "must be a whole number from 1 to 256",
            })?;
    }
    if proxy.max_calls_per_agent > proxy.max_calls {
        return Err(ConfigError::Invalid {
            var: "WARDEN_PROXY_MAX_CALLS_PER_AGENT",
            reason: "must not exceed WARDEN_PROXY_MAX_CALLS",
        });
    }
    Ok(proxy)
}

/// A whole number in `range` from the variable `var`, or `default` if unset.
fn bounded_u32(
    get: &impl Fn(&'static str) -> Option<String>,
    var: &'static str,
    range: std::ops::RangeInclusive<u32>,
    reason: &'static str,
    default: u32,
) -> Result<u32, ConfigError> {
    get(var).map_or(Ok(default), |raw| {
        raw.trim()
            .parse()
            .ok()
            .filter(|n| range.contains(n))
            .ok_or(ConfigError::Invalid { var, reason })
    })
}

/// The per-agent request limits from the environment, defaults where unset.
/// The window is capped so that no setting can block an agent for long.
fn request_limits(
    get: &impl Fn(&'static str) -> Option<String>,
) -> Result<RequestLimits, ConfigError> {
    let defaults = RequestLimits::default();
    let limits = RequestLimits {
        max_pending: bounded_u32(
            get,
            "WARDEN_REQUEST_MAX_PENDING_PER_AGENT",
            1..=256,
            "must be a whole number from 1 to 256",
            defaults.max_pending,
        )?,
        max_new: bounded_u32(
            get,
            "WARDEN_REQUEST_MAX_NEW_PER_AGENT",
            1..=1024,
            "must be a whole number from 1 to 1024",
            defaults.max_new,
        )?,
        window_secs: bounded_u32(
            get,
            "WARDEN_REQUEST_LIMIT_WINDOW_SECS",
            60..=3600,
            "must be a whole number of seconds from 60 to 3600",
            defaults.window_secs,
        )?,
    };
    if limits.max_pending > limits.max_new {
        return Err(ConfigError::Invalid {
            var: "WARDEN_REQUEST_MAX_PENDING_PER_AGENT",
            reason: "must not exceed WARDEN_REQUEST_MAX_NEW_PER_AGENT",
        });
    }
    Ok(limits)
}

/// The longest commit signing grant and its signatures per day, from the environment.
fn commit_signing_limits(
    get: &impl Fn(&'static str) -> Option<String>,
) -> Result<(Window, u32), ConfigError> {
    let window = get("WARDEN_COMMIT_SIGNING_MAX_WINDOW").map_or(
        Ok(Window::COMMIT_SIGNING_DEFAULT),
        |raw| {
            Window::commit_signing(raw.trim()).map_err(|_| ConfigError::Invalid {
                var: "WARDEN_COMMIT_SIGNING_MAX_WINDOW",
                reason: "must be 1d, 7d, 30d or 90d",
            })
        },
    )?;
    let per_day = bounded_u32(
        get,
        "WARDEN_COMMIT_SIGNING_MAX_PER_DAY",
        1..=1_000_000,
        "must be a whole number from 1 to 1000000",
        crate::requests::SIGNATURES_PER_DAY,
    )?;
    Ok((window, per_day))
}

/// The secret in the file at `path`, which `var` names: one line, without its
/// line ending. It must be a regular file that other users cannot access.
fn read_secret_file(var: &'static str, path: &Path) -> Result<Zeroizing<String>, ConfigError> {
    let unreadable = |e: io::Error| ConfigError::SecretFile {
        var,
        kind: e.kind(),
    };
    let invalid = |reason| ConfigError::Invalid { var, reason };
    let meta = fs::metadata(path).map_err(unreadable)?;
    if !meta.is_file() {
        return Err(invalid("must name a regular file"));
    }
    if meta.permissions().mode() & 0o007 != 0 {
        return Err(invalid("the file must not be accessible to other users"));
    }
    // Allocated once at its largest, so that growing it leaves no copy of the
    // secret behind for `Zeroizing` to miss.
    let mut value = Zeroizing::new(String::with_capacity(
        usize::from(MAX_SECRET_FILE_BYTES) + 1,
    ));
    File::open(path)
        .map_err(unreadable)?
        .take(u64::from(MAX_SECRET_FILE_BYTES) + 1)
        .read_to_string(&mut value)
        .map_err(|e| match e.kind() {
            io::ErrorKind::InvalidData => invalid("the file is not valid UTF-8"),
            _ => unreadable(e),
        })?;
    if value.len() > usize::from(MAX_SECRET_FILE_BYTES) {
        return Err(invalid("the file is too large for a secret"));
    }
    let line_length = value.trim_end_matches(['\r', '\n']).len();
    value.truncate(line_length);
    if value.contains(['\r', '\n']) {
        return Err(invalid("the file must hold a single line"));
    }
    if value.trim().is_empty() {
        return Err(invalid("the file is empty"));
    }
    Ok(value)
}

/// The secrets configured through `*_FILE` variables, each under the name of
/// the variable it stands for. Setting both forms of one secret is refused:
/// neither can be assumed to be the one meant.
fn read_secret_files(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<Vec<(&'static str, Zeroizing<String>)>, ConfigError> {
    let mut secrets = Vec::new();
    let variables = ChannelKind::ALL
        .iter()
        .flat_map(|kind| kind.file_variables())
        .chain([&CONNECT_TOKEN_VARIABLES]);
    for &(var, file_var) in variables {
        let Some(path) = lookup(file_var).filter(|v| !v.trim().is_empty()) else {
            continue;
        };
        if lookup(var).is_some_and(|v| !v.trim().is_empty()) {
            return Err(ConfigError::Invalid {
                var: file_var,
                reason: "set together with the variable it stands for; set only one",
            });
        }
        secrets.push((var, read_secret_file(file_var, Path::new(&path))?));
    }
    Ok(secrets)
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

    /// Read the configuration through `lookup` (variable name to value). This
    /// reads the files that `*_FILE` variables name, so it blocks.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the first missing or invalid variable.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        // First, so that a refused combination reads no secret file.
        let local_backend = wants_local_backend(&lookup)?;
        let secrets = read_secret_files(&lookup)?;
        let lookup = |var: &str| {
            secrets
                .iter()
                .find(|(name, _)| *name == var)
                .map(|(_, value)| String::clone(value))
                .or_else(|| lookup(var))
        };
        let get = |var: &'static str| lookup(var).filter(|v| !v.trim().is_empty());
        let required = |var: &'static str| get(var).ok_or(ConfigError::Missing(var));
        let addr = |var: &'static str, default: &str| {
            get(var)
                .unwrap_or_else(|| default.to_owned())
                .parse::<SocketAddr>()
                .map_err(|_| ConfigError::Invalid {
                    var,
                    reason: "not a valid socket address (host:port)",
                })
        };

        let allowed_plain_http = AllowedPlainHttp::read(&lookup)?;
        let public_url = parse_public_url(&required("WARDEN_PUBLIC_URL")?)?;
        let backend = if local_backend {
            BackendSettings::Local(LocalSettings {
                policy_file: local_path(LOCAL_POLICY_FILE, &required(LOCAL_POLICY_FILE)?)?,
                secrets_dir: local_path(LOCAL_SECRETS_DIR, &required(LOCAL_SECRETS_DIR)?)?,
            })
        } else {
            BackendSettings::OnePassword(ConnectSettings {
                url: parse_service_url(CONNECT_URL, &required(CONNECT_URL)?, &allowed_plain_http)?,
                token: SecretString::from(required("WARDEN_OP_CONNECT_TOKEN")?),
                vault: get("WARDEN_OP_VAULT").unwrap_or_else(|| "Warden".to_owned()),
            })
        };
        let notify = parse_channels(&lookup, &allowed_plain_http)?;

        let proxy = proxy_limits(&get)?;
        let requests = request_limits(&get)?;
        let (commit_signing_max_window, commit_signing_max_per_day) = commit_signing_limits(&get)?;
        let link_hosts = get("WARDEN_REQUEST_LINK_HOSTS")
            .map_or_else(
                || Ok(LinkHosts::default()),
                |value| LinkHosts::parse(&value),
            )
            .map_err(|reason| ConfigError::Invalid {
                var: "WARDEN_REQUEST_LINK_HOSTS",
                reason,
            })?;

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
            audience_path: get("WARDEN_AUDIENCE_PATH")
                .unwrap_or_else(|| DEFAULT_AUDIENCE_PATH.to_owned())
                .into(),
            api_listen: addr("WARDEN_API_LISTEN", "127.0.0.1:8080")?,
            approval_listen: addr("WARDEN_APPROVAL_LISTEN", "127.0.0.1:8081")?,
            public_url,
            owner_login: required("WARDEN_OWNER_LOGIN")?,
            backend,
            notify,
            proxy,
            requests,
            commit_signing_max_window,
            commit_signing_max_per_day,
            link_hosts,
            relay,
            body_read_timeout: BodyReadTimeout::default(),
        })
    }
}

#[cfg(test)]
mod tests;
