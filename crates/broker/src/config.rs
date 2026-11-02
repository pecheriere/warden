//! Server configuration, read from environment variables.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read as _};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use secrecy::SecretString;
use url::Url;
use zeroize::Zeroizing;

use crate::notify::{ChannelKind, ChannelList, parse_channels};
use crate::policy::onepassword::parse_host_port;
use crate::proxy::ProxyLimits;
use crate::requests::RequestLimits;
use crate::signed::BodyReadTimeout;

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
    /// `WARDEN_OP_CONNECT_URL`.
    pub connect_url: Url,
    /// `WARDEN_OP_CONNECT_TOKEN`.
    pub connect_token: SecretString,
    /// `WARDEN_OP_VAULT`, default `Warden`.
    pub vault: String,
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
    /// The SSH relay.
    pub relay: RelayConfig,
    /// How long the body of a signed request may take to arrive. Not set
    /// from the environment: always [`BodyReadTimeout::default`]; tests
    /// shorten it.
    pub body_read_timeout: BodyReadTimeout,
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
        let notify = parse_channels(&lookup)?;

        let proxy = proxy_limits(&get)?;
        let requests = request_limits(&get)?;

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
            connect_url,
            connect_token: SecretString::from(required("WARDEN_OP_CONNECT_TOKEN")?),
            vault: get("WARDEN_OP_VAULT").unwrap_or_else(|| "Warden".to_owned()),
            notify,
            proxy,
            requests,
            relay,
            body_read_timeout: BodyReadTimeout::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use secrecy::ExposeSecret as _;
    use tempfile::TempDir;

    use super::{Config, ConfigError, MAX_SECRET_FILE_BYTES};
    use crate::notify::ChannelSettings;
    use crate::requests::RequestLimits;

    const TOKEN_FILE: &str = "WARDEN_OP_CONNECT_TOKEN_FILE";
    const SECRET: &str = "ops_not-a-real-token";

    /// A valid configuration, without the Connect token, plus `extra`.
    fn lookup(extra: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let base = [
            ("WARDEN_DB_PATH", "/tmp/warden.db"),
            ("WARDEN_AUDIT_PATH", "/tmp/audit"),
            ("WARDEN_PUBLIC_URL", "https://warden.example.ts.net"),
            ("WARDEN_OWNER_LOGIN", "owner@example.com"),
            ("WARDEN_OP_CONNECT_URL", "http://192.0.2.1:8080"),
            ("WARDEN_NOTIFY", "ntfy"),
            ("WARDEN_NOTIFY_NTFY_URL", "https://ntfy.example.com/topic"),
        ];
        let vars: Vec<(String, String)> = extra
            .iter()
            .chain(&base)
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |var| vars.iter().find(|(k, _)| k == var).map(|(_, v)| v.clone())
    }

    fn request_limits(extra: &[(&str, &str)]) -> Result<RequestLimits, ConfigError> {
        let mut vars = vec![("WARDEN_OP_CONNECT_TOKEN", SECRET)];
        vars.extend_from_slice(extra);
        Config::from_lookup(lookup(&vars)).map(|config| config.requests)
    }

    #[test]
    fn request_limits_default_and_can_be_set() {
        assert_eq!(request_limits(&[]).unwrap(), RequestLimits::default());
        assert_eq!(
            request_limits(&[
                ("WARDEN_REQUEST_MAX_PENDING_PER_AGENT", "2"),
                ("WARDEN_REQUEST_MAX_NEW_PER_AGENT", "2"),
                ("WARDEN_REQUEST_LIMIT_WINDOW_SECS", "60"),
            ])
            .unwrap(),
            RequestLimits {
                max_pending: 2,
                max_new: 2,
                window_secs: 60,
            }
        );
    }

    #[test]
    fn request_limits_out_of_range_are_refused() {
        for (var, value) in [
            ("WARDEN_REQUEST_MAX_PENDING_PER_AGENT", "0"),
            ("WARDEN_REQUEST_MAX_PENDING_PER_AGENT", "257"),
            ("WARDEN_REQUEST_MAX_PENDING_PER_AGENT", "many"),
            ("WARDEN_REQUEST_MAX_NEW_PER_AGENT", "0"),
            ("WARDEN_REQUEST_MAX_NEW_PER_AGENT", "1025"),
            ("WARDEN_REQUEST_LIMIT_WINDOW_SECS", "59"),
            ("WARDEN_REQUEST_LIMIT_WINDOW_SECS", "3601"),
        ] {
            let got = request_limits(&[(var, value)]);
            assert!(
                matches!(got, Err(ConfigError::Invalid { var: named, .. }) if named == var),
                "{var}={value}: {got:?}"
            );
        }
    }

    #[test]
    fn pending_limit_must_fit_under_the_new_request_limit() {
        let got = request_limits(&[
            ("WARDEN_REQUEST_MAX_PENDING_PER_AGENT", "6"),
            ("WARDEN_REQUEST_MAX_NEW_PER_AGENT", "5"),
        ]);
        assert!(
            matches!(
                got,
                Err(ConfigError::Invalid {
                    var: "WARDEN_REQUEST_MAX_PENDING_PER_AGENT",
                    ..
                })
            ),
            "{got:?}"
        );
    }

    fn secret_file(dir: &TempDir, name: &str, content: &[u8], mode: u32) -> String {
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn token_from_file(path: &str) -> Result<Config, ConfigError> {
        Config::from_lookup(lookup(&[(TOKEN_FILE, path)]))
    }

    fn is_invalid_token_file(err: &ConfigError) -> bool {
        matches!(err, ConfigError::Invalid { var, .. } if *var == TOKEN_FILE)
    }

    #[test]
    fn reads_the_connect_token_from_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(&dir, "token", SECRET.as_bytes(), 0o400);
        let config = token_from_file(&path).unwrap();
        assert_eq!(config.connect_token.expose_secret(), SECRET);
    }

    #[test]
    fn strips_the_line_ending_of_a_secret_file() {
        for ending in ["\n", "\r\n", "\n\n"] {
            let dir = tempfile::tempdir().unwrap();
            let content = format!("{SECRET}{ending}");
            let path = secret_file(&dir, "token", content.as_bytes(), 0o400);
            let config = token_from_file(&path).unwrap();
            assert_eq!(config.connect_token.expose_secret(), SECRET, "{ending:?}");
        }
    }

    #[test]
    fn follows_a_symlink_to_a_secret_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(&dir, "token", SECRET.as_bytes(), 0o400);
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        let config = token_from_file(link.to_str().unwrap()).unwrap();
        assert_eq!(config.connect_token.expose_secret(), SECRET);
    }

    #[test]
    fn accepts_group_access_to_a_secret_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(&dir, "token", SECRET.as_bytes(), 0o440);
        assert!(token_from_file(&path).is_ok());
    }

    #[test]
    fn plain_variable_still_works_when_the_file_variable_is_blank() {
        let config = Config::from_lookup(lookup(&[
            ("WARDEN_OP_CONNECT_TOKEN", SECRET),
            (TOKEN_FILE, " "),
        ]))
        .unwrap();
        assert_eq!(config.connect_token.expose_secret(), SECRET);
    }

    #[test]
    fn empty_plain_variable_does_not_conflict_with_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(&dir, "token", SECRET.as_bytes(), 0o400);
        let config = Config::from_lookup(lookup(&[
            ("WARDEN_OP_CONNECT_TOKEN", ""),
            (TOKEN_FILE, &path),
        ]))
        .unwrap();
        assert_eq!(config.connect_token.expose_secret(), SECRET);
    }

    #[test]
    fn reports_a_missing_token_under_its_plain_name() {
        assert_eq!(
            Config::from_lookup(lookup(&[])).unwrap_err(),
            ConfigError::Missing("WARDEN_OP_CONNECT_TOKEN")
        );
    }

    #[test]
    fn refuses_both_forms_of_a_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(&dir, "token", SECRET.as_bytes(), 0o400);
        let err = Config::from_lookup(lookup(&[
            ("WARDEN_OP_CONNECT_TOKEN", "other"),
            (TOKEN_FILE, &path),
        ]))
        .unwrap_err();
        assert!(is_invalid_token_file(&err), "{err}");
    }

    /// A secret pasted as the path by mistake must not reach the logs, so the
    /// message names the variable and not the path.
    #[test]
    fn refuses_a_missing_file_without_echoing_the_path() {
        let err = token_from_file(SECRET).unwrap_err();
        assert_eq!(
            err,
            ConfigError::SecretFile {
                var: TOKEN_FILE,
                kind: io::ErrorKind::NotFound
            }
        );
        assert!(
            !format!("{err} {err:?}").contains(SECRET),
            "the error echoes the path"
        );
    }

    #[test]
    fn refuses_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let err = token_from_file(dir.path().to_str().unwrap()).unwrap_err();
        assert!(is_invalid_token_file(&err), "{err}");
    }

    #[test]
    fn refuses_a_file_other_users_can_access() {
        for mode in [0o404, 0o402, 0o401, 0o644] {
            let dir = tempfile::tempdir().unwrap();
            let path = secret_file(&dir, "token", SECRET.as_bytes(), mode);
            let err = token_from_file(&path).unwrap_err();
            assert_eq!(
                err,
                ConfigError::Invalid {
                    var: TOKEN_FILE,
                    reason: "the file must not be accessible to other users"
                },
                "{mode:o}"
            );
        }
    }

    /// Whatever is wrong with the content, the error names the variable and
    /// shows none of the content.
    #[test]
    fn refuses_bad_content_without_echoing_it() {
        let oversize = SECRET.repeat(usize::from(MAX_SECRET_FILE_BYTES));
        let invalid_utf8 = [SECRET.as_bytes(), &[0xff, 0xfe]].concat();
        let two_lines = format!("{SECRET}\n{SECRET}");
        let cases: [&[u8]; 6] = [
            b"",
            b"\n",
            b"   \n",
            two_lines.as_bytes(),
            &invalid_utf8,
            oversize.as_bytes(),
        ];
        for content in cases {
            let dir = tempfile::tempdir().unwrap();
            let path = secret_file(&dir, "token", content, 0o400);
            let err = token_from_file(&path).unwrap_err();
            assert!(
                is_invalid_token_file(&err),
                "a different error was returned"
            );
            let shown = format!("{err} {err:?}");
            assert!(!shown.contains(SECRET), "the error echoes the content");
        }
    }

    #[test]
    fn accepts_a_secret_file_at_the_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let content = "x".repeat(usize::from(MAX_SECRET_FILE_BYTES));
        let path = secret_file(&dir, "token", content.as_bytes(), 0o400);
        assert!(token_from_file(&path).is_ok());
    }

    #[test]
    fn reads_notifier_secrets_from_files() {
        let dir = tempfile::tempdir().unwrap();
        let webhook = secret_file(
            &dir,
            "webhook",
            b"https://ha.example.com/api/webhook/id\n",
            0o400,
        );
        let topic = secret_file(
            &dir,
            "topic",
            b"https://ntfy.example.com/private-topic\n",
            0o400,
        );
        let token = secret_file(&dir, "ntfy", b"tk_not-real\n", 0o400);
        let vars = lookup(&[
            ("WARDEN_OP_CONNECT_TOKEN", SECRET),
            ("WARDEN_NOTIFY", "homeassistant,ntfy"),
            ("WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL_FILE", &webhook),
            ("WARDEN_NOTIFY_NTFY_URL_FILE", &topic),
            ("WARDEN_NOTIFY_NTFY_TOKEN_FILE", &token),
        ]);
        let config = Config::from_lookup(|var| {
            (var != "WARDEN_NOTIFY_NTFY_URL")
                .then(|| vars(var))
                .flatten()
        })
        .unwrap();
        let mut channels = config.notify.iter();
        let ChannelSettings::HomeAssistant { webhook_url } = channels.next().unwrap() else {
            panic!("the first channel is Home Assistant");
        };
        assert_eq!(webhook_url.expose_url().path(), "/api/webhook/id");
        let ChannelSettings::Ntfy {
            url,
            token: Some(token),
        } = channels.next().unwrap()
        else {
            panic!("the second channel is ntfy, with a token");
        };
        assert_eq!(url.path(), "/private-topic");
        assert_eq!(token.expose_secret(), "tk_not-real");
    }

    #[test]
    fn refuses_a_secret_file_of_an_unlisted_channel() {
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(
            &dir,
            "webhook",
            b"https://ha.example.com/api/webhook/id",
            0o400,
        );
        let err = Config::from_lookup(lookup(&[
            ("WARDEN_OP_CONNECT_TOKEN", SECRET),
            ("WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL_FILE", &path),
        ]))
        .unwrap_err();
        assert_eq!(
            err,
            ConfigError::Invalid {
                var: "WARDEN_NOTIFY_HOMEASSISTANT_WEBHOOK_URL",
                reason: "set but the channel is not listed in WARDEN_NOTIFY",
            }
        );
    }
}
