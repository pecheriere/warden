//! The CLI configuration file and the agent key.
//!
//! The configuration (`server`, `agent`, and for a key-signed agent an
//! `[ssh_key]` table) lives in `$XDG_CONFIG_HOME/warden/config.toml`,
//! falling back to `~/.config/warden/config.toml`, mode 0600 in a 0700
//! directory. None of it is secret.
//!
//! An agent authenticates in one of two ways:
//!
//! - **Signed requests** (`[ssh_key]` present): every call is signed with an
//!   SSH key held by an `ssh-agent` (`docs/agent-protocol.md`). The table
//!   records the public key, the agent socket (else `$SSH_AUTH_SOCK` at each
//!   call) and the broker's audience pinned at login. No secret is stored,
//!   and no Keychain is needed.
//! - **Bearer key** (legacy): the key is read from `WARDEN_AGENT_KEY` when
//!   set, otherwise from the macOS Keychain (service `warden-broker`,
//!   account `<server>|<agent>`). It is never written to a file.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use url::Url;
use warden_broker_proto::AgentName;
use warden_broker_proto::signing::Audience;
use zeroize::Zeroizing;

use crate::sign::{self, Signer};

/// Environment variable that overrides the Keychain as the agent key source.
pub const AGENT_KEY_ENV: &str = "WARDEN_AGENT_KEY";

/// Keychain service under which agent keys are stored.
#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "warden-broker";

/// Where the broker is and which agent this machine acts as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Base URL of the broker's agent API.
    pub server: Url,
    /// Name of the agent whose key is used.
    pub agent: AgentName,
    /// How a key-signed agent signs; absent for a bearer-key agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<SshKeyConfig>,
}

/// The signing key of a key-signed agent and the broker it signs for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshKeyConfig {
    /// The signing key's public half, an OpenSSH line without comment.
    pub public_key: String,
    /// The `ssh-agent` socket holding the key; `$SSH_AUTH_SOCK` at each call
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_socket: Option<PathBuf>,
    /// The broker's audience, pinned at login from `GET /v1/info`.
    pub audience: Audience,
}

impl Config {
    /// The signer of a key-signed agent, or `None` for a bearer-key agent.
    /// The `ssh-agent` socket is resolved now.
    ///
    /// # Errors
    /// If the recorded key is not acceptable or there is no agent socket.
    pub fn signer(&self) -> Result<Option<Signer>> {
        let Some(ssh_key) = &self.ssh_key else {
            return Ok(None);
        };
        let key = sign::parse_signing_key(&ssh_key.public_key)
            .context("the configured signing key is refused")?;
        let socket = sign::agent_socket(ssh_key.agent_socket.as_deref())?;
        Ok(Some(Signer::new(
            self.agent.clone(),
            ssh_key.audience.clone(),
            key,
            socket,
        )))
    }
}

/// Path of the configuration file.
///
/// # Errors
/// If neither `XDG_CONFIG_HOME` nor the home directory is known.
pub fn config_path() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
        Some(dir) if dir.is_absolute() => dir,
        _ => dirs::home_dir()
            .context("cannot determine the home directory")?
            .join(".config"),
    };
    Ok(base.join("warden").join("config.toml"))
}

/// The broker URL must be HTTPS (Tailscale Serve), or plain HTTP to a
/// loopback address: the agent key travels in every request.
///
/// # Errors
/// If the URL could send the agent key in clear text or carries parts that
/// make no sense for a base URL.
pub fn check_server_url(url: &Url) -> Result<()> {
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(name)) => name == "localhost",
        None => false,
    };
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        "http" => bail!("server URL must use https unless it points at a loopback address"),
        other => bail!("unsupported server URL scheme {other:?}"),
    }
    if url.host().is_none() {
        bail!("server URL has no host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("server URL must not contain credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("server URL must not have a query or fragment");
    }
    Ok(())
}

/// A key-signed agent's server URL must be the root of its origin: the
/// API paths are at the root, and the path sent is signed, so there is no
/// prefix a proxy could strip or add.
///
/// # Errors
/// If `url` has a path other than `/`.
pub fn check_root_url(url: &Url) -> Result<()> {
    if url.path() != "/" {
        bail!(
            "with --ssh-key the server URL must have no path (the API is at the root of the \
             broker's origin, and the path is signed), for example https://warden.example.ts.net"
        );
    }
    Ok(())
}

/// Agent keys look like `wdn_` followed by 43 base64url characters.
///
/// # Errors
/// If `key` does not have that shape. The message never includes the key.
pub fn check_agent_key(key: &str) -> Result<()> {
    let ok = key.strip_prefix("wdn_").is_some_and(|rest| {
        rest.len() == 43
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    if ok {
        Ok(())
    } else {
        bail!("agent key is malformed (expected wdn_ followed by 43 base64url characters)")
    }
}

/// Load the configuration from [`config_path`].
///
/// # Errors
/// If the file is missing, unreadable or invalid.
pub fn load() -> Result<Config> {
    let path = config_path()?;
    load_from(&path).with_context(|| {
        format!(
            "cannot load {}; run `warden login --server <url> --agent <name> --ssh-key \
             <path.pub>` (signing key) or `warden login --server <url> --agent <name>` (bearer \
             key) first",
            path.display()
        )
    })
}

fn load_from(path: &Path) -> Result<Config> {
    let raw = fs::read_to_string(path)?;
    let config: Config = toml::from_str(&raw)?;
    check_server_url(&config.server)?;
    if let Some(ssh_key) = &config.ssh_key {
        check_root_url(&config.server)?;
        sign::parse_signing_key(&ssh_key.public_key)
            .context("the configured signing key is refused")?;
        if let Some(socket) = &ssh_key.agent_socket {
            check_socket_path(socket)?;
        }
    }
    Ok(config)
}

/// A configured `ssh-agent` socket must be an absolute path, so it means the
/// same from every working directory.
///
/// # Errors
/// If `path` is relative.
pub fn check_socket_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("the ssh-agent socket path must be absolute");
    }
    Ok(())
}

/// The configuration at [`config_path`], or `None` when there is none.
///
/// # Errors
/// If the configuration path cannot be determined, or a configuration
/// exists but cannot be read or is invalid: it may hold a pinned audience,
/// which must not be overwritten unseen.
pub fn load_existing() -> Result<Option<Config>> {
    load_existing_from(&config_path()?)
}

fn load_existing_from(path: &Path) -> Result<Option<Config>> {
    match load_from(path) {
        Ok(config) => Ok(Some(config)),
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(e) => Err(e.context(format!(
            "cannot load the existing configuration {}; fix or remove it, then log in again",
            path.display()
        ))),
    }
}

/// Write the configuration to [`config_path`].
///
/// # Errors
/// If the file cannot be written.
pub fn save(config: &Config) -> Result<PathBuf> {
    let path = config_path()?;
    save_to(&path, config)?;
    Ok(path)
}

/// Write `config` to `path` atomically: mode 0600, parent created 0700.
fn save_to(path: &Path, config: &Config) -> Result<()> {
    let dir = path.parent().context("configuration path has no parent")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("cannot create {}", dir.display()))?;
    let tmp = path.with_extension("toml.tmp");
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("cannot remove {}", tmp.display())),
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("cannot create {}", tmp.display()))?;
    file.write_all(toml::to_string(config)?.as_bytes())?;
    file.sync_all()?;
    fs::rename(&tmp, path).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(())
}

/// Keychain account for `config`: `<server>|<agent>`.
#[cfg(any(target_os = "macos", test))]
fn keychain_account(config: &Config) -> String {
    format!("{}|{}", config.server, config.agent)
}

/// The agent key: `WARDEN_AGENT_KEY` if set, otherwise the Keychain entry.
///
/// # Errors
/// If no key is available or it is malformed.
pub fn agent_key(config: &Config) -> Result<Zeroizing<String>> {
    let key = match std::env::var(AGENT_KEY_ENV) {
        Ok(key) => Zeroizing::new(key),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{AGENT_KEY_ENV} is not valid UTF-8"),
        Err(std::env::VarError::NotPresent) => keychain_get(config)?,
    };
    check_agent_key(&key)?;
    Ok(key)
}

/// The login-Keychain entry for `config`'s agent key.
#[cfg(target_os = "macos")]
fn keychain_entry(config: &Config) -> Result<keyring_core::Entry> {
    use keyring_core::api::CredentialStoreApi as _;
    apple_native_keyring_store::keychain::Store::new()
        .context("cannot open the Keychain")?
        .build(KEYCHAIN_SERVICE, &keychain_account(config), None)
        .context("cannot open the Keychain entry")
}

#[cfg(target_os = "macos")]
fn keychain_get(config: &Config) -> Result<Zeroizing<String>> {
    keychain_entry(config)?
        .get_password()
        .map(Zeroizing::new)
        .with_context(|| {
            format!(
                "no agent key in the Keychain for {}; run `warden login` or set {AGENT_KEY_ENV}",
                keychain_account(config)
            )
        })
}

#[cfg(not(target_os = "macos"))]
fn keychain_get(_config: &Config) -> Result<Zeroizing<String>> {
    bail!("no Keychain on this platform; set {AGENT_KEY_ENV}")
}

/// Store the agent key in the Keychain.
///
/// # Errors
/// If the Keychain refuses, or there is none on this platform.
#[cfg(target_os = "macos")]
pub fn store_agent_key(config: &Config, key: &str) -> Result<()> {
    keychain_entry(config)?
        .set_password(key)
        .context("cannot store the agent key in the Keychain")
}

/// Store the agent key in the Keychain.
///
/// # Errors
/// Always: there is no Keychain on this platform.
#[cfg(not(target_os = "macos"))]
pub fn store_agent_key(_config: &Config, _key: &str) -> Result<()> {
    bail!("no Keychain on this platform; set {AGENT_KEY_ENV} instead of running `warden login`")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::{
        Config, SshKeyConfig, check_agent_key, check_server_url, keychain_account,
        load_existing_from, load_from, save_to,
    };

    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    fn sample() -> Config {
        Config {
            server: url("https://warden.example.ts.net/"),
            agent: "bot".parse().unwrap(),
            ssh_key: None,
        }
    }

    fn ed25519_line() -> String {
        use ssh_key::rand_core::OsRng;
        ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap()
    }

    fn signed_sample() -> Config {
        Config {
            ssh_key: Some(SshKeyConfig {
                public_key: ed25519_line(),
                agent_socket: Some("/run/user/1000/agent.sock".into()),
                audience: "40ad20029e94984d193159667b296d8a".parse().unwrap(),
            }),
            ..sample()
        }
    }

    #[test]
    fn signed_config_roundtrips_and_holds_no_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let config = signed_sample();
        save_to(&path, &config).unwrap();
        assert_eq!(load_from(&path).unwrap(), config);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("[ssh_key]"), "{raw}");
        assert!(!raw.contains("wdn_"), "{raw}");

        // The socket is optional: $SSH_AUTH_SOCK is used at each call.
        let mut no_socket = signed_sample();
        no_socket.ssh_key.as_mut().unwrap().agent_socket = None;
        std::fs::remove_file(&path).unwrap();
        save_to(&path, &no_socket).unwrap();
        assert!(
            !std::fs::read_to_string(&path)
                .unwrap()
                .contains("agent_socket")
        );
        assert_eq!(load_from(&path).unwrap(), no_socket);
    }

    /// Only a missing configuration counts as none; a broken one (which may
    /// hold a pinned audience) stops the login, naming the file.
    #[test]
    fn existing_config_is_none_only_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        assert_eq!(load_existing_from(&path).unwrap(), None);
        let config = signed_sample();
        save_to(&path, &config).unwrap();
        assert_eq!(load_existing_from(&path).unwrap(), Some(config));
        std::fs::write(&path, "server = \"https://w.example/\"\n[ssh_key\n").unwrap();
        let err = format!("{:#}", load_existing_from(&path).unwrap_err());
        assert!(err.contains(&path.display().to_string()), "{err}");
        assert!(err.contains("fix or remove it"), "{err}");
    }

    #[test]
    fn signed_config_is_checked_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, config: &Config| {
            let path = dir.path().join(name);
            std::fs::write(&path, toml::to_string(config).unwrap()).unwrap();
            path
        };
        // A path under the origin: refused in key mode only.
        let mut with_path = signed_sample();
        with_path.server = url("https://warden.example.ts.net/api/");
        let err = format!(
            "{:#}",
            load_from(&write("path.toml", &with_path)).unwrap_err()
        );
        assert!(err.contains("no path"), "{err}");
        let bearer_with_path = Config {
            server: url("https://warden.example.ts.net/api/"),
            ..sample()
        };
        assert!(load_from(&write("bearer.toml", &bearer_with_path)).is_ok());

        let mut relative = signed_sample();
        relative.ssh_key.as_mut().unwrap().agent_socket = Some("agent.sock".into());
        assert!(load_from(&write("rel.toml", &relative)).is_err());

        let mut published = signed_sample();
        published.ssh_key.as_mut().unwrap().public_key =
            warden_broker_proto::signing::PUBLISHED_TEST_KEYS[0].to_owned();
        assert!(load_from(&write("pub.toml", &published)).is_err());

        let path = dir.path().join("unknown.toml");
        std::fs::write(
            &path,
            format!(
                "server = \"https://w.example/\"\nagent = \"a\"\n[ssh_key]\npublic_key = \"{}\"\n\
                 audience = \"40ad20029e94984d193159667b296d8a\"\nprivate_key = \"x\"\n",
                ed25519_line()
            ),
        )
        .unwrap();
        assert!(load_from(&path).is_err());
    }

    #[test]
    fn server_url_must_be_https_or_loopback_http() {
        assert!(check_server_url(&url("https://warden.example.ts.net/")).is_ok());
        assert!(check_server_url(&url("http://127.0.0.1:8080/")).is_ok());
        assert!(check_server_url(&url("http://[::1]:8080/")).is_ok());
        assert!(check_server_url(&url("http://localhost:1/")).is_ok());
        assert!(check_server_url(&url("http://warden.example.ts.net/")).is_err());
        assert!(check_server_url(&url("http://10.0.0.1/")).is_err());
        assert!(check_server_url(&url("ftp://127.0.0.1/")).is_err());
        assert!(check_server_url(&url("https://u:p@warden.example/")).is_err());
        assert!(check_server_url(&url("https://warden.example/?a=b")).is_err());
    }

    #[test]
    fn agent_key_shape() {
        let good = format!("wdn_{}", "A".repeat(43));
        assert!(check_agent_key(&good).is_ok());
        assert!(check_agent_key(&format!("wdn_{}", "-_aZ09".repeat(7) + "x")).is_ok());
        assert!(check_agent_key(&format!("wdx_{}", "A".repeat(43))).is_err());
        assert!(check_agent_key(&format!("wdn_{}", "A".repeat(42))).is_err());
        assert!(check_agent_key(&format!("wdn_{}\n", "A".repeat(42))).is_err());
        let err = check_agent_key("wdn_secret").unwrap_err().to_string();
        assert!(!err.contains("secret"), "{err}");
    }

    #[test]
    fn keychain_account_is_server_and_agent() {
        assert_eq!(
            keychain_account(&sample()),
            "https://warden.example.ts.net/|bot"
        );
    }

    #[test]
    fn config_roundtrips_with_private_modes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("warden").join("config.toml");
        save_to(&path, &sample()).unwrap();
        save_to(&path, &sample()).unwrap();
        assert_eq!(load_from(&path).unwrap(), sample());
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    #[test]
    fn config_with_cleartext_remote_server_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "server = \"http://warden.example/\"\nagent = \"a\"\n",
        )
        .unwrap();
        assert!(load_from(&path).is_err());
    }
}
