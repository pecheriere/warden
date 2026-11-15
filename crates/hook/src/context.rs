//! What the hook knows about the machine: the destinations warden covers, the
//! owner's SSH aliases and which paths belong to warden itself.

mod ssh_config;

use std::path::{Component, Path, PathBuf};

use url::Url;
use warden_broker_proto::offers::Offers;

pub use self::ssh_config::{IncludeReader, SshAliases};

/// Reads a small file as text: `None` when the file is missing,
/// unreadable, not text or larger than 64 KiB (the caller enforces the cap).
pub type FileReader = dyn Fn(&Path) -> Option<String>;

/// What the broker offers this agent, reduced to what the hook matches on.
/// `Coverage::default()` covers nothing; an unknown cache is `None` in
/// [`Context::coverage`], not an empty `Coverage`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Coverage {
    /// The SSH targets warden offers.
    pub ssh: Vec<SshCover>,
    /// The API secrets warden offers.
    pub api: Vec<ApiCover>,
    /// Whether warden offers GitHub tokens.
    pub github: bool,
}

/// One SSH target warden offers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshCover {
    /// The target's name.
    pub name: String,
    /// Its host, when the listing shows it (`None` for a name-only listing).
    pub host: Option<String>,
    /// The users an agent may ask for.
    pub users: Vec<String>,
}

/// One API secret warden offers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiCover {
    /// The secret's name.
    pub name: String,
    /// Its upstream origin, when the listing shows it.
    pub origin: Option<String>,
}

impl From<&Offers> for Coverage {
    fn from(offers: &Offers) -> Self {
        Self {
            ssh: offers
                .ssh_targets
                .iter()
                .map(|t| SshCover {
                    name: t.name.as_str().to_owned(),
                    host: t.destination.as_ref().map(|d| d.host.clone()),
                    users: t.users.iter().map(|u| u.as_str().to_owned()).collect(),
                })
                .collect(),
            api: offers
                .api_secrets
                .iter()
                .map(|s| ApiCover {
                    name: s.name.as_str().to_owned(),
                    origin: s.origin.clone(),
                })
                .collect(),
            github: offers.github.configured,
        }
    }
}

/// The scheme, lowercased host and port (with the scheme's default) of a URL.
fn origin_key(url: &str) -> Option<(String, String, u16)> {
    let url = Url::parse(url).ok()?;
    Some((
        url.scheme().to_owned(),
        url.host_str()?.to_ascii_lowercase(),
        url.port_or_known_default()?,
    ))
}

impl Coverage {
    /// The target a command reaching `host_or_alias` goes through, if any.
    /// It matches the target's listed host, its name used as an alias, or an
    /// `~/.ssh/config` alias whose `HostName` is the listed host. Hosts
    /// compare case-insensitively.
    #[must_use]
    pub fn ssh_target_for(&self, host_or_alias: &str, aliases: &SshAliases) -> Option<&SshCover> {
        let asked = host_or_alias.to_ascii_lowercase();
        let resolved = aliases.host_for(&asked);
        self.ssh.iter().find(|cover| {
            cover.name.eq_ignore_ascii_case(&asked)
                || cover.host.as_deref().is_some_and(|host| {
                    host.eq_ignore_ascii_case(&asked)
                        || resolved.is_some_and(|r| host.eq_ignore_ascii_case(r))
                })
        })
    }

    /// The API secret whose origin is the one of `url`: scheme, host and port
    /// (defaults filled in) must all match. An unparsable URL or origin
    /// matches nothing.
    #[must_use]
    pub fn api_for(&self, url: &str) -> Option<&ApiCover> {
        let wanted = origin_key(url)?;
        self.api.iter().find(|cover| {
            cover
                .origin
                .as_deref()
                .and_then(origin_key)
                .is_some_and(|origin| origin == wanted)
        })
    }
}

/// Everything the hook looks at besides the command itself.
pub struct Context {
    /// What warden covers; `None` when the offers cache is missing or stale.
    pub coverage: Option<Coverage>,
    /// The owner's SSH aliases.
    pub aliases: SshAliases,
    /// The directory warden's agent sockets live in.
    pub warden_socket_dir: PathBuf,
    /// Reads a small file as text; the 64 KiB cap is the reader's job.
    pub read_small_file: Box<FileReader>,
    /// Whether the checkout's git config names `warden git-credential`;
    /// `None` outside a checkout.
    pub github_helper: Option<bool>,
}

impl Context {
    /// Whether `path` is under the warden socket directory. The match is on
    /// the literal text: `~` and variables are not expanded, so an unexpanded
    /// path is not exempt, and a path with a `..` component is refused.
    #[must_use]
    pub fn is_warden_socket(&self, path: &str) -> bool {
        let Some(dir) = self.warden_socket_dir.to_str() else {
            return false;
        };
        let dir = dir.trim_end_matches('/');
        let Some(rest) = path
            .strip_prefix(dir)
            .and_then(|rest| rest.strip_prefix('/'))
        else {
            return false;
        };
        !rest.is_empty()
            && !Path::new(path)
                .components()
                .any(|c| matches!(c, Component::ParentDir))
    }

    /// Whether `file` is an SSH config that routes through warden: it reads,
    /// names at least one `IdentityAgent`, and every one is a warden socket.
    #[must_use]
    pub fn is_warden_ssh_config(&self, file: &str) -> bool {
        let Some(text) = (self.read_small_file)(Path::new(file)) else {
            return false;
        };
        let agents = ssh_config::identity_agents(&text);
        !agents.is_empty() && agents.iter().all(|agent| self.is_warden_socket(agent))
    }
}

#[cfg(test)]
mod tests;
