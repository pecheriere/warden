//! What the hook knows about the machine: the destinations warden covers, the
//! owner's SSH aliases and which paths belong to warden itself.

mod ssh_config;

use std::path::{Component, Path, PathBuf};

use url::Url;
use warden_broker_proto::offers::Offers;

pub use self::ssh_config::{IncludeReader, SshAliases};

use self::ssh_config::warden_hosts;

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
        }
    }
}

/// The lowercased host of a URL; a URL without a scheme is read as `http://`.
fn host_key(url: &str) -> Option<String> {
    let parsed = Url::parse(url)
        .ok()
        .filter(|u| u.host_str().is_some())
        .or_else(|| Url::parse(&format!("http://{url}")).ok())?;
    Some(parsed.host_str()?.to_ascii_lowercase())
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

    /// The API secret whose origin has the host of `url`. Only the host
    /// matches (ASCII case-insensitive): the scheme and port are ignored,
    /// since a command may reach the same host over either. A URL without a
    /// scheme is read as `http://`. An unparsable URL or origin matches
    /// nothing.
    #[must_use]
    pub fn api_for(&self, url: &str) -> Option<&ApiCover> {
        let wanted = host_key(url)?;
        self.api.iter().find(|cover| {
            cover
                .origin
                .as_deref()
                .and_then(host_key)
                .is_some_and(|host| host == wanted)
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
}

impl Context {
    /// Whether `path` is under the warden socket directory. The match is on
    /// the literal text after collapsing repeated `/`: `~` and variables are
    /// not expanded, except a leading `$TMPDIR` or `${TMPDIR}`, which stands
    /// for the parent of the socket directory (the CLI makes the directory
    /// `$TMPDIR/warden-<uid>`). A path with a `..` component is refused, and
    /// an empty, `/` or relative socket directory exempts nothing.
    #[must_use]
    pub fn is_warden_socket(&self, path: &str) -> bool {
        let Some(dir) = self.warden_socket_dir.to_str() else {
            return false;
        };
        let dir = collapse_slashes(dir);
        let dir = dir.trim_end_matches('/');
        if !dir.starts_with('/') || has_parent_dir(dir) {
            return false;
        }
        let expanded = match tmpdir_rest(path) {
            Some(rest) => {
                let parent = dir.rsplit_once('/').map_or("", |(parent, _)| parent);
                format!("{parent}/{rest}")
            }
            None => path.to_owned(),
        };
        let expanded = collapse_slashes(&expanded);
        let Some(rest) = expanded
            .strip_prefix(dir)
            .and_then(|rest| rest.strip_prefix('/'))
        else {
            return false;
        };
        !rest.is_empty() && !has_parent_dir(&expanded) && !has_parent_dir(path)
    }

    /// Whether `file` is an SSH config of the shape `warden ssh-config`
    /// writes, for `host`: it reads; every literal `Host` block has its own
    /// `IdentityAgent`, a warden socket, and no `IdentityFile` but `none`;
    /// it has no pattern `Host`, `Include`, `Match`, `ProxyCommand`,
    /// `ProxyJump`, `PKCS11Provider`, `SecurityKeyProvider`,
    /// `CertificateFile` or option before the first `Host`; and `host`
    /// (case-insensitive) is one of its `Host` names. One block that goes
    /// around warden refuses the whole file.
    #[must_use]
    pub fn is_warden_ssh_config(&self, file: &str, host: &str) -> bool {
        let Some(text) = (self.read_small_file)(Path::new(file)) else {
            return false;
        };
        let host = host.to_ascii_lowercase();
        warden_hosts(&text, &|agent| self.is_warden_socket(agent))
            .is_some_and(|hosts| hosts.contains(&host))
    }
}

/// `text` with every run of `/` made one.
fn collapse_slashes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c != '/' || !out.ends_with('/') {
            out.push(c);
        }
    }
    out
}

/// The part of `path` after a leading `$TMPDIR/` or `${TMPDIR}/`.
fn tmpdir_rest(path: &str) -> Option<&str> {
    path.strip_prefix("$TMPDIR/")
        .or_else(|| path.strip_prefix("${TMPDIR}/"))
}

fn has_parent_dir(path: &str) -> bool {
    Path::new(path)
        .components()
        .any(|c| matches!(c, Component::ParentDir))
}

#[cfg(test)]
mod tests;
