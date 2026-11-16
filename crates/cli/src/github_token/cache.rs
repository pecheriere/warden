//! The cache of GitHub tokens, `<state>/github-token.json`: one entry per
//! repository and permission set asked for, shared by `warden github token` and the
//! git credential helper.
//!
//! The file necessarily holds the tokens in clear, so it is served only while it is
//! a regular file of this user with mode exactly 0600 that parses in the one shape
//! below: anything else (an older version's file included) is treated as absent and
//! replaced on the next write, never trusted.
//!
//! ```json
//! {"version":3,"agent":"…","server":"…","entries":[
//!   {"repository":"o/r","repository_id":1001,"grant_id":"…","token":"…","expires_at":0,
//!    "asked":"full"}]}
//! ```

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use warden_broker_proto::Id;
use warden_broker_proto::github_permissions::PermissionSet;
use warden_broker_proto::github_token::GithubTokenResponse;
use warden_broker_proto::release::RepoName;
use zeroize::Zeroizing;

use super::{Identity, MIN_REMAINING_SECS};
use crate::agent;

/// The cache's name in the state directory.
const CACHE_FILE: &str = "github-token.json";

/// The largest cache file read or written, in bytes.
pub(super) const MAX_CACHE_BYTES: usize = 16 * 1024;

/// The most entries the cache keeps.
pub(super) const MAX_ENTRIES: usize = 32;

/// The longest token accepted, in bytes.
const MAX_TOKEN_BYTES: usize = 1024;

/// The version of the file's shape.
const VERSION: u8 = 3;

/// What an entry's `asked` is when no permissions were named: the grant's whole set.
const FULL: &str = "full";

/// Bytes of an entry besides its token, repository name and `asked`, with room to
/// spare.
const ENTRY_OVERHEAD: usize = 256;

/// Bytes of the file besides its entries, with room to spare.
const FILE_OVERHEAD: usize = 1024;

/// The permissions a token was asked for, which is what it is cached under: not
/// what GitHub answered, so that asking again for the same finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskedSet {
    /// The grant's whole set: no `permissions` on the wire.
    Full,
    /// Exactly these, which the grant must hold.
    Exactly(PermissionSet),
}

impl AskedSet {
    /// The key in the file: `full`, or the set as [`PermissionSet`] writes it.
    pub(super) fn key(&self) -> String {
        match self {
            Self::Full => FULL.to_owned(),
            Self::Exactly(set) => set.to_string(),
        }
    }
}

/// Whether `key` is one [`AskedSet::key`] writes.
fn well_formed_key(key: &str) -> bool {
    key == FULL || PermissionSet::parse(key).is_ok_and(|set| set.to_string() == key)
}

/// A token in memory, wiped when dropped.
#[derive(Clone)]
pub(super) struct Entry {
    /// The repository it is for.
    pub repository: RepoName,
    /// GitHub's id for it.
    pub repository_id: u64,
    /// The grant it was minted under.
    pub grant_id: Id,
    /// The token.
    pub token: Zeroizing<String>,
    /// When GitHub ends it, in seconds since the Unix epoch.
    pub expires_at: i64,
    /// The [`AskedSet::key`] it was asked for.
    pub asked: String,
}

impl Entry {
    /// The entry for `response`, which answers a request for `asked`.
    pub fn new(response: GithubTokenResponse, asked: &AskedSet) -> Self {
        let GithubTokenResponse {
            token,
            expires_at,
            grant_id,
            repository,
            repository_id,
            permissions: _,
        } = response;
        Self {
            repository,
            repository_id,
            grant_id,
            token: Zeroizing::new(token),
            expires_at,
            asked: asked.key(),
        }
    }

    /// The bytes it takes in the file, at most. The token is counted as JSON encodes
    /// it: `"` and `\` take two bytes, a control character up to six.
    pub(super) fn size_bound(&self) -> usize {
        let token: usize = self
            .token
            .bytes()
            .map(|b| match b {
                b'"' | b'\\' => 2,
                0..=0x1f => 6,
                _ => 1,
            })
            .sum();
        // `asked` holds only permission names, `:`, `,` and `_`, which JSON does not escape.
        ENTRY_OVERHEAD + token + self.repository.as_str().len() + self.asked.len()
    }
}

/// An entry as read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEntry {
    repository: RepoName,
    repository_id: u64,
    grant_id: Id,
    token: String,
    expires_at: i64,
    asked: String,
}

/// The file as read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u8,
    agent: String,
    server: String,
    entries: Vec<StoredEntry>,
}

/// An entry as written.
#[derive(Serialize)]
struct EntryRef<'a> {
    repository: &'a RepoName,
    repository_id: u64,
    grant_id: &'a Id,
    token: &'a str,
    expires_at: i64,
    asked: &'a str,
}

/// The file as written.
#[derive(Serialize)]
struct StoredRef<'a> {
    version: u8,
    agent: &'a str,
    server: &'a str,
    entries: Vec<EntryRef<'a>>,
}

/// Whether `token` can go on a line of git's credential protocol and into an
/// environment variable as it is: printable ASCII without spaces, of a sane length.
pub(super) fn well_formed(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token.bytes().all(|b| b.is_ascii_graphic())
}

/// The tokens minted for one identity.
pub(super) struct Cache {
    /// Whom the tokens were minted for.
    pub identity: Identity,
    /// The tokens, at most [`MAX_ENTRIES`].
    pub entries: Vec<Entry>,
}

impl Cache {
    /// A cache of no tokens, for `identity`.
    pub fn empty(identity: Identity) -> Self {
        Self {
            identity,
            entries: Vec::new(),
        }
    }

    /// The cache at `path`, if it is a regular file of this user with mode exactly
    /// 0600, at most [`MAX_CACHE_BYTES`], that parses, with well formed tokens. A
    /// symlink is never followed and a FIFO never waited on.
    pub fn load(path: &Path) -> Option<Self> {
        use rustix::fs::{Mode, OFlags};
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let file = fs::File::from(rustix::fs::open(path, flags, Mode::empty()).ok()?);
        let meta = file.metadata().ok()?;
        if !meta.is_file()
            || meta.uid() != rustix::process::getuid().as_raw()
            || meta.mode() & 0o7777 != 0o600
        {
            return None;
        }
        // Room for one byte more than allowed, so that reading never grows the
        // buffer and leaves a copy behind.
        let mut raw = Zeroizing::new(Vec::with_capacity(MAX_CACHE_BYTES + 1));
        let limit = u64::try_from(MAX_CACHE_BYTES + 1).ok()?;
        file.take(limit).read_to_end(&mut raw).ok()?;
        if raw.len() > MAX_CACHE_BYTES {
            return None;
        }
        let Stored {
            version,
            agent,
            server,
            entries,
        } = serde_json::from_slice(&raw).ok()?;
        if version != VERSION || entries.len() > MAX_ENTRIES {
            return None;
        }
        let entries = entries
            .into_iter()
            .map(|e| {
                let token = Zeroizing::new(e.token);
                (well_formed(&token) && well_formed_key(&e.asked)).then_some(Entry {
                    repository: e.repository,
                    repository_id: e.repository_id,
                    grant_id: e.grant_id,
                    token,
                    expires_at: e.expires_at,
                    asked: e.asked,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            identity: Identity { agent, server },
            entries,
        })
    }

    /// The entry for `repository`, ignoring case, asked for `asked`, with at least
    /// [`MIN_REMAINING_SECS`] left at `now`.
    pub fn lookup(&self, repository: &RepoName, asked: &AskedSet, now: i64) -> Option<&Entry> {
        let key = asked.key();
        self.entries.iter().find(|e| {
            e.repository.matches(repository)
                && e.asked == key
                && e.expires_at.saturating_sub(now) >= MIN_REMAINING_SECS
        })
    }

    /// Forget the entries that are no longer served at `now`.
    pub fn drop_expired(&mut self, now: i64) {
        self.entries
            .retain(|e| e.expires_at.saturating_sub(now) >= MIN_REMAINING_SECS);
    }

    /// Add `entry`, replacing the one with the same repository (id or name) and
    /// `asked`. An entry of the same repository minted under another grant is
    /// dropped as well, with all that repository's others: a new grant supersedes
    /// the tokens of the old one. What does not fit in [`MAX_ENTRIES`] entries or [`MAX_CACHE_BYTES`] bytes is
    /// dropped, the entry ending soonest first, but never `entry` itself.
    pub fn put(&mut self, entry: Entry) {
        let same_repository = |e: &Entry| {
            e.repository_id == entry.repository_id || e.repository.matches(&entry.repository)
        };
        let superseded = self
            .entries
            .iter()
            .any(|e| same_repository(e) && e.grant_id != entry.grant_id);
        self.entries
            .retain(|e| !(same_repository(e) && (superseded || e.asked == entry.asked)));
        self.entries.push(entry);
        while self.entries.len() > MAX_ENTRIES || self.size_bound() > MAX_CACHE_BYTES {
            let Some(soonest) = self
                .entries
                .iter()
                .enumerate()
                .take(self.entries.len() - 1)
                .min_by_key(|(_, e)| e.expires_at)
                .map(|(i, _)| i)
            else {
                break;
            };
            self.entries.remove(soonest);
        }
    }

    /// The bytes the file takes, at most.
    pub(super) fn size_bound(&self) -> usize {
        FILE_OVERHEAD
            + self.identity.agent.len()
            + self.identity.server.len()
            + self.entries.iter().map(Entry::size_bound).sum::<usize>()
    }

    /// Forget the entries of grant `grant`. Returns whether there were any.
    pub fn discard(&mut self, grant: &Id) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.grant_id != *grant);
        self.entries.len() != before
    }

    /// Forget the entries of `repositories`, ignoring case. Returns whether there
    /// were any.
    pub fn discard_repositories(&mut self, repositories: &[RepoName]) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|e| !repositories.iter().any(|r| e.repository.matches(r)));
        self.entries.len() != before
    }

    /// Replace the cache at `path` with this one: written to a new 0600 file beside
    /// it, which is renamed over whatever was there (a rename replaces a symlink,
    /// never what it points to).
    pub fn write(&self, path: &Path) -> Result<()> {
        let stored = StoredRef {
            version: VERSION,
            agent: &self.identity.agent,
            server: &self.identity.server,
            entries: self
                .entries
                .iter()
                .map(|e| EntryRef {
                    repository: &e.repository,
                    repository_id: e.repository_id,
                    grant_id: &e.grant_id,
                    token: &e.token,
                    expires_at: e.expires_at,
                    asked: &e.asked,
                })
                .collect(),
        };
        // Sized up front, so that writing never grows the buffer and leaves a copy.
        let mut contents = Zeroizing::new(Vec::with_capacity(MAX_CACHE_BYTES));
        serde_json::to_writer(&mut *contents, &stored).context("cannot encode the token cache")?;
        let (_, temp) = agent::temp_beside(path)?;
        let written = agent::write_temp(&temp, &contents)
            .and_then(|()| {
                // Whatever the umask took away, the mode is exactly 0600, or the
                // cache would never be served.
                fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))
                    .with_context(|| format!("cannot restrict {}", temp.display()))
            })
            .and_then(|()| {
                fs::rename(&temp, path).with_context(|| format!("cannot write {}", path.display()))
            });
        if written.is_err() {
            // Best effort: the error that matters is the one returned.
            let _ = fs::remove_file(&temp);
        }
        written
    }
}

/// `<state>/github-token.json`.
pub(super) fn cache_path() -> Result<PathBuf> {
    Ok(agent::state_dir()?.join(CACHE_FILE))
}

/// Delete the cached tokens minted under `grant`, as when the grant is revoked from
/// here. Returns whether there were any.
///
/// # Errors
/// If the state directory is unusable or the file cannot be rewritten or removed.
pub fn discard(grant: &Id) -> Result<bool> {
    rewrite_without(|cache| cache.discard(grant))
}

/// Delete the cached tokens of `repositories`, whatever grant they were minted
/// under: a request that has just been approved may give them other permissions,
/// and a token minted before it must not be served in its place. Returns whether
/// there were any.
///
/// # Errors
/// If the state directory is unusable or the file cannot be rewritten or removed.
pub fn discard_repositories(repositories: &[RepoName]) -> Result<bool> {
    rewrite_without(|cache| cache.discard_repositories(repositories))
}

/// Load the cache, forget entries with `forget`, and write back what is left, or
/// remove the file when nothing is. Returns whether `forget` dropped any.
fn rewrite_without(forget: impl FnOnce(&mut Cache) -> bool) -> Result<bool> {
    let path = cache_path()?;
    let Some(mut cache) = Cache::load(&path) else {
        return Ok(false);
    };
    if !forget(&mut cache) {
        return Ok(false);
    }
    if cache.entries.is_empty() {
        fs::remove_file(&path).with_context(|| format!("cannot remove {}", path.display()))?;
    } else {
        cache.write(&path)?;
    }
    Ok(true)
}
