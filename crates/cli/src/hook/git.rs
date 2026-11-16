//! What `warden hook check` reads of git and `gh`, without running either: the
//! configuration of the checkout the command runs in, and whether the `gh` on
//! `PATH` is the wrapper `warden setup github` writes.
//!
//! Every file goes through the hook's [`Reader`], so the 64 KiB cap and the
//! regular-file checks apply. The library parses the text.

use std::ffi::OsStr;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use warden_agent_hook::context::GitConfig;

use super::files::Reader;
use crate::setup_github::{is_executable, is_ours};

/// The text of a file git reads when it is there: `Some("")` when nothing is
/// at `path`, `None` when something is but cannot be read.
fn optional(path: &Path, reader: &Reader) -> Option<String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            Some(String::new())
        }
        Err(_) => None,
        Ok(_) => reader.read(path),
    }
}

/// The configuration file of the checkout holding `cwd`: the nearest `.git`
/// above it is the git directory, or a file `gitdir: <path>` naming it (a
/// worktree), whose `commondir` file names the directory the configuration
/// is in. `None` outside a checkout or when one of these cannot be read.
fn config_path(cwd: &Path, reader: &Reader) -> Option<PathBuf> {
    let (dir, dot_git) = cwd
        .ancestors()
        .map(|dir| (dir, dir.join(".git")))
        .find(|(_, dot_git)| std::fs::symlink_metadata(dot_git).is_ok())?;
    let meta = std::fs::metadata(&dot_git).ok()?;
    let git_dir = if meta.is_dir() {
        dot_git
    } else {
        let text = reader.read(&dot_git)?;
        let target = text.lines().next()?.strip_prefix("gitdir:")?.trim();
        if target.is_empty() {
            return None;
        }
        dir.join(target)
    };
    let common = optional(&git_dir.join("commondir"), reader)?;
    let common = common.trim();
    let common_dir = if common.is_empty() {
        git_dir
    } else {
        git_dir.join(common)
    };
    Some(common_dir.join("config"))
}

/// Git's configuration for a command run in `cwd`: the global files
/// (`$XDG_CONFIG_HOME/git/config`, or `~/.config/git/config`, then
/// `~/.gitconfig`), then the checkout's. `None` when `cwd` is missing,
/// relative or outside a checkout, or a file that is there cannot be read or
/// parsed.
#[must_use]
pub fn git_config(
    cwd: Option<&str>,
    home: Option<&Path>,
    xdg_config_home: Option<&Path>,
    reader: &Reader,
) -> Option<GitConfig> {
    let cwd = Path::new(cwd?);
    if !cwd.is_absolute() {
        return None;
    }
    let local = reader.read(&config_path(cwd, reader)?)?;
    let xdg = xdg_config_home
        .map(Path::to_path_buf)
        .or_else(|| home.map(|home| home.join(".config")))
        .map(|dir| dir.join("git/config"));
    let globals = xdg
        .into_iter()
        .chain(home.map(|home| home.join(".gitconfig")));
    let mut texts = Vec::new();
    for path in globals {
        texts.push(optional(&path, reader)?);
    }
    texts.push(local);
    GitConfig::parse(&texts.iter().map(String::as_str).collect::<Vec<_>>())
}

/// Whether the first executable `gh` in `path_var` is the wrapper `warden
/// setup github` writes. Relative and empty entries are skipped, as
/// `warden setup github` skips them.
#[must_use]
pub fn gh_wrapped(path_var: Option<&OsStr>, reader: &Reader) -> bool {
    let Some(path_var) = path_var else {
        return false;
    };
    std::env::split_paths(path_var)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join("gh"))
        .find(|gh| is_executable(gh))
        .and_then(|gh| reader.read(&gh))
        .is_some_and(|text| is_ours(text.as_bytes()))
}

#[cfg(test)]
mod tests;
