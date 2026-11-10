//! Where this program is installed, as a path that survives an upgrade.
//!
//! `warden setup git` and `warden setup github` write the program's path into git's
//! configuration and into the `gh` wrapper. Resolving every symlink there would record
//! a package manager's versioned directory (Homebrew's `Cellar/warden/<version>`), which
//! an upgrade removes. The path the program was started from is kept instead, but only
//! after it is shown to be this very binary: a path that merely looks right, such as a
//! `PATH` entry an attacker can write, is never recorded.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};

/// This program's stable absolute path, verified to be this binary.
///
/// # Errors
/// If the operating system cannot say where this program is.
pub fn stable_exe() -> Result<PathBuf> {
    let started = std::env::current_exe().context("cannot tell where this program is")?;
    let real = std::fs::canonicalize(&started).context("cannot tell where this program is")?;
    let cwd = std::env::current_dir().ok();
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    Ok(choose(&started, &real, cwd.as_deref(), &path_var, &|p| {
        std::fs::canonicalize(p).ok()
    }))
}

/// The path to record: `started` made absolute when it is the same file as `real`,
/// otherwise `real`.
///
/// `canonical` resolves a path to its real file, or `None` when it cannot.
fn choose(
    started: &Path,
    real: &Path,
    cwd: Option<&Path>,
    path_var: &OsStr,
    canonical: &dyn Fn(&Path) -> Option<PathBuf>,
) -> PathBuf {
    let Some(candidate) = absolute_candidate(started, cwd, path_var, real, canonical) else {
        return real.to_path_buf();
    };
    if canonical(&candidate).as_deref() == Some(real) {
        candidate
    } else {
        real.to_path_buf()
    }
}

/// `started` as an absolute path without `.` or `..` parts, or `None` when there is no
/// safe way to make it one. A bare name is looked up in `path_var`, taking the first
/// entry that is `real`.
fn absolute_candidate(
    started: &Path,
    cwd: Option<&Path>,
    path_var: &OsStr,
    real: &Path,
    canonical: &dyn Fn(&Path) -> Option<PathBuf>,
) -> Option<PathBuf> {
    let joined = if started.is_absolute() {
        started.to_path_buf()
    } else if started.components().count() == 1 {
        std::env::split_paths(path_var)
            .filter(|dir| dir.is_absolute())
            .map(|dir| dir.join(started))
            .find(|p| canonical(p).as_deref() == Some(real))?
    } else {
        cwd?.join(started)
    };
    let mut clean = PathBuf::new();
    for part in joined.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => return None,
            other => clean.push(other),
        }
    }
    Some(clean)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn real() -> PathBuf {
        PathBuf::from("/opt/homebrew/Cellar/warden/1.0.0/bin/warden")
    }

    /// Resolves the links of a fake file system.
    fn fake(path: &Path) -> Option<PathBuf> {
        match path.to_str()? {
            "/opt/homebrew/bin/warden" | "/opt/homebrew/Cellar/warden/1.0.0/bin/warden" => {
                Some(real())
            }
            "/tmp/evil/warden" => Some(PathBuf::from("/tmp/evil/warden")),
            _ => None,
        }
    }

    #[test]
    fn keeps_a_symlink_that_is_this_binary() {
        let got = choose(
            Path::new("/opt/homebrew/bin/warden"),
            &real(),
            None,
            OsStr::new(""),
            &fake,
        );
        assert_eq!(got, Path::new("/opt/homebrew/bin/warden"));
    }

    #[test]
    fn falls_back_when_the_path_is_another_file() {
        let got = choose(
            Path::new("/tmp/evil/warden"),
            &real(),
            None,
            OsStr::new(""),
            &fake,
        );
        assert_eq!(got, real());
    }

    #[test]
    fn falls_back_when_the_path_does_not_resolve() {
        let got = choose(
            Path::new("/nowhere/warden"),
            &real(),
            None,
            OsStr::new(""),
            &fake,
        );
        assert_eq!(got, real());
    }

    #[test]
    fn a_bare_name_takes_the_first_path_entry_that_is_this_binary() {
        let path = std::env::join_paths(["/tmp/evil", "relative/bin", "/opt/homebrew/bin"])
            .expect("paths join");
        let got = choose(Path::new("warden"), &real(), None, &path, &fake);
        assert_eq!(got, Path::new("/opt/homebrew/bin/warden"));
    }

    #[test]
    fn a_bare_name_found_nowhere_falls_back() {
        let got = choose(
            Path::new("warden"),
            &real(),
            None,
            OsStr::new("/tmp/evil"),
            &fake,
        );
        assert_eq!(got, real());
    }

    #[test]
    fn a_relative_path_is_joined_to_the_working_directory() {
        let got = choose(
            Path::new("./bin/warden"),
            &real(),
            Some(Path::new("/opt/homebrew")),
            OsStr::new(""),
            &fake,
        );
        assert_eq!(got, Path::new("/opt/homebrew/bin/warden"));
    }

    #[test]
    fn a_relative_path_without_a_working_directory_falls_back() {
        let got = choose(
            Path::new("bin/warden"),
            &real(),
            None,
            OsStr::new(""),
            &fake,
        );
        assert_eq!(got, real());
    }

    #[test]
    fn parent_components_fall_back() {
        let got = choose(
            Path::new("/opt/homebrew/../homebrew/bin/warden"),
            &real(),
            None,
            OsStr::new(""),
            &|p| (p.file_name()? == "warden").then(real),
        );
        assert_eq!(got, real());
    }

    #[cfg(unix)]
    #[test]
    fn a_real_symlink_is_kept() {
        let dir = tempfile::tempdir().expect("temp dir");
        let versioned = dir.path().join("Cellar");
        std::fs::create_dir(&versioned).expect("mkdir");
        let target = versioned.join("warden");
        std::fs::write(&target, b"").expect("write");
        let link = dir.path().join("warden");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let real = std::fs::canonicalize(&target).expect("canonicalize");
        let got = choose(&link, &real, None, OsStr::new(""), &|p| {
            std::fs::canonicalize(p).ok()
        });
        assert_eq!(got, link);
    }
}
