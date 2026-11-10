//! Where this program is installed, as a path that survives an upgrade.
//!
//! `warden setup git` and `warden setup github` write the program's path into git's
//! configuration and into the `gh` wrapper. Resolving every symlink there would record
//! a package manager's versioned directory (Homebrew's `Cellar/warden/<version>`), which
//! an upgrade removes. The path the program was started from (`argv[0]`, which is the
//! only place Linux keeps it, as `/proc/self/exe` is already resolved) is kept instead,
//! when, at the time of setup:
//!
//! - it names the same file as the running binary, and
//! - the symlink and every directory on the way to it, as written and not resolved, is
//!   owned by the current user or root and is not writable by group or others.
//!
//! The second condition keeps setup from recording a link that someone else could
//! repoint. It says nothing about later: the recorded link is as safe afterwards as the
//! directories it sits in, and warden does not watch them. Otherwise the resolved path
//! is recorded.

use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};

/// The ownership and permissions of one file system entry.
#[derive(Clone, Copy)]
struct Entry {
    uid: u32,
    mode: u32,
    is_symlink: bool,
}

/// Looks an entry up; the flag says whether to follow a symlink.
type Lookup<'a> = &'a dyn Fn(&Path, bool) -> Option<Entry>;

/// Resolves a path to its real file, or `None` when it cannot.
type Canonical<'a> = &'a dyn Fn(&Path) -> Option<PathBuf>;

/// Why the path warden was started from was not recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Someone other than the user or root owns it or a directory on the way, or group or
    /// others can write there.
    OthersCanWrite,
    /// An entry on the way could not be read, so it could not be checked.
    Unverified,
}

/// A path warden was started from that is this binary but was not recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fallback {
    pub started: PathBuf,
    pub reason: Reason,
}

/// The path to record, and why it is not the one warden was started from, if it is not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StableExe {
    pub path: PathBuf,
    /// Set only when the path recorded differs from a path that names this binary.
    pub fallback: Option<Fallback>,
}

impl StableExe {
    /// One line telling the user that the resolved path was recorded, and why, when it
    /// was recorded instead of the path warden was started from.
    pub fn notice(&self) -> Option<String> {
        let fallback = self.fallback.as_ref()?;
        let why = match fallback.reason {
            Reason::OthersCanWrite => "sits in a directory that others can write",
            Reason::Unverified => "could not be verified",
        };
        Some(format!(
            "recorded {}, not {}, which {why}. That path stops working when warden is upgraded, \
             so run this command again after upgrading.",
            self.path.display(),
            fallback.started.display()
        ))
    }
}

/// This program's stable absolute path, verified to be this binary and not repointable
/// by other users.
///
/// # Errors
/// If the operating system cannot say where this program is.
pub fn stable_exe() -> Result<StableExe> {
    let current = std::env::current_exe().context("cannot tell where this program is")?;
    let real = std::fs::canonicalize(&current).context("cannot tell where this program is")?;
    let cwd = std::env::current_dir().ok();
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let mut started: Vec<PathBuf> = std::env::args_os()
        .next()
        .map(PathBuf::from)
        .into_iter()
        .collect();
    started.push(current);
    let uid = rustix::process::getuid().as_raw();
    Ok(choose(
        &started,
        &real,
        cwd.as_deref(),
        &path_var,
        uid,
        &|p| std::fs::canonicalize(p).ok(),
        &|p, follow| {
            let meta = if follow {
                std::fs::metadata(p)
            } else {
                std::fs::symlink_metadata(p)
            }
            .ok()?;
            Some(Entry {
                uid: meta.uid(),
                mode: meta.mode(),
                is_symlink: meta.is_symlink(),
            })
        },
    ))
}

/// The path to record: the first of `started` that, made absolute, is the same file as
/// `real` and passes [`trusted`], otherwise `real`, with the reason when a candidate that
/// is not `real` itself was refused.
fn choose(
    started: &[PathBuf],
    real: &Path,
    cwd: Option<&Path>,
    path_var: &OsStr,
    uid: u32,
    canonical: Canonical<'_>,
    lookup: Lookup<'_>,
) -> StableExe {
    let mut refused = None;
    for candidate in started
        .iter()
        .filter_map(|s| absolute_candidate(s, cwd, path_var, real, canonical))
        .filter(|c| canonical(c).as_deref() == Some(real))
    {
        if candidate == real {
            break;
        }
        match trusted(&candidate, uid, lookup) {
            Ok(()) => {
                return StableExe {
                    path: candidate,
                    fallback: None,
                };
            }
            Err(reason) => {
                refused.get_or_insert(Fallback {
                    started: candidate,
                    reason,
                });
            }
        }
    }
    StableExe {
        path: real.to_path_buf(),
        fallback: refused,
    }
}

/// Whether `path` and each directory above it, as written, are owned by `uid` or root
/// and not writable by group or others (a sticky bit does not make that safe). A
/// symlink's own permission bits mean nothing to the system, so only its owner is read;
/// what it points to is read as well, under the same rule.
fn trusted(path: &Path, uid: u32, lookup: Lookup<'_>) -> Result<(), Reason> {
    let sound = |e: Entry, own_bits_count: bool| {
        (e.uid == uid || e.uid == 0) && (!own_bits_count || e.mode & 0o022 == 0)
    };
    for p in path.ancestors() {
        let Some(link) = lookup(p, false) else {
            return Err(Reason::Unverified);
        };
        let ok = if link.is_symlink {
            let Some(target) = lookup(p, true) else {
                return Err(Reason::Unverified);
            };
            sound(link, false) && sound(target, true)
        } else {
            sound(link, true)
        };
        if !ok {
            return Err(Reason::OthersCanWrite);
        }
    }
    Ok(())
}

/// `started` as an absolute path without `.` or `..` parts, or `None` when there is no
/// safe way to make it one. A bare name is looked up in `path_var`, taking the first
/// entry that is `real`.
fn absolute_candidate(
    started: &Path,
    cwd: Option<&Path>,
    path_var: &OsStr,
    real: &Path,
    canonical: Canonical<'_>,
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

    const ME: u32 = 501;

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

    fn entry(uid: u32, mode: u32, is_symlink: bool) -> Entry {
        Entry {
            uid,
            mode,
            is_symlink,
        }
    }

    /// A file system where everything is owned by `ME` and private to it.
    fn base(path: &Path, follow: bool) -> Entry {
        let is_symlink = !follow && path == Path::new("/opt/homebrew/bin/warden");
        entry(
            ME,
            if is_symlink { 0o120_777 } else { 0o040_755 },
            is_symlink,
        )
    }

    /// The file system as a lookup.
    fn private() -> impl Fn(&Path, bool) -> Option<Entry> {
        |path, follow| Some(base(path, follow))
    }

    fn pick_full(
        started: &[&str],
        cwd: Option<&Path>,
        path_var: &OsStr,
        lookup: Lookup<'_>,
    ) -> StableExe {
        let started: Vec<PathBuf> = started.iter().map(PathBuf::from).collect();
        choose(&started, &real(), cwd, path_var, ME, &fake, lookup)
    }

    fn pick(started: &[&str], cwd: Option<&Path>, path_var: &OsStr, lookup: Lookup<'_>) -> PathBuf {
        pick_full(started, cwd, path_var, lookup).path
    }

    fn pick_one(started: &str) -> PathBuf {
        pick(&[started], None, OsStr::new(""), &private())
    }

    #[test]
    fn keeps_a_symlink_that_is_this_binary() {
        assert_eq!(
            pick_one("/opt/homebrew/bin/warden"),
            Path::new("/opt/homebrew/bin/warden")
        );
    }

    #[test]
    fn falls_back_when_the_path_is_another_file() {
        assert_eq!(pick_one("/tmp/evil/warden"), real());
    }

    #[test]
    fn falls_back_when_the_path_does_not_resolve() {
        assert_eq!(pick_one("/nowhere/warden"), real());
    }

    #[test]
    fn falls_back_without_a_candidate() {
        assert_eq!(pick(&[], None, OsStr::new(""), &private()), real());
    }

    #[test]
    fn the_next_candidate_is_tried_when_the_first_is_not_this_binary() {
        let got = pick(
            &["/tmp/evil/warden", "/opt/homebrew/bin/warden"],
            None,
            OsStr::new(""),
            &private(),
        );
        assert_eq!(got, Path::new("/opt/homebrew/bin/warden"));
    }

    #[test]
    fn a_bare_name_takes_the_first_path_entry_that_is_this_binary() {
        let path = std::env::join_paths(["/tmp/evil", "relative/bin", "/opt/homebrew/bin"])
            .expect("paths join");
        let got = pick(&["warden"], None, &path, &private());
        assert_eq!(got, Path::new("/opt/homebrew/bin/warden"));
    }

    #[test]
    fn a_bare_name_found_nowhere_falls_back() {
        let got = pick(&["warden"], None, OsStr::new("/tmp/evil"), &private());
        assert_eq!(got, real());
    }

    #[test]
    fn a_relative_path_is_joined_to_the_working_directory() {
        let got = pick(
            &["./bin/warden"],
            Some(Path::new("/opt/homebrew")),
            OsStr::new(""),
            &private(),
        );
        assert_eq!(got, Path::new("/opt/homebrew/bin/warden"));
    }

    #[test]
    fn a_relative_path_without_a_working_directory_falls_back() {
        assert_eq!(pick_one("bin/warden"), real());
    }

    #[test]
    fn parent_components_fall_back() {
        let got = choose(
            &[PathBuf::from("/opt/homebrew/../homebrew/bin/warden")],
            &real(),
            None,
            OsStr::new(""),
            ME,
            &|p| (p.file_name()? == "warden").then(real),
            &private(),
        );
        assert_eq!(got.path, real());
    }

    /// `private`, except for the entries `f` replaces.
    fn but(
        f: impl Fn(&Path, bool) -> Option<Option<Entry>>,
    ) -> impl Fn(&Path, bool) -> Option<Entry> {
        move |p, follow| f(p, follow).unwrap_or_else(|| Some(base(p, follow)))
    }

    #[test]
    fn a_directory_others_can_write_on_the_way_falls_back() {
        for mode in [0o040_775, 0o040_757, 0o041_777] {
            let lookup = but(|p, _| (p == Path::new("/opt")).then(|| Some(entry(ME, mode, false))));
            let got = pick(&["/opt/homebrew/bin/warden"], None, OsStr::new(""), &lookup);
            assert_eq!(got, real(), "{mode:o}");
        }
    }

    #[test]
    fn a_directory_owned_by_someone_else_falls_back() {
        let lookup = but(|p, _| {
            (p == Path::new("/opt/homebrew")).then(|| Some(entry(ME + 1, 0o040_755, false)))
        });
        let got = pick(&["/opt/homebrew/bin/warden"], None, OsStr::new(""), &lookup);
        assert_eq!(got, real());
    }

    #[test]
    fn a_root_owned_directory_is_trusted() {
        let lookup = but(|p, _| (p == Path::new("/opt")).then(|| Some(entry(0, 0o040_755, false))));
        let got = pick(&["/opt/homebrew/bin/warden"], None, OsStr::new(""), &lookup);
        assert_eq!(got, Path::new("/opt/homebrew/bin/warden"));
    }

    #[test]
    fn a_symlink_owned_by_someone_else_falls_back() {
        let lookup = but(|p, follow| {
            (p == Path::new("/opt/homebrew/bin/warden") && !follow)
                .then(|| Some(entry(ME + 1, 0o120_777, true)))
        });
        let got = pick(&["/opt/homebrew/bin/warden"], None, OsStr::new(""), &lookup);
        assert_eq!(got, real());
    }

    #[test]
    fn a_symlink_whose_target_others_can_write_falls_back() {
        let lookup = but(|p, follow| {
            (p == Path::new("/opt/homebrew/bin/warden") && follow)
                .then(|| Some(entry(ME, 0o100_777, false)))
        });
        let got = pick(&["/opt/homebrew/bin/warden"], None, OsStr::new(""), &lookup);
        assert_eq!(got, real());
    }

    #[test]
    fn an_entry_that_cannot_be_read_falls_back() {
        let lookup = but(|p, _| (p == Path::new("/opt")).then_some(None));
        let got = pick(&["/opt/homebrew/bin/warden"], None, OsStr::new(""), &lookup);
        assert_eq!(got, real());
    }

    #[test]
    fn a_refused_link_says_why() {
        let writable =
            but(|p, _| (p == Path::new("/opt")).then(|| Some(entry(ME, 0o040_775, false))));
        let got = pick_full(
            &["/opt/homebrew/bin/warden"],
            None,
            OsStr::new(""),
            &writable,
        );
        assert_eq!(
            got.fallback,
            Some(Fallback {
                started: PathBuf::from("/opt/homebrew/bin/warden"),
                reason: Reason::OthersCanWrite,
            })
        );
        let unreadable = but(|p, _| (p == Path::new("/opt")).then_some(None));
        let got = pick_full(
            &["/opt/homebrew/bin/warden"],
            None,
            OsStr::new(""),
            &unreadable,
        );
        assert_eq!(got.fallback.map(|f| f.reason), Some(Reason::Unverified));
    }

    #[test]
    fn nothing_is_said_when_the_started_path_is_the_recorded_one() {
        let got = pick_full(
            &["/opt/homebrew/Cellar/warden/1.0.0/bin/warden"],
            None,
            OsStr::new(""),
            &but(|_, _| Some(None)),
        );
        assert_eq!(got.path, real());
        assert_eq!(got.fallback, None);
        assert_eq!(got.notice(), None);
    }

    #[test]
    fn nothing_is_said_when_a_trusted_link_is_kept_or_none_names_this_binary() {
        assert_eq!(
            pick_full(
                &["/opt/homebrew/bin/warden"],
                None,
                OsStr::new(""),
                &private()
            )
            .notice(),
            None
        );
        assert_eq!(
            pick_full(&["/tmp/evil/warden"], None, OsStr::new(""), &private()).notice(),
            None
        );
    }

    #[test]
    fn the_notice_names_both_paths_the_reason_and_the_rerun() {
        let writable =
            but(|p, _| (p == Path::new("/opt")).then(|| Some(entry(ME, 0o040_775, false))));
        let notice = pick_full(
            &["/opt/homebrew/bin/warden"],
            None,
            OsStr::new(""),
            &writable,
        )
        .notice()
        .expect("a notice");
        assert!(
            notice.contains("/opt/homebrew/Cellar/warden/1.0.0/bin/warden"),
            "{notice}"
        );
        assert!(notice.contains("/opt/homebrew/bin/warden"), "{notice}");
        assert!(notice.contains("others can write"), "{notice}");
        assert!(notice.contains("again after upgrading"), "{notice}");
        let unreadable = but(|p, _| (p == Path::new("/opt")).then_some(None));
        let notice = pick_full(
            &["/opt/homebrew/bin/warden"],
            None,
            OsStr::new(""),
            &unreadable,
        )
        .notice()
        .expect("a notice");
        assert!(notice.contains("could not be verified"), "{notice}");
    }
}
