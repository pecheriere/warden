//! Keeping warden's files private to its user, whatever the directory's mode.
//!
//! The database, its `SQLite` companions, the audit log and the audience are
//! created 0600, and an existing one with group or other bits is corrected
//! when it is opened. The relay's host key is stricter: `relay::host_key`
//! refuses a loose one, as `ssh` does.
//!
//! **A file that cannot be made private stops warden.** Nothing else protects
//! it, so carrying on would hide the problem. A file that is already private
//! needs no change, so it works on a read-only mount too.
//!
//! **A data directory that cannot be made private is reported, not fatal.** The
//! files in it are private without its help, it may be shared with something
//! else, and `warden-server doctor` fails it until it is corrected. warden
//! changes it only when warden's own non-root user owns it: under root,
//! ownership does not show that the directory is warden's, and `/var/lib` should
//! not become 0700 because a database was put there.

use std::ffi::OsString;
use std::fs::{self, File, Permissions};
use std::io;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};

const FILE_MODE: u32 = 0o600;
const DIRECTORY_MODE: u32 = 0o700;
/// The bits a private file or directory does not have.
const GROUP_AND_OTHER: u32 = 0o077;
/// What `SQLite` keeps next to a database, named after its real path.
const DATABASE_COMPANIONS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// A file could not be kept private to warden's user.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PrivateFileError {
    /// The file could not be opened or inspected.
    #[error("{}: cannot check that it is private to warden's user: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// The I/O failure.
        #[source]
        source: io::Error,
    },
    /// Something other than a regular file is at the path.
    #[error("{} is not a regular file", path.display())]
    NotRegular {
        /// The path.
        path: PathBuf,
    },
    /// The file has group or other bits, and they could not be removed.
    #[error(
        "{} has mode {mode:04o}, and warden could not change it to 0600: {source}. \
         Change it as its owner, or correct the mount it is on",
        path.display()
    )]
    Loose {
        /// The file.
        path: PathBuf,
        /// Its mode.
        mode: u32,
        /// Why it could not be changed.
        #[source]
        source: io::Error,
    },
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> PrivateFileError + '_ {
    move |source| PrivateFileError::Io {
        path: path.to_owned(),
        source,
    }
}

/// The directory holding the database at `db_path`, the data directory.
#[must_use]
pub fn data_directory(db_path: &Path) -> &Path {
    match db_path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

/// Make the open `file`, found at `path`, private to warden's user.
pub(crate) fn make_private(file: &File, path: &Path) -> Result<(), PrivateFileError> {
    make_private_with(file, path, |file| {
        file.set_permissions(Permissions::from_mode(FILE_MODE))
    })
}

fn make_private_with(
    file: &File,
    path: &Path,
    change_mode: impl FnOnce(&File) -> io::Result<()>,
) -> Result<(), PrivateFileError> {
    let meta = file.metadata().map_err(io_error(path))?;
    if !meta.is_file() {
        return Err(PrivateFileError::NotRegular {
            path: path.to_owned(),
        });
    }
    let mode = meta.mode() & 0o7777;
    if mode & GROUP_AND_OTHER == 0 {
        return Ok(());
    }
    let loose = |source| PrivateFileError::Loose {
        path: path.to_owned(),
        mode,
        source,
    };
    change_mode(file).map_err(loose)?;
    // Some file systems accept the call and keep the mode.
    let after = file.metadata().map_err(io_error(path))?.mode();
    if after & GROUP_AND_OTHER != 0 {
        return Err(loose(io::Error::other("the mode did not change")));
    }
    Ok(())
}

/// Make the existing regular file at `path` private. Does not follow a symbolic
/// link at `path`, and does not wait on a FIFO.
pub(crate) fn make_existing_private(path: &Path) -> Result<(), PrivateFileError> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = rustix::fs::open(path, flags, Mode::empty())
        .map_err(|e| io_error(path)(e.into()))
        .map(File::from)?;
    make_private(&file, path)
}

/// Create the database file 0600 if it is missing, and make it and the files
/// `SQLite` keeps next to it private. Must run before `SQLite` opens it: `SQLite`
/// would create the database with the umask's mode, and it gives a new WAL or
/// SHM file the mode of the database, so a private database keeps them private.
pub(crate) fn prepare_database(db_path: &Path) -> Result<(), PrivateFileError> {
    let flags = OFlags::RDONLY | OFlags::CREATE | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = rustix::fs::open(db_path, flags, Mode::RUSR | Mode::WUSR)
        .map_err(|e| io_error(db_path)(e.into()))
        .map(File::from)?;
    make_private(&file, db_path)?;
    // SQLite resolves a link, so that is where it keeps the companions.
    let real = fs::canonicalize(db_path).map_err(io_error(db_path))?;
    for suffix in DATABASE_COMPANIONS {
        let mut name = OsString::from(real.as_os_str());
        name.push(suffix);
        match make_existing_private(Path::new(&name)) {
            Err(PrivateFileError::Io { source, .. })
                if source.kind() == io::ErrorKind::NotFound => {}
            other => other?,
        }
    }
    Ok(())
}

/// What became of the data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DirectoryState {
    /// It already had no group or other bits.
    Private,
    /// warden removed them.
    Tightened,
    /// It still has them, for this reason.
    Left {
        /// Why warden did not or could not change it.
        reason: String,
    },
}

/// Which change a directory with this mode and owner gets.
fn directory_plan(mode: u32, owner: u32, euid: u32) -> Result<bool, &'static str> {
    if mode & GROUP_AND_OTHER == 0 {
        Ok(false)
    } else if euid == 0 {
        Err("warden runs as root, so owning it does not show the directory is warden's own")
    } else if owner != euid {
        Err("it belongs to another user")
    } else {
        Ok(true)
    }
}

fn tighten_directory(directory: &Path, euid: u32) -> DirectoryState {
    let left = |reason: String| DirectoryState::Left { reason };
    let opened = File::open(directory).and_then(|dir| {
        let meta = dir.metadata()?;
        Ok((dir, meta))
    });
    let (dir, meta) = match opened {
        Ok(opened) => opened,
        Err(e) => return left(format!("it cannot be read: {e}")),
    };
    match directory_plan(meta.mode(), meta.uid(), euid) {
        Ok(false) => DirectoryState::Private,
        Err(reason) => left(reason.to_owned()),
        Ok(true) => match dir.set_permissions(Permissions::from_mode(DIRECTORY_MODE)) {
            Ok(()) => DirectoryState::Tightened,
            Err(e) => left(format!("its mode could not be changed: {e}")),
        },
    }
}

/// Make the directory holding the database at `db_path` private, if warden's
/// own non-root user owns it. See the module's description for why failing to
/// do so is reported to the caller rather than an error.
pub async fn tighten_data_directory(db_path: &Path) -> DirectoryState {
    let directory = data_directory(db_path).to_owned();
    let euid = rustix::process::geteuid().as_raw();
    tokio::task::spawn_blocking(move || tighten_directory(&directory, euid))
        .await
        .unwrap_or_else(|e| DirectoryState::Left {
            reason: format!("the check did not finish: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::{
        DirectoryState, FILE_MODE, File, Path, Permissions, PrivateFileError, data_directory,
        directory_plan, fs, io, make_existing_private, make_private, make_private_with,
        prepare_database, tighten_directory,
    };

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn file_with_mode(path: &Path, mode: u32) -> File {
        fs::write(path, "x").unwrap();
        fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
        File::open(path).unwrap()
    }

    #[test]
    fn a_loose_file_becomes_private_and_keeps_its_content() {
        let dir = tempfile::tempdir().unwrap();
        for loose in [0o644, 0o640, 0o666, 0o604, 0o660] {
            let path = dir.path().join("file");
            let file = file_with_mode(&path, loose);
            make_private(&file, &path).unwrap();
            assert_eq!(mode(&path), FILE_MODE, "{loose:o}");
            assert_eq!(fs::read_to_string(&path).unwrap(), "x");
        }
    }

    #[test]
    fn a_private_file_is_left_alone_even_where_its_mode_cannot_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        for private in [0o600, 0o400] {
            let file = file_with_mode(&path, private);
            make_private_with(&file, &path, |_| panic!("no change is needed")).unwrap();
            assert_eq!(mode(&path), private);
        }
    }

    #[test]
    fn a_failure_to_change_the_mode_stops_warden_and_names_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        let file = file_with_mode(&path, 0o644);
        let error = make_private_with(&file, &path, |_| {
            Err(io::Error::from(io::ErrorKind::ReadOnlyFilesystem))
        })
        .unwrap_err();
        assert!(matches!(error, PrivateFileError::Loose { mode: 0o644, .. }));
        let message = error.to_string();
        assert!(message.contains("file has mode 0644"), "{message}");
        assert!(message.contains("read-only"), "{message}");
    }

    #[test]
    fn a_file_system_that_ignores_the_change_is_noticed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        let file = file_with_mode(&path, 0o644);
        let error = make_private_with(&file, &path, |_| Ok(())).unwrap_err();
        assert!(error.to_string().contains("did not change"), "{error}");
    }

    #[test]
    fn something_other_than_a_file_is_refused_without_waiting_on_it() {
        let dir = tempfile::tempdir().unwrap();
        let error = make_existing_private(dir.path()).unwrap_err();
        assert!(
            matches!(error, PrivateFileError::NotRegular { .. }),
            "{error}"
        );
        // Linux refuses to open a directory for creating a file, and macOS
        // opens it and leaves the check to find out.
        prepare_database(dir.path()).unwrap_err();

        // Opening a FIFO without O_NONBLOCK would wait for a writer forever.
        let fifo = dir.path().join("fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        for error in [
            make_existing_private(&fifo).unwrap_err(),
            prepare_database(&fifo).unwrap_err(),
        ] {
            assert!(
                matches!(error, PrivateFileError::NotRegular { .. }),
                "{error}"
            );
        }
    }

    #[test]
    fn a_new_database_file_is_created_private() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("warden.db");
        prepare_database(&db).unwrap();
        assert_eq!(mode(&db), FILE_MODE);
    }

    #[test]
    fn existing_database_companions_become_private() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("warden.db");
        let names = [
            "warden.db",
            "warden.db-wal",
            "warden.db-shm",
            "warden.db-journal",
        ];
        for name in names {
            file_with_mode(&dir.path().join(name), 0o644);
        }
        prepare_database(&db).unwrap();
        for name in names {
            assert_eq!(mode(&dir.path().join(name)), FILE_MODE, "{name}");
        }
    }

    #[test]
    fn a_linked_database_has_its_real_file_and_companions_made_private() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.db");
        let wal = dir.path().join("real.db-wal");
        file_with_mode(&real, 0o644);
        file_with_mode(&wal, 0o644);
        let link = dir.path().join("warden.db");
        symlink(&real, &link).unwrap();
        prepare_database(&link).unwrap();
        assert_eq!(mode(&real), FILE_MODE);
        assert_eq!(mode(&wal), FILE_MODE);
    }

    #[test]
    fn a_link_in_place_of_a_companion_is_refused_and_its_target_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        file_with_mode(&outside, 0o644);
        symlink(&outside, dir.path().join("warden.db-wal")).unwrap();
        let error = prepare_database(&dir.path().join("warden.db")).unwrap_err();
        assert!(matches!(error, PrivateFileError::Io { .. }), "{error}");
        assert_eq!(mode(&outside), 0o644);
    }

    #[test]
    fn a_read_only_directory_still_allows_private_files() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("warden.db");
        file_with_mode(&db, 0o600);
        fs::set_permissions(dir.path(), Permissions::from_mode(0o500)).unwrap();
        let result = prepare_database(&db);
        fs::set_permissions(dir.path(), Permissions::from_mode(0o700)).unwrap();
        result.unwrap();
    }

    #[test]
    fn only_warden_owning_the_directory_as_non_root_changes_it() {
        assert_eq!(directory_plan(0o40700, 10, 10), Ok(false));
        assert_eq!(directory_plan(0o40755, 10, 10), Ok(true));
        assert_eq!(directory_plan(0o40750, 10, 10), Ok(true));
        assert!(directory_plan(0o40755, 11, 10).is_err());
        assert!(directory_plan(0o40755, 0, 0).is_err());
        // Already private needs nothing, whoever owns it.
        assert_eq!(directory_plan(0o40700, 0, 0), Ok(false));
        assert_eq!(directory_plan(0o40700, 11, 10), Ok(false));
    }

    #[test]
    fn the_directory_is_tightened_and_a_refusal_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let euid = rustix::process::geteuid().as_raw();
        let other = euid + 1;
        fs::set_permissions(dir.path(), Permissions::from_mode(0o755)).unwrap();
        // Another user's directory here means this process's user is not its
        // owner: pretend to be someone else, and nothing changes.
        assert!(matches!(
            tighten_directory(dir.path(), other),
            DirectoryState::Left { .. }
        ));
        assert_eq!(mode(dir.path()), 0o755);
        if euid != 0 {
            assert_eq!(
                tighten_directory(dir.path(), euid),
                DirectoryState::Tightened
            );
            assert_eq!(mode(dir.path()), 0o700);
            assert_eq!(tighten_directory(dir.path(), euid), DirectoryState::Private);
        }
        let missing = dir.path().join("missing");
        assert!(matches!(
            tighten_directory(&missing, euid),
            DirectoryState::Left { .. }
        ));
    }

    #[test]
    fn the_data_directory_of_a_bare_name_is_the_current_one() {
        assert_eq!(data_directory(Path::new("warden.db")), Path::new("."));
        assert_eq!(
            data_directory(Path::new("/data/warden.db")),
            Path::new("/data")
        );
    }
}
