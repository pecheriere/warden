//! Keeping warden's files private to its user, whatever the directory's mode.
//!
//! The database, its `SQLite` companions, the audit log and the audience are
//! created 0600, and an existing one with group or other bits is corrected
//! when it is opened. A symbolic link in place of one is refused, so a mode is
//! never changed on a file somewhere else. The relay's host key is stricter:
//! `relay::host_key` refuses a loose one, as `ssh` does.
//!
//! **A file that cannot be made private stops warden.** Nothing else protects
//! it, so carrying on would hide the problem. A file that is already private
//! needs no change, so it works on a read-only mount too.
//!
//! **warden changes the data directory only when it is clearly warden's**: its
//! own non-root user owns it, and nothing but warden's own files is in it. So
//! `/data` or a directory made for warden is corrected, and `$HOME` or `/var/lib`
//! holding a database is not. A directory warden leaves alone has one of two
//! outcomes. If others can write to it they can replace the files in it, whatever
//! the files' modes, so warden refuses to start. If they can only read it they can
//! see the files' names and sizes but not their contents, so warden warns, and
//! `warden-server doctor` fails it.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Permissions};
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};

const FILE_MODE: u32 = 0o600;
const DIRECTORY_MODE: u32 = 0o700;
/// The bits a private file or directory does not have.
const GROUP_AND_OTHER: u32 = 0o077;
/// The bits that let someone else replace what is in a directory.
const GROUP_AND_OTHER_WRITE: u32 = 0o022;
/// What `SQLite` keeps next to a database, named after its real path.
const DATABASE_COMPANIONS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// A file or the data directory could not be kept private to warden's user.
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
    /// warden's user may not open the file.
    #[error(
        "{} belongs to uid {owner} with mode {mode:04o}, and warden, running as uid {euid}, \
         cannot open it: {source}. Give it to warden's user: chown {euid} {}",
        path.display(),
        path.display()
    )]
    NoAccess {
        /// The file.
        path: PathBuf,
        /// Who owns it.
        owner: u32,
        /// Its mode.
        mode: u32,
        /// Who warden runs as.
        euid: u32,
        /// The I/O failure.
        #[source]
        source: io::Error,
    },
    /// A symbolic link is at the path.
    #[error("{} is a symbolic link: point the setting at the file itself", path.display())]
    SymbolicLink {
        /// The path.
        path: PathBuf,
    },
    /// Something other than a regular file is at the path.
    #[error("{} is not a regular file", path.display())]
    NotRegular {
        /// The path.
        path: PathBuf,
    },
    /// The file has group or other bits, and they could not be removed.
    #[error(
        "{} belongs to uid {owner} with mode {mode:04o}, and warden, running as uid {euid}, \
         could not change it to 0600: {source}. As its owner or root, run chown {euid} and \
         chmod 0600 on it, or correct the mount it is on",
        path.display()
    )]
    Loose {
        /// The file.
        path: PathBuf,
        /// Who owns it.
        owner: u32,
        /// Its mode.
        mode: u32,
        /// Who warden runs as.
        euid: u32,
        /// Why it could not be changed.
        #[source]
        source: io::Error,
    },
    /// Others can write to the data directory, and warden left it alone.
    #[error(
        "the data directory {} has mode {mode:04o}, so others can replace warden's files in \
         it, and warden did not change it: {reason}. Use a directory only warden's user can \
         write to: mode 0700, owned by that user",
        path.display()
    )]
    DirectoryWritable {
        /// The directory.
        path: PathBuf,
        /// Its mode.
        mode: u32,
        /// Why warden did not or could not change it.
        reason: String,
    },
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> PrivateFileError + '_ {
    move |source| PrivateFileError::Io {
        path: path.to_owned(),
        source,
    }
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Why opening `path` failed, in the most useful terms available.
fn open_error(path: &Path, errno: rustix::io::Errno) -> PrivateFileError {
    let source = io::Error::from(errno);
    if errno == rustix::io::Errno::LOOP {
        return PrivateFileError::SymbolicLink {
            path: path.to_owned(),
        };
    }
    if source.kind() == io::ErrorKind::PermissionDenied
        && let Ok(meta) = fs::symlink_metadata(path)
    {
        return PrivateFileError::NoAccess {
            path: path.to_owned(),
            owner: meta.uid(),
            mode: meta.mode() & 0o7777,
            euid: euid(),
            source,
        };
    }
    io_error(path)(source)
}

/// Open `path` without following a symbolic link or waiting on a FIFO.
fn open(path: &Path, flags: OFlags, mode: Mode) -> Result<File, PrivateFileError> {
    let flags = flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    rustix::fs::open(path, flags, mode)
        .map(File::from)
        .map_err(|errno| open_error(path, errno))
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
fn make_private(file: &File, path: &Path) -> Result<(), PrivateFileError> {
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
        owner: meta.uid(),
        mode,
        euid: euid(),
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

/// Make the existing regular file at `path` private.
pub(crate) fn make_existing_private(path: &Path) -> Result<(), PrivateFileError> {
    let file = open(path, OFlags::RDONLY, Mode::empty())?;
    make_private(&file, path)
}

/// Open the audit log at `path` for reading and appending, creating it if it is
/// missing, and make it private.
pub(crate) fn open_private_log(path: &Path) -> Result<File, PrivateFileError> {
    let flags = OFlags::RDWR | OFlags::APPEND | OFlags::CREATE;
    let file = open(path, flags, Mode::RUSR | Mode::WUSR)?;
    make_private(&file, path)?;
    Ok(file)
}

/// Create the database file 0600 if it is missing, and make it and the files
/// `SQLite` keeps next to it private. Must run before `SQLite` opens it: `SQLite`
/// would create the database with the umask's mode, and it gives a new WAL or
/// SHM file the mode of the database, so a private database keeps them private.
pub(crate) fn prepare_database(db_path: &Path) -> Result<(), PrivateFileError> {
    let flags = OFlags::RDONLY | OFlags::CREATE;
    let file = open(db_path, flags, Mode::RUSR | Mode::WUSR)?;
    make_private(&file, db_path)?;
    // SQLite resolves links in the directories above it, and keeps the
    // companions at the path it gets.
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

/// What became of the data directory, when warden can start.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DirectoryState {
    /// It already had no group or other bits.
    Private,
    /// warden removed them.
    Tightened,
    /// Others can read it, but not write to it, and warden left it alone.
    Readable {
        /// Why warden did not or could not change it.
        reason: String,
    },
    /// warden could not find out its mode. Opening the files in it will say
    /// more if that is a problem.
    Unchecked {
        /// What went wrong.
        reason: String,
    },
}

/// Whether `name` is one of warden's files in the data directory: a name in
/// `own`, one of the database's companions, or a temporary file warden makes
/// for one (`.<name>.<hex>.tmp`).
fn is_own_file(name: &OsStr, own: &[&OsStr]) -> bool {
    own.iter().any(|&file| {
        if name == file {
            return true;
        }
        let bytes = name.as_bytes();
        let file = file.as_bytes();
        let companion = bytes.strip_prefix(file).is_some_and(|suffix| {
            DATABASE_COMPANIONS
                .iter()
                .any(|companion| suffix == companion.as_bytes())
        });
        let temporary = bytes
            .strip_prefix(b".")
            .and_then(|rest| rest.strip_prefix(file))
            .and_then(|rest| rest.strip_prefix(b"."))
            .is_some_and(|rest| rest.ends_with(b".tmp"));
        companion || temporary
    })
}

/// Why warden does not call `directory` its own, if it does not.
fn not_warden_s(directory: &Path, owner: u32, euid: u32, own: &[&OsStr]) -> Option<String> {
    if euid == 0 {
        return Some("warden runs as root, so owning it does not show that it is warden's".into());
    }
    if owner != euid {
        return Some(format!(
            "it belongs to uid {owner}, and warden runs as uid {euid}"
        ));
    }
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(e) => return Some(format!("what is in it cannot be listed: {e}")),
    };
    for entry in entries {
        match entry {
            Ok(entry) if is_own_file(&entry.file_name(), own) => {}
            Ok(_) => return Some("it holds files that are not warden's".into()),
            Err(e) => return Some(format!("what is in it cannot be listed: {e}")),
        }
    }
    None
}

fn tighten_directory(
    directory: &Path,
    own: &[&OsStr],
    euid: u32,
) -> Result<DirectoryState, PrivateFileError> {
    let meta = match fs::metadata(directory) {
        Ok(meta) => meta,
        Err(e) => {
            return Ok(DirectoryState::Unchecked {
                reason: e.to_string(),
            });
        }
    };
    let mode = meta.mode() & 0o7777;
    if mode & GROUP_AND_OTHER == 0 {
        return Ok(DirectoryState::Private);
    }
    let reason = match not_warden_s(directory, meta.uid(), euid, own) {
        Some(reason) => reason,
        None => match fs::set_permissions(directory, Permissions::from_mode(DIRECTORY_MODE)) {
            Ok(()) => return Ok(DirectoryState::Tightened),
            Err(e) => format!("its mode could not be changed: {e}"),
        },
    };
    if mode & GROUP_AND_OTHER_WRITE == 0 {
        Ok(DirectoryState::Readable { reason })
    } else {
        Err(PrivateFileError::DirectoryWritable {
            path: directory.to_owned(),
            mode,
            reason,
        })
    }
}

/// Make the directory holding the database at `db_path` private if it is clearly
/// warden's (see the module's description). `others` are the paths of warden's
/// other files, which may be in it.
///
/// # Errors
/// [`PrivateFileError::DirectoryWritable`] if others can write to it and warden
/// left it alone.
pub async fn tighten_data_directory(
    db_path: &Path,
    others: &[&Path],
) -> Result<DirectoryState, PrivateFileError> {
    let directory = data_directory(db_path).to_owned();
    let names: Vec<OsString> = std::iter::once(db_path)
        .chain(others.iter().copied())
        .filter_map(Path::file_name)
        .map(OsStr::to_owned)
        .collect();
    let euid = euid();
    tokio::task::spawn_blocking(move || {
        let own: Vec<&OsStr> = names.iter().map(OsString::as_os_str).collect();
        tighten_directory(&directory, &own, euid)
    })
    .await
    .map_err(|e| PrivateFileError::Io {
        path: data_directory(db_path).to_owned(),
        source: io::Error::other(e),
    })?
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use super::{
        DirectoryState, FILE_MODE, File, OsStr, Path, Permissions, PrivateFileError,
        data_directory, fs, io, is_own_file, make_existing_private, make_private,
        make_private_with, open_error, open_private_log, prepare_database, tighten_directory,
    };

    fn own() -> [&'static OsStr; 4] {
        ["warden.db", "audit.jsonl", "audience", "relay_host_ed25519"].map(OsStr::new)
    }

    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

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
        assert!(message.contains("with mode 0644"), "{message}");
        assert!(message.contains("file belongs to uid"), "{message}");
        assert!(message.contains("chown"), "{message}");
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
    fn a_link_in_place_of_a_file_is_refused_and_its_target_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        file_with_mode(&outside, 0o644);
        let link = dir.path().join("link");
        symlink(&outside, &link).unwrap();
        for error in [
            prepare_database(&link).unwrap_err(),
            open_private_log(&link).unwrap_err(),
            make_existing_private(&link).unwrap_err(),
        ] {
            assert!(
                matches!(error, PrivateFileError::SymbolicLink { .. }),
                "{error}"
            );
            assert!(error.to_string().contains("symbolic link"), "{error}");
        }
        assert_eq!(mode(&outside), 0o644);
    }

    #[test]
    fn a_database_under_a_linked_directory_has_its_companions_made_private() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        file_with_mode(&real.join("warden.db-wal"), 0o644);
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        prepare_database(&link.join("warden.db")).unwrap();
        assert_eq!(mode(&real.join("warden.db")), FILE_MODE);
        assert_eq!(mode(&real.join("warden.db-wal")), FILE_MODE);
    }

    #[test]
    fn a_file_warden_may_not_open_is_named_with_its_owner_and_what_to_do() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("warden.db");
        file_with_mode(&path, 0o600);
        let message = open_error(&path, rustix::io::Errno::ACCESS).to_string();
        let uid = euid();
        assert!(message.contains("warden.db belongs to uid"), "{message}");
        assert!(
            message.contains(&format!("uid {uid} with mode 0600")),
            "{message}"
        );
        assert!(message.contains(&format!("chown {uid} ")), "{message}");
        assert!(message.contains("warden.db"), "{message}");
    }

    #[test]
    fn a_link_in_place_of_a_companion_is_refused_and_its_target_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        file_with_mode(&outside, 0o644);
        symlink(&outside, dir.path().join("warden.db-wal")).unwrap();
        let error = prepare_database(&dir.path().join("warden.db")).unwrap_err();
        assert!(
            matches!(error, PrivateFileError::SymbolicLink { .. }),
            "{error}"
        );
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
    fn warden_s_own_files_are_told_from_others() {
        let own = own();
        for name in [
            "warden.db",
            "warden.db-wal",
            "warden.db-shm",
            "warden.db-journal",
            "audit.jsonl",
            "audience",
            "relay_host_ed25519",
            ".audience.00112233aabbccdd.tmp",
            ".relay_host_ed25519.00112233aabbccdd.tmp",
        ] {
            assert!(is_own_file(OsStr::new(name), &own), "{name}");
        }
        for name in [
            "notes.txt",
            ".ssh",
            "warden.db.bak",
            "lost+found",
            ".audience.tmp.other",
            ".other.00112233aabbccdd.tmp",
        ] {
            assert!(!is_own_file(OsStr::new(name), &own), "{name}");
        }
    }

    fn directory_with_mode(mode: u32, files: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for file in files {
            fs::write(dir.path().join(file), "x").unwrap();
        }
        fs::set_permissions(dir.path(), Permissions::from_mode(mode)).unwrap();
        dir
    }

    #[test]
    fn a_directory_holding_only_warden_s_files_is_tightened() {
        for files in [
            &[][..],
            &["warden.db", "warden.db-wal", "audit.jsonl", "audience"][..],
        ] {
            let dir = directory_with_mode(0o755, files);
            let state = tighten_directory(dir.path(), &own(), euid()).unwrap();
            assert_eq!(state, DirectoryState::Tightened, "{files:?}");
            assert_eq!(mode(dir.path()), 0o700);
            let state = tighten_directory(dir.path(), &own(), euid()).unwrap();
            assert_eq!(state, DirectoryState::Private);
        }
        // Writable by others is corrected too when it is warden's.
        let dir = directory_with_mode(0o777, &["warden.db"]);
        let state = tighten_directory(dir.path(), &own(), euid()).unwrap();
        assert_eq!(state, DirectoryState::Tightened);
        assert_eq!(mode(dir.path()), 0o700);
    }

    #[test]
    fn a_shared_parent_directory_keeps_its_mode_and_is_reported() {
        let dir = directory_with_mode(0o755, &["warden.db", "notes.txt"]);
        let state = tighten_directory(dir.path(), &own(), euid()).unwrap();
        assert!(
            matches!(&state, DirectoryState::Readable { reason } if reason.contains("not warden's")),
            "{state:?}"
        );
        assert_eq!(mode(dir.path()), 0o755);
    }

    #[test]
    fn a_shared_directory_others_can_write_to_stops_warden_and_keeps_its_mode() {
        for loose in [0o775, 0o757, 0o777, 0o1777] {
            let dir = directory_with_mode(loose, &["warden.db", "notes.txt"]);
            let error = tighten_directory(dir.path(), &own(), euid()).unwrap_err();
            let message = error.to_string();
            assert!(
                matches!(error, PrivateFileError::DirectoryWritable { .. }),
                "{message}"
            );
            assert!(message.contains("can replace warden's files"), "{message}");
            assert!(message.contains(&format!("{loose:04o}")), "{message}");
            assert_eq!(
                fs::metadata(dir.path()).unwrap().permissions().mode() & 0o7777,
                loose
            );
        }
    }

    #[test]
    fn another_user_s_or_root_s_directory_is_left_alone() {
        let other = euid() + 1;
        let dir = directory_with_mode(0o755, &[]);
        let state = tighten_directory(dir.path(), &own(), other).unwrap();
        assert!(
            matches!(&state, DirectoryState::Readable { reason } if reason.contains("belongs to uid")),
            "{state:?}"
        );
        assert_eq!(mode(dir.path()), 0o755);
        let state = tighten_directory(dir.path(), &own(), 0).unwrap();
        assert!(
            matches!(&state, DirectoryState::Readable { reason } if reason.contains("root")),
            "{state:?}"
        );
        assert_eq!(mode(dir.path()), 0o755);
        let dir = directory_with_mode(0o777, &[]);
        tighten_directory(dir.path(), &own(), 0).unwrap_err();
        assert_eq!(mode(dir.path()), 0o777);
    }

    #[test]
    fn a_missing_directory_is_reported_as_not_checked_rather_than_blamed_on_its_mode() {
        let dir = tempfile::tempdir().unwrap();
        let state = tighten_directory(&dir.path().join("missing"), &own(), euid()).unwrap();
        assert!(
            matches!(state, DirectoryState::Unchecked { .. }),
            "{state:?}"
        );
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
