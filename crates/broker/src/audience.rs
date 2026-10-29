//! The broker's audience: a random identifier of 32 lowercase hex characters,
//! created once and kept in a private file (`WARDEN_AUDIENCE_PATH`). Signed
//! agent requests name it, so a request signed for one broker is refused by
//! every other; `GET /v1/info` publishes it so clients can pin it at login.
//!
//! The identifier is not secret, but it must never change, so the file is
//! created the way the relay host key is: written to a fresh `0600`
//! temporary file in the same directory, synced, then hard-linked into place,
//! which fails rather than replaces if another process created it
//! meanwhile (that one is then loaded instead).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use warden_broker_proto::signing::Audience;

/// Largest file read; the identifier is 32 characters and a newline.
const MAX_FILE_BYTES: u64 = 64;

/// The audience file could not be loaded or created.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AudienceError {
    /// The file could not be read or written.
    #[error("audience file {}: {source}", path.display())]
    Io {
        /// The file (or its temporary sibling).
        path: PathBuf,
        /// The I/O failure.
        #[source]
        source: io::Error,
    },
    /// The file exists but is not a usable audience.
    #[error("audience file {}: {reason}", path.display())]
    Invalid {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The blocking file work could not run to completion.
    #[error("audience file: loading task failed")]
    Task,
}

/// Load the audience at `path`, creating it first if there is none. Runs the
/// file work on the blocking pool.
///
/// # Errors
/// See [`load_or_create_blocking`].
pub async fn load_or_create(path: PathBuf) -> Result<Audience, AudienceError> {
    tokio::task::spawn_blocking(move || load_or_create_blocking(&path))
        .await
        .map_err(|_| AudienceError::Task)?
}

/// Load the audience at `path`, creating it first if there is none. An
/// existing file is never overwritten; it must be a regular file (not a
/// symbolic link) owned by this process's user, not writable by group or
/// others, holding 32 lowercase hex characters.
///
/// # Errors
/// [`AudienceError::Io`] if the file or its directory cannot be read or
/// written; [`AudienceError::Invalid`] if the file is not an audience.
pub fn load_or_create_blocking(path: &Path) -> Result<Audience, AudienceError> {
    match load(path) {
        Err(AudienceError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            create(path)
        }
        loaded => loaded,
    }
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> AudienceError + '_ {
    move |source| AudienceError::Io {
        path: path.to_owned(),
        source,
    }
}

fn invalid(path: &Path, reason: &'static str) -> AudienceError {
    AudienceError::Invalid {
        path: path.to_owned(),
        reason,
    }
}

fn load(path: &Path) -> Result<Audience, AudienceError> {
    // Refuse a link before opening (a clear message), and open without
    // following one, so a link swapped in between is refused too.
    if fs::symlink_metadata(path)
        .map_err(io_error(path))?
        .file_type()
        .is_symlink()
    {
        return Err(invalid(path, "is a symbolic link"));
    }
    let file = File::from(
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| io_error(path)(e.into()))?,
    );
    // Checked on the open file, so the checks and the read see the same one.
    let meta = file.metadata().map_err(io_error(path))?;
    if !meta.is_file() {
        return Err(invalid(path, "is not a regular file"));
    }
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(invalid(path, "is owned by another user"));
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err(invalid(path, "is writable by group or others"));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(invalid(path, "is too large to be an audience"));
    }
    let mut text = String::new();
    file.take(MAX_FILE_BYTES)
        .read_to_string(&mut text)
        .map_err(|e| {
            if e.kind() == io::ErrorKind::InvalidData {
                invalid(path, "is not 32 lowercase hex characters")
            } else {
                io_error(path)(e)
            }
        })?;
    let id = text.strip_suffix('\n').unwrap_or(&text);
    Audience::try_from(id.to_owned())
        .map_err(|_| invalid(path, "is not 32 lowercase hex characters"))
}

fn create(path: &Path) -> Result<Audience, AudienceError> {
    let audience = Audience::random();
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| invalid(path, "does not name a file"))?;
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix)
        .map_err(|_| io_error(path)(io::Error::other("OS random number generator unavailable")))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".{}.tmp", hex::encode(suffix)));
    let tmp = dir.join(tmp_name);

    let text = format!("{audience}\n");
    let written = write_new(&tmp, text.as_bytes()).and_then(|()| match fs::hard_link(&tmp, path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(io_error(path)(e)),
    });
    // The temporary name is never needed again, whatever happened.
    let removed = fs::remove_file(&tmp);
    if !written? {
        // Another process created it first; use theirs.
        return load(path);
    }
    removed.map_err(io_error(&tmp))?;
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(io_error(dir))?;
    Ok(audience)
}

/// Write `bytes` to a new file at `path`, mode 0600, and sync it.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), AudienceError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io_error(path))?;
    file.write_all(bytes).map_err(io_error(path))?;
    file.sync_all().map_err(io_error(path))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::{AudienceError, load_or_create, load_or_create_blocking};

    #[tokio::test]
    async fn audience_created_once_and_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audience");
        let first = load_or_create(path.clone()).await.unwrap();
        assert_eq!(first.as_str().len(), 32);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // Loaded, not regenerated, however often it is asked for.
        for _ in 0..3 {
            assert_eq!(load_or_create(path.clone()).await.unwrap(), first);
        }
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{first}\n")
        );
        // No temporary file is left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn concurrent_first_starts_agree() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audience");
        let mut tasks = Vec::new();
        for _ in 0..8 {
            tasks.push(tokio::spawn(load_or_create(path.clone())));
        }
        let mut seen = std::collections::HashSet::new();
        for task in tasks {
            seen.insert(task.await.unwrap().unwrap());
        }
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn an_existing_unusable_file_is_refused_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audience");
        for bad in [
            "",
            "nope\n",
            "ABCDEF0123456789ABCDEF0123456789\n",
            &"a".repeat(200),
        ] {
            std::fs::write(&path, bad).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(matches!(
                load_or_create_blocking(&path),
                Err(AudienceError::Invalid { .. })
            ));
            assert_eq!(std::fs::read_to_string(&path).unwrap(), bad);
        }
        std::fs::write(&path, "40ad20029e94984d193159667b296d8a\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            load_or_create_blocking(&path),
            Err(AudienceError::Invalid { .. })
        ));
    }

    #[test]
    fn a_symbolic_link_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "40ad20029e94984d193159667b296d8a\n").unwrap();
        let path = dir.path().join("audience");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(matches!(
            load_or_create_blocking(&path),
            Err(AudienceError::Invalid { .. })
        ));
    }
}
