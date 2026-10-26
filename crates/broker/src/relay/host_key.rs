//! The relay's SSH host key: Ed25519, generated on first use and kept in a
//! private file (`WARDEN_RELAY_HOST_KEY_PATH`). Its public half goes into
//! every relay grant so the CLI can pin it.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rustix::fs::{Mode, OFlags};

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use zeroize::Zeroizing;

/// Largest key file read; an OpenSSH Ed25519 key is about 400 bytes.
const MAX_FILE_BYTES: u64 = 16 * 1024;

/// A temporary key file older than this was left by a creator that died
/// before linking it into place; a live creator links within milliseconds.
const STALE_TMP_AGE: Duration = Duration::from_secs(60);

/// The relay host key could not be loaded or created. Messages never carry
/// key material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HostKeyError {
    /// The file could not be read or written.
    #[error("relay host key {}: {source}", path.display())]
    Io {
        /// The key file (or its temporary sibling).
        path: PathBuf,
        /// The I/O failure.
        #[source]
        source: io::Error,
    },
    /// The file exists but is not a usable key.
    #[error("relay host key {}: {reason}", path.display())]
    Invalid {
        /// The key file.
        path: PathBuf,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The key could not be generated or encoded.
    #[error("relay host key: {0}")]
    Key(#[from] ssh_key::Error),
    /// The blocking file work could not run to completion.
    #[error("relay host key: loading task failed")]
    Task,
    /// The key could not be handed to the SSH server.
    #[error("relay host key: cannot be loaded into the SSH server")]
    Server,
}

/// The relay's Ed25519 host key. The private half is wiped from memory when
/// this is dropped (ssh-key zeroizes Ed25519 private keys on drop) and is
/// never printed: `Debug` shows only the public key's fingerprint.
pub struct RelayHostKey {
    key: PrivateKey,
}

impl fmt::Debug for RelayHostKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayHostKey")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl RelayHostKey {
    /// The public key, OpenSSH format (`ssh-ed25519 AAAA…`).
    ///
    /// # Errors
    /// If the key cannot be encoded.
    pub fn public_key_openssh(&self) -> Result<String, HostKeyError> {
        Ok(self.key.public_key().to_openssh()?)
    }

    /// The key as the SSH server library's type, converted through its
    /// OpenSSH text (held in a wiped buffer).
    pub(crate) fn russh_private_key(&self) -> Result<russh::keys::PrivateKey, HostKeyError> {
        let text = self.key.to_openssh(LineEnding::LF)?;
        russh::keys::PrivateKey::from_openssh(text.as_str()).map_err(|_| HostKeyError::Server)
    }

    /// The public key's SHA-256 fingerprint (`SHA256:…`), for logs.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
    }
}

/// Load the host key at `path`, creating it first if there is none. Runs
/// the file work on the blocking pool.
///
/// # Errors
/// See [`load_or_create_blocking`].
pub async fn load_or_create(path: PathBuf) -> Result<RelayHostKey, HostKeyError> {
    tokio::task::spawn_blocking(move || load_or_create_blocking(&path))
        .await
        .map_err(|_| HostKeyError::Task)?
}

/// Load the host key at `path`, creating it first if there is none.
///
/// A new key is written to a fresh `0600` temporary file in the same
/// directory, synced, then hard-linked into place, which fails rather than
/// replaces if another process created the key meanwhile (that key is then
/// loaded instead), so the file is never seen half written and is never
/// overwritten; temporary files a crashed creator left behind are removed
/// first. An existing file must be a regular file (not a symbolic link)
/// owned by this process's user, not readable or writable by group or
/// others, holding an unencrypted OpenSSH Ed25519 private key.
///
/// # Errors
/// [`HostKeyError::Io`] if the file or its directory cannot be read or
/// written; [`HostKeyError::Invalid`] if the file is not a private Ed25519
/// key; [`HostKeyError::Key`] if generation fails.
pub fn load_or_create_blocking(path: &Path) -> Result<RelayHostKey, HostKeyError> {
    match load(path) {
        Err(HostKeyError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            create(path)
        }
        loaded => loaded,
    }
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> HostKeyError + '_ {
    move |source| HostKeyError::Io {
        path: path.to_owned(),
        source,
    }
}

fn invalid(path: &Path, reason: &'static str) -> HostKeyError {
    HostKeyError::Invalid {
        path: path.to_owned(),
        reason,
    }
}

fn load(path: &Path) -> Result<RelayHostKey, HostKeyError> {
    load_owned_by(path, rustix::process::geteuid().as_raw())
}

/// Load the key at `path`, which must belong to user `owner`.
fn load_owned_by(path: &Path, owner: u32) -> Result<RelayHostKey, HostKeyError> {
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
    if meta.uid() != owner {
        return Err(invalid(path, "is owned by another user"));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(invalid(
            path,
            "is accessible by group or others; it must be mode 0600",
        ));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(invalid(path, "is too large to be an Ed25519 key"));
    }
    let mut text = Zeroizing::new(Vec::new());
    file.take(MAX_FILE_BYTES)
        .read_to_end(&mut text)
        .map_err(io_error(path))?;
    let key = PrivateKey::from_openssh(text.as_slice())
        .map_err(|_| invalid(path, "is not an OpenSSH private key"))?;
    if key.is_encrypted() {
        return Err(invalid(
            path,
            "is encrypted; the relay needs it unencrypted",
        ));
    }
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(invalid(path, "is not an Ed25519 key"));
    }
    Ok(RelayHostKey { key })
}

fn create(path: &Path) -> Result<RelayHostKey, HostKeyError> {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
    let text = key.to_openssh(LineEnding::LF)?;
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| invalid(path, "does not name a file"))?;
    remove_stale_tmp(dir, name);
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix)
        .map_err(|_| io_error(path)(io::Error::other("OS random number generator unavailable")))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".{}.tmp", hex::encode(suffix)));
    let tmp = dir.join(tmp_name);

    let written = write_new(&tmp, text.as_bytes()).and_then(|()| match fs::hard_link(&tmp, path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(io_error(path)(e)),
    });
    // The temporary name is never needed again, whatever happened.
    let removed = fs::remove_file(&tmp);
    if !written? {
        // Another process created the key first; use theirs.
        return load(path);
    }
    removed.map_err(io_error(&tmp))?;
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(io_error(dir))?;
    Ok(RelayHostKey { key })
}

/// Remove temporary key files (`.<name>.<hex>.tmp`) in `dir` older than
/// [`STALE_TMP_AGE`]: a creator that died between writing and linking
/// leaves one behind, holding a private key nobody will use. Best effort: a
/// file that cannot be inspected or removed is left alone.
fn remove_stale_tmp(dir: &Path, name: &std::ffi::OsStr) {
    let Some(name) = name.to_str() else {
        return;
    };
    let prefix = format!(".{name}.");
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let is_tmp = file_name
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_suffix(".tmp"))
            .is_some_and(|hex| hex.len() == 16 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
        if !is_tmp {
            continue;
        }
        let stale = entry
            .metadata()
            .ok()
            .filter(fs::Metadata::is_file)
            .and_then(|meta| meta.modified().ok())
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age > STALE_TMP_AGE);
        if stale && let Err(e) = fs::remove_file(entry.path()) {
            tracing::warn!(file = %entry.path().display(), error = %e, "could not remove a stale relay host key temporary file");
        }
    }
}

/// Write `bytes` to a new file at `path`, mode 0600, and sync it.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), HostKeyError> {
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

    use std::time::{Duration, SystemTime};

    use super::{HostKeyError, load_or_create, load_or_create_blocking, load_owned_by};

    fn mode(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[tokio::test]
    async fn creates_a_private_ed25519_key_once_and_reloads_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay_host_ed25519");
        let first = load_or_create(path.clone()).await.unwrap();
        assert_eq!(mode(&path), 0o600);
        let public = first.public_key_openssh().unwrap();
        assert!(public.starts_with("ssh-ed25519 "), "{public}");

        let again = load_or_create(path.clone()).await.unwrap();
        assert_eq!(again.public_key_openssh().unwrap(), public);
        // Only the key file is left behind.
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["relay_host_ed25519"]);
    }

    #[test]
    fn concurrent_first_use_agrees_on_one_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay_host_ed25519");
        let keys: Vec<String> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| s.spawn(|| load_or_create_blocking(&path).unwrap()))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap().public_key_openssh().unwrap())
                .collect()
        });
        assert!(keys.iter().all(|k| *k == keys[0]), "{keys:?}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn refuses_a_key_others_can_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay_host_ed25519");
        load_or_create_blocking(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let err = load_or_create_blocking(&path).unwrap_err();
        assert!(matches!(err, HostKeyError::Invalid { .. }), "{err:?}");
        assert!(err.to_string().contains("0600"), "{err}");
    }

    #[test]
    fn refuses_other_key_types_encrypted_keys_and_garbage_without_echoing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay_host_ed25519");
        let cases = [
            include_str!("../../tests/fixtures/throwaway-test-only-ecdsa.key"),
            include_str!("../../tests/fixtures/throwaway-test-only-ed25519-encrypted.key"),
            "not-a-key-but-a-secret-looking-string",
        ];
        for contents in cases {
            std::fs::write(&path, contents).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let err = load_or_create_blocking(&path).unwrap_err();
            assert!(matches!(err, HostKeyError::Invalid { .. }), "{err:?}");
            let shown = format!("{err} {err:?}");
            assert!(!shown.contains("secret-looking"), "{shown}");
            assert!(!shown.contains("BEGIN"), "{shown}");
            // The bad file is left alone, never replaced.
            assert_eq!(std::fs::read_to_string(&path).unwrap(), contents);
        }
    }

    #[test]
    fn refuses_a_symbolic_link() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("elsewhere");
        load_or_create_blocking(&real).unwrap();
        let path = dir.path().join("relay_host_ed25519");
        std::os::unix::fs::symlink(&real, &path).unwrap();
        let err = load_or_create_blocking(&path).unwrap_err();
        assert!(matches!(err, HostKeyError::Invalid { .. }), "{err:?}");
        assert!(err.to_string().contains("symbolic link"), "{err}");
        // A dangling link is refused too, not followed to create a key.
        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("absent"), &dangling).unwrap();
        let err = load_or_create_blocking(&dangling).unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert!(!dir.path().join("absent").exists());
    }

    #[test]
    fn refuses_a_key_owned_by_another_user() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay_host_ed25519");
        load_or_create_blocking(&path).unwrap();
        let me = rustix::process::geteuid().as_raw();
        load_owned_by(&path, me).unwrap();
        let err = load_owned_by(&path, me.wrapping_add(1)).unwrap_err();
        assert!(matches!(err, HostKeyError::Invalid { .. }), "{err:?}");
        assert!(err.to_string().contains("another user"), "{err}");
    }

    #[test]
    fn creating_removes_stale_temporary_files_only() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join(".relay_host_ed25519.00112233aabbccdd.tmp");
        let fresh = dir.path().join(".relay_host_ed25519.0123456789abcdef.tmp");
        let other = dir.path().join(".other.00112233aabbccdd.tmp");
        for file in [&stale, &fresh, &other] {
            std::fs::write(file, "leftover").unwrap();
        }
        let old = SystemTime::now() - Duration::from_secs(3600);
        for file in [&stale, &other] {
            std::fs::File::options()
                .write(true)
                .open(file)
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        load_or_create_blocking(&dir.path().join("relay_host_ed25519")).unwrap();
        assert!(!stale.exists());
        // A recent one may belong to a creator still running.
        assert!(fresh.exists());
        assert!(other.exists());
    }

    #[test]
    fn missing_directory_is_an_io_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent").join("relay_host_ed25519");
        let err = load_or_create_blocking(&path).unwrap_err();
        assert!(matches!(err, HostKeyError::Io { .. }), "{err:?}");
    }

    #[test]
    fn debug_shows_only_the_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay_host_ed25519");
        let key = load_or_create_blocking(&path).unwrap();
        let shown = format!("{key:?}");
        assert!(shown.contains(&key.fingerprint()), "{shown}");
        assert!(key.fingerprint().starts_with("SHA256:"));
        let private = std::fs::read_to_string(&path).unwrap();
        let body: String = private.lines().nth(1).unwrap().to_owned();
        assert!(!shown.contains(&body), "{shown}");
        assert!(!shown.contains("PRIVATE"), "{shown}");
    }
}
