//! Reading the local backend's files without trusting the path.
//!
//! Every read walks the path from `/`, one `openat` per component with
//! `O_NOFOLLOW`, and decides on `fstat` of what it opened, never on a second
//! lookup of the name. So a symbolic link anywhere on the path is refused, and
//! nothing can be swapped between the check and the read. A FIFO cannot block
//! the open (`O_NONBLOCK`) and is then refused as not a regular file.
//!
//! Nothing here returns a path or a file's content in an error.

use std::fmt;
use std::fs::{File, Metadata};
use std::io::{self, Read as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use zeroize::Zeroizing;

/// Largest secret file read. Far above any key, password or token; it keeps a
/// wrong file from being read into memory whole.
const MAX_SECRET_BYTES: usize = 32 * 1024;

/// Largest policy file read.
const MAX_POLICY_BYTES: usize = 1024 * 1024;

/// The permission bits for group and others.
const GROUP_OTHER: u32 = 0o077;

/// The write bits for group and others.
const GROUP_OTHER_WRITE: u32 = 0o022;

/// Whoever can write into a sticky directory can still not replace what
/// another user owns there.
const STICKY: u32 = 0o1000;

const SYMLINK: &str =
    "a part of the path is a symbolic link or not a directory; give the real path";

/// Why a file was not read. Fixed text and an error kind: never a path, and
/// never anything from the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    /// It breaks a rule, or its content is unusable.
    Rule(&'static str),
    /// It does not exist.
    Missing,
    /// The system refused or failed to read it, which may pass.
    Io(io::ErrorKind),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rule(reason) => f.write_str(reason),
            Self::Missing => f.write_str("does not exist"),
            Self::Io(kind) => write!(f, "cannot be read: {kind}"),
        }
    }
}

impl From<Errno> for Refusal {
    fn from(errno: Errno) -> Self {
        match errno {
            Errno::NOENT => Self::Missing,
            Errno::LOOP | Errno::NOTDIR => Self::Rule(SYMLINK),
            other => Self::Io(io::Error::from(other).kind()),
        }
    }
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

/// Who may own a directory on the way, or the policy file: this process's user
/// or root. Anyone else could change what warden reads.
fn trusted_owner(uid: u32, euid: u32) -> bool {
    uid == euid || uid == 0
}

/// A directory on the way to a file: a trusted owner, and nobody else can
/// replace what is inside it.
fn check_ancestor(directory: &File, euid: u32) -> Result<(), Refusal> {
    let meta = directory.metadata().map_err(|e| Refusal::Io(e.kind()))?;
    if !trusted_owner(meta.uid(), euid) {
        return Err(Refusal::Rule(
            "a directory on the path belongs to another user",
        ));
    }
    if meta.mode() & GROUP_OTHER_WRITE != 0 && meta.mode() & STICKY == 0 {
        return Err(Refusal::Rule(
            "a directory on the path can be written by group or others",
        ));
    }
    Ok(())
}

/// Open `path`, an absolute path, checking each directory on the way.
fn open_directory(path: &Path, euid: u32) -> Result<File, Refusal> {
    let mut current = File::from(rustix::fs::open("/", directory_flags(), Mode::empty())?);
    check_ancestor(&current, euid)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                current = File::from(rustix::fs::openat(
                    &current,
                    name,
                    directory_flags(),
                    Mode::empty(),
                )?);
                check_ancestor(&current, euid)?;
            }
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                return Err(Refusal::Rule("the path must be absolute, without .."));
            }
        }
    }
    Ok(current)
}

/// Open the file `name` in `directory` without following a link or blocking.
fn open_regular(directory: &File, name: &Path) -> Result<(File, std::fs::Metadata), Refusal> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let file = File::from(rustix::fs::openat(directory, name, flags, Mode::empty())?);
    let meta = file.metadata().map_err(|e| Refusal::Io(e.kind()))?;
    if !meta.is_file() {
        return Err(Refusal::Rule("is not a regular file"));
    }
    Ok((file, meta))
}

/// All of `file`, as text, in memory wiped on drop. Allocated once at its
/// largest, so that growing it leaves no copy for `Zeroizing` to miss.
fn read_limited(file: File, limit: usize) -> Result<Zeroizing<String>, Refusal> {
    let mut text = Zeroizing::new(String::with_capacity(limit + 1));
    let most = u64::try_from(limit).map_or(u64::MAX, |n| n.saturating_add(1));
    file.take(most)
        .read_to_string(&mut text)
        .map_err(|e| match e.kind() {
            io::ErrorKind::InvalidData => Refusal::Rule("is not valid UTF-8"),
            kind => Refusal::Io(kind),
        })?;
    if text.len() > limit {
        return Err(Refusal::Rule("is too large"));
    }
    Ok(text)
}

/// The policy file's text. Nothing in it is secret, but warden obeys it, so
/// only its owner may be able to change it: this user or root, and not
/// writable by group or others.
pub(super) fn read_policy(path: &Path, euid: u32) -> Result<Zeroizing<String>, Refusal> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(Refusal::Rule("must name a file"));
    };
    let directory = open_directory(parent, euid)?;
    let (file, meta) = open_regular(&directory, Path::new(name))?;
    check_policy_file(&meta, euid)?;
    read_limited(file, MAX_POLICY_BYTES)
}

/// The rules for what was opened as the policy file. It must have exactly one
/// name. None means it was replaced or removed after this path was bound to it:
/// a bind mount of the single file keeps showing the old content after a rename
/// over the source, and obeying that would ignore a revocation. A second name
/// is refused too, because it would hide that from this check.
fn check_policy_file(meta: &Metadata, euid: u32) -> Result<(), Refusal> {
    if meta.nlink() == 0 {
        return Err(Refusal::Rule(
            "was replaced or removed, and this path still shows the old file; mount the directory \
             holding it, not the single file",
        ));
    }
    if meta.nlink() != 1 {
        return Err(Refusal::Rule("has more than one name (a hard link)"));
    }
    if !trusted_owner(meta.uid(), euid) {
        return Err(Refusal::Rule("belongs to another user"));
    }
    if meta.mode() & GROUP_OTHER_WRITE != 0 {
        return Err(Refusal::Rule("can be written by group or others"));
    }
    Ok(())
}

/// The secret file `name` in `directory`. The directory and the file must
/// belong to this user and give group and others nothing; the file must have
/// one name, so that no other path, under other permissions, reaches it. A
/// blank file is refused: it is never a credential.
pub(super) fn read_secret(
    directory: &Path,
    name: &str,
    euid: u32,
) -> Result<Zeroizing<String>, Refusal> {
    let directory = open_directory(directory, euid)?;
    let meta = directory.metadata().map_err(|e| Refusal::Io(e.kind()))?;
    if meta.uid() != euid {
        return Err(Refusal::Rule(
            "the secrets directory belongs to another user",
        ));
    }
    if meta.mode() & GROUP_OTHER != 0 {
        return Err(Refusal::Rule(
            "the secrets directory must not be accessible to group or others",
        ));
    }
    let (file, meta) = open_regular(&directory, Path::new(name))?;
    if meta.uid() != euid {
        return Err(Refusal::Rule("belongs to another user"));
    }
    if meta.mode() & GROUP_OTHER != 0 {
        return Err(Refusal::Rule("must not be accessible to group or others"));
    }
    if meta.nlink() != 1 {
        return Err(Refusal::Rule("has more than one name (a hard link)"));
    }
    let text = read_limited(file, MAX_SECRET_BYTES)?;
    if text.trim().is_empty() {
        return Err(Refusal::Rule("is empty"));
    }
    Ok(text)
}

/// A single-line secret, without its line ending. Anything else in it, spaces
/// included, is kept.
pub(super) fn one_line(mut text: Zeroizing<String>) -> Result<Zeroizing<String>, Refusal> {
    let length = text
        .strip_suffix('\n')
        .map_or(text.as_str(), |rest| {
            rest.strip_suffix('\r').unwrap_or(rest)
        })
        .len();
    text.truncate(length);
    if text.contains(['\r', '\n']) {
        return Err(Refusal::Rule("must hold a single line"));
    }
    Ok(text)
}

/// A secret's file name from the policy: one plain name inside the secrets
/// directory, so that an edit of the policy can never point a credential at
/// another file on the host.
pub(super) fn check_file_name(name: &str) -> Result<(), &'static str> {
    let plain = name.len() <= 64
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if plain {
        Ok(())
    } else {
        Err(
            "must be a file name in WARDEN_LOCAL_SECRETS_DIR: up to 64 letters, digits, ., _ or -, \
             starting with a letter or digit",
        )
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;
    use zeroize::Zeroizing;

    use super::{
        MAX_POLICY_BYTES, MAX_SECRET_BYTES, Refusal, check_file_name, check_policy_file, one_line,
        read_policy, read_secret,
    };

    const SECRET: &[u8] = b"not-a-real-secret-value\n";

    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn chmod(path: &Path, mode: u32) {
        fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    }

    /// A private directory at its real path: the system's temporary directory
    /// may itself be reached through a link.
    fn private_dir() -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap();
        chmod(&path, 0o700);
        (dir, path)
    }

    fn write(dir: &Path, name: &str, content: &[u8], mode: u32) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        chmod(&path, mode);
        path
    }

    fn rule(result: Result<Zeroizing<String>, Refusal>) -> &'static str {
        match result {
            Err(Refusal::Rule(reason)) => reason,
            other => panic!("expected a rule refusal, got {:?}", other.map(|_| "text")),
        }
    }

    #[test]
    fn reads_a_private_secret() {
        for mode in [0o400, 0o600] {
            let (_guard, dir) = private_dir();
            write(&dir, "token", SECRET, mode);
            let text = read_secret(&dir, "token", euid()).unwrap();
            assert_eq!(text.as_bytes(), SECRET);
        }
    }

    #[test]
    fn refuses_a_secret_group_or_others_can_access() {
        for mode in [0o640, 0o440, 0o604, 0o404, 0o620, 0o602, 0o610, 0o601] {
            let (_guard, dir) = private_dir();
            write(&dir, "token", SECRET, mode);
            assert_eq!(
                rule(read_secret(&dir, "token", euid())),
                "must not be accessible to group or others",
                "{mode:o}"
            );
        }
    }

    #[test]
    fn refuses_a_secrets_directory_group_or_others_can_access() {
        for mode in [0o750, 0o705, 0o710] {
            let (_guard, dir) = private_dir();
            write(&dir, "token", SECRET, 0o600);
            chmod(&dir, mode);
            let refusal = rule(read_secret(&dir, "token", euid()));
            assert_eq!(
                refusal, "the secrets directory must not be accessible to group or others",
                "{mode:o}"
            );
        }
    }

    /// Without being root, a file of another user cannot be made: asking on
    /// behalf of another uid is the same comparison.
    #[test]
    fn refuses_files_of_another_user() {
        let (_guard, dir) = private_dir();
        write(&dir, "token", SECRET, 0o600);
        let other = euid() + 1;
        let refusal = rule(read_secret(&dir, "token", other));
        assert!(refusal.contains("another user"), "{refusal}");
    }

    #[test]
    fn refuses_a_symbolic_link_to_a_secret() {
        let (_guard, dir) = private_dir();
        write(&dir, "real", SECRET, 0o600);
        symlink(dir.join("real"), dir.join("link")).unwrap();
        assert_eq!(rule(read_secret(&dir, "link", euid())), super::SYMLINK);
    }

    #[test]
    fn refuses_a_symbolic_link_anywhere_on_the_path() {
        let (_guard, base) = private_dir();
        let real = base.join("real");
        fs::create_dir(&real).unwrap();
        chmod(&real, 0o700);
        write(&real, "token", SECRET, 0o600);
        write(&real, "policy.toml", b"", 0o600);
        let link = base.join("link");
        symlink(&real, &link).unwrap();
        assert_eq!(rule(read_secret(&link, "token", euid())), super::SYMLINK);
        assert_eq!(
            rule(read_policy(&link.join("policy.toml"), euid())),
            super::SYMLINK
        );
    }

    #[test]
    fn refuses_a_hard_link() {
        let (_guard, dir) = private_dir();
        let path = write(&dir, "token", SECRET, 0o600);
        fs::hard_link(&path, dir.join("other")).unwrap();
        assert_eq!(
            rule(read_secret(&dir, "token", euid())),
            "has more than one name (a hard link)"
        );
    }

    #[test]
    fn refuses_a_directory_or_a_fifo_without_blocking() {
        let (_guard, dir) = private_dir();
        fs::create_dir(dir.join("subdir")).unwrap();
        chmod(&dir.join("subdir"), 0o700);
        assert_eq!(
            rule(read_secret(&dir, "subdir", euid())),
            "is not a regular file"
        );
        // A hung open is what this guards against, and it would hang the test.
        let made = std::process::Command::new("mkfifo")
            .arg(dir.join("fifo"))
            .status()
            .unwrap();
        assert!(made.success());
        chmod(&dir.join("fifo"), 0o600);
        assert_eq!(
            rule(read_secret(&dir, "fifo", euid())),
            "is not a regular file"
        );
    }

    #[test]
    fn a_missing_file_is_told_apart() {
        let (_guard, dir) = private_dir();
        assert_eq!(
            read_secret(&dir, "absent", euid()).map(|_| ()),
            Err(Refusal::Missing)
        );
        assert_eq!(
            read_policy(&dir.join("absent"), euid()).map(|_| ()),
            Err(Refusal::Missing)
        );
    }

    #[test]
    fn refuses_unusable_secret_content_without_echoing_it() {
        let oversize = vec![b'x'; MAX_SECRET_BYTES + 1];
        let invalid = [b"not-a-real-secret".as_slice(), &[0xff, 0xfe]].concat();
        let cases: [&[u8]; 4] = [b"", b" \n\n", &oversize, &invalid];
        for content in cases {
            let (_guard, dir) = private_dir();
            write(&dir, "token", content, 0o600);
            let refusal = read_secret(&dir, "token", euid()).unwrap_err();
            assert!(!refusal.to_string().contains("not-a-real"), "{refusal}");
        }
    }

    #[test]
    fn accepts_a_secret_at_the_size_limit() {
        let (_guard, dir) = private_dir();
        write(&dir, "token", &vec![b'x'; MAX_SECRET_BYTES], 0o600);
        assert!(read_secret(&dir, "token", euid()).is_ok());
    }

    #[test]
    fn a_policy_may_be_read_by_others_but_not_written() {
        for mode in [0o600, 0o640, 0o644, 0o444] {
            let (_guard, dir) = private_dir();
            let path = write(&dir, "policy.toml", b"", mode);
            assert!(read_policy(&path, euid()).is_ok(), "{mode:o}");
        }
        for mode in [0o660, 0o606, 0o666] {
            let (_guard, dir) = private_dir();
            let path = write(&dir, "policy.toml", b"", mode);
            assert_eq!(
                rule(read_policy(&path, euid())),
                "can be written by group or others",
                "{mode:o}"
            );
        }
    }

    #[test]
    fn a_policy_in_a_directory_others_can_write_is_refused_unless_sticky() {
        let (_guard, dir) = private_dir();
        let path = write(&dir, "policy.toml", b"", 0o600);
        chmod(&dir, 0o777);
        assert_eq!(
            rule(read_policy(&path, euid())),
            "a directory on the path can be written by group or others"
        );
        chmod(&dir, 0o1777);
        assert!(read_policy(&path, euid()).is_ok());
    }

    /// What a bind mount of the single file shows after a rename over its
    /// source: an open file with no name left. Mounting needs root, so this
    /// takes the same state from an open file whose name was removed.
    #[test]
    fn a_policy_with_no_name_left_is_refused() {
        let (_guard, dir) = private_dir();
        let path = write(&dir, "policy.toml", b"", 0o600);
        let open = fs::File::open(&path).unwrap();
        assert!(check_policy_file(&open.metadata().unwrap(), euid()).is_ok());
        fs::remove_file(&path).unwrap();
        let meta = open.metadata().unwrap();
        let refusal = check_policy_file(&meta, euid()).unwrap_err();
        assert!(refusal.to_string().contains("was replaced"), "{refusal}");
    }

    #[test]
    fn a_policy_with_a_second_name_is_refused() {
        let (_guard, dir) = private_dir();
        let path = write(&dir, "policy.toml", b"", 0o600);
        fs::hard_link(&path, dir.join("second-name")).unwrap();
        assert_eq!(
            rule(read_policy(&path, euid())),
            "has more than one name (a hard link)"
        );
    }

    #[test]
    fn refuses_an_oversized_policy() {
        let (_guard, dir) = private_dir();
        let path = write(
            &dir,
            "policy.toml",
            &vec![b'#'; MAX_POLICY_BYTES + 1],
            0o600,
        );
        assert_eq!(rule(read_policy(&path, euid())), "is too large");
    }

    #[test]
    fn one_line_takes_one_line_ending_and_keeps_spaces() {
        let line = |s: &str| one_line(Zeroizing::new(s.to_owned()));
        assert_eq!(line("abc").unwrap().as_str(), "abc");
        assert_eq!(line("abc\n").unwrap().as_str(), "abc");
        assert_eq!(line("abc\r\n").unwrap().as_str(), "abc");
        assert_eq!(line(" a c \n").unwrap().as_str(), " a c ");
        for bad in ["abc\n\n", "a\nb", "a\rb\n"] {
            assert!(line(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn file_names_stay_inside_the_secrets_directory() {
        for good in ["ssh-ca", "home-api.token", "a_1", "0"] {
            assert!(check_file_name(good).is_ok(), "{good}");
        }
        let long = "a".repeat(65);
        for bad in [
            "",
            ".",
            "..",
            ".hidden",
            "../x",
            "a/b",
            "/etc/shadow",
            "a b",
            "a\n",
            long.as_str(),
        ] {
            assert!(check_file_name(bad).is_err(), "{bad}");
        }
    }
}
