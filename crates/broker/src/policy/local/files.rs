//! Reading the local backend's files without trusting the path.
//!
//! Every read walks the path from `/`, one `openat` per component with
//! `O_NOFOLLOW`, and decides on `fstat` of what it opened, never on a second
//! lookup of the name. So a symbolic link anywhere on the path is refused, and
//! nothing can be swapped between the check and the read. A FIFO cannot block
//! the open (`O_NONBLOCK`) and is then refused as not a regular file. A file
//! that is a mount of its own is refused as well: it stays on the old file when
//! the one it came from is replaced, whatever names that file keeps.
//!
//! Nothing here returns a path or a file's content in an error.

use std::fmt;
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path};

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use zeroize::Zeroizing;

/// Largest secret file read. Far above any key, password or token; it keeps a
/// wrong file from being read into memory whole.
const MAX_SECRET_BYTES: usize = 32 * 1024;

/// Largest policy file read.
pub(super) const MAX_POLICY_BYTES: usize = 1024 * 1024;

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
pub(super) fn open_directory(path: &Path, euid: u32) -> Result<File, Refusal> {
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
pub(super) fn open_regular(
    directory: &File,
    name: &Path,
) -> Result<(File, std::fs::Metadata), Refusal> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let file = File::from(rustix::fs::openat(directory, name, flags, Mode::empty())?);
    let meta = file.metadata().map_err(|e| Refusal::Io(e.kind()))?;
    if !meta.is_file() {
        return Err(Refusal::Rule("is not a regular file"));
    }
    // Only Linux has bind mounts of a single file among the systems warden runs on.
    #[cfg(target_os = "linux")]
    check_not_a_mount(&file)?;
    Ok((file, meta))
}

#[cfg(target_os = "linux")]
const MOUNTED_ALONE: &str = "is a mount of this one file, which keeps showing the old file after \
                             it is replaced; mount the directory holding it";

#[cfg(target_os = "linux")]
const CANNOT_TELL: &str = "cannot be checked for a mount of the single file: this needs Linux 5.8 \
                           or later, with the statx system call allowed";

/// A bind mount of one file stays on that file's inode. After a rename over the
/// source, the mount shows the old content: with no name left when the old file
/// was replaced, which `nlink` shows, but with one name when it was first moved
/// aside as a backup, which nothing about the file shows. So the mount itself is
/// refused, before any edit, rather than its aftermath. The kernel has reported
/// this since Linux 5.8; on one that does not, warden cannot tell, and refuses.
#[cfg(target_os = "linux")]
fn check_not_a_mount(file: &File) -> Result<(), Refusal> {
    use rustix::fs::{AtFlags, StatxFlags, statx};

    statx_rule(&statx(
        file,
        c"",
        AtFlags::EMPTY_PATH,
        StatxFlags::BASIC_STATS,
    ))
}

/// The decision on what the `statx` call returned.
#[cfg(target_os = "linux")]
fn statx_rule(result: &rustix::io::Result<rustix::fs::Statx>) -> Result<(), Refusal> {
    match result {
        Ok(stat) => mount_rule(stat.stx_attributes_mask, stat.stx_attributes),
        Err(errno) => Err(statx_failed(*errno)),
    }
}

/// A kernel without `statx`, or a sandbox that forbids it, cannot answer: name what
/// is needed, because it stops this backend altogether.
#[cfg(target_os = "linux")]
fn statx_failed(errno: Errno) -> Refusal {
    match errno {
        Errno::NOSYS | Errno::PERM | Errno::ACCESS => Refusal::Rule(CANNOT_TELL),
        other => Refusal::from(other),
    }
}

/// The decision on what `statx` reports.
#[cfg(target_os = "linux")]
fn mount_rule(
    known: rustix::fs::StatxAttributes,
    attributes: rustix::fs::StatxAttributes,
) -> Result<(), Refusal> {
    use rustix::fs::StatxAttributes;

    if !known.contains(StatxAttributes::MOUNT_ROOT) {
        return Err(Refusal::Rule(CANNOT_TELL));
    }
    if attributes.contains(StatxAttributes::MOUNT_ROOT) {
        return Err(Refusal::Rule(MOUNTED_ALONE));
    }
    Ok(())
}

/// All of `file`, as text, in memory wiped on drop. Allocated once at its
/// largest, so that growing it leaves no copy for `Zeroizing` to miss.
pub(super) fn read_limited(file: impl Read, limit: usize) -> Result<Zeroizing<String>, Refusal> {
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
pub(super) fn check_policy_file(meta: &Metadata, euid: u32) -> Result<(), Refusal> {
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

    /// What the kernel reports decides, and not knowing refuses.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_mount_of_one_file_is_refused_and_so_is_not_being_able_to_tell() {
        use rustix::fs::StatxAttributes;

        use super::{MOUNTED_ALONE, mount_rule};

        let (none, root) = (StatxAttributes::empty(), StatxAttributes::MOUNT_ROOT);
        assert_eq!(mount_rule(root, none), Ok(()));
        assert_eq!(mount_rule(root, root), Err(Refusal::Rule(MOUNTED_ALONE)));
        assert!(
            matches!(mount_rule(none, none), Err(Refusal::Rule(reason)) if reason.contains("5.8"))
        );
    }

    /// A kernel or sandbox refusing the call is told apart from a failed read.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_kernel_without_statx_is_named_as_the_reason() {
        use rustix::io::Errno;

        for errno in [Errno::NOSYS, Errno::PERM, Errno::ACCESS] {
            assert_eq!(
                super::statx_rule(&Err(errno)),
                Err(Refusal::Rule(super::CANNOT_TELL))
            );
        }
        assert!(matches!(
            super::statx_rule(&Err(Errno::IO)),
            Err(Refusal::Io(_))
        ));
    }

    /// The real kernel's answer, on something always a mount (`/`) and on a
    /// plain file.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_kernel_tells_a_mount_from_a_plain_file() {
        let (_guard, dir) = private_dir();
        let path = write(&dir, "plain", b"", 0o600);
        assert_eq!(
            super::check_not_a_mount(&fs::File::open(path).unwrap()),
            Ok(())
        );
        assert_eq!(
            super::check_not_a_mount(&fs::File::open("/").unwrap()),
            Err(Refusal::Rule(super::MOUNTED_ALONE))
        );
    }

    /// A real bind mount of one file, which CI prepares because mounting needs
    /// root: refused before and after the file behind it is moved aside and
    /// replaced, the case that leaves the old file with one name.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_bind_mount_of_the_policy_file_is_refused() {
        let mounted = std::env::var_os("WARDEN_TEST_BIND_MOUNTED_FILE")
            .expect("WARDEN_TEST_BIND_MOUNTED_FILE names a file bind-mounted on its own");
        let source = std::env::var_os("WARDEN_TEST_BIND_MOUNT_SOURCE")
            .expect("WARDEN_TEST_BIND_MOUNT_SOURCE names the file behind that mount");
        let mounted = Path::new(&mounted);
        assert_eq!(rule(read_policy(mounted, euid())), super::MOUNTED_ALONE);
        let (directory, name) = (mounted.parent().unwrap(), mounted.file_name().unwrap());
        assert_eq!(
            rule(read_secret(directory, name.to_str().unwrap(), euid())),
            super::MOUNTED_ALONE
        );
        let source = Path::new(&source);
        let backup = source.with_extension("bak");
        fs::rename(source, &backup).unwrap();
        fs::write(source, b"new").unwrap();
        let after = rule(read_policy(mounted, euid()));
        fs::remove_file(source).unwrap();
        fs::rename(&backup, source).unwrap();
        assert_eq!(after, super::MOUNTED_ALONE);
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

    /// The configuration refuses these paths first; here they must not resolve to
    /// anything either.
    #[test]
    fn a_path_that_names_no_file_or_climbs_is_refused() {
        assert_eq!(
            rule(read_policy(Path::new("/"), euid())),
            "must name a file"
        );
        assert_eq!(
            rule(read_policy(Path::new("../policy.toml"), euid())),
            "the path must be absolute, without .."
        );
        let (_guard, dir) = private_dir();
        write(&dir, "token", SECRET, 0o600);
        fs::create_dir(dir.join("sub")).unwrap();
        chmod(&dir.join("sub"), 0o700);
        assert_eq!(
            rule(read_secret(&dir.join("sub/.."), "token", euid())),
            "the path must be absolute, without .."
        );
    }

    /// Asking on behalf of another uid, as in `refuses_files_of_another_user`.
    #[test]
    fn a_policy_file_of_another_user_is_refused() {
        let (_guard, dir) = private_dir();
        let path = write(&dir, "policy.toml", b"", 0o600);
        let meta = fs::metadata(&path).unwrap();
        let refusal = check_policy_file(&meta, euid() + 1).unwrap_err();
        assert!(matches!(refusal, Refusal::Rule("belongs to another user")));
    }
}
