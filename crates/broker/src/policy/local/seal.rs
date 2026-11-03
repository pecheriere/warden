//! `warden-server seal-policy`: give a finished policy file its digest, and put
//! it in place in one step.
//!
//! The one thing here that writes to the local backend's files, and warden itself
//! never calls it. It runs as whoever edits the policy, on the host or wherever
//! the directory is writable, so it needs none of warden's settings.
//!
//! Sealing says "this content is finished". It cannot tell a finished file from a
//! file another writer is still overwriting, so what it takes is the operator's
//! word, and the draft's own `[end_of_policy]` line: a draft cut short has lost that
//! line and is refused rather than sealed as a wider policy. A policy file whose
//! digest no longer matches may be a mix of two versions, so it is not sealed where
//! it stands until a person has seen what it allows and said so: see [`Unverified`].

use std::ffi::{OsStr, OsString};
use std::fmt::Display;
use std::fs::{File, Metadata, Permissions};
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, fchown};
use std::path::Path;

use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
use thiserror::Error;
use zeroize::Zeroizing;

use super::files::{
    MAX_POLICY_BYTES, Refusal, check_file_name, check_policy_file, open_directory, open_regular,
    read_limited,
};
use super::{DIGEST_LINE_START, END_MARKER, PolicyFile, digest_line, parse_policy, verify_seal};

/// A new policy file's mode: warden needs to read it, and nothing in it is secret.
const NEW_FILE_MODE: u32 = 0o644;

/// How often a temporary name is drawn before giving up. Random names do not
/// collide: more than one failure means something else is going on.
const TEMPORARY_NAME_ATTEMPTS: usize = 8;

/// What to do with a policy file sealed where it stands whose digest does not match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unverified {
    /// Refuse, and show what the file would allow.
    Refuse,
    /// A person has read that: seal it.
    Accept,
}

/// Why nothing was sealed. Never quotes a file.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct SealError(String);

/// What a sealed file holds, to show the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedPolicy {
    /// Entries under `[targets]`.
    pub targets: usize,
    /// Entries under `[api_secrets]`.
    pub api_entries: usize,
    /// One line for each entry: what it allows, as [`ACCESS_NOTE`] describes.
    pub access: Vec<String>,
}

/// `draft` as a sealed policy file: its text through its `[end_of_policy]` line, then the
/// digest. A digest line already there is replaced, so a sealed file can be edited
/// and sealed again. The marker must be there already, as the author's word that
/// the draft is whole. This does not parse the policy.
///
/// # Errors
/// [`SealError`] when `draft` does not end with the marker.
pub fn seal_text(draft: &str) -> Result<Zeroizing<String>, SealError> {
    let body = draft.trim_end();
    let body = match body.rsplit_once('\n') {
        Some((before, last)) if last.starts_with(DIGEST_LINE_START) => before.trim_end(),
        _ => body,
    };
    let ends_with_marker = body
        .strip_suffix(END_MARKER)
        .is_some_and(|before| before.is_empty() || before.ends_with('\n'));
    if !ends_with_marker {
        return Err(SealError(format!(
            "the last line must be {END_MARKER}, to show the draft is whole: add it if the draft \
             is finished"
        )));
    }
    let mut sealed = Zeroizing::new(String::with_capacity(body.len() + 128));
    sealed.push_str(body);
    sealed.push('\n');
    let digest = digest_line(&sealed);
    sealed.push_str(&digest);
    sealed.push('\n');
    Ok(sealed)
}

/// What a person is told about the list of what each entry allows.
pub const ACCESS_NOTE: &str = "Settings are shown whole and as written, so a value pasted into \
                               one shows too; a website only as its origin, a format and a CA \
                               only as present, a secret file only by its name if that is a \
                               valid one. No secret file is read.";

/// A setting whole, with anything a terminal could act on escaped. Never cut: the
/// difference a person is looking for can be anywhere in it.
fn whole(value: &str) -> String {
    value.escape_default().to_string()
}

/// A setting that names a secret file. A value that is no valid name is not a name,
/// and may be the secret itself, so it is not shown. One that is valid cannot be told
/// from a secret by looking at it, and which file goes where is what a person must
/// check; so that is shown.
fn secret_file(value: Option<&str>) -> String {
    match value {
        None => "(not set)".to_owned(),
        Some(name) if check_file_name(name).is_ok() => name.to_owned(),
        Some(_) => "(not a valid file name, not shown)".to_owned(),
    }
}

/// What each entry allows, for a person to read: see [`ACCESS_NOTE`].
fn access_lines(policy: &PolicyFile) -> Vec<String> {
    let shown = |value: Option<&str>| value.map_or_else(|| "(not set)".to_owned(), whole);
    let or_default = |value: Option<&str>| value.map_or_else(|| "(default)".to_owned(), whole);
    let list = |value: Option<&Vec<String>>| {
        value.map_or_else(|| "(default)".to_owned(), |items| whole(&items.join(", ")))
    };
    let mut lines = Vec::new();
    if let Some(ca) = &policy.ca {
        lines.push(format!(
            "SSH CA: secret file {}",
            secret_file(Some(&ca.private_key_file))
        ));
    }
    if let Some(key) = &policy.commit_signing {
        lines.push(format!(
            "commit signing: secret file {}",
            secret_file(Some(&key.private_key_file))
        ));
    }
    for (name, entry) in &policy.targets {
        lines.push(format!(
            "target {}: address {}, mode {}, users {}, window {}, {} host key(s), key file {}, \
             password file {}",
            whole(name),
            shown(entry.address.as_deref()),
            shown(entry.mode.as_deref()),
            list(entry.users.as_ref()),
            shown(entry.max_window.as_deref()),
            entry.host_keys.as_ref().map_or(0, Vec::len),
            secret_file(entry.private_key_file.as_deref()),
            secret_file(entry.password_file.as_deref()),
        ));
    }
    for (name, entry) in &policy.api_secrets {
        let origin = entry.website.as_deref().map_or_else(
            || "(not set)".to_owned(),
            |website| {
                url::Url::parse(website).map_or_else(
                    |_| "(not a URL)".to_owned(),
                    |url| whole(&url.origin().ascii_serialization()),
                )
            },
        );
        lines.push(format!(
            "API {}: origin {origin}, methods {}, path prefix {}, window {}, header {}, format {}, \
             own CA {}, secret file {}",
            whole(name),
            list(entry.methods.as_ref()),
            or_default(entry.path_prefix.as_deref()),
            shown(entry.max_window.as_deref()),
            or_default(entry.header.as_deref()),
            if entry.format.is_some() {
                "own"
            } else {
                "(default)"
            },
            if entry.ca_pem.is_some() { "yes" } else { "no" },
            secret_file(entry.credential_file.as_deref()),
        ));
    }
    lines
}

/// Whose file a replacement must be, and with what mode.
pub(super) struct Ownership {
    uid: u32,
    gid: u32,
    mode: u32,
}

/// `what` was refused for `refusal`. A refusal over who owns a file says what to do.
fn refused(what: &str, refusal: Refusal) -> SealError {
    let hint = match refusal {
        Refusal::Rule(reason) if reason.contains("another user") => {
            ". warden trusts only root and its own user, and this command holds a file to the \
             rules warden does: run it as the user that owns the file, such as with the image: \
             docker run --rm --user \"$(stat -c %u <file>)\" ..."
        }
        _ => "",
    };
    SealError(format!("{what} {refusal}{hint}"))
}

/// Seal `policy`, from `draft` if given and from its own content otherwise, and
/// replace it by a rename, so that a reader sees the old file or the new one.
/// A draft that does not parse as a policy leaves the file untouched. Every path
/// follows the rules warden reads the policy by, because a draft turns into access;
/// so what this accepts warden can read. It keeps the owner and mode of the file it
/// replaces.
///
/// A file sealed where it stands whose digest does not match may be a mix of two
/// versions, which nothing here can tell from an edit: see [`Unverified`]. A file
/// with no digest yet has nothing to contradict, and a draft is what its author
/// wrote; neither needs that step.
///
/// # Errors
/// [`SealError`] when anything is refused or fails. The policy file is then as it
/// was and no temporary file is left, except that a failure to make the rename
/// durable comes after the file was replaced, and says so.
pub fn seal_policy_file(
    policy: &Path,
    draft: Option<&Path>,
    unverified: Unverified,
) -> Result<SealedPolicy, SealError> {
    seal_as(
        policy,
        draft,
        unverified,
        rustix::process::geteuid().as_raw(),
    )
}

/// [`seal_policy_file`] on behalf of `euid`.
pub(super) fn seal_as(
    policy: &Path,
    draft: Option<&Path>,
    unverified: Unverified,
    euid: u32,
) -> Result<SealedPolicy, SealError> {
    let policy = std::path::absolute(policy).map_err(|e| {
        SealError(format!(
            "the policy file's path cannot be used: {}",
            e.kind()
        ))
    })?;
    let (Some(parent), Some(name)) = (policy.parent(), policy.file_name()) else {
        return Err(SealError("the policy file must name a file".to_owned()));
    };
    let directory =
        open_directory(parent, euid).map_err(|e| refused("the policy file's directory:", e))?;
    let current = match open_regular(&directory, Path::new(name)) {
        Ok((file, meta)) => {
            check_policy_file(&meta, euid).map_err(|e| refused("the policy file", e))?;
            Some((file, meta))
        }
        Err(Refusal::Missing) => None,
        Err(e) => return Err(refused("the policy file", e)),
    };
    let ownership = current.as_ref().map(|(_, meta)| Ownership {
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode() & 0o777,
    });
    let current_id = current.as_ref().map(|(_, meta)| (meta.dev(), meta.ino()));
    let (source, in_place) = match (draft, current) {
        (Some(path), _) => {
            let (text, meta) = read_draft(path, euid).map_err(|e| refused("the draft", e))?;
            // Naming the file as its own draft is still sealing it where it stands.
            (text, current_id == Some((meta.dev(), meta.ino())))
        }
        (None, Some((file, _))) => {
            let text =
                read_limited(file, MAX_POLICY_BYTES).map_err(|e| refused("the policy file", e))?;
            (text, true)
        }
        (None, None) => {
            return Err(SealError(
                "the policy file does not exist; give a draft with --from".to_owned(),
            ));
        }
    };
    let sealed = seal_text(&source)?;
    if sealed.len() > MAX_POLICY_BYTES {
        return Err(SealError("the policy file would be too large".to_owned()));
    }
    let parsed = parse_policy(&sealed).map_err(|e| SealError(format!("the draft {e}")))?;
    let access = access_lines(&parsed);
    if in_place
        && unverified == Unverified::Refuse
        && has_digest_line(&source)
        && verify_seal(&source).is_err()
    {
        return Err(SealError(format!(
            "not sealed: the policy file does not match its digest, so it was edited, or it is a \
             mix of two versions left by an overwrite. warden cannot tell which. It would \
             allow:\n  {}\n{ACCESS_NOTE}\nCheck every line. If this is what you meant, run again with \
             --accept-unverified. Otherwise write a draft you have checked and seal it with \
             --from <draft>.",
            if access.is_empty() {
                "nothing".to_owned()
            } else {
                access.join("\n  ")
            },
        )));
    }
    let target = Target {
        directory: &directory,
        name,
        ownership: ownership.as_ref(),
    };
    replace(&target, &sealed, temporary_suffix, File::sync_all)?;
    Ok(SealedPolicy {
        targets: parsed.targets.len(),
        api_entries: parsed.api_secrets.len(),
        access,
    })
}

/// Whether `text` ends with a digest line, as [`seal_text`] sees it.
fn has_digest_line(text: &str) -> bool {
    text.trim_end()
        .rsplit('\n')
        .next()
        .is_some_and(|line| line.starts_with(DIGEST_LINE_START))
}

/// A draft, by the same rules as the policy file it becomes: a regular file, its
/// own mount or a link refused, owned by this user or root, and nobody else able to
/// change it or anything on the way to it.
pub(super) fn read_draft(path: &Path, euid: u32) -> Result<(Zeroizing<String>, Metadata), Refusal> {
    let path = std::path::absolute(path).map_err(|e| Refusal::Io(e.kind()))?;
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(Refusal::Rule("must name a file"));
    };
    let directory = open_directory(parent, euid)?;
    let (file, meta) = open_regular(&directory, Path::new(name))?;
    check_policy_file(&meta, euid)?;
    Ok((read_limited(file, MAX_POLICY_BYTES)?, meta))
}

/// Removes the temporary file unless it was renamed.
struct TemporaryName<'a> {
    directory: &'a File,
    name: &'a OsStr,
    renamed: bool,
}

impl Drop for TemporaryName<'_> {
    fn drop(&mut self) {
        if !self.renamed {
            // Already failing with the error that matters; a leftover file is
            // harmless, because warden reads only the policy file's own name.
            let _ = rustix::fs::unlinkat(self.directory, self.name, AtFlags::empty());
        }
    }
}

/// A name no earlier seal left behind. A process id will not do: in a container it
/// is the same every time, so one leftover file would stop every later seal.
fn temporary_suffix() -> Result<String, SealError> {
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix)
        .map_err(|_| SealError("no random name for the temporary file".to_owned()))?;
    Ok(hex::encode(suffix))
}

/// Where the sealed text goes.
pub(super) struct Target<'a> {
    pub(super) directory: &'a File,
    pub(super) name: &'a OsStr,
    pub(super) ownership: Option<&'a Ownership>,
}

/// The file is untouched: a write beside it failed.
fn not_written(shown: &OsStr, kind: impl Display) -> SealError {
    SealError(format!(
        "the policy file cannot be written, and is as it was: {}: {kind}",
        shown.display()
    ))
}

/// A new file beside the target, under a name no other file has.
fn create_temporary(
    target: &Target<'_>,
    mut suffix: impl FnMut() -> Result<String, SealError>,
) -> Result<(File, OsString), SealError> {
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut taken = OsString::new();
    for _ in 0..TEMPORARY_NAME_ATTEMPTS {
        let mut temporary = OsString::from(".");
        temporary.push(target.name);
        temporary.push(format!(".seal-{}", suffix()?));
        match rustix::fs::openat(
            target.directory,
            &temporary,
            flags,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => return Ok((File::from(fd), temporary)),
            Err(Errno::EXIST) => taken = temporary,
            Err(errno) => return Err(not_written(&temporary, io::Error::from(errno).kind())),
        }
    }
    Err(not_written(&taken, "the name is already taken"))
}

/// Write `text` to a new file beside the target, durable before the rename, and
/// rename it over the target. `sync_directory` makes the rename durable.
pub(super) fn replace(
    target: &Target<'_>,
    text: &str,
    suffix: impl FnMut() -> Result<String, SealError>,
    sync_directory: impl FnOnce(&File) -> io::Result<()>,
) -> Result<(), SealError> {
    let (mut file, temporary) = create_temporary(target, suffix)?;
    let io = |e: io::Error| not_written(&temporary, e.kind());
    let mut guard = TemporaryName {
        directory: target.directory,
        name: &temporary,
        renamed: false,
    };
    file.write_all(text.as_bytes()).map_err(io)?;
    let mode = if let Some(owner) = target.ownership {
        let meta = file.metadata().map_err(io)?;
        if (meta.uid(), meta.gid()) != (owner.uid, owner.gid) {
            fchown(&file, Some(owner.uid), Some(owner.gid)).map_err(io)?;
        }
        owner.mode
    } else {
        NEW_FILE_MODE
    };
    file.set_permissions(Permissions::from_mode(mode))
        .map_err(io)?;
    file.sync_all().map_err(io)?;
    rustix::fs::renameat(target.directory, &temporary, target.directory, target.name)
        .map_err(|errno| not_written(&temporary, io::Error::from(errno).kind()))?;
    guard.renamed = true;
    sync_directory(target.directory).map_err(|e| {
        SealError(format!(
            "the policy file was replaced, and warden reads the new one, but the change may not \
             survive a crash: syncing its directory failed: {}",
            e.kind()
        ))
    })
}
