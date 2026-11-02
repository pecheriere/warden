//! `warden-server seal-policy`: give a finished policy file its digest, and put
//! it in place in one step.
//!
//! The one thing here that writes to the local backend's files, and warden itself
//! never calls it. It runs as whoever edits the policy, on the host or wherever
//! the directory is writable, so it needs none of warden's settings.
//!
//! Sealing says "this content is finished". It cannot tell a finished file from a
//! file another writer is still overwriting, so what it takes is the operator's
//! word, and the draft's own `[end_of_policy]` line: a draft cut short has lost that line
//! and is refused rather than sealed as a wider policy.

use std::ffi::{OsStr, OsString};
use std::fs::{File, Permissions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, fchown};
use std::path::Path;

use rustix::fs::{AtFlags, Mode, OFlags};
use thiserror::Error;
use zeroize::Zeroizing;

use super::files::{
    MAX_POLICY_BYTES, Refusal, check_policy_file, open_directory, open_regular, read_limited,
};
use super::{DIGEST_LINE_START, END_MARKER, digest_line, parse_policy};

/// A new policy file's mode: warden needs to read it, and nothing in it is secret.
const NEW_FILE_MODE: u32 = 0o644;

/// Why nothing was sealed. Never quotes a file.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct SealError(String);

/// What a sealed file holds, to show the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedPolicy {
    /// Entries under `[targets]`.
    pub targets: usize,
    /// Entries under `[api_secrets]`.
    pub api_secrets: usize,
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

/// Whose file a replacement must be, and with what mode.
struct Ownership {
    uid: u32,
    gid: u32,
    mode: u32,
}

/// Seal `policy`, from `draft` if given and from its own content otherwise, and
/// replace it by a rename, so that a reader sees the old file or the new one.
/// A draft that does not parse as a policy leaves the file untouched. The path
/// follows the rules warden reads it by, so what this accepts warden can read,
/// and it keeps the owner and mode of the file it replaces.
///
/// # Errors
/// [`SealError`] when anything is refused or fails; the policy file is then as it
/// was, and no temporary file is left.
pub fn seal_policy_file(policy: &Path, draft: Option<&Path>) -> Result<SealedPolicy, SealError> {
    let euid = rustix::process::geteuid().as_raw();
    let whole = |what: &str, reason: &dyn std::fmt::Display| SealError(format!("{what} {reason}"));
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
        open_directory(parent, euid).map_err(|e| whole("the policy file's directory:", &e))?;
    let current = match open_regular(&directory, Path::new(name)) {
        Ok((file, meta)) => {
            check_policy_file(&meta, euid).map_err(|e| whole("the policy file", &e))?;
            Some((file, meta))
        }
        Err(Refusal::Missing) => None,
        Err(e) => return Err(whole("the policy file", &e)),
    };
    let ownership = current.as_ref().map(|(_, meta)| Ownership {
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode() & 0o777,
    });
    let source = match (draft, current) {
        (Some(path), _) => read_draft(path).map_err(|e| whole("the draft", &e))?,
        (None, Some((file, _))) => {
            read_limited(file, MAX_POLICY_BYTES).map_err(|e| whole("the policy file", &e))?
        }
        (None, None) => {
            return Err(whole(
                "the policy file",
                &"does not exist; give a draft with --from",
            ));
        }
    };
    let sealed = seal_text(&source)?;
    if sealed.len() > MAX_POLICY_BYTES {
        return Err(whole("the policy file", &"would be too large"));
    }
    let parsed = parse_policy(&sealed).map_err(|e| whole("the draft", &e))?;
    replace(&directory, name, &sealed, ownership.as_ref())
        .map_err(|e| whole("the policy file could not be replaced:", &e))?;
    Ok(SealedPolicy {
        targets: parsed.targets.len(),
        api_secrets: parsed.api_secrets.len(),
    })
}

/// A draft may be anywhere the operator keeps it, so only its last component is
/// held to a rule: a regular file, reached without following a link or blocking.
fn read_draft(path: &Path) -> Result<Zeroizing<String>, Refusal> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let file = File::from(rustix::fs::open(path, flags, Mode::empty())?);
    let meta = file.metadata().map_err(|e| Refusal::Io(e.kind()))?;
    if !meta.is_file() {
        return Err(Refusal::Rule("is not a regular file"));
    }
    read_limited(file, MAX_POLICY_BYTES)
}

/// Removes the temporary file unless it was renamed.
struct TemporaryName<'a> {
    directory: &'a File,
    name: &'a OsString,
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

/// Write `text` to a new file beside `name`, durable before the rename, and rename
/// it over `name`.
fn replace(
    directory: &File,
    name: &OsStr,
    text: &str,
    ownership: Option<&Ownership>,
) -> Result<(), Refusal> {
    let io = |e: std::io::Error| Refusal::Io(e.kind());
    let mut temporary = OsString::from(".");
    temporary.push(name);
    temporary.push(format!(".seal-{}", std::process::id()));
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut file = File::from(rustix::fs::openat(
        directory,
        &temporary,
        flags,
        Mode::from_raw_mode(0o600),
    )?);
    let mut guard = TemporaryName {
        directory,
        name: &temporary,
        renamed: false,
    };
    file.write_all(text.as_bytes()).map_err(io)?;
    let mode = if let Some(owner) = ownership {
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
    rustix::fs::renameat(directory, &temporary, directory, name)?;
    guard.renamed = true;
    directory.sync_all().map_err(io)
}
