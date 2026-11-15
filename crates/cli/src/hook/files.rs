//! The small-file reader the hook gives its detection library: the files an
//! `ssh -F` or an `Include` names, which an agent may point anywhere.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rustix::fs::OFlags;

/// The largest file the hook reads, in bytes.
pub const MAX_BYTES: u64 = 64 * 1024;

/// The text of the regular file at `path`: `None` when it is missing,
/// unreadable, not a regular file (a directory, a FIFO or a device would
/// block or never end), over [`MAX_BYTES`] or not UTF-8. The file is opened
/// without blocking, so a FIFO never holds the hook up.
#[must_use]
pub fn read_small(path: &Path) -> Option<String> {
    let flags = i32::try_from(OFlags::NONBLOCK.bits()).ok()?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut body = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut body).ok()?;
    if u64::try_from(body.len()).ok()? > MAX_BYTES {
        return None;
    }
    String::from_utf8(body).ok()
}

/// Reads small files for one run: a relative path is resolved against the
/// event's working directory, and each path is read once.
pub struct Reader {
    cwd: Option<PathBuf>,
    seen: RefCell<HashMap<PathBuf, Option<String>>>,
}

impl Reader {
    /// A reader resolving relative paths against `cwd`; `None`, or a
    /// relative `cwd`, leaves relative paths as they are.
    #[must_use]
    pub fn new(cwd: Option<&str>) -> Self {
        Self {
            cwd: cwd.map(PathBuf::from).filter(|dir| dir.is_absolute()),
            seen: RefCell::new(HashMap::new()),
        }
    }

    /// The text of the file at `path`, as [`read_small`] gives it.
    #[must_use]
    pub fn read(&self, path: &Path) -> Option<String> {
        let full = match &self.cwd {
            Some(cwd) if path.is_relative() => cwd.join(path),
            _ => path.to_path_buf(),
        };
        self.seen
            .borrow_mut()
            .entry(full)
            .or_insert_with_key(|full| read_small(full))
            .clone()
    }
}

#[cfg(test)]
mod tests;
