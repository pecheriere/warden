//! The offers cache: what `warden hook check` reads instead of calling the
//! broker. `warden prime` and `warden list` write it, `<state>/offers-cache.json`
//! at mode 0600, and a copy older than 24 hours is not used.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use serde_json::Value;
use warden_broker_proto::offers::Offers;

use crate::agent::state_dir;
use crate::client::read_offer;

/// The file's name in the state directory.
const FILE_NAME: &str = "offers-cache.json";
/// A cache older than this is not used.
const MAX_AGE: Duration = Duration::from_hours(24);
/// A cache larger than this is not read.
const MAX_BYTES: u64 = 1024 * 1024;

/// Makes temp file names unique within the process.
static SEQUENCE: AtomicU32 = AtomicU32::new(0);

#[expect(dead_code, reason = "used by write and read, wired in a later commit")]
fn cache_path() -> Result<PathBuf> {
    Ok(state_dir()?.join(FILE_NAME))
}

/// Stores the broker's offers body for later hook runs.
///
/// # Errors
/// If the state directory or the file cannot be written.
#[expect(
    dead_code,
    reason = "used by warden prime and list, wired in a later commit"
)]
pub fn write(offers_json: &Value) -> Result<()> {
    write_to(&cache_path()?, offers_json)
}

/// The cached offers, when there are some, they are readable and less than 24
/// hours old at `now`.
#[must_use]
#[expect(
    dead_code,
    reason = "used by warden hook check, wired in the next commit"
)]
pub fn read(now: SystemTime) -> Option<Offers> {
    read_from(&cache_path().ok()?, now)
}

/// [`write`] to `path`: a private temp file beside it, renamed over it.
fn write_to(path: &Path, offers_json: &Value) -> Result<()> {
    let dir = path.parent().context("the cache path has no directory")?;
    let temp = dir.join(format!(
        ".{FILE_NAME}.{}.{}.tmp",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = write_temp(&temp, offers_json)
        .and_then(|()| std::fs::rename(&temp, path).context("cannot replace the offers cache"));
    if result.is_err() {
        // Best effort: the error being returned is the one that matters.
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn write_temp(temp: &Path, offers_json: &Value) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp)
        .context("cannot create the offers cache")?;
    file.write_all(&serde_json::to_vec(offers_json)?)
        .context("cannot write the offers cache")?;
    file.sync_all().context("cannot write the offers cache")
}

/// [`read`] from `path`.
fn read_from(path: &Path, now: SystemTime) -> Option<Offers> {
    // A first look without opening, so that a FIFO is never waited on.
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_BYTES {
        return None;
    }
    // A modification time after `now` counts as fresh; a clock error as stale.
    if now
        .duration_since(meta.modified().ok()?)
        .is_ok_and(|age| age > MAX_AGE)
    {
        return None;
    }
    let mut body = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut body).ok()?;
    if u64::try_from(body.len()).ok()? > MAX_BYTES {
        return None;
    }
    read_offer(&serde_json::from_slice(&body).ok()?).ok()
}

#[cfg(test)]
mod tests;
