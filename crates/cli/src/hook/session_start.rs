//! `warden hook session-start`: what a Claude Code `SessionStart` hook prints
//! into the model's context. It is `warden prime --brief`, then the owner's
//! rules file for this machine, and it saves the offers the broker answered for
//! `warden hook check`. It exits 0 whatever happens.

use std::io::{Read, Write};
use std::path::Path;

use crate::config;
use crate::prime;

/// The owner's rules file, next to `config.toml`.
const RULES_FILE: &str = "agent-rules.md";
/// How much of the rules file is printed.
const RULES_CAP: usize = 8 * 1024;
/// Claude Code replaces a `SessionStart` output of more than 10,000
/// characters with a path and a preview that the model is not told to read, so
/// the whole output stays under this.
const OUTPUT_CAP_CHARS: usize = 9_500;
const HEADING: &str = "\n## The owner's rules for this machine\n\n";
const CUT_NOTE: &str = "\n(cut: the file is longer than 8 KiB)\n";
const UNREADABLE: &str = "warden: the owner's rules file cannot be read.";

/// Prints the brief and the owner's rules, then saves the offers.
pub async fn run() {
    let (brief, offers) = prime::brief_and_offers(prime::OFFERS_TIMEOUT).await;
    let dir = config::config_path()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf));
    let text = render(&brief, dir.as_deref());
    // A closed stdout leaves no one to tell.
    let _ = std::io::stdout().lock().write_all(text.as_bytes());
    // Silent on failure: stdout is the model's context, and a stale cache only
    // makes `hook check` less informed.
    if let Some(body) = offers {
        let _ = super::cache::write(&body);
    }
}

/// `brief`, then the rules file in `config_dir`.
fn render(brief: &str, config_dir: Option<&Path>) -> String {
    let mut out = brief.to_owned();
    let Some(dir) = config_dir else {
        return out;
    };
    match read_rules(&dir.join(RULES_FILE)) {
        Rules::Missing => {}
        Rules::Unreadable => {
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(UNREADABLE);
            out.push('\n');
        }
        Rules::Found { text, longer } => {
            out.push_str(HEADING);
            let used = out.chars().count() + CUT_NOTE.chars().count();
            let budget = OUTPUT_CAP_CHARS.saturating_sub(used);
            let (kept, cut) = cut(&text, budget, longer);
            out.push_str(kept);
            if cut {
                out.push_str(CUT_NOTE);
            } else if !kept.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    out
}

/// The longest start of `text` of at most `RULES_CAP` bytes and `budget`
/// characters, cut at a character boundary, and whether anything was left
/// out. The note's room is in `budget`; a file that fits whole is not cut.
fn cut(text: &str, budget: usize, longer: bool) -> (&str, bool) {
    let mut end = 0;
    for (count, (index, c)) in text.char_indices().enumerate() {
        let next = index + c.len_utf8();
        if next > RULES_CAP || count >= budget {
            return (&text[..end], true);
        }
        end = next;
    }
    (text, longer)
}

enum Rules {
    Missing,
    Unreadable,
    /// The start of the file, at most one byte past the cap, and whether the
    /// file goes beyond the cap.
    Found {
        text: String,
        longer: bool,
    },
}

fn read_rules(path: &Path) -> Rules {
    match std::fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Rules::Missing,
        // Not opened otherwise: a FIFO would be waited on.
        Ok(meta) if meta.is_file() => {}
        _ => return Rules::Unreadable,
    }
    let Ok(file) = std::fs::File::open(path) else {
        return Rules::Unreadable;
    };
    let mut bytes = Vec::new();
    if file
        .take(RULES_CAP as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return Rules::Unreadable;
    }
    let longer = bytes.len() > RULES_CAP;
    Rules::Found {
        text: String::from_utf8_lossy(&bytes).into_owned(),
        longer,
    }
}

#[cfg(test)]
mod tests;
