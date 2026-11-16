//! `warden hook session-start`: what a Claude Code `SessionStart` hook prints
//! into the model's context. It is `warden prime --brief`, then the owner's
//! rules file for this machine, and it saves the offers the broker answered for
//! `warden hook check`. It exits 0 whatever happens.

use std::io::{Read as _, Write as _};
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
/// Ends the rules when the file is longer than `RULES_CAP`.
const CUT_NOTE: &str = "\n(cut: the file is longer than 8 KiB)\n";
/// Ends the rules when only the output limit cut them.
const OUTPUT_CUT_NOTE: &str = "\n(cut: the output limit was reached)\n";
/// Printed in place of the rules when the output limit leaves no room for them.
const LEFT_OUT: &str = "\nwarden: the owner's rules were left out: the output limit was reached.\n";
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

/// `brief`, then the rules file in `config_dir`; never more than
/// `OUTPUT_CAP_CHARS` characters in all.
///
/// A brief that alone passes the limit is cut to it, at a character boundary,
/// and the rules are left out: Claude Code would replace anything over 10,000
/// characters with a path the model is not told to read, so a bounded start of
/// the brief is the safer thing to hand over. (The brief is a few KiB at most
/// in practice; this only bounds a broker that offers far more than usual.)
fn render(brief: &str, config_dir: Option<&Path>) -> String {
    let mut out = clip(brief, OUTPUT_CAP_CHARS).to_owned();
    let Some(dir) = config_dir else {
        return out;
    };
    match read_rules(&dir.join(RULES_FILE)) {
        Rules::Missing => {}
        Rules::Unreadable => {
            let separator = if out.is_empty() || out.ends_with('\n') {
                ""
            } else {
                "\n"
            };
            push_within(&mut out, &format!("{separator}{UNREADABLE}\n"));
        }
        Rules::Found { text, longer } => {
            let room = OUTPUT_CAP_CHARS.saturating_sub(out.chars().count());
            let heading = HEADING.chars().count();
            // The final newline a file lacks is added, so it counts.
            let newline = usize::from(!text.ends_with('\n'));
            let note = if longer || text.len() > RULES_CAP {
                CUT_NOTE
            } else {
                OUTPUT_CUT_NOTE
            };
            if !longer
                && text.len() <= RULES_CAP
                && heading + text.chars().count() + newline <= room
            {
                out.push_str(HEADING);
                out.push_str(&text);
                if newline == 1 {
                    out.push('\n');
                }
            } else if let Some(avail) = room
                .checked_sub(heading + note.chars().count())
                .filter(|a| *a > 0)
            {
                out.push_str(HEADING);
                out.push_str(cut(&text, avail));
                out.push_str(note);
            } else {
                push_within(&mut out, LEFT_OUT);
            }
        }
    }
    out
}

/// `text` as it is, or its first `limit` characters.
fn clip(text: &str, limit: usize) -> &str {
    match text.char_indices().nth(limit) {
        Some((index, _)) => &text[..index],
        None => text,
    }
}

/// Appends `line` when the output stays within the limit, otherwise nothing.
fn push_within(out: &mut String, line: &str) {
    if out.chars().count() + line.chars().count() <= OUTPUT_CAP_CHARS {
        out.push_str(line);
    }
}

/// The longest start of `text` of at most `RULES_CAP` bytes and `avail`
/// characters, cut at a character boundary.
fn cut(text: &str, avail: usize) -> &str {
    let mut end = 0;
    for (count, (index, c)) in text.char_indices().enumerate() {
        let next = index + c.len_utf8();
        if next > RULES_CAP || count >= avail {
            break;
        }
        end = next;
    }
    &text[..end]
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
    let Some(file) = super::files::open_regular(path) else {
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
