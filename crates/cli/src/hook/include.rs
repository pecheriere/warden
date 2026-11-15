//! `Include` lines of `~/.ssh/config`: which files an argument names, and
//! their text for the alias reader.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::files::{MAX_BYTES, is_regular_file};

/// The most directory entries one listing looks at.
const MAX_ENTRIES: usize = 10_000;

/// Resolves the `Include` arguments of one run. All of them share one budget
/// of [`MAX_BYTES`] of text, so many lines cannot add up to more, and each
/// directory is listed once.
pub struct Includes<'a> {
    home: &'a Path,
    remaining: Cell<u64>,
    listings: RefCell<HashMap<PathBuf, Vec<String>>>,
}

impl<'a> Includes<'a> {
    /// A resolver for the user whose home directory is `home`.
    #[must_use]
    pub fn new(home: &'a Path) -> Self {
        Self {
            home,
            remaining: Cell::new(MAX_BYTES),
            listings: RefCell::new(HashMap::new()),
        }
    }

    /// The text of the files an `Include` argument names, joined by
    /// newlines: `~/` stands for the home directory, a relative path is
    /// relative to `<home>/.ssh`, and `*` and `?` match in the last path
    /// component only. Files come from `read` (which refuses what is not a
    /// small regular file) in sorted order. Once the shared budget is spent
    /// nothing is listed or read any more. `None` when nothing was read.
    pub fn text(&self, argument: &str, read: &dyn Fn(&Path) -> Option<String>) -> Option<String> {
        let mut text = String::new();
        for word in argument.split_whitespace() {
            let word = word.trim_matches('"');
            for file in self.expand(word) {
                if self.remaining.get() == 0 {
                    return (!text.is_empty()).then_some(text);
                }
                let Some(body) = read(&file) else {
                    continue;
                };
                let joined = u64::try_from(body.len() + 1).unwrap_or(u64::MAX);
                if joined > self.remaining.get() {
                    self.remaining.set(0);
                    return (!text.is_empty()).then_some(text);
                }
                self.remaining.set(self.remaining.get() - joined);
                text.push_str(&body);
                text.push('\n');
            }
        }
        (!text.is_empty()).then_some(text)
    }

    /// The paths a single `Include` pattern names, sorted.
    fn expand(&self, pattern: &str) -> Vec<PathBuf> {
        if self.remaining.get() == 0 {
            return Vec::new();
        }
        let full = match pattern.strip_prefix("~/") {
            Some(rest) => self.home.join(rest),
            None if pattern.starts_with('/') => PathBuf::from(pattern),
            None => self.home.join(".ssh").join(pattern),
        };
        let Some(name) = full.file_name().and_then(|name| name.to_str()) else {
            return Vec::new();
        };
        if !name.contains(['*', '?']) {
            return vec![full];
        }
        let Some(dir) = full.parent() else {
            return Vec::new();
        };
        let mut listings = self.listings.borrow_mut();
        let entries = listings
            .entry(dir.to_path_buf())
            .or_insert_with_key(|dir| list(dir));
        entries
            .iter()
            .filter(|entry| glob_matches(name, entry))
            .map(|entry| dir.join(entry))
            .collect()
    }
}

/// The names of the regular files in `dir`, sorted; devices, pipes and
/// directories are never candidates.
fn list(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .take(MAX_ENTRIES)
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            is_regular_file(&entry.path()).then_some(name)
        })
        .collect();
    names.sort();
    names
}

/// Whether `name` matches `pattern`, where `*` is any run of characters and
/// `?` any one. Like the shell's glob, a name with a leading `.` matches
/// only a pattern that starts with `.`.
fn glob_matches(pattern: &str, name: &str) -> bool {
    if name.starts_with('.') && !pattern.starts_with('.') {
        return false;
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some((p, n));
                p += 1;
            }
            Some(c) if *c == '?' || *c == name[n] => {
                p += 1;
                n += 1;
            }
            _ => {
                let Some((star_p, star_n)) = star else {
                    return false;
                };
                p = star_p + 1;
                n = star_n + 1;
                star = Some((star_p, star_n + 1));
            }
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests;
