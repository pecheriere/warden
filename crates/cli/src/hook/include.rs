//! `Include` lines of `~/.ssh/config`: which files an argument names, and
//! their text for the alias reader.

use std::path::{Path, PathBuf};

use super::files::MAX_BYTES;

/// The text of the files an `Include` argument names, joined by newlines:
/// `~/` stands for `home`, a relative path is relative to `<home>/.ssh`, and
/// `*` and `?` match in the last path component only. Files come from `read`
/// (which refuses what is not a small regular file) in sorted order, and the
/// text stops growing before it passes 64 KiB. `None` when nothing was read.
pub fn include_text(
    argument: &str,
    home: &Path,
    read: &dyn Fn(&Path) -> Option<String>,
) -> Option<String> {
    let mut text = String::new();
    for word in argument.split_whitespace() {
        let word = word.trim_matches('"');
        for file in expand(word, home) {
            let Some(body) = read(&file) else {
                continue;
            };
            let joined = text.len() + body.len() + 1;
            if u64::try_from(joined).is_ok_and(|n| n > MAX_BYTES) {
                return (!text.is_empty()).then_some(text);
            }
            text.push_str(&body);
            text.push('\n');
        }
    }
    (!text.is_empty()).then_some(text)
}

/// The paths a single `Include` pattern names, sorted.
fn expand(pattern: &str, home: &Path) -> Vec<PathBuf> {
    let full = match pattern.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if pattern.starts_with('/') => PathBuf::from(pattern),
        None => home.join(".ssh").join(pattern),
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
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|entry| glob_matches(name, entry))
        .map(|entry| dir.join(entry))
        .collect();
    found.sort();
    found
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
