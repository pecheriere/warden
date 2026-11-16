//! Git's configuration files, read as git reads them, reduced to what the
//! `owner-github` signal asks: where `git push` sends a remote's commits, and
//! whether the first credential helper git asks for a URL is warden's.
//!
//! The CLI reads the files; this module only parses their text. It follows
//! git-config(1) for the syntax and gitcredentials(7) for the helpers, with
//! these limits: `include` and `includeIf` are not followed, the system file
//! and `config.worktree` are not read, and a `*` in a URL pattern matches a
//! whole host label only.

use std::iter::Peekable;
use std::str::Chars;

use url::Url;

/// One `section.subsection.name = value` line.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    /// The section, lowercased.
    section: String,
    /// The subsection, case kept (`[section "subsection"]`).
    subsection: Option<String>,
    /// The variable's name, lowercased.
    name: String,
    /// Its value; `None` for a name alone, which git reads as `true`.
    value: Option<String>,
}

/// The entries of git's configuration files, in the order git reads them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GitConfig {
    entries: Vec<Entry>,
}

impl GitConfig {
    /// Parses `files`, given in the order git reads them: the global files
    /// (`$XDG_CONFIG_HOME/git/config`, then `~/.gitconfig`), then the
    /// repository's. `None` when one of them is malformed, as git then refuses
    /// to run.
    #[must_use]
    pub fn parse(files: &[&str]) -> Option<Self> {
        let mut entries = Vec::new();
        for text in files {
            parse_file(text, &mut entries)?;
        }
        Some(Self { entries })
    }

    /// The values of `section.subsection.name`, in order.
    fn values<'a>(
        &'a self,
        section: &'a str,
        subsection: Option<&'a str>,
        name: &'a str,
    ) -> impl Iterator<Item = &'a str> + 'a {
        self.entries
            .iter()
            .filter(move |e| {
                e.section == section && e.subsection.as_deref() == subsection && e.name == name
            })
            .filter_map(|e| e.value.as_deref())
    }

    /// The URLs `git push <repository>` sends to: the remote's `pushurl`s,
    /// else its `url`s; a URL that is no remote's stands for itself. With no
    /// repository, the remote is `remote.pushDefault`, else `origin` (the
    /// current branch's own settings are not read). A name that is neither a
    /// remote nor a URL is a local path, which sends nowhere. `url.<base>`
    /// rewrites apply as git applies them: `pushInsteadOf`, then `insteadOf`,
    /// for a `url`; `insteadOf` alone for a `pushurl`.
    #[must_use]
    pub fn push_urls(&self, repository: Option<&str>) -> Vec<String> {
        let name = repository
            .or_else(|| self.values("remote", None, "pushdefault").last())
            .unwrap_or("origin");
        let push: Vec<String> = self
            .values("remote", Some(name), "pushurl")
            .filter(|url| !url.is_empty())
            .map(|url| self.rewrite(url, false))
            .collect();
        if !push.is_empty() {
            return push;
        }
        let urls: Vec<String> = self
            .values("remote", Some(name), "url")
            .filter(|url| !url.is_empty())
            .map(|url| self.rewrite(url, true))
            .collect();
        if !urls.is_empty() {
            return urls;
        }
        if name.contains("://") {
            return vec![self.rewrite(name, true)];
        }
        Vec::new()
    }

    /// `url` after the longest matching `url.<base>.pushInsteadOf` (when
    /// `push`), else the longest matching `url.<base>.insteadOf`.
    fn rewrite(&self, url: &str, push: bool) -> String {
        let longest = |key: &str| {
            self.entries
                .iter()
                .filter(|e| e.section == "url" && e.name == key)
                .filter_map(|e| Some((e.subsection.as_deref()?, e.value.as_deref()?)))
                .filter(|(_, prefix)| !prefix.is_empty() && url.starts_with(prefix))
                .max_by_key(|(_, prefix)| prefix.len())
                .map(|(base, prefix)| format!("{base}{}", &url[prefix.len()..]))
        };
        push.then(|| longest("pushinsteadof"))
            .flatten()
            .or_else(|| longest("insteadof"))
            .unwrap_or_else(|| url.to_owned())
    }

    /// Whether the first credential helper git asks for `url` runs
    /// `warden git-credential`. The helpers are every `credential.helper` and
    /// every `credential.<pattern>.helper` whose pattern matches `url`, in
    /// order, an empty value dropping those before it; `command_line` holds
    /// the `-c name=value` settings of the git command, which come last.
    ///
    /// A helper counts as warden's when its program's basename is `warden`.
    /// That is deliberately weaker than the same-program check of `warden
    /// doctor`: this decides only a `warn`-level hint, and the agent could
    /// edit the configuration away anyway (see the threat model).
    #[must_use]
    pub fn warden_helper_for(&self, url: &str, command_line: &[&str]) -> bool {
        let Some(target) = Url::parse(url).ok().filter(|u| u.host_str().is_some()) else {
            return false;
        };
        let extra: Vec<Entry> = command_line
            .iter()
            .filter_map(|setting| command_line_entry(setting))
            .collect();
        let mut helpers: Vec<&str> = Vec::new();
        for entry in self.entries.iter().chain(&extra) {
            if entry.section != "credential" || entry.name != "helper" {
                continue;
            }
            let Some(value) = entry.value.as_deref() else {
                continue;
            };
            let applies = entry
                .subsection
                .as_deref()
                .is_none_or(|pattern| url_matches(pattern, &target));
            if !applies {
                continue;
            }
            if value.is_empty() {
                helpers.clear();
            } else {
                helpers.push(value);
            }
        }
        helpers
            .first()
            .and_then(|value| helper_program(value))
            .is_some_and(|program| program.rsplit('/').next() == Some("warden"))
    }
}

/// A `-c section[.subsection].name=value` setting as an entry: the section
/// ends at the first `.`, the name starts after the last one.
fn command_line_entry(setting: &str) -> Option<Entry> {
    let (key, value) = setting.split_once('=')?;
    let (section, rest) = key.split_once('.')?;
    let (subsection, name) = match rest.rsplit_once('.') {
        Some((subsection, name)) => (Some(subsection.to_owned()), name),
        None => (None, rest),
    };
    Some(Entry {
        section: section.to_ascii_lowercase(),
        subsection,
        name: name.to_ascii_lowercase(),
        value: Some(value.to_owned()),
    })
}

/// Whether a `credential.<pattern>` section applies to `target`, as git's
/// URL matching decides: the same scheme, host (a `*` label matches any one
/// label) and port, the pattern's user if it has one, and its path as a
/// prefix of whole segments.
fn url_matches(pattern: &str, target: &Url) -> bool {
    let Ok(pattern) = Url::parse(pattern) else {
        return false;
    };
    let hosts_match = match (pattern.host_str(), target.host_str()) {
        (Some(want), Some(have)) => {
            let want: Vec<&str> = want.split('.').collect();
            let have: Vec<&str> = have.split('.').collect();
            want.len() == have.len()
                && want
                    .iter()
                    .zip(&have)
                    .all(|(w, h)| *w == "*" || w.eq_ignore_ascii_case(h))
        }
        _ => false,
    };
    let path = pattern.path().trim_end_matches('/');
    let path_matches = path.is_empty()
        || target.path() == path
        || target
            .path()
            .strip_prefix(path)
            .is_some_and(|rest| rest.starts_with('/'));
    pattern.scheme() == target.scheme()
        && hosts_match
        && pattern.port_or_known_default() == target.port_or_known_default()
        && (pattern.username().is_empty() || pattern.username() == target.username())
        && path_matches
}

/// Adds the entries of one file; `None` when it is malformed.
fn parse_file(text: &str, entries: &mut Vec<Entry>) -> Option<()> {
    let text = text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .replace("\r\n", "\n");
    let mut chars = text.chars().peekable();
    let mut section: Option<(String, Option<String>)> = None;
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        match chars.peek() {
            None => return Some(()),
            Some('#' | ';') => skip_line(&mut chars),
            Some('[') => {
                chars.next();
                section = Some(header(&mut chars)?);
            }
            Some(c) if c.is_ascii_alphabetic() => {
                let (name, value) = variable(&mut chars)?;
                let (section, subsection) = section.clone()?;
                entries.push(Entry {
                    section,
                    subsection,
                    name,
                    value,
                });
            }
            Some(_) => return None,
        }
    }
}

fn skip_line(chars: &mut Peekable<Chars<'_>>) {
    for c in chars.by_ref() {
        if c == '\n' {
            break;
        }
    }
}

/// A section header after its `[`: `[section]`, `[section "subsection"]`, or
/// the old `[section.subsection]`, whose subsection is lowercased.
fn header(chars: &mut Peekable<Chars<'_>>) -> Option<(String, Option<String>)> {
    let mut name = String::new();
    while let Some(c) = chars.next_if(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.')) {
        name.push(c.to_ascii_lowercase());
    }
    if name.is_empty() {
        return None;
    }
    match chars.next()? {
        ']' => match name.split_once('.') {
            Some((section, subsection)) if !section.is_empty() => {
                Some((section.to_owned(), Some(subsection.to_owned())))
            }
            Some(_) => None,
            None => Some((name, None)),
        },
        ' ' | '\t' => {
            while chars.next_if(|c| matches!(c, ' ' | '\t')).is_some() {}
            if chars.next()? != '"' || name.contains('.') {
                return None;
            }
            let mut subsection = String::new();
            loop {
                match chars.next()? {
                    '"' => break,
                    '\n' => return None,
                    '\\' => match chars.next()? {
                        '\n' => return None,
                        c => subsection.push(c),
                    },
                    c => subsection.push(c),
                }
            }
            (chars.next()? == ']').then_some((name, Some(subsection)))
        }
        _ => None,
    }
}

/// A `name = value` line, or a name alone.
fn variable(chars: &mut Peekable<Chars<'_>>) -> Option<(String, Option<String>)> {
    let mut name = String::new();
    while let Some(c) = chars.next_if(|c| c.is_ascii_alphanumeric() || *c == '-') {
        name.push(c.to_ascii_lowercase());
    }
    while chars.next_if(|c| matches!(c, ' ' | '\t')).is_some() {}
    match chars.next() {
        None | Some('\n') => Some((name, None)),
        Some('#' | ';') => {
            skip_line(chars);
            Some((name, None))
        }
        Some('=') => Some((name, Some(value(chars)?))),
        Some(_) => None,
    }
}

/// A value after its `=`, up to the end of the line: quotes kept together,
/// escapes read, a comment dropped, whitespace trimmed at both ends and each
/// whitespace character inside made a space, as git does.
fn value(chars: &mut Peekable<Chars<'_>>) -> Option<String> {
    let mut out = String::new();
    let mut quoted = false;
    let mut spaces = 0_usize;
    while let Some(c) = chars.next() {
        let literal = match c {
            '\n' if quoted => return None,
            '\n' => break,
            '#' | ';' if !quoted => {
                skip_line(chars);
                break;
            }
            '"' => {
                quoted = !quoted;
                continue;
            }
            c if c.is_whitespace() && !quoted => {
                if !out.is_empty() {
                    spaces += 1;
                }
                continue;
            }
            '\\' => match chars.next() {
                Some('\n') => continue,
                Some('n') => '\n',
                Some('t') => '\t',
                Some('b') => '\u{8}',
                Some(c @ ('"' | '\\')) => c,
                _ => return None,
            },
            c => c,
        };
        out.extend(std::iter::repeat_n(' ', spaces));
        spaces = 0;
        out.push(literal);
    }
    (!quoted).then_some(out)
}

/// The program a helper value runs as `<program> git-credential`, in the forms git
/// runs it in: through the shell (`!` then the program single-quoted, as
/// `warden setup github` writes it, or plain), or as an absolute path without `!`.
/// `None` for any other value, including a program with characters the shell would
/// read otherwise.
#[must_use]
pub fn helper_program(value: &str) -> Option<String> {
    let (shell, rest) = match value.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, value),
    };
    let program = rest.strip_suffix(" git-credential")?;
    if shell && program.starts_with('\'') {
        return unquote(program);
    }
    let plain = !program.is_empty()
        && program
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+,:@%".contains(c));
    // Without `!`, git runs only an absolute path itself; anything else names a
    // `git credential-<name>` command.
    (plain && (shell || program.starts_with('/'))).then(|| program.to_owned())
}

/// `quoted` read as the shell reads single-quoted parts joined by `\'`.
fn unquote(quoted: &str) -> Option<String> {
    let mut program = String::new();
    let mut rest = quoted;
    loop {
        // A quoted part, then either the end or an escaped quote and another part.
        let inner = rest.strip_prefix('\'')?;
        let end = inner.find('\'')?;
        program.push_str(&inner[..end]);
        rest = &inner[end + 1..];
        if rest.is_empty() {
            return Some(program);
        }
        rest = rest.strip_prefix("\\'")?;
        program.push('\'');
        if rest.is_empty() {
            return Some(program);
        }
    }
}

#[cfg(test)]
mod tests;
