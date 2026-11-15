//! A forgiving reader for the parts of `~/.ssh/config` the hook needs: which
//! alias names a real host, and which `IdentityAgent` sockets a file names.
//!
//! It never fails and never panics: text it does not understand is skipped.

use std::collections::HashMap;

/// Reads an included file: gets the include's raw argument, returns the text.
pub type IncludeReader<'a> = dyn Fn(&str) -> Option<String> + 'a;

/// `Host` aliases mapped to their `HostName`, lowercased by alias.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SshAliases {
    hosts: HashMap<String, String>,
}

/// One logical line of a config: its keyword (lowercased) and its value.
fn split_line(line: &str) -> Option<(String, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let (keyword, rest) = line.split_at(end);
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim();
    Some((keyword.to_ascii_lowercase(), rest))
}

/// The value with one pair of surrounding double quotes removed.
fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

/// Where in the file the reader is.
enum Block {
    /// Before any `Host` or `Match` line.
    Global,
    /// Inside a `Host` block, with its literal aliases (lowercased).
    Host(Vec<String>),
    /// Inside a `Match` block, which the hook ignores.
    Match,
}

/// Whether a `Host` pattern names one host rather than a set of them.
fn is_literal(pattern: &str) -> bool {
    !pattern.is_empty() && !pattern.starts_with('!') && !pattern.contains(['*', '?'])
}

impl SshAliases {
    /// Reads `text`, resolving one level of `Include` through `include`,
    /// which gets the include's raw argument and returns the file's text.
    #[must_use]
    pub fn parse(text: &str, include: &IncludeReader<'_>) -> Self {
        let mut aliases = Self::default();
        aliases.read(text, Some(include));
        aliases
    }

    /// The `HostName` the config gives `alias`, if it declares one.
    #[must_use]
    pub fn host_for(&self, alias: &str) -> Option<&str> {
        self.hosts
            .get(&alias.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// Reads one file. `include` is `None` inside an included file, so
    /// includes go one level deep only.
    fn read(&mut self, text: &str, include: Option<&IncludeReader<'_>>) {
        let mut block = Block::Global;
        for line in text.lines() {
            let Some((keyword, value)) = split_line(line) else {
                continue;
            };
            match keyword.as_str() {
                "host" => {
                    block = Block::Host(
                        value
                            .split_whitespace()
                            .map(unquote)
                            .filter(|p| is_literal(p))
                            .map(str::to_ascii_lowercase)
                            .collect(),
                    );
                }
                "match" => block = Block::Match,
                "hostname" => {
                    if let Block::Host(names) = &block {
                        let host = unquote(value);
                        if !host.is_empty() {
                            for name in names {
                                // ssh uses the first value it finds.
                                self.hosts
                                    .entry(name.clone())
                                    .or_insert_with(|| host.to_owned());
                            }
                        }
                    }
                }
                "include" => {
                    if let Some(include) = include {
                        for path in value.split_whitespace().map(unquote) {
                            if let Some(included) = include(path) {
                                self.read(&included, None);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Every `IdentityAgent` value in `text`, unquoted and unexpanded.
pub(super) fn identity_agents(text: &str) -> Vec<&str> {
    text.lines()
        .filter_map(split_line)
        .filter(|(keyword, _)| keyword == "identityagent")
        .map(|(_, value)| unquote(value))
        .collect()
}
