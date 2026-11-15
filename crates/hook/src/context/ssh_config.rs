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
#[derive(Clone)]
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

/// `HostName` with `%h` replaced by the alias and `%%` by `%`; any other
/// `%` token stays literal.
fn expand_tokens(value: &str, alias: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.clone().next() {
            Some('h') => {
                chars.next();
                out.push_str(alias);
            }
            Some('%') => {
                chars.next();
                out.push('%');
            }
            _ => out.push('%'),
        }
    }
    out
}

impl SshAliases {
    /// Reads `text`, resolving one level of `Include` through `include`.
    /// The callback gets the include's raw argument (as written, `~` and
    /// all) and returns the file's text; the caller resolves `~`, paths
    /// relative to `~/.ssh` and globs. An `Include` inside a `Host` block is
    /// read in that block's context, as `ssh` does.
    #[must_use]
    pub fn parse(text: &str, include: &IncludeReader<'_>) -> Self {
        let mut aliases = Self::default();
        aliases.read(text, Some(include), Block::Global);
        aliases
    }

    /// The `HostName` the config gives `alias`, if it declares one.
    #[must_use]
    pub fn host_for(&self, alias: &str) -> Option<&str> {
        self.hosts
            .get(&alias.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// Reads one file, starting in `block`. `include` is `None` inside an
    /// included file, so includes go one level deep only.
    fn read(&mut self, text: &str, include: Option<&IncludeReader<'_>>, start: Block) {
        let mut block = start;
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
                                    .or_insert_with(|| expand_tokens(host, name));
                            }
                        }
                    }
                }
                "include" => {
                    if let Some(include) = include {
                        for path in value.split_whitespace().map(unquote) {
                            if let Some(included) = include(path) {
                                self.read(&included, None, block.clone());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// What a config file that routes through warden declares.
pub(super) struct WardenShape<'a> {
    /// Every `IdentityAgent` value, unquoted and unexpanded.
    pub agents: Vec<&'a str>,
    /// The literal `Host` names, lowercased.
    pub hosts: Vec<String>,
}

/// The agents and host names of `text`, or `None` when it uses anything
/// warden's own file never does: `Include`, `Match`, `ProxyCommand`,
/// `ProxyJump`, or an `IdentityFile` other than `none`.
pub(super) fn warden_shape(text: &str) -> Option<WardenShape<'_>> {
    let mut shape = WardenShape {
        agents: Vec::new(),
        hosts: Vec::new(),
    };
    for (keyword, value) in text.lines().filter_map(split_line) {
        match keyword.as_str() {
            "include" | "match" | "proxycommand" | "proxyjump" => return None,
            "identityfile" if !unquote(value).eq_ignore_ascii_case("none") => return None,
            "identityagent" => shape.agents.push(unquote(value)),
            "host" => shape.hosts.extend(
                value
                    .split_whitespace()
                    .map(unquote)
                    .filter(|p| is_literal(p))
                    .map(str::to_ascii_lowercase),
            ),
            _ => {}
        }
    }
    Some(shape)
}
