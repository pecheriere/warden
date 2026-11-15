//! A small option reader shared by the per-tool detectors.
//!
//! It is not any tool's real parser: it only has to tell options, their values
//! and positional words apart well enough to find a destination or a flag.

/// One word group of a command line.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Item<'a> {
    /// An option (`-i`, `--header`) and its value, when it takes one.
    Opt {
        /// The option as written, with its dashes (`-H`, `--header`).
        name: String,
        /// The value, from the same word or the next one.
        value: Option<&'a str>,
    },
    /// A word that is not an option or an option's value.
    Positional(&'a str),
}

/// Reads `args`. `short_values` lists the short option letters that take a
/// value; `long_values` the long options that do. A short cluster (`-vvv`,
/// `-sSH x`) is split into letters up to the first one that takes a value,
/// whose value is the rest of the word or the next word. `--` ends options.
pub(super) fn read<'a>(
    args: &'a [String],
    short_values: &str,
    long_values: &[&str],
) -> Vec<Item<'a>> {
    let mut items = Vec::new();
    let mut words = args.iter().map(String::as_str);
    let mut only_positional = false;
    while let Some(word) = words.next() {
        if only_positional || !word.starts_with('-') || word == "-" {
            items.push(Item::Positional(word));
        } else if word == "--" {
            only_positional = true;
        } else if let Some(long) = word.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            let value = if inline.is_some() {
                inline
            } else if long_values.contains(&name) {
                words.next()
            } else {
                None
            };
            items.push(Item::Opt {
                name: format!("--{name}"),
                value,
            });
        } else {
            for (at, letter) in word.char_indices().skip(1) {
                let name = format!("-{letter}");
                if short_values.contains(letter) {
                    let rest = &word[at + letter.len_utf8()..];
                    let value = if rest.is_empty() {
                        words.next()
                    } else {
                        Some(rest)
                    };
                    items.push(Item::Opt { name, value });
                    break;
                }
                items.push(Item::Opt { name, value: None });
            }
        }
    }
    items
}

/// The program's name without its directory.
pub(super) fn program_name(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// Whether `host` is shaped like a host name or address, which is all a
/// subject may be: hosts of a command are only reported when they are plain.
pub(super) fn is_plain_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('-')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Whether `host` is the machine itself, which no policy covers.
pub(super) fn is_loopback(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    matches!(host.as_str(), "localhost" | "0.0.0.0" | "[::]" | "::") || host.starts_with("127.")
}
