//! The wrappers that only run another program (`sudo`, `env`, …) and the
//! options of theirs that take a value.

/// How one wrapper reads its options.
struct Wrapper {
    /// Options whose value is the next word (`--name=value` needs nothing).
    value_options: &'static [&'static str],
    /// Options whose value is a string of shell words to run.
    split_options: &'static [&'static str],
    /// `NAME=value` words follow the options.
    assignments: bool,
    /// `-v` and `-V` only look a name up and run nothing.
    lookup_only: bool,
}

const NONE: &[&str] = &[];

fn wrapper(name: &str) -> Option<Wrapper> {
    let plain = |value_options| Wrapper {
        value_options,
        split_options: NONE,
        assignments: false,
        lookup_only: false,
    };
    Some(match name {
        "sudo" => plain(&[
            "-u",
            "-g",
            "-h",
            "-p",
            "-C",
            "-D",
            "-r",
            "-t",
            "-R",
            "-T",
            "-U",
            "--user",
            "--group",
            "--host",
            "--prompt",
            "--chdir",
            "--role",
            "--type",
            "--other-user",
            "--chroot",
            "--command-timeout",
            "--close-from",
        ]),
        "env" => Wrapper {
            value_options: &["-u", "-C", "-S", "--unset", "--chdir", "--split-string"],
            split_options: &["-S", "--split-string"],
            assignments: true,
            lookup_only: false,
        },
        "exec" => plain(&["-a"]),
        "time" => plain(&["-f", "-o", "--format", "--output"]),
        "nohup" => plain(NONE),
        "command" => Wrapper {
            lookup_only: true,
            ..plain(NONE)
        },
        _ => return None,
    })
}

/// The words after the leading wrappers and options of `argv`, and the strings
/// of shell words the options handed to the program (`env -S`). A wrapper that
/// only looks a name up leaves no words.
pub(super) fn unwrap(argv: &[String]) -> (&[String], Vec<&str>) {
    let mut rest = argv;
    let mut strings = Vec::new();
    loop {
        let [first, tail @ ..] = rest else {
            return (rest, strings);
        };
        let name = first.rsplit('/').next().unwrap_or(first);
        let Some(wrapper) = wrapper(name) else {
            return (rest, strings);
        };
        match skip_options(tail, &wrapper, &mut strings) {
            Some(words) => rest = words,
            None => return (&[], strings),
        }
    }
}

fn skip_options<'a>(
    mut words: &'a [String],
    wrapper: &Wrapper,
    strings: &mut Vec<&'a str>,
) -> Option<&'a [String]> {
    while let [word, tail @ ..] = words {
        if word == "--" {
            return Some(tail);
        }
        if word.starts_with('-') && word.len() > 1 {
            if wrapper.lookup_only && (word == "-v" || word == "-V") {
                return None;
            }
            let option = word.as_str();
            if wrapper.value_options.contains(&option) {
                if wrapper.split_options.contains(&option)
                    && let Some(value) = tail.first()
                {
                    strings.push(value);
                }
                words = tail.get(1..).unwrap_or_default();
            } else {
                if let Some(value) = option.strip_prefix("--split-string=")
                    && !wrapper.split_options.is_empty()
                {
                    strings.push(value);
                }
                words = tail;
            }
        } else if wrapper.assignments && super::split_assignment(word).is_some() {
            words = tail;
        } else {
            break;
        }
    }
    Some(words)
}
