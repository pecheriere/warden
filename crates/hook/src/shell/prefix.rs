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
    /// Positional words that follow the options and are not the program
    /// (`timeout`'s duration).
    skip_positionals: usize,
    /// The words after the options are a script, as for `eval`.
    rest_is_script: bool,
}

const NONE: &[&str] = &[];

fn wrapper(name: &str) -> Option<Wrapper> {
    let plain = |value_options| Wrapper {
        value_options,
        split_options: NONE,
        assignments: false,
        lookup_only: false,
        skip_positionals: 0,
        rest_is_script: false,
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
            split_options: &["-S", "--split-string"],
            assignments: true,
            ..plain(&["-u", "-C", "-S", "--unset", "--chdir", "--split-string"])
        },
        "exec" => plain(&["-a"]),
        "time" => plain(&["-f", "-o", "--format", "--output"]),
        "nohup" => plain(NONE),
        "timeout" => Wrapper {
            skip_positionals: 1,
            ..plain(&["-s", "-k", "--signal", "--kill-after"])
        },
        "nice" => plain(&["-n", "--adjustment"]),
        "ionice" => plain(&[
            "-c",
            "-n",
            "-p",
            "-P",
            "-u",
            "--class",
            "--classdata",
            "--pid",
        ]),
        "stdbuf" => plain(&["-i", "-o", "-e", "--input", "--output", "--error"]),
        "doas" => plain(&["-u", "-C"]),
        "xargs" => plain(&[
            "-I",
            "-n",
            "-P",
            "-L",
            "-d",
            "-E",
            "-s",
            "-a",
            "--max-args",
            "--max-procs",
            "--max-lines",
            "--delimiter",
            "--eof",
            "--max-chars",
            "--arg-file",
        ]),
        "watch" => Wrapper {
            rest_is_script: true,
            ..plain(&["-n", "--interval", "-q"])
        },
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
pub(super) fn unwrap(argv: &[String]) -> (&[String], Vec<String>) {
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
    strings: &mut Vec<String>,
) -> Option<&'a [String]> {
    while let [word, tail @ ..] = words {
        if word == "--" {
            words = tail;
            break;
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
                    strings.push(value.clone());
                }
                words = tail.get(1..).unwrap_or_default();
            } else {
                if let Some(value) = option.strip_prefix("--split-string=")
                    && !wrapper.split_options.is_empty()
                {
                    strings.push(value.to_owned());
                }
                words = tail;
            }
        } else if wrapper.assignments && super::split_assignment(word).is_some() {
            words = tail;
        } else {
            break;
        }
    }
    let words = words.get(wrapper.skip_positionals..).unwrap_or_default();
    if wrapper.rest_is_script {
        if !words.is_empty() {
            strings.push(words.join(" "));
        }
        return Some(&[]);
    }
    Some(words)
}
