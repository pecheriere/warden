//! A best-effort splitter of shell text into simple commands.
//!
//! It is not a shell: it only has to show which programs a command line could
//! run, so detection can look at their arguments. It never panics, and on
//! input it cannot parse (an unterminated quote, say) it returns what it could
//! split.

mod prefix;

/// The deepest `$(…)` or backtick nesting that is followed.
const MAX_SUBSTITUTION_DEPTH: u8 = 4;

/// Words that start or end a compound command without being a program.
const RESERVED_WORDS: [&str; 13] = [
    "{", "}", "!", "if", "then", "else", "elif", "fi", "while", "until", "do", "done", "esac",
];

/// One command with its leading `NAME=value` assignments and its words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleCommand {
    /// The leading `NAME=value` assignments, in order.
    pub env: Vec<(String, String)>,
    /// The program and its arguments, unquoted, redirections removed.
    pub argv: Vec<String>,
}

/// Splits `input` into the simple commands it contains, including those inside
/// `$(…)`, backticks and `bash -c '…'` strings. A command comes before the
/// commands nested in it. Assignment-only commands are dropped.
#[must_use]
pub fn simple_commands(input: &str) -> Vec<SimpleCommand> {
    parse(input, 0, 0)
}

/// The words of `command` after the wrappers that only run another program:
/// `sudo`, `env`, `nohup`, `exec`, `command` and `time`, with their options (and
/// the values of those that take one) and, for `env`, their `NAME=value` words.
/// `command -v` and `command -V` only look a name up, so they leave nothing.
#[must_use]
pub fn effective_argv(command: &SimpleCommand) -> &[String] {
    prefix::unwrap(&command.argv).0
}

fn split_assignment(word: &str) -> Option<(&str, &str)> {
    let (name, value) = word.split_once('=')?;
    let mut chars = name.chars();
    let first = chars.next()?;
    let valid = (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    valid.then_some((name, value))
}

/// The scripts `command` runs through the shell itself: a `bash -c` string, the
/// joined arguments of `eval` and an `env -S` string.
fn nested_scripts(command: &SimpleCommand) -> Vec<String> {
    let (words, mut scripts) = prefix::unwrap(&command.argv);
    scripts.retain(|script| !script.is_empty());
    let mut scripts: Vec<String> = scripts;
    if let [program, args @ ..] = words {
        let name = program.rsplit('/').next().unwrap_or(program);
        if name == "eval" {
            let joined = args.join(" ");
            if !joined.trim().is_empty() {
                scripts.push(joined);
            }
        } else if matches!(name, "bash" | "sh" | "zsh" | "dash")
            && let Some(script) = shell_c_string(args)
        {
            scripts.push(script.to_string());
        }
    }
    scripts
}

/// The `-c` string among a shell's options, skipping `-x`, `+x`, `-o name`,
/// `+o name` and flag clusters such as `-ec`.
fn shell_c_string(options: &[String]) -> Option<&str> {
    let mut options = options.iter();
    while let Some(arg) = options.next() {
        if arg == "--" || !(arg.starts_with('-') || arg.starts_with('+')) {
            return None;
        }
        if matches!(arg.as_str(), "--rcfile" | "--init-file") {
            options.next();
        } else if arg.starts_with("--") {
            // A long option without a value: nothing to do.
        } else if arg.starts_with('-') && arg.contains('c') {
            return options.next().map(String::as_str);
        } else if arg.contains('o') {
            options.next();
        }
    }
    None
}

fn parse(input: &str, depth: u8, shell_nesting: u8) -> Vec<SimpleCommand> {
    let mut scanner = Scanner {
        chars: input.chars().collect(),
        pos: 0,
        depth,
        shell_nesting,
        out: Vec::new(),
        words: Vec::new(),
        word: String::new(),
        in_word: false,
        quoted: false,
        redirect_target: false,
        nested: Vec::new(),
        heredocs: Vec::new(),
        paren_close: None,
    };
    scanner.run();
    scanner.out
}

struct Heredoc {
    delimiter: String,
    strip_tabs: bool,
}

struct Scanner {
    chars: Vec<char>,
    /// For each `(` outside quotes, the index of the `)` that closes it
    /// (`usize::MAX` when none does); built once, on the first `((` at the
    /// start of a command, so that scanning for `))` stays linear.
    paren_close: Option<Vec<usize>>,
    pos: usize,
    depth: u8,
    /// 1 inside a `bash -c` string, which is not recursed into again.
    shell_nesting: u8,
    out: Vec<SimpleCommand>,
    words: Vec<String>,
    word: String,
    in_word: bool,
    /// Whether the current word has any quoting or escaping in it.
    quoted: bool,
    /// The next word is a redirection's target and is dropped.
    redirect_target: bool,
    /// Commands found in substitutions of the command being read.
    nested: Vec<SimpleCommand>,
    heredocs: Vec<Heredoc>,
}

impl Scanner {
    fn peek(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos.checked_add(offset)?).copied()
    }

    fn run(&mut self) {
        while let Some(c) = self.peek(0) {
            self.pos += 1;
            match c {
                ' ' | '\t' => self.end_word(),
                '\n' => {
                    self.end_command();
                    self.skip_heredoc_bodies();
                }
                '(' => self.open_paren(),
                ';' | ')' => self.end_command(),
                '&' => {
                    if self.peek(0) == Some('>') {
                        self.pos += 1;
                        self.end_word();
                        self.redirect_target = true;
                    } else {
                        if self.peek(0) == Some('&') {
                            self.pos += 1;
                        }
                        self.end_command();
                    }
                }
                '|' => {
                    if matches!(self.peek(0), Some('|' | '&')) {
                        self.pos += 1;
                    }
                    self.end_command();
                }
                '<' | '>' => self.redirect(c),
                '#' if !self.in_word => self.skip_comment(),
                _ => self.word_char(c),
            }
        }
        self.end_command();
    }

    /// A `(`: arithmetic `((…))` at the start of a command is skipped, `name()`
    /// is a function definition and anything else opens a subshell.
    fn open_paren(&mut self) {
        self.end_word();
        if self.words.is_empty()
            && self.peek(0) == Some('(')
            && let Some(end) = self.arithmetic_end()
        {
            self.pos = end + 1;
        } else if self.words.len() == 1 && self.peek(0) == Some(')') && !self.redirect_target {
            self.words.clear();
            self.pos += 1;
        } else {
            self.end_command();
        }
    }

    /// The index of the final `)` of an `((…))` whose second `(` is next, if
    /// it is closed by `))`.
    fn arithmetic_end(&mut self) -> Option<usize> {
        let first = self.pos.checked_sub(1)?;
        let end = *self.paren_closes().get(first)?;
        (end != usize::MAX && self.chars.get(end.checked_sub(1)?) == Some(&')')).then_some(end)
    }

    /// The closing `)` of every `(`, found in one forward pass. Quotes and
    /// backslashes hide parentheses the way [`Self::matching_paren`] reads
    /// them.
    fn paren_closes(&mut self) -> &[usize] {
        if self.paren_close.is_none() {
            let mut close = vec![usize::MAX; self.chars.len()];
            let mut open = Vec::new();
            let mut i = 0;
            while let Some(&c) = self.chars.get(i) {
                match c {
                    '\\' => i += 1,
                    '\'' => i = self.skip_quote(i, '\''),
                    '"' => i = self.skip_quote(i, '"'),
                    '(' => open.push(i),
                    ')' => {
                        if let Some(at) = open.pop()
                            && let Some(slot) = close.get_mut(at)
                        {
                            *slot = i;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            self.paren_close = Some(close);
        }
        self.paren_close.as_deref().unwrap_or_default()
    }

    fn word_char(&mut self, c: char) {
        match c {
            '\'' => self.single_quoted(),
            '"' => self.double_quoted(),
            '\\' => match self.peek(0) {
                Some('\n') => self.pos += 1,
                Some(next) => {
                    self.pos += 1;
                    self.in_word = true;
                    self.quoted = true;
                    self.word.push(next);
                }
                None => {}
            },
            '`' => self.backticks(),
            '$' if self.peek(0) == Some('(') => {
                self.pos += 1;
                self.dollar_paren();
            }
            _ => {
                self.in_word = true;
                self.word.push(c);
            }
        }
    }

    fn single_quoted(&mut self) {
        self.in_word = true;
        self.quoted = true;
        while let Some(c) = self.peek(0) {
            self.pos += 1;
            if c == '\'' {
                break;
            }
            self.word.push(c);
        }
    }

    fn double_quoted(&mut self) {
        self.in_word = true;
        self.quoted = true;
        while let Some(c) = self.peek(0) {
            self.pos += 1;
            match c {
                '"' => break,
                '\\' => match self.peek(0) {
                    Some('\n') => self.pos += 1,
                    Some(next @ ('$' | '`' | '"' | '\\')) => {
                        self.pos += 1;
                        self.word.push(next);
                    }
                    _ => self.word.push('\\'),
                },
                '`' => self.backticks(),
                '$' if self.peek(0) == Some('(') => {
                    self.pos += 1;
                    self.dollar_paren();
                }
                _ => self.word.push(c),
            }
        }
    }

    /// After `$(`: the text up to the matching `)` joins the word, and its
    /// commands are recorded. `$((…))` arithmetic is skipped.
    fn dollar_paren(&mut self) {
        self.in_word = true;
        let arithmetic = self.peek(0) == Some('(');
        let start = self.pos;
        let end = self.matching_paren(start);
        let inner: String = self
            .chars
            .get(start..end)
            .unwrap_or_default()
            .iter()
            .collect();
        self.pos = end.saturating_add(1).min(self.chars.len());
        if !arithmetic {
            self.substitution(&inner);
        }
    }

    fn backticks(&mut self) {
        self.in_word = true;
        let mut inner = String::new();
        while let Some(c) = self.peek(0) {
            self.pos += 1;
            match c {
                '`' => break,
                '\\' if matches!(self.peek(0), Some('`' | '\\' | '$')) => {
                    if let Some(next) = self.peek(0) {
                        inner.push(next);
                    }
                    self.pos += 1;
                }
                _ => inner.push(c),
            }
        }
        self.substitution(&inner);
    }

    fn substitution(&mut self, inner: &str) {
        self.word.push_str(inner);
        if self.depth < MAX_SUBSTITUTION_DEPTH {
            let found = parse(inner, self.depth + 1, self.shell_nesting);
            self.nested.extend(found);
        }
    }

    /// The index of the `)` closing a `$(` whose body starts at `start`, or
    /// the end of input.
    fn matching_paren(&self, start: usize) -> usize {
        let mut open = 1_usize;
        let mut i = start;
        while let Some(&c) = self.chars.get(i) {
            match c {
                '\\' => i += 1,
                '\'' => i = self.skip_quote(i, '\''),
                '"' => i = self.skip_quote(i, '"'),
                '(' => open += 1,
                ')' => {
                    open -= 1;
                    if open == 0 {
                        return i;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        self.chars.len()
    }

    /// The index of the quote closing the one at `i`, or the end of input.
    fn skip_quote(&self, mut i: usize, quote: char) -> usize {
        i += 1;
        while let Some(&c) = self.chars.get(i) {
            if c == quote {
                return i;
            }
            if c == '\\' && quote == '"' {
                i += 1;
            }
            i += 1;
        }
        self.chars.len()
    }

    fn skip_comment(&mut self) {
        while let Some(c) = self.peek(0) {
            if c == '\n' {
                break;
            }
            self.pos += 1;
        }
    }

    fn redirect(&mut self, c: char) {
        // `2>f`: a file descriptor number in front belongs to the operator.
        if self.in_word && !self.quoted && self.word.chars().all(|d| d.is_ascii_digit()) {
            self.word.clear();
            self.in_word = false;
        } else {
            self.end_word();
        }
        if c == '<' && self.peek(0) == Some('<') {
            self.pos += 1;
            if self.peek(0) == Some('<') {
                self.pos += 1;
                self.redirect_target = true;
            } else {
                self.heredoc_operator();
            }
            return;
        }
        if self.peek(0) == Some(c) || matches!(self.peek(0), Some('&' | '|')) {
            self.pos += 1;
        }
        self.redirect_target = true;
    }

    /// After `<<`: reads the delimiter word and queues the body to skip.
    fn heredoc_operator(&mut self) {
        let strip_tabs = self.peek(0) == Some('-');
        if strip_tabs {
            self.pos += 1;
        }
        while matches!(self.peek(0), Some(' ' | '\t')) {
            self.pos += 1;
        }
        let mut delimiter = String::new();
        while let Some(c) = self.peek(0) {
            if c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>') {
                break;
            }
            self.pos += 1;
            match c {
                '\'' | '"' => {
                    while let Some(q) = self.peek(0) {
                        self.pos += 1;
                        if q == c {
                            break;
                        }
                        delimiter.push(q);
                    }
                }
                '\\' => {
                    if let Some(next) = self.peek(0) {
                        self.pos += 1;
                        delimiter.push(next);
                    }
                }
                _ => delimiter.push(c),
            }
        }
        self.heredocs.push(Heredoc {
            delimiter,
            strip_tabs,
        });
    }

    fn skip_heredoc_bodies(&mut self) {
        for heredoc in std::mem::take(&mut self.heredocs) {
            while self.pos < self.chars.len() {
                let start = self.pos;
                let end = self
                    .chars
                    .get(start..)
                    .unwrap_or_default()
                    .iter()
                    .position(|&c| c == '\n')
                    .map_or(self.chars.len(), |n| start + n);
                self.pos = (end + 1).min(self.chars.len());
                let line: String = self
                    .chars
                    .get(start..end)
                    .unwrap_or_default()
                    .iter()
                    .collect();
                let line = if heredoc.strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    line.as_str()
                };
                if line == heredoc.delimiter {
                    break;
                }
            }
        }
    }

    fn end_word(&mut self) {
        if !self.in_word {
            return;
        }
        let word = std::mem::take(&mut self.word);
        let quoted = std::mem::take(&mut self.quoted);
        self.in_word = false;
        if self.redirect_target {
            self.redirect_target = false;
        } else if !quoted && self.words.is_empty() && RESERVED_WORDS.contains(&word.as_str()) {
            // `{`, `!`, `then` and the like start a command without being one.
        } else if !quoted && word == "{" && self.words.len() == 2 && self.words[0] == "function" {
            // `function name {`: the definition's header is not a command.
            self.words.clear();
        } else {
            self.words.push(word);
        }
    }

    fn end_command(&mut self) {
        self.end_word();
        self.redirect_target = false;
        let mut words = std::mem::take(&mut self.words);
        let mut env = Vec::new();
        let mut taken = 0;
        for word in &words {
            let Some((name, value)) = split_assignment(word) else {
                break;
            };
            env.push((name.to_string(), value.to_string()));
            taken += 1;
        }
        let mut argv = words.split_off(taken);
        if argv
            .first()
            .is_some_and(|word| matches!(word.as_str(), "for" | "case" | "select"))
        {
            // A loop or `case` header runs no program.
            argv.clear();
        }
        let mut found = Vec::new();
        if argv.is_empty() {
            found.append(&mut self.nested);
        } else {
            let command = SimpleCommand { env, argv };
            let scripts = if self.shell_nesting == 0 {
                nested_scripts(&command)
            } else {
                Vec::new()
            };
            found.push(command);
            found.append(&mut self.nested);
            for script in scripts {
                found.extend(parse(&script, self.depth, 1));
            }
        }
        self.out.extend(found);
    }
}

#[cfg(test)]
mod tests;
