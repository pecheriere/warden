//! A best-effort splitter of shell text into simple commands.
//!
//! It is not a shell: it only has to show which programs a command line could
//! run, so detection can look at their arguments. It never panics, and on
//! input it cannot parse (an unterminated quote, say) it returns what it could
//! split.

/// The deepest `$(…)` or backtick nesting that is followed.
const MAX_SUBSTITUTION_DEPTH: u8 = 4;

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
/// `sudo`, `env`, `nohup`, `exec`, `command` and `time`, with their options and
/// (for `env`) their `NAME=value` words.
#[must_use]
pub fn effective_argv(command: &SimpleCommand) -> &[String] {
    let mut rest = command.argv.as_slice();
    loop {
        let [first, tail @ ..] = rest else {
            return rest;
        };
        let name = first.rsplit('/').next().unwrap_or(first);
        let (value_options, assignments): (&[&str], bool) = match name {
            "sudo" => (
                &[
                    "-u", "-g", "-h", "-p", "-C", "-r", "-t", "-D", "-R", "-T", "-U",
                ],
                false,
            ),
            "env" => (&["-u", "-C", "-S"], true),
            "nohup" | "exec" | "command" | "time" => (&[], false),
            _ => return rest,
        };
        rest = skip_wrapper_options(tail, value_options, assignments);
    }
}

fn skip_wrapper_options<'a>(
    mut words: &'a [String],
    value_options: &[&str],
    assignments: bool,
) -> &'a [String] {
    while let [word, tail @ ..] = words {
        if word == "--" {
            return tail;
        }
        if word.starts_with('-') && word.len() > 1 {
            words = if value_options.contains(&word.as_str()) {
                tail.get(1..).unwrap_or_default()
            } else {
                tail
            };
        } else if assignments && is_assignment(word) {
            words = tail;
        } else {
            break;
        }
    }
    words
}

fn is_assignment(word: &str) -> bool {
    split_assignment(word).is_some()
}

fn split_assignment(word: &str) -> Option<(&str, &str)> {
    let (name, value) = word.split_once('=')?;
    let mut chars = name.chars();
    let first = chars.next()?;
    let valid = (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    valid.then_some((name, value))
}

fn is_shell(word: &str) -> bool {
    matches!(
        word.rsplit('/').next().unwrap_or(word),
        "bash" | "sh" | "zsh" | "dash"
    )
}

/// The script of a `bash -c '…'` command, if `command` is one.
fn shell_script(command: &SimpleCommand) -> Option<&str> {
    let words = effective_argv(command);
    let [shell, options @ ..] = words else {
        return None;
    };
    if !is_shell(shell) {
        return None;
    }
    let mut options = options.iter();
    while let Some(arg) = options.next() {
        if arg == "--" || !arg.starts_with('-') {
            return None;
        }
        if !arg.starts_with("--") && arg.contains('c') {
            return options.next().map(String::as_str);
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
                ';' | '(' | ')' => self.end_command(),
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
        self.in_word = false;
        self.quoted = false;
        if self.redirect_target {
            self.redirect_target = false;
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
        let argv = words.split_off(taken);
        let mut found = Vec::new();
        if argv.is_empty() {
            found.append(&mut self.nested);
        } else {
            let command = SimpleCommand { env, argv };
            let script = shell_script(&command).map(str::to_string);
            found.push(command);
            found.append(&mut self.nested);
            if let Some(script) = script
                && self.shell_nesting == 0
            {
                found.extend(parse(&script, self.depth, 1));
            }
        }
        self.out.extend(found);
    }
}

#[cfg(test)]
mod tests;
