//! The report of the `doctor` commands, shared by `warden-server doctor` and
//! `warden doctor`: each check passed, failed or could not be checked, and
//! the exit code says which of those the run ended with.
//!
//! Could-not-check is never a pass: it has its own label in the output, and
//! the summary lists each one with what to do by hand. It only changes the exit
//! code with `--strict`, so that a healthy setup can exit 0. A report without
//! any check counts as could-not-check either way.

use std::fmt::Write as _;

use unicode_properties::{GeneralCategory, UnicodeGeneralCategory as _};

/// Exit code: no check failed. Some may not have run: the report lists them.
pub const EXIT_NOTHING_FAILED: u8 = 0;
/// Exit code: at least one check failed.
pub const EXIT_FAILED: u8 = 1;
/// Exit code, with `--strict` only: no check failed, but at least one could
/// not be checked. Not 2,
/// which is how the argument parser reports a usage error.
pub const EXIT_COULD_NOT_CHECK: u8 = 7;

/// What one check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The check ran and the result is good.
    Pass,
    /// The check ran and the result is bad.
    Fail,
    /// The check could not determine the result.
    CouldNotCheck,
}

impl Status {
    const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "FAIL",
            Self::CouldNotCheck => "COULD NOT CHECK",
        }
    }
}

/// One line of a report. A check that did not pass always says what to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Stable name of the check, for example `connect.vault`.
    pub name: String,
    /// What it found.
    pub status: Status,
    /// What was seen. May hold text from an upstream: [`Report::render`]
    /// makes it safe to print on a terminal.
    pub detail: String,
    /// What the owner should do, when the check did not pass.
    pub action: Option<String>,
}

impl Check {
    /// A check that passed.
    #[must_use]
    pub fn pass(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: Status::Pass,
            detail: detail.into(),
            action: None,
        }
    }

    /// A check that failed, and how to fix it.
    #[must_use]
    pub fn fail(
        name: impl Into<String>,
        detail: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: Status::Fail,
            detail: detail.into(),
            action: Some(action.into()),
        }
    }

    /// A check that could not run, and what to do by hand instead.
    #[must_use]
    pub fn could_not_check(
        name: impl Into<String>,
        detail: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: Status::CouldNotCheck,
            detail: detail.into(),
            action: Some(action.into()),
        }
    }
}

/// The result of one `doctor` run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The command, shown as the heading.
    pub title: String,
    /// The checks, in the order they ran.
    pub checks: Vec<Check>,
    /// What the run did, in one sentence: what it sent and what it changed.
    pub effects: String,
}

impl Report {
    fn count(&self, status: Status) -> usize {
        self.checks.iter().filter(|c| c.status == status).count()
    }

    /// The exit code of this report: see the `EXIT_*` constants. Only with
    /// `strict` does a check that could not run change it, except that a
    /// report with no check at all has shown nothing and never exits 0.
    #[must_use]
    pub fn exit_code(&self, strict: bool) -> u8 {
        if self.count(Status::Fail) > 0 {
            EXIT_FAILED
        } else if self.checks.is_empty() || (strict && self.count(Status::CouldNotCheck) > 0) {
            EXIT_COULD_NOT_CHECK
        } else {
            EXIT_NOTHING_FAILED
        }
    }

    /// The report as text for a terminal or a log, without colour, with the
    /// exit code `strict` gives. All text goes through [`sanitize`].
    #[must_use]
    pub fn render(&self, strict: bool) -> String {
        let width = self
            .checks
            .iter()
            .map(|c| c.name.chars().count())
            .max()
            .unwrap_or(0);
        let label_width = Status::CouldNotCheck.label().len();
        let indent = " ".repeat(label_width + 2);
        let mut out = format!("{}\n\n", sanitize(&self.title));
        for check in &self.checks {
            let label = check.status.label();
            let name = sanitize(&check.name);
            let detail = sanitize(&check.detail);
            // Writing to a String cannot fail.
            let _ = writeln!(out, "{label:<label_width$}  {name:<width$}  {detail}");
            if let Some(action) = &check.action {
                let _ = writeln!(out, "{indent}to do: {}", sanitize(action));
            }
        }
        let _ = writeln!(
            out,
            "\nResult: {} passed, {} failed, {} could not be checked. Exit code {}.",
            self.count(Status::Pass),
            self.count(Status::Fail),
            self.count(Status::CouldNotCheck),
            self.exit_code(strict)
        );
        let unchecked = self.count(Status::CouldNotCheck);
        if unchecked > 0 {
            let hint = if strict {
                ""
            } else {
                " --strict makes them exit 7."
            };
            let _ = writeln!(
                out,
                "\nNot checked, so not passed: {unchecked}. Do these by hand.{hint}"
            );
            for check in self
                .checks
                .iter()
                .filter(|c| c.status == Status::CouldNotCheck)
            {
                let action = check.action.as_deref().unwrap_or("Check this by hand.");
                let _ = writeln!(out, "  {}: {}", sanitize(&check.name), sanitize(action));
            }
        }
        let _ = writeln!(out, "What this run did: {}", sanitize(&self.effects));
        out
    }
}

/// `text` safe to print on a terminal: control characters (C0, C1),
/// invisible format characters (bidi overrides, zero-width marks) and line
/// and paragraph separators are each replaced by `?`.
#[must_use]
pub fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| {
            let unsafe_char = c.is_control()
                || matches!(
                    c.general_category(),
                    GeneralCategory::Format
                        | GeneralCategory::LineSeparator
                        | GeneralCategory::ParagraphSeparator
                );
            if unsafe_char { '?' } else { c }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        Check, EXIT_COULD_NOT_CHECK, EXIT_FAILED, EXIT_NOTHING_FAILED, Report, Status, sanitize,
    };

    fn report(checks: Vec<Check>) -> Report {
        Report {
            title: "doctor".to_owned(),
            checks,
            effects: "nothing".to_owned(),
        }
    }

    #[test]
    fn all_passed_exits_zero_even_when_strict() {
        let report = report(vec![Check::pass("a", "fine")]);
        assert_eq!(report.exit_code(false), EXIT_NOTHING_FAILED);
        assert_eq!(report.exit_code(true), EXIT_NOTHING_FAILED);
    }

    #[test]
    fn a_failure_outranks_could_not_check() {
        let report = report(vec![
            Check::could_not_check("a", "unknown", "look"),
            Check::fail("b", "bad", "fix"),
            Check::pass("c", "fine"),
        ]);
        assert_eq!(report.exit_code(false), EXIT_FAILED);
        assert_eq!(report.exit_code(true), EXIT_FAILED);
    }

    #[test]
    fn could_not_check_exits_zero_unless_strict() {
        let report = report(vec![
            Check::pass("a", "fine"),
            Check::could_not_check("b", "unknown", "look"),
        ]);
        assert_eq!(report.exit_code(false), EXIT_NOTHING_FAILED);
        assert_eq!(report.exit_code(true), EXIT_COULD_NOT_CHECK);
    }

    #[test]
    fn an_empty_report_is_not_a_pass() {
        assert_eq!(report(vec![]).exit_code(false), EXIT_COULD_NOT_CHECK);
        assert_eq!(report(vec![]).exit_code(true), EXIT_COULD_NOT_CHECK);
    }

    #[test]
    fn the_exit_code_cannot_be_mistaken_for_a_usage_error() {
        // clap exits 2 on a usage error.
        assert_ne!(EXIT_COULD_NOT_CHECK, 2);
        assert_ne!(EXIT_FAILED, 2);
    }

    #[test]
    fn could_not_check_looks_different_from_a_pass() {
        let report = report(vec![
            Check::pass("first", "seen"),
            Check::could_not_check("second", "unknown", "look by hand"),
        ]);
        for strict in [false, true] {
            let text = report.render(strict);
            let line = text.lines().find(|l| l.contains("second")).unwrap();
            assert!(line.starts_with("COULD NOT CHECK"), "{line}");
            assert!(text.contains("to do: look by hand"), "{text}");
        }
    }

    #[test]
    fn the_summary_lists_what_was_not_checked_even_when_exiting_zero() {
        let report = report(vec![
            Check::pass("first", "seen"),
            Check::could_not_check("second", "unknown", "look by hand"),
        ]);
        let text = report.render(false);
        assert!(
            text.contains("1 passed, 0 failed, 1 could not be checked. Exit code 0."),
            "{text}"
        );
        assert!(text.contains("Not checked, so not passed: 1."), "{text}");
        assert!(text.contains("  second: look by hand"), "{text}");
        assert!(!text.contains("  first:"), "{text}");
        assert!(text.contains("--strict"), "{text}");
        let strict = report.render(true);
        assert!(strict.contains("Exit code 7."), "{strict}");
        assert!(strict.contains("  second: look by hand"), "{strict}");
    }

    #[test]
    fn with_everything_checked_there_is_no_list() {
        let text = report(vec![Check::pass("a", "fine")]).render(false);
        assert!(!text.contains("Not checked"), "{text}");
    }

    #[test]
    fn render_says_what_the_run_did() {
        let text = report(vec![Check::pass("a", "fine")]).render(false);
        assert!(text.contains("What this run did: nothing"), "{text}");
    }

    #[test]
    fn upstream_text_cannot_forge_lines_or_escape_codes() {
        let check = Check {
            name: "a".to_owned(),
            status: Status::Fail,
            detail: "bad\npass  forged\u{1b}[2J\u{202e}".to_owned(),
            action: Some("fix\r\nthis".to_owned()),
        };
        let text = report(vec![check]).render(false);
        assert!(!text.contains('\u{1b}'), "{text}");
        assert!(!text.contains('\u{202e}'), "{text}");
        assert!(text.contains("bad?pass  forged?[2J?"), "{text}");
        assert!(text.contains("fix??this"), "{text}");
    }

    #[test]
    fn sanitize_replaces_control_format_and_separator_characters() {
        assert_eq!(sanitize("plain text: ok"), "plain text: ok");
        // C0 and C1 controls.
        assert_eq!(sanitize("a\u{1b}[31mb\r\n\0"), "a?[31mb???");
        assert_eq!(sanitize("a\u{9b}2Jb\u{85}"), "a?2Jb?");
        // Format characters: bidi overrides and isolates, zero-width.
        assert_eq!(sanitize("x\u{202e}y\u{2066}z\u{200b}w\u{feff}"), "x?y?z?w?");
        // Line and paragraph separators.
        assert_eq!(sanitize("x\u{2028}y\u{2029}z"), "x?y?z");
        // Other non-ASCII text is kept.
        assert_eq!(
            sanitize("caf\u{e9} \u{5e9}\u{5dc}"),
            "caf\u{e9} \u{5e9}\u{5dc}"
        );
    }
}
