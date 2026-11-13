//! The text `warden prime` prints: the blocks of `docs/agent-instructions.md`
//! fenced with four backticks and `markdown`, built into the CLI.
//!
//! In a block, markers each on their own line shape the text.
//! `<!-- warden:section <name> -->` and `<!-- warden:end -->` wrap a section,
//! printed only when the broker offers that kind of access; sections do not nest
//! and each appears once. `<!-- warden:offers -->` is where the offers go: once
//! outside the sections, and once in the brief section. Text in a block outside
//! any section always prints in the full text; text outside the blocks never
//! prints.

use std::collections::HashSet;
use std::fmt;

/// The document the instructions come from.
pub const DOC: &str = include_str!("../../../../docs/agent-instructions.md");

/// The line that opens an instruction block, and the one that closes it.
const FENCE_OPEN: &str = "````markdown";
const FENCE_CLOSE: &str = "````";
const MARKER_START: &str = "<!-- warden:";
const MARKER_END: &str = " -->";

/// A marked part of the instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Section {
    Ssh,
    Api,
    Signing,
    Github,
    Release,
    /// The short form, printed alone by `warden prime --brief`.
    Brief,
}

impl Section {
    pub const ALL: [Self; 6] = [
        Self::Ssh,
        Self::Api,
        Self::Signing,
        Self::Github,
        Self::Release,
        Self::Brief,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Api => "api",
            Self::Signing => "signing",
            Self::Github => "github",
            Self::Release => "release",
            Self::Brief => "brief",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name() == name)
    }
}

#[derive(Debug, Clone)]
enum Line {
    Text(String),
    Offers,
}

/// A run of lines, in a section or outside all of them.
#[derive(Debug, Clone)]
struct Part {
    section: Option<Section>,
    lines: Vec<Line>,
}

/// The instructions, parsed.
#[derive(Debug, Clone)]
pub struct Template {
    parts: Vec<Part>,
}

/// Why the document is not a valid template, at which line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateError {
    line: usize,
    problem: String,
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "docs/agent-instructions.md, line {}: {}",
            self.line, self.problem
        )
    }
}

impl std::error::Error for TemplateError {}

fn at(line: usize, problem: impl Into<String>) -> TemplateError {
    TemplateError {
        line,
        problem: problem.into(),
    }
}

#[derive(Clone, Copy)]
enum Marker {
    Section(Section),
    End,
    Offers,
}

/// The marker on `line`, numbered `number`, if it holds one.
fn marker(line: &str, number: usize) -> Result<Option<Marker>, TemplateError> {
    let trimmed = line.trim();
    if !trimmed.starts_with(MARKER_START) {
        if trimmed.contains(MARKER_START) {
            return Err(at(number, "a warden marker must be on its own line"));
        }
        return Ok(None);
    }
    let body = trimmed
        .strip_prefix(MARKER_START)
        .and_then(|rest| rest.strip_suffix(MARKER_END));
    match body.map(|b| b.split_once(' ')) {
        Some(None) if body == Some("end") => Ok(Some(Marker::End)),
        Some(None) if body == Some("offers") => Ok(Some(Marker::Offers)),
        Some(Some(("section", name))) => Section::from_name(name)
            .map(|section| Some(Marker::Section(section)))
            .ok_or_else(|| at(number, format!("unknown section in {trimmed}"))),
        _ => Err(at(number, format!("unknown marker {trimmed}"))),
    }
}

/// What the parser has seen so far.
struct Parser {
    parts: Vec<Part>,
    /// The section open, and the line it opened at.
    open: Option<(Section, usize)>,
    seen: HashSet<Section>,
    /// The line of the offers marker outside the sections, and of the brief one.
    offers: Option<usize>,
    brief_offers: Option<usize>,
}

impl Parser {
    fn push(&mut self, line: Line) {
        if let Some(part) = self.parts.last_mut() {
            part.lines.push(line);
        }
    }

    fn start(&mut self, section: Option<Section>) {
        self.parts.push(Part {
            section,
            lines: Vec::new(),
        });
    }

    fn marker(&mut self, marker: Marker, number: usize) -> Result<(), TemplateError> {
        match marker {
            Marker::Section(section) => {
                if let Some((outer, from)) = self.open {
                    return Err(at(
                        number,
                        format!(
                            "section {} inside section {} from line {from}",
                            section.name(),
                            outer.name()
                        ),
                    ));
                }
                if !self.seen.insert(section) {
                    return Err(at(number, format!("section {} twice", section.name())));
                }
                self.open = Some((section, number));
                self.start(Some(section));
            }
            Marker::End => {
                if self.open.take().is_none() {
                    return Err(at(number, "warden:end with no section open"));
                }
                self.start(None);
            }
            Marker::Offers => {
                let slot = match self.open {
                    None => &mut self.offers,
                    Some((Section::Brief, _)) => &mut self.brief_offers,
                    Some((other, _)) => {
                        return Err(at(
                            number,
                            format!("warden:offers inside section {}", other.name()),
                        ));
                    }
                };
                if let Some(first) = slot.replace(number) {
                    return Err(at(
                        number,
                        format!("a second warden:offers here, after line {first}"),
                    ));
                }
                self.push(Line::Offers);
            }
        }
        Ok(())
    }

    fn finish(self, last: usize) -> Result<Template, TemplateError> {
        if let Some(missing) = Section::ALL.into_iter().find(|s| !self.seen.contains(s)) {
            return Err(at(last, format!("no section {}", missing.name())));
        }
        if self.offers.is_none() {
            return Err(at(last, "no warden:offers outside the sections"));
        }
        if self.brief_offers.is_none() {
            return Err(at(last, "no warden:offers in section brief"));
        }
        Ok(Template { parts: self.parts })
    }
}

impl Template {
    /// The fenced blocks of `doc` (docs/agent-instructions.md), parsed.
    ///
    /// # Errors
    /// On a marker that is unknown, unbalanced, nested, repeated or not on its
    /// own line, or a missing section or offers marker. The error names the
    /// marker and the line.
    pub fn parse(doc: &str) -> Result<Self, TemplateError> {
        let mut parser = Parser {
            parts: vec![Part {
                section: None,
                lines: Vec::new(),
            }],
            open: None,
            seen: HashSet::new(),
            offers: None,
            brief_offers: None,
        };
        let mut fence: Option<usize> = None;
        let mut last = 0;
        for (number, line) in (1..).zip(doc.lines()) {
            last = number;
            if fence.is_none() {
                if line == FENCE_OPEN {
                    fence = Some(number);
                } else if line.contains(MARKER_START) {
                    return Err(at(number, "a warden marker outside an instruction block"));
                }
                continue;
            }
            if line == FENCE_CLOSE {
                if let Some((section, from)) = parser.open {
                    return Err(at(
                        number,
                        format!(
                            "section {} from line {from} has no warden:end before the block ends",
                            section.name()
                        ),
                    ));
                }
                fence = None;
                continue;
            }
            match marker(line, number)? {
                Some(marker) => parser.marker(marker, number)?,
                None => parser.push(Line::Text(line.to_owned())),
            }
        }
        if let Some(from) = fence {
            return Err(at(from, "the instruction block has no closing fence"));
        }
        parser.finish(last)
    }

    /// The full text: what is outside the sections, and the sections in `keep`
    /// (the brief section never), with `offers` at the marker.
    #[must_use]
    pub fn full(&self, keep: &HashSet<Section>, offers: &str) -> String {
        let lines = self
            .parts
            .iter()
            .filter(|part| match part.section {
                None => true,
                Some(Section::Brief) => false,
                Some(section) => keep.contains(&section),
            })
            .flat_map(|part| &part.lines);
        render(lines, offers)
    }

    /// The brief section, with `offers` at its marker.
    #[must_use]
    pub fn brief(&self, offers: &str) -> String {
        let lines = self
            .parts
            .iter()
            .filter(|part| part.section == Some(Section::Brief))
            .flat_map(|part| &part.lines);
        render(lines, offers)
    }
}

/// `lines` as text, with `offers` at the marker, without blank lines at either
/// end or two in a row (a left-out section leaves the blank lines around it).
fn render<'a>(lines: impl Iterator<Item = &'a Line>, offers: &str) -> String {
    let mut out = String::new();
    let mut after_blank = true;
    let mut push = |line: &str| {
        let blank = line.trim().is_empty();
        if !(blank && after_blank) {
            out.push_str(line);
            out.push('\n');
        }
        after_blank = blank;
    };
    for line in lines {
        match line {
            Line::Text(text) => push(text),
            Line::Offers => offers.lines().for_each(&mut push),
        }
    }
    while out.ends_with("\n\n") {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{DOC, Section, Template};

    /// A document with one fenced block holding `body`.
    fn doc(body: &str) -> String {
        format!("# Title\n\nPrelude.\n\n````markdown\n{body}````\n\nAfter.\n")
    }

    /// Every section, each with one line, and both offers markers.
    const COMPLETE: &str = "\
Intro.

<!-- warden:offers -->

<!-- warden:section ssh -->
SSH text.
<!-- warden:end -->

<!-- warden:section api -->
API text.
<!-- warden:end -->

<!-- warden:section signing -->
Signing text.
<!-- warden:end -->

<!-- warden:section github -->
GitHub text.
<!-- warden:end -->

<!-- warden:section release -->
Release text.
<!-- warden:end -->

Outro.
<!-- warden:section brief -->
Brief text.
<!-- warden:offers -->
<!-- warden:end -->
";

    fn error(doc: &str) -> String {
        Template::parse(doc).unwrap_err().to_string()
    }

    #[test]
    fn parses_the_real_doc() {
        let template = Template::parse(DOC).unwrap();
        let none = template.full(&HashSet::new(), "OFFERS");
        for section in Section::ALL {
            let with = template.full(&HashSet::from([section]), "OFFERS");
            // The brief section never prints in the full text; every other one adds to it.
            assert_eq!(with == none, section == Section::Brief, "{section:?}");
        }
        let all: HashSet<Section> = Section::ALL.into();
        let full = template.full(&all, "OFFERS");
        assert!(full.starts_with("## Privileged access: warden\n"), "{full}");
        assert!(full.contains("\nOFFERS\n"), "{full}");
        assert!(!full.contains("<!--"), "{full}");
        let brief = template.brief("OFFERS");
        assert!(brief.contains("\nOFFERS\n"), "{brief}");
        assert!(brief.contains("warden prime"), "{brief}");
        assert!(!brief.contains("<!--"), "{brief}");
    }

    #[test]
    fn unbalanced_marker_is_an_error() {
        let unclosed =
            doc(&COMPLETE.replacen("SSH text.\n<!-- warden:end -->\n", "SSH text.\n", 1));
        let message = error(&unclosed);
        assert!(message.contains("section ssh"), "{message}");
        assert!(message.contains("line "), "{message}");

        let stray_end = doc(&format!("<!-- warden:end -->\n{COMPLETE}"));
        let message = error(&stray_end);
        assert!(message.contains("line 6"), "{message}");
        assert!(message.contains("warden:end"), "{message}");

        let unclosed_fence = format!("````markdown\n{COMPLETE}");
        assert!(error(&unclosed_fence).contains("closing"));
    }

    #[test]
    fn unknown_section_is_an_error() {
        let misspelled = doc(&COMPLETE.replacen("section github", "section gihtub", 1));
        let message = error(&misspelled);
        assert!(message.contains("gihtub"), "{message}");
        assert!(message.contains("line "), "{message}");

        let unknown_marker = doc(&format!("<!-- warden:offer -->\n{COMPLETE}"));
        assert!(error(&unknown_marker).contains("line 6"));

        let missing = doc(&COMPLETE.replacen(
            "<!-- warden:section release -->\nRelease text.\n<!-- warden:end -->\n",
            "",
            1,
        ));
        assert!(error(&missing).contains("release"));

        let inline = doc(&format!("Text <!-- warden:end --> text.\n{COMPLETE}"));
        assert!(error(&inline).contains("own line"));

        let outside = format!("<!-- warden:offers -->\n{}", doc(COMPLETE));
        assert!(error(&outside).contains("line 1"));
    }

    #[test]
    fn nested_section_is_an_error() {
        let nested =
            doc(&COMPLETE.replacen("SSH text.\n", "SSH text.\n<!-- warden:section api -->\n", 1));
        let message = error(&nested);
        assert!(message.contains("inside section ssh"), "{message}");

        let twice = doc(&format!(
            "{COMPLETE}<!-- warden:section ssh -->\nAgain.\n<!-- warden:end -->\n"
        ));
        assert!(error(&twice).contains("twice"));

        let offers_in_section =
            doc(&COMPLETE.replacen("API text.\n", "API text.\n<!-- warden:offers -->\n", 1));
        assert!(error(&offers_in_section).contains("section api"));
    }

    #[test]
    fn full_drops_sections_not_kept() {
        let template = Template::parse(&doc(COMPLETE)).unwrap();
        let keep = HashSet::from([Section::Ssh, Section::Release]);
        assert_eq!(
            template.full(&keep, "OFFERS"),
            "Intro.\n\nOFFERS\n\nSSH text.\n\nRelease text.\n\nOutro.\n"
        );
        assert_eq!(
            template.full(&HashSet::new(), "OFFERS"),
            "Intro.\n\nOFFERS\n\nOutro.\n"
        );
    }

    #[test]
    fn full_never_contains_brief() {
        let template = Template::parse(&doc(COMPLETE)).unwrap();
        let all: HashSet<Section> = Section::ALL.into();
        let full = template.full(&all, "OFFERS");
        assert!(!full.contains("Brief text."), "{full}");
        assert!(
            !full.contains("Prelude") && !full.contains("After"),
            "{full}"
        );
        assert_eq!(template.brief("OFFERS"), "Brief text.\nOFFERS\n");
    }

    #[test]
    fn offers_marker_replaced() {
        let template = Template::parse(&doc(COMPLETE)).unwrap();
        let full = template.full(&HashSet::new(), "SSH targets:\n  web-01\n");
        assert_eq!(full, "Intro.\n\nSSH targets:\n  web-01\n\nOutro.\n");
        let missing = doc(&COMPLETE.replacen("<!-- warden:offers -->\n\n", "", 1));
        assert!(error(&missing).contains("offers"));
    }
}
