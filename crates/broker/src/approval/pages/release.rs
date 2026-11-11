//! What the pages say about a release. The owner approves a signed tag and a published
//! release from a phone, so the page shows what the broker read from GitHub, never
//! what the agent said, and shows all of it as text: nothing a commit or a changelog
//! contains can become markup, and nothing invisible can hide in it.

use maud::{Markup, html};
use warden_broker_proto::release::{ReleaseGrant, ReleaseSteps};
use warden_broker_proto::{Access, CreateRequest};

use super::{icon, warning_icon};
use crate::requests::{ReleaseFacts, ReleasePolicy, ReleaseProgress};

/// No step claimed yet.
const NOTHING_DONE: ReleaseProgress = ReleaseProgress {
    tag: false,
    manifest: false,
    publish: false,
};

/// What the owner is told the grant lasts, in place of a choice of windows.
pub(super) const LIFETIME: &str = "For at most 1 day, and it ends when the last step is done.";

/// `text` with every character that does not show as itself written out as
/// `\u{..}`: control characters other than the line feed and the tab, and the
/// characters that reorder or hide text. What is left is safe to read as it is
/// once escaped as HTML.
pub(super) fn visible(text: &str) -> String {
    text.chars()
        .map(|c| {
            if hides(c) {
                format!("\\u{{{:x}}}", u32::from(c))
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Whether `c` is a control character other than `\n` and `\t`, or one that
/// reorders text (the bidirectional controls), has no width (zero-width
/// characters, the invisible operators, the soft hyphen, the tag characters and
/// the byte order mark) or breaks the line (the line and paragraph separators).
fn hides(c: char) -> bool {
    (c.is_control() && c != '\n' && c != '\t')
        || matches!(
            c,
            '\u{ad}' | '\u{61c}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{feff}'
                | '\u{e0000}'..='\u{e007f}'
        )
}

/// The repository, tag and commit a release request names.
fn target(request: &CreateRequest) -> Option<(&str, &str, &str)> {
    match &request.access {
        Access::Release {
            repository,
            tag,
            commit,
        } => Some((repository.as_str(), tag.as_str(), commit.as_str())),
        _ => None,
    }
}

/// The steps of a release in the owner's words, each with whether `progress`
/// says it is used: a claimed step stays used even when it then failed.
fn step_words(steps: &ReleaseSteps, tag: &str, progress: ReleaseProgress) -> Vec<(String, bool)> {
    let mut words = Vec::new();
    if steps.tag {
        words.push((format!("sign and create tag {tag}"), progress.tag));
    }
    if let Some(manifest) = &steps.manifest {
        words.push((format!("sign {manifest}"), progress.manifest));
    }
    if steps.publish {
        words.push(("publish the draft".to_owned(), progress.publish));
    }
    words
}

/// What approving a release gives, for the approval and pending pages.
pub(super) fn access(request: &CreateRequest, policy: &ReleasePolicy) -> Markup {
    let (repository, tag, commit) = target(request).unwrap_or(("", "", ""));
    html! {
        span {
            "Release " code { bdi { (tag) } } " of " code { bdi { (repository) } }
            " at " code { (commit) }
        }
        strong.badge.modify {
            (icon(14, "2.4", &warning_icon())) " Signs with your release key, and publishes"
        }
        span.detail {
            "Key " code { (policy.key_fingerprint) }
            ". warden does each step when this agent asks, once, and records it."
        }
    }
}

/// What warden read from GitHub about the release, for the approval page: the commit,
/// the changelog, a link to compare it with the last release, and the steps.
pub(super) fn facts(
    request: &CreateRequest,
    policy: &ReleasePolicy,
    facts: &ReleaseFacts,
) -> Markup {
    let (repository, tag, commit) = target(request).unwrap_or(("", "", ""));
    let steps = policy.steps(facts.tag_in_place);
    let link = match &facts.previous_tag {
        Some(previous) => (
            format!("https://github.com/{repository}/compare/{previous}...{commit}"),
            format!("Compare {previous} with this commit"),
        ),
        None => (
            format!("https://github.com/{repository}/commit/{commit}"),
            "See this commit".to_owned(),
        ),
    };
    let version = tag.strip_prefix('v').unwrap_or(tag);
    html! {
        div.field {
            span.label { "Commit · read from GitHub" }
            code { (commit) }
            span { bdi { (visible(&facts.commit_title)) } }
            span.detail {
                (facts.commit_date)
                @if facts.on_default_branch { " · on the default branch" }
            }
            a.stated-link href=(link.0) target="_blank" rel="noopener noreferrer" { (link.1) " on GitHub" }
        }
        div.field {
            span.label { "Changelog for " (version) " · read from GitHub" }
            @match &facts.changelog {
                Some(text) => {
                    pre.changelog tabindex="0" aria-label="Changelog" { (visible(text)) }
                    @if facts.changelog_cut {
                        span.detail { "Cut at 16 KiB: the rest is in the repository." }
                    }
                }
                None => span.detail { "No changelog section for this version." }
            }
        }
        div.field {
            span.label { "Steps this approval allows" }
            ul.steps role="list" {
                @for (words, _) in step_words(&steps, tag, NOTHING_DONE) { li { (words) } }
            }
            @if facts.tag_in_place {
                span.detail { "The tag is already in place on this commit." }
            }
        }
    }
}

/// What an active release grant gives and which steps it has used, for the grants page.
pub(super) fn grant_access(grant: &ReleaseGrant, progress: Option<ReleaseProgress>) -> Markup {
    let progress = progress.unwrap_or(NOTHING_DONE);
    html! {
        span {
            "Release " code { bdi { (grant.tag) } } " of " code { bdi { (grant.repository) } }
            " at " code { (grant.commit) }
        }
        span.detail { "Key " code { (grant.key_fingerprint) } }
        ul.steps role="list" {
            @for (words, done) in step_words(&grant.steps, grant.tag.as_str(), progress) {
                li {
                    (words) ": "
                    @if done { strong.step-state.complete { "used" } }
                    @else { span.step-state { "not yet" } }
                }
            }
        }
        span.detail { "The result of each step is in the audit log." }
    }
}

/// The grants page's note where other grants show what they are doing.
pub(super) fn live_note() -> Markup {
    html! {
        p.detail {
            "Every step is in the audit log. Revoking stops the steps that are left at once, \
             and does not undo those already used."
        }
    }
}
