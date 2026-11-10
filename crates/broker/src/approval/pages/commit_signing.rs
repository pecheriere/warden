//! What the pages say about commit signing. Its wording matters: the owner must not
//! come away thinking that approving means reviewing, or that a signature means more
//! than it does.

use maud::{Markup, html};

use super::{icon, warning_icon};

/// What a signature does and does not mean.
const MEANING: &str = "A signature means warden signed the commit for this agent, not that you \
                       reviewed the change.";

/// What approving commit signing gives, for the approval and pending pages.
pub(super) fn access(key_fingerprint: &str) -> Markup {
    html! {
        span { "Sign this agent's commits with key " code { (key_fingerprint) } }
        strong.badge.modify {
            (icon(14, "2.4", &warning_icon())) " Signs without asking, until it ends or is revoked"
        }
        span.detail {
            "warden signs anything this agent commits during the grant, and records each one. "
            (MEANING)
        }
    }
}

/// What an active commit signing grant gives, for the grants page.
pub(super) fn grant_access(key_fingerprint: &str) -> Markup {
    html! {
        span { "Signs this agent's commits with key " code { (key_fingerprint) } }
        span.detail { (MEANING) }
    }
}

/// The grants page's note where other grants show what they are doing.
pub(super) fn live_note() -> Markup {
    html! {
        p.detail {
            "Every signature is in the audit log. Revoking stops new signatures at once, and does \
             not undo those already made."
        }
    }
}
