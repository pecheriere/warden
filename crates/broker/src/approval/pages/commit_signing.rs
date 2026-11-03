//! What the pages say about commit signing. Its wording matters: the owner must not
//! come away thinking that approving means reviewing, or that a signature means more
//! than it does.

use maud::{Markup, html};

use super::{icon, utc_parts, warning_icon};
use crate::requests::ActiveGrant;

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

/// When a grant ends, for one that can last months: the date, and how far off it is.
pub(super) fn ends(not_after: i64, now: i64) -> Markup {
    let (date, time) = utc_parts(not_after);
    let left = (not_after - now).max(0);
    let far = match left {
        0..7200 => format!("{} min", (left + 59) / 60),
        7200..172_800 => format!("{} h", left / 3600),
        _ => format!("{} days", left / 86_400),
    };
    html! { span { "Ends " (date) " " (time) " (in " (far) ")" } }
}

/// The button that starts renewing `grant`, described like its Revoke button.
pub(super) fn renew_button(grant: &ActiveGrant) -> Markup {
    html! {
        button.renew type="button" data-grant=(grant.grant_id)
            aria-describedby=(format!("agent-{0} grant-{0}", grant.grant_id)) { "Renew" }
    }
}
