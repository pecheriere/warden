//! The passkey enrollment page.

use maud::{Markup, html};

use super::{Nav, icon, key_icon, layout};

/// The passkey enrollment form.
#[must_use]
pub fn enroll() -> Markup {
    let content = html! {
        main {
            h1 { "Enroll a passkey" }
            p.lead {
                "Run " code { "warden-server enroll" } " on the server and enter the code it prints."
            }
            section.card {
                div.field {
                    label.label for="code" { "Enrollment code" }
                    input.input #code type="text" autocomplete="one-time-code"
                        autocapitalize="characters" spellcheck="false" maxlength="32";
                }
                div.field {
                    label.label for="label" { "Name for this passkey" }
                    input.input #label type="text" autocomplete="off" maxlength="64"
                        placeholder="My phone";
                }
                button.btn.approve #enroll type="button" { (icon(20, "2.2", &key_icon())) " Create passkey" }
            }
            p.result #result role="status" {}
        }
    };
    layout("Enroll a passkey", Some(Nav::Enroll), true, &content)
}
