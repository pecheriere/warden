//! The `[hook]` table of the CLI's `config.toml`.
//!
//! The table is validated by `warden_agent_hook::settings`: an invalid key or
//! value gives the defaults and a note, never a weaker setting.

use warden_agent_hook::settings::Settings;
use warden_broker_proto::doctor::Check;

use crate::config::Config;

/// The name of the doctor check for the `[hook]` table.
const CHECK: &str = "hook.settings";

/// A failed check carrying the note when the `[hook]` table of `config` is
/// invalid, and nothing when it is valid or absent.
pub fn doctor_check(config: &Config) -> Option<Check> {
    let (_, note) = Settings::from_table(config.hook.as_ref());
    note.map(|note| {
        Check::fail(
            CHECK,
            format!("hook settings: {note}"),
            "Fix the [hook] table in the CLI's config.toml (docs/configuration.md); until then the \
             defaults apply.",
        )
    })
}
