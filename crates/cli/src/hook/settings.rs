//! The `[hook]` table of the CLI's `config.toml`.
//!
//! The table is validated by `warden_agent_hook::settings`: an invalid key or
//! value gives the defaults and a note, never a weaker setting.

use std::path::Path;

use warden_agent_hook::settings::Settings;
use warden_broker_proto::doctor::Check;

use crate::config::{Config, config_path, load_existing_from};

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

/// The settings from the CLI's configuration file, and the note about an
/// invalid `[hook]` table. A missing or unreadable configuration, or one
/// that does not parse, gives the defaults and no note: `warden doctor`
/// reports those.
pub fn load() -> (Settings, Option<String>) {
    match config_path() {
        Ok(path) => load_from(&path),
        Err(_) => Settings::from_table(None),
    }
}

/// [`load`] for the configuration at `path`.
fn load_from(path: &Path) -> (Settings, Option<String>) {
    let config = load_existing_from(path).ok().flatten();
    Settings::from_table(config.as_ref().and_then(|c| c.hook.as_ref()))
}

#[cfg(test)]
mod tests;
