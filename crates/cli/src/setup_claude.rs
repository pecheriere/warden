//! `warden setup claude`: install the warden plugin for Claude Code.
//!
//! Runs `claude plugin` to add this repository's marketplace, pinned to the
//! release tag of this CLI's own version, then to install the plugin at user
//! scope and update it. Adding a marketplace named `warden` again points it at
//! the new tag, and the update moves an installed plugin there, so running this
//! again after upgrading warden is the upgrade. Each command runs without a
//! shell, and the first that fails stops the rest, with its exit status. This
//! command touches no file itself and needs no grant. Without `claude` on the
//! `PATH`, it prints the `/plugin` commands to run in a session instead.

use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use anyhow::{Context as _, Result};

use crate::{EXIT_ERROR, Exit};

/// The GitHub repository that holds the marketplace.
const REPOSITORY: &str = "pecheriere/warden";

/// The plugin, as `<plugin>@<marketplace>`.
const PLUGIN: &str = "warden@warden";

/// The program that manages Claude Code plugins.
const CLAUDE: &str = "claude";

/// The marketplace source pinned to the release tag of `version`.
fn source(version: &str) -> String {
    format!("{REPOSITORY}#v{version}")
}

/// The commands that install the plugin of `version`, each as its argv.
pub fn commands(version: &str) -> Vec<Vec<String>> {
    let source = source(version);
    [
        vec!["plugin", "marketplace", "add", &source, "--scope", "user"],
        vec!["plugin", "install", PLUGIN, "--scope", "user"],
        vec!["plugin", "update", PLUGIN, "--scope", "user"],
    ]
    .into_iter()
    .map(|args| {
        std::iter::once(CLAUDE)
            .chain(args)
            .map(str::to_owned)
            .collect()
    })
    .collect()
}

/// The first executable regular file called `name` in `path_var`. Relative and
/// empty entries, which depend on the current directory, are skipped.
fn find_on_path(path_var: &OsStr, name: &str) -> Option<PathBuf> {
    std::env::split_paths(path_var)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|path| {
            fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
}

/// Prints the commands for `version` to `out`, or, unless `dry_run`, runs each
/// with `run_one` as `claude`, the program found on the `PATH`. Without one,
/// prints the `/plugin` commands to run in a Claude Code session instead.
fn run_with(
    dry_run: bool,
    version: &str,
    claude: Option<&Path>,
    out: &mut dyn Write,
    run_one: &mut dyn FnMut(&Path, &[String]) -> io::Result<ExitStatus>,
) -> Result<()> {
    let commands = commands(version);
    if dry_run {
        for command in &commands {
            writeln!(out, "{}", command.join(" "))?;
        }
        return Ok(());
    }
    let Some(claude) = claude else {
        writeln!(
            out,
            "{CLAUDE} is not on the PATH. In a Claude Code session, run:\n\
             /plugin marketplace add {}\n\
             /plugin install {PLUGIN}",
            source(version)
        )?;
        return Ok(());
    };
    for command in &commands {
        let line = command.join(" ");
        writeln!(out, "{line}")?;
        out.flush()?;
        let status = run_one(claude, &command[1..]).with_context(|| format!("running `{line}`"))?;
        if !status.success() {
            let code = status
                .code()
                .and_then(|code| u8::try_from(code).ok())
                .filter(|&code| code != 0)
                .unwrap_or(EXIT_ERROR);
            return Err(Exit::new(code, format!("`{line}` failed: {status}")).into());
        }
    }
    Ok(())
}

/// `warden setup claude`.
pub fn run(dry_run: bool) -> Result<()> {
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let claude = find_on_path(&path_var, CLAUDE);
    let mut run_one = |program: &Path, args: &[String]| Command::new(program).args(args).status();
    run_with(
        dry_run,
        env!("CARGO_PKG_VERSION"),
        claude.as_deref(),
        &mut io::stdout().lock(),
        &mut run_one,
    )
}

#[cfg(test)]
mod tests;
