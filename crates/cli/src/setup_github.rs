//! `warden setup github`: have git and `gh` take GitHub tokens from warden.
//!
//! In git's global configuration, `credential.https://github.com.helper` becomes
//! an empty value, which drops the helpers configured before it, then
//! `!<this program> git-credential`. And `~/.local/bin/gh` becomes a script that
//! sets `GH_TOKEN` from `warden github token` and runs the real `gh`, the first one
//! on `PATH` at setup that is not this script. A `~/.local/bin/gh` this command did
//! not write is never replaced. Everything is checked before anything changes,
//! and every change is printed.

use std::ffi::OsStr;
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context as _, Result, anyhow, bail, ensure};

use crate::agent;

/// The git setting this sets.
const HELPER_KEY: &str = "credential.https://github.com.helper";

/// The line that marks a `gh` wrapper as written by this command.
const MARKER: &str = "# Written by `warden setup github`, which may replace it.";

/// The most of an existing `gh` read to look for [`MARKER`], in bytes.
const MAX_WRAPPER_BYTES: u64 = 64 * 1024;

/// `value` quoted for a POSIX shell: in single quotes, each `'` as `'\''`.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// The helper value git runs, through the shell, with the operation appended.
fn helper_value(exe: &str) -> String {
    format!("!{} git-credential", shell_quote(exe))
}

/// The program a helper value runs as `<program> git-credential`, in the forms git
/// runs it in: through the shell (`!` then the program single-quoted, as
/// [`helper_value`] writes it, or plain), or as an absolute path without `!`.
/// `None` for any other value, including a program with characters the shell would
/// read otherwise.
pub fn helper_program(value: &str) -> Option<String> {
    let (shell, rest) = match value.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, value),
    };
    let program = rest.strip_suffix(" git-credential")?;
    if shell && program.starts_with('\'') {
        return unquote(program);
    }
    let plain = !program.is_empty()
        && program
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+,:@%".contains(c));
    // Without `!`, git runs only an absolute path itself; anything else names a
    // `git credential-<name>` command.
    (plain && (shell || program.starts_with('/'))).then(|| program.to_owned())
}

/// `quoted` read as the shell reads single-quoted parts joined by `\'`.
fn unquote(quoted: &str) -> Option<String> {
    let mut program = String::new();
    let mut rest = quoted;
    loop {
        // A quoted part, then either the end or an escaped quote and another part.
        let inner = rest.strip_prefix('\'')?;
        let end = inner.find('\'')?;
        program.push_str(&inner[..end]);
        rest = &inner[end + 1..];
        if rest.is_empty() {
            return Some(program);
        }
        rest = rest.strip_prefix("\\'")?;
        program.push('\'');
        if rest.is_empty() {
            return Some(program);
        }
    }
}

/// This program, as the helper and the wrapper name it.
fn this_exe() -> Result<String> {
    let exe = crate::exe_path::stable_exe()?;
    printable(&exe, "this program")
}

/// This program's path as `warden setup github` writes it, if it can tell.
pub fn this_program() -> Option<String> {
    this_exe().ok()
}

/// The `gh` wrapper running `real_gh` with a token from `exe`.
fn wrapper_script(exe: &str, real_gh: &str) -> String {
    format!(
        "#!/bin/sh\n{MARKER}\n# Gives gh a GitHub token from warden: see `warden setup github`.\n\
         GH_TOKEN=\"$({} github token)\" || exit $?\nexport GH_TOKEN\nexec {} \"$@\"\n",
        shell_quote(exe),
        shell_quote(real_gh)
    )
}

/// Whether `contents` are a wrapper this command wrote.
fn is_ours(contents: &[u8]) -> bool {
    contents
        .split(|b| *b == b'\n')
        .any(|line| line == MARKER.as_bytes())
}

/// What is at `path` now.
#[derive(Debug, PartialEq, Eq)]
enum Existing {
    Nothing,
    Ours,
    Foreign,
}

fn existing(path: &Path) -> Result<Existing> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Existing::Nothing),
        Err(e) => return Err(e).with_context(|| format!("cannot inspect {}", path.display())),
    };
    if !meta.is_file() {
        return Ok(Existing::Foreign);
    }
    let mut contents = Vec::new();
    fs::File::open(path)
        .and_then(|f| f.take(MAX_WRAPPER_BYTES).read_to_end(&mut contents))
        .with_context(|| format!("cannot read {}", path.display()))?;
    Ok(if is_ours(&contents) {
        Existing::Ours
    } else {
        Existing::Foreign
    })
}

/// Whether `path` is an executable regular file, following symlinks.
fn is_executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// The first `gh` in `path_var` that is not `wrapper` and not a wrapper this
/// command wrote, with the index of its directory. Relative and empty entries,
/// which depend on the directory `gh` runs in, are skipped.
fn find_real_gh(path_var: &OsStr, wrapper: &Path) -> Option<(usize, PathBuf)> {
    let wrapper = fs::canonicalize(wrapper).ok();
    std::env::split_paths(path_var)
        .enumerate()
        .filter(|(_, dir)| dir.is_absolute())
        .map(|(index, dir)| (index, dir.join("gh")))
        .find(|(_, gh)| {
            is_executable(gh)
                && (wrapper.is_none() || fs::canonicalize(gh).ok() != wrapper)
                && !matches!(existing(gh), Ok(Existing::Ours))
        })
}

/// The index in `path_var` of `dir`, compared as written and as resolved.
fn position(path_var: &OsStr, dir: &Path) -> Option<usize> {
    let resolved = fs::canonicalize(dir).ok();
    std::env::split_paths(path_var).position(|entry| {
        entry == dir || (resolved.is_some() && fs::canonicalize(&entry).ok() == resolved)
    })
}

fn git_config(args: &[&str]) -> Result<Output> {
    Command::new("git")
        .arg("config")
        .arg("--global")
        .args(args)
        .output()
        .context("cannot run git")
}

fn check_git(out: &Output, what: &str) -> Result<()> {
    ensure!(
        out.status.success(),
        "git config {what} failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(())
}

/// The values of [`HELPER_KEY`] in git's global configuration, in order.
fn global_helpers() -> Result<Vec<String>> {
    let out = git_config(&["--get-all", HELPER_KEY])?;
    // 1: the key is not set.
    match out.status.code() {
        Some(0) => Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(ToOwned::to_owned)
            .collect()),
        Some(1) => Ok(Vec::new()),
        _ => {
            check_git(&out, &format!("--get-all {HELPER_KEY}"))?;
            Ok(Vec::new())
        }
    }
}

/// Make [`HELPER_KEY`] exactly an empty value then `helper`, saying what changed.
fn set_helper(helper: &str) -> Result<()> {
    let wanted = [String::new(), helper.to_owned()];
    let old = global_helpers()?;
    if old == wanted {
        println!("{HELPER_KEY}: already set");
        return Ok(());
    }
    if !old.is_empty() {
        for value in &old {
            println!("{HELPER_KEY}: was {value:?}");
        }
        check_git(
            &git_config(&["--unset-all", HELPER_KEY])?,
            &format!("--unset-all {HELPER_KEY}"),
        )?;
    }
    for value in &wanted {
        check_git(
            &git_config(&["--add", HELPER_KEY, value])?,
            &format!("--add {HELPER_KEY}"),
        )?;
    }
    println!("{HELPER_KEY} = \"\" (git consults no helper configured before it for GitHub)");
    println!("{HELPER_KEY} = {helper}");
    Ok(())
}

/// Write `script` to `path` (0755) through a file beside it, so that `gh` never
/// runs half a script.
fn write_wrapper(path: &Path, script: &str) -> Result<()> {
    let (_, temp) = agent::temp_beside(path)?;
    let written = agent::write_temp(&temp, script.as_bytes())
        .and_then(|()| {
            fs::set_permissions(&temp, fs::Permissions::from_mode(0o755))
                .with_context(|| format!("cannot make {} executable", temp.display()))
        })
        .and_then(|()| replace_if_ours(&temp, path));
    if written.is_err() {
        // Best effort: the error that matters is the one returned.
        let _ = fs::remove_file(&temp);
    }
    written
}

/// Rename `temp` to `path`, looking at `path` again first: a file that appeared
/// since the first look and is not ours is never replaced. Where nothing is, the
/// rename refuses to replace anything that appears in the meantime.
fn replace_if_ours(temp: &Path, path: &Path) -> Result<()> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    let flags = match existing(path)? {
        Existing::Nothing => RenameFlags::NOREPLACE,
        Existing::Ours => RenameFlags::empty(),
        Existing::Foreign => bail!(
            "{} appeared meanwhile and was not written by warden, so it was left as it is",
            path.display()
        ),
    };
    renameat_with(CWD, temp, CWD, path, flags)
        .map_err(std::io::Error::from)
        .with_context(|| format!("cannot write {}", path.display()))
}

/// A path for a shell script or git's configuration: UTF-8, no control characters.
fn printable(path: &Path, what: &str) -> Result<String> {
    let text = path
        .to_str()
        .ok_or_else(|| anyhow!("the path of {what} is not valid UTF-8"))?;
    ensure!(
        !text.chars().any(char::is_control),
        "the path of {what} holds a control character"
    );
    Ok(text.to_owned())
}

/// Set git and `gh` up.
///
/// # Errors
/// If `~/.local/bin/gh` exists and this command did not write it, or this program
/// cannot be located, nothing is changed. If git refuses a value or the wrapper
/// cannot be written, the message says so; what was changed before stays changed.
pub fn run() -> Result<()> {
    let exe = this_exe()?;
    let home = dirs::home_dir().context("cannot determine the home directory")?;
    let bin = home.join(".local/bin");
    let wrapper = bin.join("gh");
    if existing(&wrapper)? == Existing::Foreign {
        bail!(
            "{} exists and was not written by warden, so nothing was changed. Move it away, \
             then run `warden setup github` again",
            wrapper.display()
        );
    }
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let real_gh = find_real_gh(&path_var, &wrapper)
        .map(|(index, gh)| printable(&gh, "gh").map(|text| (index, text)))
        .transpose()?;

    set_helper(&helper_value(&exe))?;

    let Some((gh_index, real_gh)) = real_gh else {
        println!(
            "gh: not found on PATH, so no wrapper was written. Install gh, then run `warden \
             setup github` again"
        );
        return Ok(());
    };
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(&bin)
        .with_context(|| format!("cannot create {}", bin.display()))?;
    write_wrapper(&wrapper, &wrapper_script(&exe, &real_gh))?;
    println!(
        "{}: written; it runs {real_gh} with a token from warden",
        wrapper.display()
    );
    if position(&path_var, &bin).is_none_or(|index| index > gh_index) {
        eprintln!(
            "warden: warning: {} is not before {real_gh} on PATH, so plain `gh` runs without a \
             token from warden. Put it first, for example in your shell profile: export \
             PATH=\"$HOME/.local/bin:$PATH\"",
            bin.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::{
        Existing, MARKER, existing, find_real_gh, helper_program, helper_value, is_ours, position,
        shell_quote, wrapper_script, write_wrapper,
    };

    #[test]
    fn values_are_quoted_for_the_shell() {
        assert_eq!(shell_quote("/opt/bin/warden"), "'/opt/bin/warden'");
        assert_eq!(shell_quote("/a b/it's"), r"'/a b/it'\''s'");
        assert_eq!(
            helper_value("/opt/my bin/warden"),
            "!'/opt/my bin/warden' git-credential"
        );
    }

    #[test]
    fn a_helper_value_gives_back_its_program() {
        for exe in ["/opt/bin/warden", "/a b/it's", "/x'", "'", "/a''b"] {
            assert_eq!(
                helper_program(&helper_value(exe)).as_deref(),
                Some(exe),
                "{exe}"
            );
        }
        for (value, program) in [
            ("!/opt/bin/warden git-credential", "/opt/bin/warden"),
            ("!warden git-credential", "warden"),
            ("/opt/bin/warden git-credential", "/opt/bin/warden"),
        ] {
            assert_eq!(helper_program(value).as_deref(), Some(program), "{value}");
        }
        for other in [
            "osxkeychain",
            "",
            "warden git-credential",
            "!'/opt/bin/warden' git-credential --x",
            "'/opt/bin/warden' git-credential",
            "!'/opt/bin/warden'x git-credential",
            "!'/opt/bin/warden git-credential",
            "!/opt/my bin/warden git-credential",
            "!$(evil)/warden git-credential",
            "!/opt/bin/warden;x git-credential",
        ] {
            assert_eq!(helper_program(other), None, "{other}");
        }
    }

    #[test]
    fn the_wrapper_sets_the_token_or_stops_and_carries_the_marker() {
        let script = wrapper_script("/opt/bin/warden", "/usr/bin/gh");
        assert!(script.starts_with("#!/bin/sh\n"), "{script}");
        assert!(
            script.contains("GH_TOKEN=\"$('/opt/bin/warden' github token)\" || exit $?\n"),
            "{script}"
        );
        assert!(script.contains("export GH_TOKEN\n"), "{script}");
        assert!(script.ends_with("exec '/usr/bin/gh' \"$@\"\n"), "{script}");
        assert!(is_ours(script.as_bytes()));
        assert!(!is_ours(b"#!/bin/sh\nexec gh \"$@\"\n"));
        let quoted = format!("echo '{MARKER}'\n");
        assert!(
            !is_ours(quoted.as_bytes()),
            "the marker must be a line of its own"
        );
    }

    fn executable(path: &std::path::Path, contents: &str) {
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn the_real_gh_is_the_first_on_path_that_is_not_a_wrapper() {
        let root = tempfile::tempdir().unwrap();
        let (mine, theirs, other, plain) = (
            root.path().join("mine"),
            root.path().join("theirs"),
            root.path().join("other"),
            root.path().join("plain"),
        );
        for dir in [&mine, &theirs, &other, &plain] {
            fs::create_dir(dir).unwrap();
        }
        let wrapper = mine.join("gh");
        executable(&wrapper, &wrapper_script("/w", "/g"));
        // Another wrapper of ours elsewhere, a gh that cannot run, then the real one.
        executable(&theirs.join("gh"), &wrapper_script("/w", "/g"));
        fs::write(other.join("gh"), "not executable").unwrap();
        executable(&plain.join("gh"), "#!/bin/sh\n");
        let path = std::env::join_paths(
            ["", "relative", mine.to_str().unwrap()]
                .into_iter()
                .chain([&theirs, &other, &plain].map(|d| d.to_str().unwrap())),
        )
        .unwrap();
        assert_eq!(find_real_gh(&path, &wrapper), Some((5, plain.join("gh"))));
        assert_eq!(position(&path, &mine), Some(2));
        assert_eq!(position(&path, &root.path().join("absent")), None);
        let none = std::env::join_paths([mine.to_str().unwrap()]).unwrap();
        assert_eq!(find_real_gh(&none, &wrapper), None);
    }

    #[test]
    fn the_wrapper_never_replaces_a_file_that_is_not_ours() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("gh");
        write_wrapper(&path, &wrapper_script("/w", "/g")).unwrap();
        assert_eq!(existing(&path).unwrap(), Existing::Ours);
        write_wrapper(&path, &wrapper_script("/w2", "/g")).unwrap();
        assert!(fs::read_to_string(&path).unwrap().contains("'/w2'"));
        fs::write(&path, "#!/bin/sh\necho mine\n").unwrap();
        assert!(write_wrapper(&path, &wrapper_script("/w", "/g")).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "#!/bin/sh\necho mine\n");
        let names: Vec<_> = fs::read_dir(root.path()).unwrap().flatten().collect();
        assert_eq!(names.len(), 1, "no temporary file left: {names:?}");
    }

    #[test]
    fn only_a_regular_file_with_the_marker_is_ours() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("gh");
        assert_eq!(existing(&path).unwrap(), Existing::Nothing);
        fs::write(&path, wrapper_script("/w", "/g")).unwrap();
        assert_eq!(existing(&path).unwrap(), Existing::Ours);
        fs::write(&path, "#!/bin/sh\n").unwrap();
        assert_eq!(existing(&path).unwrap(), Existing::Foreign);
        fs::remove_file(&path).unwrap();
        let target = root.path().join("target");
        fs::write(&target, wrapper_script("/w", "/g")).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert_eq!(
            existing(&path).unwrap(),
            Existing::Foreign,
            "a symlink is not ours"
        );
    }
}
