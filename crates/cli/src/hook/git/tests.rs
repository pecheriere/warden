use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use super::{gh_wrapped, git_config};
use crate::hook::files::Reader;

const ORIGIN: &str = "https://github.com/example-owner/example-repo.git";
const WARDEN: &str = "[credential]\n\thelper = !/opt/bin/warden git-credential\n";
const REMOTE: &str =
    "[remote \"origin\"]\n\turl = https://github.com/example-owner/example-repo.git\n";

/// Whether the configuration read from `cwd` has warden's helper for
/// `origin`, `None` when it could not be read.
fn helper(cwd: &Path, home: Option<&Path>, xdg: Option<&Path>) -> Option<bool> {
    let reader = Reader::new(cwd.to_str());
    git_config(cwd.to_str(), home, xdg, &reader).map(|config| {
        assert_eq!(config.push_urls(None), vec![ORIGIN.to_owned()]);
        config.warden_helper_for(ORIGIN, &[])
    })
}

/// A checkout at `root/repo` with `config` as its configuration.
fn checkout(root: &Path, config: &str) -> std::path::PathBuf {
    let git = root.join("repo/.git");
    fs::create_dir_all(&git).unwrap();
    fs::create_dir_all(root.join("repo/src/deep")).unwrap();
    fs::write(git.join("config"), config).unwrap();
    root.join("repo")
}

#[test]
fn the_checkout_is_found_from_a_subdirectory() {
    let root = tempfile::tempdir().unwrap();
    let repo = checkout(root.path(), &format!("{REMOTE}{WARDEN}"));
    assert_eq!(helper(&repo, None, None), Some(true));
    assert_eq!(helper(&repo.join("src/deep"), None, None), Some(true));
}

#[test]
fn global_files_come_before_the_checkout_s() {
    let root = tempfile::tempdir().unwrap();
    let repo = checkout(root.path(), REMOTE);
    let home = root.path().join("home");
    fs::create_dir_all(home.join(".config/git")).unwrap();
    assert_eq!(helper(&repo, Some(&home), None), Some(false));
    fs::write(home.join(".gitconfig"), WARDEN).unwrap();
    assert_eq!(helper(&repo, Some(&home), None), Some(true));
    // The XDG file is read before `~/.gitconfig`.
    fs::write(
        home.join(".config/git/config"),
        "[credential]\n\thelper = osxkeychain\n",
    )
    .unwrap();
    assert_eq!(helper(&repo, Some(&home), None), Some(false));
    // `$XDG_CONFIG_HOME` replaces `~/.config`.
    let xdg = root.path().join("xdg");
    fs::create_dir_all(&xdg).unwrap();
    assert_eq!(helper(&repo, Some(&home), Some(&xdg)), Some(true));
    // The checkout's empty value drops the global helpers.
    fs::write(
        repo.join(".git/config"),
        format!("{REMOTE}[credential]\n\thelper =\n"),
    )
    .unwrap();
    assert_eq!(helper(&repo, Some(&home), Some(&xdg)), Some(false));
}

#[test]
fn a_worktree_follows_its_gitdir_to_the_common_config() {
    let root = tempfile::tempdir().unwrap();
    let main = checkout(root.path(), &format!("{REMOTE}{WARDEN}"));
    let gitdir = main.join(".git/worktrees/feature");
    fs::create_dir_all(&gitdir).unwrap();
    fs::write(gitdir.join("commondir"), "../..\n").unwrap();
    let worktree = root.path().join("feature");
    fs::create_dir_all(worktree.join("sub")).unwrap();
    fs::write(
        worktree.join(".git"),
        format!("gitdir: {}\n", gitdir.display()),
    )
    .unwrap();
    assert_eq!(helper(&worktree.join("sub"), None, None), Some(true));
    // A relative `gitdir:` is relative to the `.git` file's directory.
    fs::write(
        worktree.join(".git"),
        "gitdir: ../repo/.git/worktrees/feature\n",
    )
    .unwrap();
    assert_eq!(helper(&worktree, None, None), Some(true));
}

#[test]
fn unreadable_or_missing_configuration_is_none() {
    let root = tempfile::tempdir().unwrap();
    let outside = root.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    let reader = Reader::new(None);
    assert!(git_config(outside.to_str(), None, None, &reader).is_none());
    assert!(git_config(None, None, None, &reader).is_none());
    assert!(git_config(Some("relative/dir"), None, None, &reader).is_none());

    let repo = checkout(root.path(), REMOTE);
    // A global file that is there but cannot be read: a directory.
    let home = root.path().join("home");
    fs::create_dir_all(home.join(".gitconfig")).unwrap();
    assert_eq!(helper(&repo, Some(&home), None), None);
    // A malformed checkout configuration.
    fs::write(repo.join(".git/config"), "[remote \"origin\"\n").unwrap();
    assert_eq!(helper(&repo, None, None), None);
    // A `.git` file that names nothing.
    let broken = root.path().join("broken");
    fs::create_dir_all(&broken).unwrap();
    fs::write(broken.join(".git"), "not a gitdir line\n").unwrap();
    assert!(git_config(broken.to_str(), None, None, &reader).is_none());
}

fn executable(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn the_first_gh_on_path_decides_if_it_is_warden_s_wrapper() {
    let root = tempfile::tempdir().unwrap();
    let (first, second) = (root.path().join("first"), root.path().join("second"));
    fs::create_dir_all(&first).unwrap();
    fs::create_dir_all(&second).unwrap();
    let wrapper = "#!/bin/sh\n# Written by `warden setup github`, which may replace it.\nexec gh\n";
    executable(&second.join("gh"), wrapper);
    let path = std::env::join_paths([
        "relative",
        first.to_str().unwrap(),
        second.to_str().unwrap(),
    ])
    .unwrap();
    let reader = Reader::new(None);
    assert!(gh_wrapped(Some(&path), &reader));
    // A `gh` before it that is not executable is skipped; one that is wins.
    fs::write(first.join("gh"), "#!/bin/sh\n").unwrap();
    assert!(gh_wrapped(Some(&path), &reader));
    executable(&first.join("gh"), "#!/bin/sh\nexec /usr/bin/true\n");
    assert!(!gh_wrapped(Some(&path), &Reader::new(None)));
    assert!(!gh_wrapped(None, &reader));
}
