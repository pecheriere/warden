//! `owner-github`: `gh` and `git push` with the owner's own GitHub login.

use std::path::{Path, PathBuf};

use crate::context::{Context, Coverage, GitConfig, SshAliases};
use crate::detect::{OWNER_GITHUB_SUBJECTS, check};
use crate::settings::{Settings, Signal};

/// A checkout with an HTTPS remote on github.com, an SSH one, and one
/// elsewhere.
const REMOTES: &str = "\
[remote \"origin\"]
\turl = https://github.com/example-owner/example-repo.git
[remote \"mirror\"]
\turl = git@github.com:example-owner/example-repo.git
[remote \"lab\"]
\turl = https://git.example.internal/example-repo.git
";

/// The three lines of `docs/agent-usage.md` for one checkout.
const WARDEN_HELPER: &str = "\
[credential \"https://github.com\"]
\thelper =
\thelper = !/opt/bin/warden git-credential
\tuseHttpPath = true
";

const OWNER_HELPER: &str = "[credential]\n\thelper = osxkeychain\n";

/// What the CLI fills in: `github` in the offers, whether git's helper for
/// github.com is warden's (`None`: not in a checkout), and the `gh` wrapper.
struct Setup {
    github: Option<bool>,
    helper: Option<bool>,
    wrapped: bool,
}

const DEFAULT: Setup = Setup {
    github: Some(true),
    helper: Some(false),
    wrapped: false,
};

fn context(setup: &Setup) -> Context {
    let git = setup.helper.map(|warden| {
        let helper = if warden { WARDEN_HELPER } else { OWNER_HELPER };
        GitConfig::parse(&[helper, REMOTES]).unwrap()
    });
    Context {
        coverage: setup.github.map(|github| Coverage {
            github,
            ..Coverage::default()
        }),
        aliases: SshAliases::default(),
        warden_socket_dir: PathBuf::from("/tmp/warden-501"),
        warden_socket_dir_real: None,
        read_small_file: Box::new(|_: &Path| None),
        git,
        gh_wrapped: setup.wrapped,
    }
}

fn signals(command: &str, setup: &Setup) -> Vec<Signal> {
    check(command, &context(setup), &Settings::default())
        .matches
        .iter()
        .map(|m| m.signal)
        .collect()
}

#[test]
fn plain_gh_and_git_push_without_warden_fire() {
    for (i, command) in [
        "gh pr list",
        "gh api user",
        "gh auth status",
        "/usr/local/bin/gh pr view 1",
        "GH_TOKEN= gh pr list",
        "git push origin x",
        "git push",
        "git push -u origin HEAD",
        "git push -o ci.skip origin x",
        "git push --repo=origin",
        "git push --repo origin",
        "git push https://github.com/example-owner/example-repo.git x",
        "git push https://GitHub.com/example-owner/other.git",
        "git -c user.name=x push origin x",
        "cd sub && git push origin x",
        "env GIT_TRACE=1 git push origin x",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            signals(command, &DEFAULT),
            vec![Signal::OwnerGithub],
            "case {i}"
        );
    }
}

#[test]
fn a_token_on_the_command_or_warden_s_helper_does_not_fire() {
    for (i, command) in [
        "GH_TOKEN=$(warden github token --repo example-owner/example-repo) gh pr list",
        "GITHUB_TOKEN=$(warden github token) gh pr list",
        "env GH_TOKEN=$(warden github token) gh api user",
        "gh",
        "gh --version",
        "gh help",
        "gh completion -s zsh",
        "git push mirror x",
        "git push lab x",
        "git push git@github.com:example-owner/example-repo.git x",
        "git push ../elsewhere x",
        "git push missing x",
        "git -C ../other push origin x",
        "git fetch origin",
        "git pull",
        "git remote add origin https://github.com/example-owner/example-repo.git",
        "git -c credential.helper= -c 'credential.helper=!/opt/bin/warden git-credential' push origin x",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(signals(command, &DEFAULT), vec![], "case {i}");
    }
}

#[test]
fn gh_auth_token_is_a_token_read_only() {
    assert_eq!(signals("gh auth token", &DEFAULT), vec![Signal::TokenRead]);
}

#[test]
fn what_the_cli_found_decides() {
    let cases: &[(Setup, &[Signal], &[Signal])] = &[
        // Warden's helper: git push goes through warden, gh does not.
        (
            Setup {
                helper: Some(true),
                ..DEFAULT
            },
            &[Signal::OwnerGithub],
            &[],
        ),
        // Not in a checkout, or its configuration unreadable.
        (
            Setup {
                helper: None,
                ..DEFAULT
            },
            &[Signal::OwnerGithub],
            &[],
        ),
        // The gh wrapper of `warden setup github`.
        (
            Setup {
                wrapped: true,
                ..DEFAULT
            },
            &[],
            &[Signal::OwnerGithub],
        ),
        // The broker has no GitHub tokens, or the offers are unknown.
        (
            Setup {
                github: Some(false),
                ..DEFAULT
            },
            &[],
            &[],
        ),
        (
            Setup {
                github: None,
                ..DEFAULT
            },
            &[],
            &[],
        ),
    ];
    for (i, (setup, gh, push)) in cases.iter().enumerate() {
        assert_eq!(signals("gh pr list", setup), *gh, "case {i}: gh");
        assert_eq!(signals("git push origin x", setup), *push, "case {i}: push");
        assert_eq!(
            signals(
                "git push https://github.com/example-owner/example-repo.git",
                setup
            ),
            *push,
            "case {i}: push to a URL"
        );
    }
}

#[test]
fn the_message_names_the_warden_route_and_never_the_command() {
    let gh = check(
        "GH_REPO=example-owner/example-repo gh pr create --title hunter2",
        &context(&DEFAULT),
        &Settings::default(),
    );
    assert!(
        gh.message
            .contains("GH_TOKEN=$(warden github token --repo <owner/name>) gh \u{2026}")
    );
    assert!(gh.message.contains("warden status"));
    assert!(
        gh.message
            .contains("warden request github <owner/name> --goal \"<what and why>\"")
    );
    let push = check(
        "git push https://build-agent:hunter2@github.com/example-owner/example-repo.git x",
        &context(&DEFAULT),
        &Settings::default(),
    );
    for (i, line) in [
        "git config --local credential.https://github.com.helper \"\"",
        "git config --local --add credential.https://github.com.helper \"!$(command -v warden) git-credential\"",
        "git config --local credential.https://github.com.useHttpPath true",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(push.message.contains(line), "line {i}");
    }
    assert!(push.message.contains("warden status"));
    for verdict in [&gh, &push] {
        assert!(verdict.message.starts_with("owner-github: "));
        for (i, secret) in ["hunter2", "example-owner", "example-repo", "build-agent"]
            .into_iter()
            .enumerate()
        {
            assert!(!verdict.message.contains(secret), "fixture {i}");
        }
        for found in &verdict.matches {
            assert!(OWNER_GITHUB_SUBJECTS.contains(&found.subject.as_str()));
        }
    }
}
