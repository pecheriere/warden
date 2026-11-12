use std::fs;
use std::process::Command;

use warden_broker_proto::doctor::Status;

use super::{GithubSetup, Helper, check, github_helpers, probe, setup_with};
use crate::client::CallError;

const THIS: &str = "/opt/bin/warden";
const OURS: &str = "!'/opt/bin/warden' git-credential";
const URL_KEY: &str = "credential.https://github.com.helper";

fn helper(key: &str, value: &str) -> Helper {
    Helper {
        key: key.to_owned(),
        value: value.to_owned(),
    }
}

/// Helpers under the URL key, except `osxkeychain` and `store`, which are generic.
fn setup(list: &[&str]) -> GithubSetup {
    GithubSetup {
        helpers: list
            .iter()
            .map(|value| match *value {
                "osxkeychain" | "store" => helper("credential.helper", value),
                _ => helper(URL_KEY, value),
            })
            .collect(),
        this_program: Some(THIS.to_owned()),
        use_http_path: true,
    }
}

fn checked(
    list: &[&str],
    grant: Option<Result<bool, CallError>>,
) -> warden_broker_proto::doctor::Check {
    check(&Ok(setup(list)), Some(true), grant)
}

#[test]
fn git_that_does_not_use_warden_for_github_is_fine() {
    for list in [
        &[][..],
        &["osxkeychain"][..],
        &["!/opt/tools/x git-credential"][..],
    ] {
        let result = checked(list, None);
        assert_eq!(result.status, Status::Pass, "{list:?}");
    }
}

#[test]
fn warden_alone_with_or_without_a_grant_passes() {
    for list in [&["", OURS][..], &["osxkeychain", "", OURS][..], &[OURS][..]] {
        let with = checked(list, Some(Ok(true)));
        assert_eq!(with.status, Status::Pass, "{list:?}");
        assert!(with.detail.contains("active grant"), "{}", with.detail);
    }
    let without = checked(&["", OURS], Some(Ok(false)));
    assert_eq!(without.status, Status::Pass);
    assert!(
        without.detail.contains("asks the owner"),
        "{}",
        without.detail
    );
}

#[test]
fn a_hand_written_helper_naming_this_program_counts() {
    for value in [
        "!/opt/bin/warden git-credential",
        "/opt/bin/warden git-credential",
    ] {
        let result = checked(&["", value], Some(Ok(true)));
        assert_eq!(result.status, Status::Pass, "{value}");
        // And it is seen alongside another helper.
        let result = checked(&["osxkeychain", value], Some(Ok(true)));
        assert_eq!(result.status, Status::Fail, "{value}");
    }
}

#[test]
fn a_warden_helper_it_cannot_read_could_not_be_checked() {
    for value in [
        "!/opt/my bin/warden git-credential",
        "!\"/opt/bin/warden\" git-credential",
        "!/opt/bin/warden git-credential --verbose",
    ] {
        let result = checked(&["osxkeychain", value], Some(Ok(true)));
        assert_eq!(result.status, Status::CouldNotCheck, "{value}");
        assert!(result.detail.contains(URL_KEY), "{}", result.detail);
    }
}

#[test]
fn a_helper_before_or_after_wardens_fails_and_is_named() {
    for list in [
        &["osxkeychain", OURS][..],
        &["", OURS, "osxkeychain"][..],
        &["osxkeychain", "", OURS, "store"][..],
    ] {
        let result = checked(list, Some(Ok(true)));
        assert_eq!(result.status, Status::Fail, "{list:?}");
        assert!(
            result.detail.contains("credential.helper"),
            "{}",
            result.detail
        );
    }
    let dropped = checked(&["", OURS, ""], Some(Ok(true)));
    assert_eq!(dropped.status, Status::Fail);
}

#[test]
fn another_warden_than_this_one_fails() {
    let elsewhere = "!'/old/place/warden' git-credential";
    let result = checked(&["", elsewhere], Some(Ok(true)));
    assert_eq!(result.status, Status::Fail);
    assert!(
        result.detail.contains("another warden"),
        "{}",
        result.detail
    );
}

#[test]
fn the_broker_not_answering_is_not_a_verdict() {
    let out = Some(Err(CallError::Unavailable("down".to_owned())));
    assert_eq!(checked(&["", OURS], out).status, Status::CouldNotCheck);
    assert_eq!(checked(&["", OURS], None).status, Status::CouldNotCheck);
    let refused = Some(Err(CallError::Refused("no".to_owned())));
    assert_eq!(checked(&["", OURS], refused).status, Status::Fail);
}

#[test]
fn git_that_cannot_say_is_not_a_pass() {
    let result = check(
        &Err("git could not read its configuration (exit 3)".to_owned()),
        None,
        None,
    );
    assert_eq!(result.status, Status::CouldNotCheck);
}

#[test]
fn generic_and_matching_helpers_are_taken_together_in_order() {
    let entries = vec![
        helper("credential.helper", "first"),
        helper(URL_KEY, ""),
        helper(URL_KEY, "ours"),
        helper("credential.https://gitlab.com.helper", "gitlab"),
        helper("credential.helper", "last"),
    ];
    let helpers = github_helpers(entries, |pattern| Ok(pattern == "https://github.com")).unwrap();
    let values: Vec<&str> = helpers.iter().map(|h| h.value.as_str()).collect();
    assert_eq!(values, ["first", "", "ours", "last"]);
    let failed = github_helpers(vec![helper(URL_KEY, "x")], |_| Err("no".to_owned()));
    assert!(failed.is_err());
}

#[test]
fn a_pattern_is_asked_about_with_its_own_user_and_path() {
    assert_eq!(
        probe("https://github.com/owner/repo"),
        (
            "https://github.com/owner/repo".to_owned(),
            "https://github.com/owner/repo".to_owned()
        )
    );
    assert_eq!(
        probe("https://*.example.com/owner/"),
        (
            "https://*.example.com/owner/".to_owned(),
            "https://github.com/owner/".to_owned()
        )
    );
    assert_eq!(
        probe("https://someone@github.com"),
        (
            "https://someone@github.com".to_owned(),
            "https://someone@github.com".to_owned()
        )
    );
    assert_eq!(
        probe("github.com/owner"),
        (
            "https://github.com/owner".to_owned(),
            "https://github.com/owner".to_owned()
        )
    );
}

/// Git's reading of `config` as its global configuration, with no system or
/// repository configuration, and `extra` set on each git command.
fn setup_of(config: &str, extra: impl Fn(&mut Command)) -> Result<GithubSetup, String> {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("gitconfig");
    fs::write(&file, config).unwrap();
    setup_with(|cmd: &mut Command| {
        cmd.env("GIT_CONFIG_GLOBAL", &file)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_DIR")
            .current_dir(dir.path());
        extra(cmd);
    })
}

fn values_of(config: &str) -> Vec<String> {
    setup_of(config, |_| {})
        .unwrap()
        .helpers
        .into_iter()
        .map(|h| h.value)
        .collect()
}

#[test]
fn git_decides_which_urls_match() {
    let values = values_of(
        "[credential]\n\thelper = first\n\
         [credential \"https://github.com\"]\n\thelper =\n\thelper = ours\n\
         [credential \"https://gitlab.com\"]\n\thelper = gitlab\n\
         [credential \"https://github.com/owner/repo\"]\n\thelper = pathy\n\
         [credential \"https://github.com/owner\"]\n\thelper = owner\n\
         [credential \"https://github.com/owner/\"]\n\thelper = slash\n\
         [credential \"github.com\"]\n\thelper = hostonly\n\
         [credential \"https://*.github.com\"]\n\thelper = sub\n\
         [credential \"https://*.com/owner\"]\n\thelper = wild\n\
         [credential \"http://github.com\"]\n\thelper = plain\n\
         [credential \"https://gitlab.com/owner/repo\"]\n\thelper = otherpath\n\
         [credential]\n\thelper = last\n",
    );
    // What `git credential fill` consults for some https://github.com URL, in this
    // order: a repository's and an owner's entries are asked for their URLs.
    assert_eq!(
        values,
        [
            "first", "", "ours", "pathy", "owner", "slash", "hostonly", "wild", "last"
        ]
    );
}

#[test]
fn doctor_fails_without_use_http_path() {
    let mut without = setup(&["", OURS]);
    without.use_http_path = false;
    for grant in [Some(Ok(true)), Some(Ok(false)), None] {
        let result = check(&Ok(without.clone()), Some(true), grant);
        assert_eq!(result.status, Status::Fail);
        assert_eq!(
            result.detail,
            "git does not send the repository to warden \
             (credential.https://github.com.useHttpPath is not true)"
        );
    }
}

#[test]
fn doctor_passes_with_use_http_path() {
    let result = check(&Ok(setup(&["", OURS])), Some(true), Some(Ok(true)));
    assert_eq!(result.status, Status::Pass);
}

#[test]
fn git_says_whether_use_http_path_is_true() {
    let read = |config: &str| setup_of(config, |_| {}).unwrap().use_http_path;
    assert!(read(
        "[credential \"https://github.com\"]\n\tuseHttpPath = true\n"
    ));
    assert!(read(
        "[credential \"https://github.com\"]\n\tuseHttpPath = yes\n"
    ));
    assert!(!read(
        "[credential \"https://github.com\"]\n\tuseHttpPath = false\n"
    ));
    // A generic value counts for github.com, and a github.com one wins over it.
    assert!(read("[credential]\n\tuseHttpPath = true\n"));
    assert!(!read(
        "[credential]\n\tuseHttpPath = true\n\
         [credential \"https://github.com\"]\n\tuseHttpPath = false\n"
    ));
    assert!(!read(
        "[credential \"https://gitlab.com\"]\n\tuseHttpPath = true\n"
    ));
    assert!(!read(""));
}

#[test]
fn a_repository_or_owner_helper_beside_warden_fails() {
    for section in ["https://github.com/owner/repo", "https://github.com/owner"] {
        let config = format!(
            "[credential \"https://github.com\"]\n\thelper =\n\thelper = {OURS}\n\
             [credential \"{section}\"]\n\thelper = store\n"
        );
        let mut setup = setup_of(&config, |_| {}).unwrap();
        setup.this_program = Some(THIS.to_owned());
        let result = check(&Ok(setup), Some(true), Some(Ok(true)));
        assert_eq!(result.status, Status::Fail, "{section}");
        assert!(result.detail.contains(section), "{}", result.detail);
    }
}

#[test]
fn an_unreadable_configuration_or_no_git_could_not_be_checked() {
    let broken = setup_of("[credential\n\thelper = x\n", |_| {});
    assert!(broken.is_err(), "{broken:?}");
    let no_git = setup_of("[credential]\n\thelper = x\n", |cmd| {
        cmd.env("PATH", "/nonexistent");
    });
    assert_eq!(no_git, Err("git could not be run".to_owned()));
    // And nothing at all is none, not a failure.
    assert_eq!(values_of(""), Vec::<String>::new());
}

#[test]
fn a_helper_naming_this_program_through_a_symlink_counts() {
    let dir = tempfile::tempdir().expect("temp dir");
    let target = dir.path().join("warden-1.0.0");
    fs::write(&target, b"").expect("write");
    let link = dir.path().join("warden");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let other = dir.path().join("other");
    fs::write(&other, b"").expect("write");
    let value = |path: &std::path::Path| format!("!'{}' git-credential", path.display());
    let with = |this: &std::path::Path, helper: &str| {
        let mut setup = setup(&["", helper]);
        setup.this_program = Some(this.display().to_string());
        check(&Ok(setup), Some(true), Some(Ok(true)))
    };
    // Doctor started through the link, the helper written with the resolved path, and the
    // other way round.
    assert_eq!(with(&link, &value(&target)).status, Status::Pass);
    assert_eq!(with(&target, &value(&link)).status, Status::Pass);
    // A different file named warden is still another warden.
    let other_warden = dir.path().join("elsewhere");
    fs::create_dir(&other_warden).expect("mkdir");
    let other_warden = other_warden.join("warden");
    std::os::unix::fs::symlink(&other, &other_warden).expect("symlink");
    assert_eq!(with(&link, &value(&other_warden)).status, Status::Fail);
}

#[test]
fn github_fails_on_broker_without_scoped_grants() {
    let result = check(&Ok(setup(&["", OURS])), Some(false), Some(Ok(true)));
    assert_eq!(result.status, Status::Fail);
    assert!(
        result.detail.contains("repository-scoped"),
        "{}",
        result.detail
    );
    assert!(
        result
            .action
            .as_deref()
            .unwrap()
            .contains("Upgrade the broker"),
        "{:?}",
        result.action
    );
}

#[test]
fn github_passes_naming_the_scoped_grants_the_broker_supports() {
    let result = check(&Ok(setup(&["", OURS])), Some(true), Some(Ok(true)));
    assert_eq!(result.status, Status::Pass);
    assert!(
        result.detail.contains("repository-scoped"),
        "{}",
        result.detail
    );
    // A broker that could not be asked is not a verdict on this check.
    let unknown = check(&Ok(setup(&["", OURS])), None, Some(Ok(true)));
    assert_eq!(unknown.status, Status::Pass);
}
