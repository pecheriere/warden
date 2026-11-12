use std::ffi::OsString;
use std::path::Path;

use warden_broker_proto::release::RepoName;

use super::{
    RepoArgError, Undetermined, choose, from_gh_value, from_helper_path, from_remote_url,
    origin_url, repo_flag,
};

fn repo(s: &str) -> RepoName {
    s.parse().unwrap()
}

fn os(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

#[test]
fn helper_path_accepts_plain_and_dot_git() {
    for path in [
        "example-owner/example-repo",
        "example-owner/example-repo.git",
        "example-owner/example-repo.git/",
    ] {
        assert_eq!(
            from_helper_path(path),
            Some(repo("example-owner/example-repo")),
            "{path}"
        );
    }
}

#[test]
fn helper_path_refuses() {
    for path in [
        "example-owner",
        "example-owner/example-repo/extra",
        "example-owner/example-repo.git/info/lfs",
        "example-owner%2Fexample-repo",
        "",
        "/",
    ] {
        assert_eq!(from_helper_path(path), None, "{path}");
    }
    // Only one suffix is stripped.
    assert_eq!(
        from_helper_path("example-owner/example-repo.git.git"),
        Some(repo("example-owner/example-repo.git"))
    );
}

#[test]
fn remote_url_forms() {
    let want = Some(repo("o/r"));
    for url in [
        "https://github.com/o/r",
        "https://github.com/o/r.git",
        "https://github.com/o/r/",
        "https://github.com/o/r.git/",
        "git@github.com:o/r",
        "git@github.com:o/r.git",
    ] {
        assert_eq!(from_remote_url(url), want, "{url}");
    }
    for url in [
        "https://gitlab.com/o/r",
        "ssh://git@github.com:2222/o/r",
        "https://user@github.com/o/r",
        "http://github.com/o/r",
        "https://github.com:443/o/r",
        "git@github.com:o/r/",
        "git@gitlab.com:o/r",
        "https://github.com/o",
        "",
    ] {
        assert_eq!(from_remote_url(url), None, "{url}");
    }
}

#[test]
fn gh_value_forms() {
    for value in ["o/r", "github.com/o/r", "https://github.com/o/r"] {
        assert_eq!(from_gh_value(value), Ok(repo("o/r")), "{value}");
    }
    assert_eq!(
        from_gh_value("ghe.example.com/o/r"),
        Err(RepoArgError::OtherHost)
    );
    assert_eq!(
        from_gh_value("https://ghe.example.com/o/r"),
        Err(RepoArgError::OtherHost)
    );
    for value in ["o", "", "https://github.com/o", "o/r/extra"] {
        assert_eq!(from_gh_value(value), Err(RepoArgError::Invalid), "{value}");
    }
}

#[test]
fn repo_arg_errors_do_not_quote_the_value() {
    for e in [RepoArgError::OtherHost, RepoArgError::Invalid] {
        assert!(!e.to_string().contains("ghe.example.com"));
    }
}

#[test]
fn repo_flag_forms() {
    let want = Ok(Some(repo("o/r")));
    assert_eq!(repo_flag(&os(&["pr", "view", "-R", "o/r"])), want);
    assert_eq!(repo_flag(&os(&["-Ro/r"])), want);
    assert_eq!(repo_flag(&os(&["--repo=o/r"])), want);
    assert_eq!(repo_flag(&os(&["--repo", "o/r"])), want);
    assert_eq!(repo_flag(&os(&["-R", "o/r", "--repo=o/r"])), want);
    assert_eq!(repo_flag(&os(&["pr", "view", "--", "-R", "x/y"])), Ok(None));
    assert_eq!(repo_flag(&os(&["pr", "view", "1"])), Ok(None));
    assert_eq!(repo_flag(&[]), Ok(None));
    assert_eq!(
        repo_flag(&os(&["-R", "o/r", "--repo", "o/s"])),
        Err(RepoArgError::Invalid)
    );
    assert_eq!(repo_flag(&os(&["-R"])), Err(RepoArgError::Invalid));
    assert_eq!(repo_flag(&os(&["-R", "o"])), Err(RepoArgError::Invalid));
    assert_eq!(
        repo_flag(&os(&["-R", "ghe.example.com/o/r"])),
        Err(RepoArgError::OtherHost)
    );
}

#[test]
fn choose_order() {
    let origin = || Some("https://github.com/o/origin".to_owned());
    let unused = || -> Option<String> { panic!("origin was read although a source answered") };
    assert_eq!(
        choose(Some(repo("o/explicit")), Some("o/env"), unused),
        Ok(repo("o/explicit"))
    );
    assert_eq!(choose(None, Some("o/env"), unused), Ok(repo("o/env")));
    assert_eq!(choose(None, None, origin), Ok(repo("o/origin")));
    assert_eq!(choose(None, Some("bad"), origin), Err(Undetermined));
    assert_eq!(
        choose(None, Some("ghe.example.com/o/r"), origin),
        Err(Undetermined)
    );
    assert_eq!(choose(None, None, || None), Err(Undetermined));
    assert_eq!(
        choose(None, None, || Some("https://gitlab.com/o/r".to_owned())),
        Err(Undetermined)
    );
}

#[test]
fn origin_url_is_none_outside_a_repository() {
    let dir = tempfile::tempdir().unwrap();
    // Not a repository (and no parent of the temp dir is one).
    assert_eq!(origin_url(&dir.path().join("missing")), None);
    assert_eq!(origin_url(Path::new("/nonexistent-warden-test-dir")), None);
}
