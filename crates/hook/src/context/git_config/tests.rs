use super::{GitConfig, helper_program};

const WARDEN: &str = "!/opt/bin/warden git-credential";
const ORIGIN: &str = "https://github.com/example-owner/example-repo.git";

fn parse(files: &[&str]) -> GitConfig {
    GitConfig::parse(files).expect("the fixture parses")
}

/// The three lines `docs/agent-usage.md` gives for one checkout.
const LOCAL_SETUP: &str = "\
[credential \"https://github.com\"]
\thelper =
\thelper = !/opt/bin/warden git-credential
\tuseHttpPath = true
";

#[test]
fn a_helper_value_gives_back_its_program() {
    for (i, (value, program)) in [
        ("!'/opt/my bin/warden' git-credential", "/opt/my bin/warden"),
        ("!'/a b/it'\\''s' git-credential", "/a b/it's"),
        ("!/opt/bin/warden git-credential", "/opt/bin/warden"),
        ("!warden git-credential", "warden"),
        ("/opt/bin/warden git-credential", "/opt/bin/warden"),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(helper_program(value).as_deref(), Some(program), "case {i}");
    }
    for (i, other) in [
        "osxkeychain",
        "",
        "warden git-credential",
        "!'/opt/bin/warden' git-credential --x",
        "!/opt/my bin/warden git-credential",
        "!$(evil)/warden git-credential",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(helper_program(other), None, "case {i}");
    }
}

#[test]
fn values_follow_git_s_quoting_rules() {
    let config = parse(&["\
# a comment
[Remote \"origin\"] ; another
\tURL = \"https://github.com/example-owner/a b\" # trailing comment
[remote \"split\"]
\turl = https://github.com/\\
example-owner/split.git
[remote \"escaped\"]
\turl = \"https://github.com/example-owner/\\\"q\\\\\"
[core] bare = false
[remote \"Origin\"]
\turl = https://git.example.internal/other.git
"]);
    assert_eq!(
        config.push_urls(Some("origin")),
        vec!["https://github.com/example-owner/a b".to_owned()]
    );
    assert_eq!(
        config.push_urls(Some("split")),
        vec!["https://github.com/example-owner/split.git".to_owned()]
    );
    assert_eq!(
        config.push_urls(Some("escaped")),
        vec!["https://github.com/example-owner/\"q\\".to_owned()]
    );
    // Subsections are case-sensitive.
    assert_eq!(
        config.push_urls(Some("Origin")),
        vec!["https://git.example.internal/other.git".to_owned()]
    );
}

#[test]
fn malformed_files_do_not_parse() {
    for (i, text) in [
        "[remote \"origin\"\n",
        "[remote origin]\n",
        "[remote]\nurl = \"open\n",
        "[remote]\nurl = a\\x\n",
        "[remote]\n9url = a\n",
        "url = before any section\n",
        "[]\n",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(GitConfig::parse(&[text]).is_none(), "case {i}");
    }
    assert!(GitConfig::parse(&["", "\n\n"]).is_some());
}

#[test]
fn push_urls_follow_git_s_choice() {
    let config = parse(&[
        "[url \"git@github.com:\"]\n\tpushInsteadOf = https://github.com/\n",
        "[remote \"origin\"]\n\turl = https://github.com/example-owner/r.git\n\
         [remote \"both\"]\n\turl = https://github.com/example-owner/r.git\n\
         \tpushurl = https://github.com/example-owner/push.git\n\
         \tpushurl = https://git.example.internal/push.git\n\
         [remote \"other\"]\n\turl = https://git.example.internal/r.git\n\
         [remote]\n\tpushDefault = other\n",
    ]);
    // pushInsteadOf rewrites `url`, not `pushurl`.
    assert_eq!(
        config.push_urls(Some("origin")),
        vec!["git@github.com:example-owner/r.git".to_owned()]
    );
    assert_eq!(
        config.push_urls(Some("both")),
        vec![
            "https://github.com/example-owner/push.git".to_owned(),
            "https://git.example.internal/push.git".to_owned()
        ]
    );
    assert_eq!(
        config.push_urls(None),
        vec!["https://git.example.internal/r.git".to_owned()]
    );
    // A URL that is no remote's is used as it is, rewritten.
    assert_eq!(
        config.push_urls(Some("https://github.com/example-owner/x.git")),
        vec!["git@github.com:example-owner/x.git".to_owned()]
    );
    // A name that is no remote's, and not a URL, is a path.
    assert_eq!(config.push_urls(Some("missing")), Vec::<String>::new());
    assert_eq!(config.push_urls(Some("../elsewhere")), Vec::<String>::new());
}

#[test]
fn the_longest_insteadof_wins() {
    let config = parse(&["\
[url \"https://mirror.example.internal/\"]
\tinsteadOf = https://github.com/
[url \"https://github.com/example-owner/\"]
\tinsteadOf = https://github.com/example-owner/
[remote \"origin\"]
\turl = https://github.com/example-owner/r.git
"]);
    assert_eq!(
        config.push_urls(Some("origin")),
        vec!["https://github.com/example-owner/r.git".to_owned()]
    );
}

#[test]
fn origin_is_the_default_remote() {
    let config = parse(&[&format!("[remote \"origin\"]\n\turl = {ORIGIN}\n")]);
    assert_eq!(config.push_urls(None), vec![ORIGIN.to_owned()]);
}

#[test]
fn the_first_helper_git_asks_decides() {
    let osxkeychain = "[credential]\n\thelper = osxkeychain\n";
    let cases: &[(&[&str], &[&str], bool)] = &[
        (&[LOCAL_SETUP], &[], true),
        // The global setup, then a local helper after it: warden is still asked first.
        (&[LOCAL_SETUP, osxkeychain], &[], true),
        (&[osxkeychain, LOCAL_SETUP], &[], true),
        // Without the empty value, the helper configured before warden is asked first.
        (
            &[
                osxkeychain,
                "[credential]\n\thelper = !/opt/bin/warden git-credential\n",
            ],
            &[],
            false,
        ),
        (&[osxkeychain], &[], false),
        (&[""], &[], false),
        // An empty value after warden's leaves no helper.
        (&[LOCAL_SETUP, "[credential]\n\thelper =\n"], &[], false),
        // Another program called something else.
        (
            &["[credential]\n\thelper = !/opt/bin/not-warden git-credential\n"],
            &[],
            false,
        ),
        // Entries for other URLs do not apply.
        (
            &[&format!(
                "[credential \"https://git.example.internal\"]\n\thelper = {WARDEN}\n"
            )],
            &[],
            false,
        ),
        (
            &[&format!(
                "[credential \"https://github.com/other-owner\"]\n\thelper = {WARDEN}\n"
            )],
            &[],
            false,
        ),
        (
            &[&format!(
                "[credential \"http://github.com\"]\n\thelper = {WARDEN}\n"
            )],
            &[],
            false,
        ),
        // A path prefix, a glob and a matching user apply.
        (
            &[&format!(
                "[credential \"https://github.com/example-owner\"]\n\thelper = {WARDEN}\n"
            )],
            &[],
            true,
        ),
        (
            &[&format!(
                "[credential \"https://*.com\"]\n\thelper = {WARDEN}\n"
            )],
            &[],
            true,
        ),
        // Command-line settings come last.
        (
            &[osxkeychain],
            &["credential.helper=", &format!("credential.helper={WARDEN}")],
            true,
        ),
        (
            &[LOCAL_SETUP],
            &["credential.https://github.com.helper="],
            false,
        ),
    ];
    for (i, (files, command_line, warden)) in cases.iter().enumerate() {
        assert_eq!(
            parse(files).warden_helper_for(ORIGIN, command_line),
            *warden,
            "case {i}"
        );
    }
}

#[test]
fn odd_urls_have_no_helper() {
    let config = parse(&[LOCAL_SETUP]);
    for (i, url) in ["", "not a url", "https://", "github.com/example-owner/r"]
        .into_iter()
        .enumerate()
    {
        assert!(!config.warden_helper_for(url, &[]), "case {i}");
    }
}
