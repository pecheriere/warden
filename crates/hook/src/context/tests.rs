use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::{ApiCover, Context, Coverage, SshAliases, SshCover};

fn no_include(_: &str) -> Option<String> {
    None
}

fn cover(name: &str, host: Option<&str>) -> SshCover {
    SshCover {
        name: name.to_owned(),
        host: host.map(str::to_owned),
        users: vec!["root".to_owned()],
    }
}

fn coverage() -> Coverage {
    Coverage {
        ssh: vec![
            cover("switch-01", Some("switch-01.example.internal")),
            cover("build-agent", None),
        ],
        api: vec![
            ApiCover {
                name: "home-api".to_owned(),
                origin: Some("https://api.example.com".to_owned()),
            },
            ApiCover {
                name: "name-only".to_owned(),
                origin: None,
            },
        ],
    }
}

fn context(files: &[(&str, &str)]) -> Context {
    let files: HashMap<PathBuf, String> = files
        .iter()
        .map(|(p, t)| (PathBuf::from(p), (*t).to_owned()))
        .collect();
    Context {
        coverage: None,
        aliases: SshAliases::default(),
        warden_socket_dir: PathBuf::from("/tmp/warden-501"),
        read_small_file: Box::new(move |p: &Path| files.get(p).cloned()),
    }
}

#[test]
fn name_listed_target_matches_by_name_only() {
    let c = coverage();
    let a = SshAliases::default();
    assert_eq!(
        c.ssh_target_for("build-agent", &a).unwrap().name,
        "build-agent"
    );
    assert!(
        c.ssh_target_for("build-agent.example.internal", &a)
            .is_none()
    );
}

#[test]
fn full_target_matches_host_and_name() {
    let c = coverage();
    let a = SshAliases::default();
    for asked in [
        "switch-01.example.internal",
        "SWITCH-01.Example.Internal",
        "switch-01",
    ] {
        assert_eq!(c.ssh_target_for(asked, &a).unwrap().name, "switch-01");
    }
    assert!(c.ssh_target_for("other.example.internal", &a).is_none());
}

#[test]
fn alias_with_hostname_matches() {
    let config =
        "Host lab\n HostName switch-01.example.internal\n IdentityAgent ~/pw-manager/agent.sock\n";
    let a = SshAliases::parse(config, &no_include);
    assert_eq!(a.host_for("LAB"), Some("switch-01.example.internal"));
    assert_eq!(
        coverage().ssh_target_for("lab", &a).unwrap().name,
        "switch-01"
    );
}

#[test]
fn include_one_level() {
    let include = |arg: &str| match arg {
        "conf.d/a" => {
            Some("Host lab\n HostName=switch-01.example.internal\nInclude conf.d/b\n".to_owned())
        }
        "conf.d/b" => Some("Host deep\n HostName deep.example.internal\n".to_owned()),
        _ => None,
    };
    let a = SshAliases::parse(
        "INCLUDE conf.d/a missing\nHost top\n  hostname top.example.internal",
        &include,
    );
    assert_eq!(a.host_for("lab"), Some("switch-01.example.internal"));
    assert_eq!(a.host_for("top"), Some("top.example.internal"));
    assert_eq!(a.host_for("deep"), None, "second level is not followed");
}

#[test]
fn wildcard_hosts_ignored() {
    let config = "Host *\n HostName everything\nHost a? !b *.x c\n HostName multi.example\nMatch host c\n HostName matched\n";
    let a = SshAliases::parse(config, &no_include);
    assert_eq!(a.host_for("*"), None);
    assert_eq!(a.host_for("a?"), None);
    assert_eq!(a.host_for("b"), None);
    assert_eq!(a.host_for("c"), Some("multi.example"));
}

#[test]
fn host_line_declares_several_aliases() {
    let a = SshAliases::parse("Host one two\n HostName h.example\n", &no_include);
    assert_eq!(a.host_for("one"), Some("h.example"));
    assert_eq!(a.host_for("two"), Some("h.example"));
}

#[test]
fn garbage_never_panics() {
    for text in [
        "",
        "=",
        "Host",
        "Host =",
        "HostName x",
        "\"\"\"",
        "Include",
        "Host \"",
        "\u{0}\u{ffff}= ==",
    ] {
        let _ = SshAliases::parse(text, &|_| Some(text.to_owned()));
    }
}

#[test]
fn api_origin_default_port() {
    let c = coverage();
    for url in [
        "https://api.example.com/v1/x",
        "https://API.example.com:443/",
        "https://api.example.com",
        "https://api.example.com:8443/",
        "http://api.example.com/",
    ] {
        assert_eq!(c.api_for(url).unwrap().name, "home-api", "{url}");
    }
}

#[test]
fn api_other_origin_no_match() {
    let c = coverage();
    for url in [
        "https://other.example.com/",
        "https://api.example.com.evil.example/",
        "not a url",
        "",
    ] {
        assert!(c.api_for(url).is_none(), "{url}");
    }
    let mut broken = coverage();
    broken.api[0].origin = Some("::bad::".to_owned());
    assert!(broken.api_for("https://api.example.com/").is_none());
}

#[test]
fn api_schemeless_matches() {
    let mut c = coverage();
    c.api[0].origin = Some("https://home-api.example.internal".to_owned());
    for url in [
        "home-api.example.internal/v1",
        "HOME-API.example.internal:8080/v1",
    ] {
        assert_eq!(c.api_for(url).unwrap().name, "home-api", "{url}");
    }
}

#[test]
fn api_other_scheme_same_host_matches() {
    let c = coverage();
    for url in ["http://api.example.com/", "ftp://api.example.com/x"] {
        assert_eq!(c.api_for(url).unwrap().name, "home-api", "{url}");
    }
}

#[test]
fn hostname_percent_tokens() {
    let a = SshAliases::parse(
        "Host lab\n HostName %h.example.internal\nHost pct\n HostName a%%b.%x\n",
        &no_include,
    );
    assert_eq!(a.host_for("lab"), Some("lab.example.internal"));
    assert_eq!(a.host_for("pct"), Some("a%b.%x"));
}

#[test]
fn include_inside_host_block_applies_to_block() {
    let include =
        |arg: &str| (arg == "extra").then(|| " HostName inc.example.internal\n".to_owned());
    let a = SshAliases::parse("Host one two\n Include extra\n", &include);
    assert_eq!(a.host_for("one"), Some("inc.example.internal"));
    assert_eq!(a.host_for("two"), Some("inc.example.internal"));
}

fn context_with_dir(dir: &str) -> Context {
    let mut ctx = context(&[]);
    ctx.warden_socket_dir = PathBuf::from(dir);
    ctx
}

#[test]
fn tmpdir_variable_prefix_is_warden_socket() {
    let ctx = context_with_dir("/var/folders/ab/T/warden-501");
    assert!(ctx.is_warden_socket("$TMPDIR/warden-501/x.sock"));
    assert!(ctx.is_warden_socket("${TMPDIR}/warden-501/x.sock"));
    assert!(ctx.is_warden_socket("/var/folders/ab/T//warden-501/x.sock"));
    assert!(!ctx.is_warden_socket("$TMPDIR/../x.sock"));
    assert!(!ctx.is_warden_socket("$TMPDIR/warden-501/../x.sock"));
    assert!(!ctx.is_warden_socket("$TMPDIR/warden-5019/x.sock"));
    assert!(!ctx.is_warden_socket("$HOME/warden-501/x.sock"));
    assert!(!ctx.is_warden_socket("$TMPDIRX/warden-501/x.sock"));
    assert!(!ctx.is_warden_socket("$TMPDIR"));
}

#[test]
fn repeated_slashes_collapse() {
    let ctx = context(&[]);
    assert!(ctx.is_warden_socket("/tmp//warden-501/x.sock"));
    assert!(ctx.is_warden_socket("/tmp/warden-501//x.sock"));
}

#[test]
fn empty_or_relative_socket_dir_exempts_nothing() {
    for dir in ["", "/", "warden-501", "relative/warden-501", "//"] {
        let ctx = context_with_dir(dir);
        for path in [
            "/x.sock",
            "/tmp/warden-501/x.sock",
            "$TMPDIR/warden-501/x.sock",
            "warden-501/x.sock",
        ] {
            assert!(!ctx.is_warden_socket(path), "{dir:?} {path}");
        }
    }
}

#[test]
fn warden_socket_prefix() {
    let ctx = context(&[]);
    assert!(ctx.is_warden_socket("/tmp/warden-501/agent.sock"));
    assert!(!ctx.is_warden_socket("/tmp/warden-501"));
    assert!(!ctx.is_warden_socket("/tmp/warden-5019/agent.sock"));
    assert!(!ctx.is_warden_socket("~/warden/agent.sock"));
    assert!(!ctx.is_warden_socket("$HOME/warden-501/agent.sock"));
    assert!(!ctx.is_warden_socket("/tmp/warden-501/../x"));
}

const WARDEN_CONFIG: &str = "Host switch-01\n IdentityAgent \"/tmp/warden-501/a.sock\"\n IdentityFile none\n IdentitiesOnly no\n";

#[test]
fn warden_ssh_config_shape() {
    let ctx = context(&[
        ("/c/ok", WARDEN_CONFIG),
        (
            "/c/two",
            "Host a B\n IdentityAgent /tmp/warden-501/a.sock\n IdentityFile none\nHost c\n IdentityAgent /tmp/warden-501/c.sock\n IdentityFile none\n",
        ),
    ]);
    assert!(ctx.is_warden_ssh_config("/c/ok", "switch-01"));
    assert!(ctx.is_warden_ssh_config("/c/ok", "SWITCH-01"));
    assert!(ctx.is_warden_ssh_config("/c/two", "b"));
    assert!(ctx.is_warden_ssh_config("/c/two", "c"));
}

#[test]
fn warden_ssh_config_refuses_other_shapes() {
    let ctx = context(&[
        ("/c/ok", WARDEN_CONFIG),
        (
            "/c/mixed",
            "Host a\n IdentityAgent /tmp/warden-501/a.sock\n IdentityAgent ~/pw/agent.sock\n",
        ),
        ("/c/none", "Host a\n HostName x\n"),
        (
            "/c/key",
            "Host a\n IdentityAgent /tmp/warden-501/a.sock\n IdentityFile ~/.ssh/id_ed25519\n",
        ),
        (
            "/c/include",
            "Include ~/.ssh/config\nHost a\n IdentityAgent /tmp/warden-501/a.sock\n IdentityFile none\n",
        ),
        (
            "/c/proxy",
            "Host a\n IdentityAgent /tmp/warden-501/a.sock\n ProxyCommand nc evil 22\n",
        ),
        (
            "/c/jump",
            "Host a\n IdentityAgent /tmp/warden-501/a.sock\n ProxyJump evil\n",
        ),
        (
            "/c/match",
            "Host a\n IdentityAgent /tmp/warden-501/a.sock\nMatch all\n IdentityFile none\n",
        ),
        (
            "/c/pattern",
            "Host *\n IdentityAgent /tmp/warden-501/a.sock\n IdentityFile none\n",
        ),
    ]);
    for file in ["mixed", "none", "key", "include", "proxy", "jump", "match"] {
        assert!(
            !ctx.is_warden_ssh_config(&format!("/c/{file}"), "a"),
            "{file}"
        );
    }
    assert!(!ctx.is_warden_ssh_config("/c/pattern", "a"));
    assert!(!ctx.is_warden_ssh_config("/c/pattern", "*"));
    assert!(!ctx.is_warden_ssh_config("/c/ok", "other-host"));
}

const AGENT: &str = " IdentityAgent /tmp/warden-501/a.sock\n IdentityFile none\n";

#[test]
fn warden_ssh_config_refuses_a_block_without_warden_agent() {
    let mixed =
        format!("Host switch-01\n{AGENT}Host other\n HostName switch-01.example.internal\n");
    let ctx = context(&[("/c/mixed", &mixed)]);
    assert!(!ctx.is_warden_ssh_config("/c/mixed", "other"));
    assert!(!ctx.is_warden_ssh_config("/c/mixed", "switch-01"));
}

#[test]
fn warden_ssh_config_refuses_each_keyword_and_shape() {
    let cases = [
        (
            "pkcs11",
            format!("Host a\n{AGENT} PKCS11Provider /lib/x.so\n"),
        ),
        (
            "securitykey",
            format!("Host a\n{AGENT} SecurityKeyProvider internal\n"),
        ),
        (
            "certificate",
            format!("Host a\n{AGENT} CertificateFile ~/.ssh/id-cert.pub\n"),
        ),
        ("option-first", format!("User root\nHost a\n{AGENT}")),
        ("negated", format!("Host a !b\n{AGENT}")),
        ("question", format!("Host a?\n{AGENT}")),
        ("star-second", format!("Host a\n{AGENT}Host *\n{AGENT}")),
        ("empty-host", format!("Host\n{AGENT}")),
        ("no-host", "# only a comment\n".to_owned()),
        (
            "not-warden-agent",
            "Host a\n IdentityAgent ~/pw/agent.sock\n".to_owned(),
        ),
        (
            "last-block-bare",
            format!("Host a\n{AGENT}Host b\n HostName x\n"),
        ),
    ];
    for (name, text) in &cases {
        let ctx = context(&[("/c/f", text)]);
        assert!(!ctx.is_warden_ssh_config("/c/f", "a"), "{name}");
    }
}

#[test]
fn warden_ssh_config_allows_leading_comments() {
    let text = format!("# warden\n\nHost a\n{AGENT}Host b\n{AGENT}");
    let ctx = context(&[("/c/f", &text)]);
    assert!(ctx.is_warden_ssh_config("/c/f", "a"));
    assert!(ctx.is_warden_ssh_config("/c/f", "b"));
}

#[test]
fn unreadable_file_is_not_warden() {
    assert!(!context(&[]).is_warden_ssh_config("/c/missing", "a"));
}
