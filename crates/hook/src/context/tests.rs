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
        github: true,
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
        github_helper: None,
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
    ] {
        assert_eq!(c.api_for(url).unwrap().name, "home-api", "{url}");
    }
}

#[test]
fn api_other_origin_no_match() {
    let c = coverage();
    for url in [
        "http://api.example.com/",
        "https://api.example.com:8443/",
        "https://other.example.com/",
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
fn warden_socket_prefix() {
    let ctx = context(&[]);
    assert!(ctx.is_warden_socket("/tmp/warden-501/agent.sock"));
    assert!(!ctx.is_warden_socket("/tmp/warden-501"));
    assert!(!ctx.is_warden_socket("/tmp/warden-5019/agent.sock"));
    assert!(!ctx.is_warden_socket("~/warden/agent.sock"));
    assert!(!ctx.is_warden_socket("$TMPDIR/warden-501/agent.sock"));
    assert!(!ctx.is_warden_socket("/tmp/warden-501/../x"));
}

#[test]
fn warden_ssh_config_needs_all_agents_under_prefix() {
    let ctx = context(&[
        (
            "/c/ok",
            "Host a\n IdentityAgent /tmp/warden-501/a.sock\nHost b\n IdentityAgent \"/tmp/warden-501/b.sock\"\n",
        ),
        (
            "/c/mixed",
            "IdentityAgent /tmp/warden-501/a.sock\nIdentityAgent ~/pw/agent.sock\n",
        ),
        ("/c/none", "Host a\n HostName x\n"),
    ]);
    assert!(ctx.is_warden_ssh_config("/c/ok"));
    assert!(!ctx.is_warden_ssh_config("/c/mixed"));
    assert!(!ctx.is_warden_ssh_config("/c/none"));
}

#[test]
fn unreadable_file_is_not_warden() {
    assert!(!context(&[]).is_warden_ssh_config("/c/missing"));
}
