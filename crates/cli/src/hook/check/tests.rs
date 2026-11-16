use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::{Machine, build_context, real_dir, respond};
use crate::hook::claude::Event;

fn event(cwd: Option<&str>) -> Event {
    Event {
        command: String::new(),
        permission_mode: None,
        cwd: cwd.map(str::to_owned),
    }
}

#[test]
fn real_dir_resolves_the_parent_and_keeps_the_name() {
    let root = tempfile::tempdir().unwrap();
    let real = std::fs::canonicalize(root.path()).unwrap();
    std::fs::create_dir(real.join("target-dir")).unwrap();
    std::os::unix::fs::symlink(real.join("target-dir"), real.join("link")).unwrap();
    // The parent is a link: the name stays, even though it does not exist.
    let via_link = real.join("link").join("warden-501");
    assert_eq!(
        real_dir(&via_link),
        Some(real.join("target-dir").join("warden-501"))
    );
}

#[test]
fn real_dir_is_none_when_the_parent_is_missing() {
    assert_eq!(real_dir(Path::new("/nonexistent-parent/warden-501")), None);
    assert_eq!(real_dir(Path::new("/")), None);
}

#[test]
fn context_reads_files_relative_to_the_event_cwd() {
    let work = tempfile::tempdir().unwrap();
    std::fs::create_dir(work.path().join("rel")).unwrap();
    std::fs::write(work.path().join("rel/config"), "Host a\n").unwrap();
    let ctx = build_context(
        &event(work.path().to_str()),
        None,
        &Machine::default(),
        PathBuf::from("/tmp/warden-501"),
    );
    assert_eq!(
        (ctx.read_small_file)(Path::new("rel/config")).as_deref(),
        Some("Host a\n")
    );
}

#[test]
fn context_reads_aliases_through_includes() {
    let home = tempfile::tempdir().unwrap();
    let ssh = home.path().join(".ssh");
    std::fs::create_dir_all(ssh.join("conf.d")).unwrap();
    std::fs::write(
        ssh.join("config"),
        "Include conf.d/*.conf\nHost lab\n  HostName a.example.internal\n",
    )
    .unwrap();
    std::fs::write(
        ssh.join("conf.d/one.conf"),
        "Host two\n  HostName b.example.internal\n",
    )
    .unwrap();
    let ctx = build_context(
        &event(None),
        None,
        &Machine {
            home: Some(home.path().to_path_buf()),
            ..Machine::default()
        },
        PathBuf::from("/tmp/warden-501"),
    );
    assert_eq!(ctx.aliases.host_for("lab"), Some("a.example.internal"));
    assert_eq!(ctx.aliases.host_for("two"), Some("b.example.internal"));
}

#[test]
fn context_without_home_has_no_aliases() {
    let ctx = build_context(
        &event(None),
        None,
        &Machine::default(),
        PathBuf::from("/tmp/warden-501"),
    );
    assert_eq!(ctx.aliases.host_for("lab"), None);
}

#[test]
fn context_accepts_sockets_under_the_real_dir() {
    let root = tempfile::tempdir().unwrap();
    let real = std::fs::canonicalize(root.path()).unwrap();
    std::fs::create_dir(real.join("tmp")).unwrap();
    std::os::unix::fs::symlink(real.join("tmp"), real.join("var")).unwrap();
    let ctx = build_context(
        &event(None),
        None,
        &Machine::default(),
        real.join("var/warden-501"),
    );
    let via_link = format!("{}/var/warden-501/a.sock", real.display());
    let resolved = format!("{}/tmp/warden-501/a.sock", real.display());
    assert!(ctx.is_warden_socket(&via_link));
    assert!(ctx.is_warden_socket(&resolved));
}

#[test]
fn respond_is_silent_for_input_that_is_not_an_event() {
    assert_eq!(respond(b"", SystemTime::now()), None);
    assert_eq!(respond(b"{", SystemTime::now()), None);
}

#[test]
fn context_reads_the_checkout_of_the_event_cwd() {
    let work = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(work.path().join(".git")).unwrap();
    std::fs::write(
        work.path().join(".git/config"),
        "[remote \"origin\"]\n\turl = https://github.com/example-owner/example-repo.git\n",
    )
    .unwrap();
    let ctx = build_context(
        &event(work.path().to_str()),
        None,
        &Machine::default(),
        PathBuf::from("/tmp/warden-501"),
    );
    let git = ctx.git.expect("the checkout's configuration");
    assert_eq!(
        git.push_urls(None),
        vec!["https://github.com/example-owner/example-repo.git".to_owned()]
    );
    assert!(!ctx.gh_wrapped);
    let outside = build_context(
        &event(None),
        None,
        &Machine::default(),
        PathBuf::from("/tmp/warden-501"),
    );
    assert!(outside.git.is_none());
}
