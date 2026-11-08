use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

use jiff::SignedDuration;
use tempfile::TempDir;
use warden_broker_proto::{Id, TargetName};

use super::{HostConfig, Request, emit, host_config, parse_min_remaining};
use crate::agent::{GrantRecord, Route};
use crate::ssh::{ActiveGrant, ssh_args};
use crate::{EXIT_NO_GRANT, Exit};

const NOW: i64 = 1_800_000_000;

fn target() -> TargetName {
    "pi".parse().unwrap()
}

/// A grants directory under a path with a space and a `%`, as a state
/// directory may have, holding one grant for `pi` whose socket exists.
struct Fixture {
    root: TempDir,
    record: GrantRecord,
}

impl Fixture {
    fn new(route: Route, not_after: i64) -> Self {
        let root = tempfile::tempdir().unwrap();
        let sockets = root.path().join("my tmp");
        fs::create_dir_all(&sockets).unwrap();
        let socket = sockets.join("abc.sock");
        fs::write(&socket, b"").unwrap();
        let record = GrantRecord {
            grant_id: Id::random(),
            target: target(),
            route,
            host: "192.0.2.10".to_owned(),
            port: 2222,
            user: "alice".parse().unwrap(),
            not_after,
            socket,
            pid: 1,
        };
        let fixture = Self { root, record };
        let dir = fixture.grant_dir();
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("grant.json"),
            serde_json::to_vec(&fixture.record).unwrap(),
        )
        .unwrap();
        fs::write(dir.join("known_hosts"), b"").unwrap();
        fixture
    }

    fn grants(&self) -> PathBuf {
        self.root.path().join("app state 100%").join("grants")
    }

    fn grant_dir(&self) -> PathBuf {
        self.grants().join(self.record.grant_id.as_str())
    }

    fn config(&self) -> HostConfig {
        host_config(&self.grants(), &target(), NOW, None).unwrap()
    }
}

fn exit_of(err: &anyhow::Error) -> &Exit {
    err.downcast_ref::<Exit>()
        .unwrap_or_else(|| panic!("not an Exit: {err:#}"))
}

#[test]
fn block_has_the_contract_text() {
    let f = Fixture::new(Route::Direct, NOW + 3600);
    let config = f.config();
    let id = f.record.grant_id.as_str();
    let socket = f.record.socket.to_str().unwrap();
    let known_hosts = f.grant_dir().join("known_hosts");
    let known_hosts = known_hosts.to_str().unwrap();
    let expected = format!(
        "# warden grant {id} for pi, not_after={end} (2027-01-15T09:00:00Z)\n\
         Host pi\n  HostName 192.0.2.10\n  Port 2222\n  User alice\n\
         \x20 IdentityAgent \"{socket}\"\n  IdentityFile none\n  IdentitiesOnly no\n\
         \x20 UserKnownHostsFile \"{kh}\"\n  StrictHostKeyChecking yes\n\
         \x20 PasswordAuthentication no\n  KbdInteractiveAuthentication no\n\
         \x20 ForwardAgent no\n",
        end = NOW + 3600,
        kh = known_hosts.replace('%', "%%"),
    );
    assert_eq!(config.config, expected);
    assert!(config.config.contains("100%%"), "{}", config.config);
}

#[test]
fn relay_block_logs_in_to_the_relay_as_the_target() {
    let f = Fixture::new(Route::Relay, NOW + 60);
    let config = f.config();
    assert_eq!(config.user, "pi");
    assert!(
        config
            .config
            .contains("\n  HostName 192.0.2.10\n  Port 2222\n  User pi\n")
    );
}

/// The pairs of the `Host` block, and those `ssh_args` passes, are the same.
#[test]
fn block_and_ssh_args_carry_the_same_options() {
    for route in [Route::Direct, Route::Relay] {
        let f = Fixture::new(route, NOW + 60);
        let config = f.config();
        let from_block: Vec<(String, String)> = config
            .config
            .lines()
            .skip_while(|l| !l.starts_with("Host "))
            .skip(1)
            .map(|l| {
                let (k, v) = l.trim_start().split_once(' ').unwrap();
                (k.to_owned(), v.to_owned())
            })
            .collect();

        let grant = ActiveGrant {
            dir: f.grant_dir(),
            record: f.record.clone(),
        };
        let args: Vec<String> = ssh_args(&grant, &[])
            .unwrap()
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        let mut from_args = Vec::new();
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "-o" => {
                    let (k, v) = it.next().unwrap().split_once('=').unwrap();
                    from_args.push((k.to_owned(), v.to_owned()));
                }
                "-p" => from_args.push(("Port".to_owned(), it.next().unwrap().clone())),
                "--" => {
                    let (user, host) = it.next().unwrap().split_once('@').unwrap();
                    from_args.push(("HostName".to_owned(), host.to_owned()));
                    from_args.push(("User".to_owned(), user.to_owned()));
                }
                "-F" => assert_eq!(it.next().unwrap(), "/dev/null"),
                other => panic!("unexpected ssh argument {other}"),
            }
        }
        let block: BTreeSet<_> = from_block.into_iter().collect();
        let args: BTreeSet<_> = from_args.into_iter().collect();
        assert_eq!(block, args, "{route:?}");
        assert_eq!(block.len(), 11, "{route:?}");
    }
}

#[test]
fn refuses_a_socket_path_quoting_cannot_carry() {
    for bad in ["a\"b.sock", "a\\b.sock", "a\nb.sock"] {
        let mut f = Fixture::new(Route::Direct, NOW + 60);
        let socket = f.root.path().join(bad);
        fs::write(&socket, b"").unwrap();
        f.record.socket = socket;
        fs::write(
            f.grant_dir().join("grant.json"),
            serde_json::to_vec(&f.record).unwrap(),
        )
        .unwrap();
        let err = host_config(&f.grants(), &target(), NOW, None).unwrap_err();
        assert!(err.downcast_ref::<Exit>().is_none(), "{bad:?}");
        assert!(format!("{err:#}").contains("IdentityAgent"), "{err:#}");
    }
}

#[test]
fn no_grant_exits_5_with_the_request_hint() {
    let f = Fixture::new(Route::Direct, NOW + 60);
    for (target, now) in [("nas", NOW), ("pi", NOW + 60)] {
        let err = host_config(&f.grants(), &target.parse().unwrap(), now, None).unwrap_err();
        let exit = exit_of(&err);
        assert_eq!(exit.code, EXIT_NO_GRANT);
        assert!(
            exit.message
                .contains(&format!("warden request ssh {target} --user")),
            "{}",
            exit.message
        );
    }
    // A grant whose agent socket is gone is not active either.
    fs::remove_file(&f.record.socket).unwrap();
    let err = host_config(&f.grants(), &target(), NOW, None).unwrap_err();
    assert_eq!(exit_of(&err).code, EXIT_NO_GRANT);
}

#[test]
fn min_remaining_refuses_a_grant_that_ends_sooner() {
    let f = Fixture::new(Route::Direct, NOW + 600);
    let ok = host_config(
        &f.grants(),
        &target(),
        NOW,
        Some(SignedDuration::from_mins(10)),
    )
    .unwrap();
    assert_eq!(ok.not_after, NOW + 600);

    let err = host_config(
        &f.grants(),
        &target(),
        NOW,
        Some(SignedDuration::from_secs(601)),
    )
    .unwrap_err();
    let exit = exit_of(&err);
    assert_eq!(exit.code, EXIT_NO_GRANT);
    assert!(
        exit.message.contains("ends in 10m, sooner than the 10m 1s")
            && exit.message.contains(f.record.grant_id.as_str())
            && exit.message.contains("warden request ssh pi --user"),
        "{}",
        exit.message
    );
}

#[test]
fn min_remaining_parses_friendly_and_iso_durations() {
    assert_eq!(
        parse_min_remaining("10m"),
        Ok(SignedDuration::from_mins(10))
    );
    assert_eq!(
        parse_min_remaining("1h30m"),
        Ok(SignedDuration::from_mins(90))
    );
    assert_eq!(
        parse_min_remaining("PT90S"),
        Ok(SignedDuration::from_secs(90))
    );
    assert_eq!(parse_min_remaining("0s"), Ok(SignedDuration::ZERO));
    for bad in ["-5m", "soon", "", "10"] {
        assert!(parse_min_remaining(bad).is_err(), "{bad:?}");
    }
}

fn request(output: Option<PathBuf>, json: bool) -> Request {
    Request {
        target: target(),
        output,
        json,
        min_remaining: None,
    }
}

#[test]
fn json_has_the_documented_fields() {
    let f = Fixture::new(Route::Relay, NOW + 60);
    let config = f.config();
    let mut out = Vec::new();
    emit(&request(None, true), &config, &mut out).unwrap();
    assert_eq!(out.last(), Some(&b'\n'));
    let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let object = value.as_object().unwrap();
    let keys: Vec<&str> = object.keys().map(String::as_str).collect();
    let mut expected = [
        "target",
        "grant",
        "host",
        "port",
        "user",
        "not_after",
        "socket",
        "known_hosts",
        "config",
    ];
    expected.sort_unstable();
    let mut keys = keys;
    keys.sort_unstable();
    assert_eq!(keys, expected);
    assert_eq!(value["target"], "pi");
    assert_eq!(value["grant"], f.record.grant_id.as_str());
    assert_eq!(value["host"], "192.0.2.10");
    assert_eq!(value["port"], 2222);
    assert_eq!(value["user"], "pi");
    assert_eq!(value["not_after"], NOW + 60);
    // Paths are plain, without the config's quoting.
    assert_eq!(value["socket"], f.record.socket.to_str().unwrap());
    let known_hosts = f.grant_dir().join("known_hosts");
    assert_eq!(value["known_hosts"], known_hosts.to_str().unwrap());
    assert_eq!(value["config"], config.config.as_str());
}

#[test]
fn block_goes_to_stdout_without_output() {
    let f = Fixture::new(Route::Direct, NOW + 60);
    let config = f.config();
    let mut out = Vec::new();
    emit(&request(None, false), &config, &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), config.config);
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn output_is_written_0600_and_replaced_atomically() {
    let f = Fixture::new(Route::Direct, NOW + 60);
    let config = f.config();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ssh_config");

    let mut out = Vec::new();
    emit(&request(Some(path.clone()), false), &config, &mut out).unwrap();
    assert_eq!(out, [] as [u8; 0], "nothing on stdout with --output");
    assert_eq!(fs::read_to_string(&path).unwrap(), config.config);
    assert_eq!(mode(&path), 0o600);

    // A reader holding the old file keeps the whole old file; the name moves
    // to a new one at once, also 0600 even if the old one was wider.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let old_inode = fs::metadata(&path).unwrap().ino();
    let mut newer = config.clone();
    newer.config.push_str("# newer\n");
    let mut out = Vec::new();
    emit(&request(Some(path.clone()), true), &newer, &mut out).unwrap();
    assert_ne!(fs::metadata(&path).unwrap().ino(), old_inode);
    assert_eq!(fs::read_to_string(&path).unwrap(), newer.config);
    assert_eq!(mode(&path), 0o600);
    // With --json too, the JSON still goes to stdout.
    let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(value["config"], newer.config.as_str());

    let names: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["ssh_config"], "no temporary file is left behind");
}

#[test]
fn output_refuses_a_symlink_or_directory() {
    let f = Fixture::new(Route::Direct, NOW + 60);
    let config = f.config();
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim");
    fs::write(&victim, b"keep").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    let dangling = dir.path().join("dangling");
    std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).unwrap();
    let subdir = dir.path().join("sub");
    fs::create_dir(&subdir).unwrap();

    for path in [&link, &dangling, &subdir] {
        let err = emit(
            &request(Some(path.clone()), false),
            &config,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("not a regular file"), "{err:#}");
    }
    assert_eq!(fs::read(&victim).unwrap(), b"keep");
    assert!(!dir.path().join("nowhere").exists());
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

/// OpenSSH itself reads the block as intended (`ssh -G` only prints the
/// resulting configuration; it connects to nothing).
#[test]
fn ssh_parses_the_block() {
    let f = Fixture::new(Route::Direct, NOW + 60);
    let config = f.config();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ssh config");
    emit(
        &request(Some(path.clone()), false),
        &config,
        &mut Vec::new(),
    )
    .unwrap();

    let out = Command::new("ssh")
        .arg("-G")
        .arg("-F")
        .arg(&path)
        .arg("pi")
        .output()
        .expect("the test needs OpenSSH's ssh client");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "ssh -G failed: {stderr}");
    let printed = String::from_utf8(out.stdout).unwrap();
    let lines: BTreeSet<&str> = printed.lines().collect();
    let known_hosts = f.grant_dir().join("known_hosts");
    for want in [
        "hostname 192.0.2.10".to_owned(),
        "port 2222".to_owned(),
        "user alice".to_owned(),
        format!("identityagent {}", f.record.socket.display()),
        "identityfile none".to_owned(),
        "identitiesonly no".to_owned(),
        format!("userknownhostsfile {}", known_hosts.display()),
        "stricthostkeychecking true".to_owned(),
        "passwordauthentication no".to_owned(),
        "kbdinteractiveauthentication no".to_owned(),
        "forwardagent no".to_owned(),
    ] {
        assert!(
            lines.contains(want.as_str()),
            "missing {want:?} in:\n{printed}"
        );
    }
}
