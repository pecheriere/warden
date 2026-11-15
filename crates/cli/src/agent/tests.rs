use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use warden_broker_proto::Id;

use super::{
    GrantRecord, Route, add_key, cleanup_expired_in, is_listening, is_safe_host, kill, load_grants,
    parse_agent_pid, record, remove_stale_temps, socket_dir, socket_path, start_in,
    write_known_hosts, write_new_private,
};

fn host_key() -> String {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap()
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// Short private roots for grants and sockets.
fn roots() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("wdnu")
        .tempdir_in("/tmp")
        .unwrap()
}

#[test]
fn known_hosts_brackets_non_default_port() {
    let dir = tempfile::tempdir().unwrap();
    let key = host_key();
    let path =
        write_known_hosts(dir.path(), "127.0.0.1", 2222, std::slice::from_ref(&key)).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("[127.0.0.1]:2222 {key}\n")
    );

    let other = tempfile::tempdir().unwrap();
    let path = write_known_hosts(other.path(), "pi.lan", 22, std::slice::from_ref(&key)).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("pi.lan {key}\n")
    );
}

#[test]
fn known_hosts_drops_comments_and_rejects_injection() {
    let dir = tempfile::tempdir().unwrap();
    let key = host_key();
    let path = write_known_hosts(dir.path(), "h", 22, &[format!("{key} root@box")]).unwrap();
    assert_eq!(std::fs::read_to_string(path).unwrap(), format!("h {key}\n"));

    let dir = tempfile::tempdir().unwrap();
    let injected = format!("{key}\n@cert-authority * {key}");
    assert!(write_known_hosts(dir.path(), "h", 22, &[injected]).is_err());
    assert!(write_known_hosts(dir.path(), "h", 22, &["@revoked x".to_owned()]).is_err());
    assert!(write_known_hosts(dir.path(), "h", 22, &[]).is_err());
    assert!(
        write_known_hosts(
            dir.path(),
            "-oProxyCommand=x",
            22,
            std::slice::from_ref(&key)
        )
        .is_err()
    );
    assert!(write_known_hosts(dir.path(), "a,b", 22, std::slice::from_ref(&key)).is_err());
    assert!(write_known_hosts(dir.path(), "*", 22, &[key]).is_err());
}

/// A relay grant pins the relay's host key at the relay's address, so
/// ssh accepts the relay and nothing else.
#[test]
fn known_hosts_pin_relay_key_at_relay_address() {
    let dir = tempfile::tempdir().unwrap();
    let relay_key = host_key();
    let path = write_known_hosts(
        dir.path(),
        "relay.example.com",
        2222,
        &[format!("{relay_key} warden-relay")],
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("[relay.example.com]:2222 {relay_key}\n")
    );
    assert_eq!(mode(&path), 0o600);
    let other = tempfile::tempdir().unwrap();
    assert!(write_known_hosts(other.path(), "-relay", 2222, &[relay_key]).is_err());
}

#[test]
fn records_without_route_are_direct() {
    let raw = serde_json::json!({
        "grant_id": Id::random(),
        "target": "pi",
        "host": "192.0.2.2",
        "port": 22,
        "user": "alice",
        "not_after": 10,
        "socket": "/tmp/s.sock",
        "pid": 1,
    });
    let rec: GrantRecord = serde_json::from_value(raw.clone()).unwrap();
    assert_eq!(rec.route, Route::Direct);
    let mut relayed = raw;
    relayed["route"] = "relay".into();
    let rec: GrantRecord = serde_json::from_value(relayed).unwrap();
    assert_eq!(rec.route, Route::Relay);
    assert_eq!(serde_json::to_value(&rec).unwrap()["route"], "relay");
}

/// The relay authenticates the bound key itself: the agent holds the
/// plain key, no certificate.
#[tokio::test]
async fn relay_key_is_added_without_certificate() {
    let root = roots();
    let id = Id::random();
    let agent = start_in(
        &root.path().join("grants"),
        &root.path().join("s"),
        &id,
        Duration::from_secs(60),
    )
    .unwrap();
    let _stop = StopOnDrop(agent.socket.clone(), agent.pid);
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    add_key(&agent, &key, Duration::from_secs(60))
        .await
        .unwrap();

    let stream = tokio::net::UnixStream::connect(&agent.socket)
        .await
        .unwrap();
    let ids = crate::ssh_agent::AgentClient::new(stream)
        .identities()
        .await
        .unwrap();
    let mut wanted = Vec::new();
    ssh_encoding::Encode::encode(key.public_key().key_data(), &mut wanted).unwrap();
    assert_eq!(ids, [wanted]);
}

#[tokio::test]
async fn add_key_refuses_ended_grant() {
    let root = roots();
    let agent = start_in(
        &root.path().join("grants"),
        &root.path().join("s"),
        &Id::random(),
        Duration::from_secs(60),
    )
    .unwrap();
    let _stop = StopOnDrop(agent.socket.clone(), agent.pid);
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let err = add_key(&agent, &key, Duration::ZERO).await.unwrap_err();
    assert_eq!(err.to_string(), "grant has already ended");
}

#[test]
fn safe_hosts() {
    assert!(is_safe_host("192.0.2.2"));
    assert!(is_safe_host("pi.example.ts.net"));
    assert!(is_safe_host("::1"));
    assert!(!is_safe_host(""));
    assert!(!is_safe_host("-p"));
    assert!(!is_safe_host("a b"));
    assert!(!is_safe_host("user@host"));
    assert!(!is_safe_host("h\n"));
}

#[test]
fn agent_pid_is_parsed_from_ssh_agent_output() {
    let out = "SSH_AUTH_SOCK=/tmp/a.sock; export SSH_AUTH_SOCK;\n\
               SSH_AGENT_PID=72517; export SSH_AGENT_PID;\necho Agent pid 72517;\n";
    assert_eq!(parse_agent_pid(out), Some(72517));
    assert_eq!(parse_agent_pid("echo nothing\n"), None);
    assert_eq!(parse_agent_pid("SSH_AGENT_PID=x; export\n"), None);
}

#[test]
fn socket_path_fits_sun_path_under_default_tmpdir() {
    let id = Id::random();
    let path = socket_path(&socket_dir(), &id).unwrap();
    assert!(path.as_os_str().len() <= 103, "{}", path.display());
    assert!(socket_path(&Path::new("/").join("x".repeat(100)), &id).is_err());
}

/// Stops a test agent even if the test panics.
struct StopOnDrop(std::path::PathBuf, u32);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        let _ = kill(&self.0, self.1);
    }
}

#[test]
fn grant_dir_is_0700_and_files_0600() {
    let root = roots();
    let grants = root.path().join("grants");
    let sockets = root.path().join("s");
    let id = Id::random();
    let agent = start_in(&grants, &sockets, &id, Duration::from_secs(60)).unwrap();
    let _stop = StopOnDrop(agent.socket.clone(), agent.pid);
    let rec = GrantRecord {
        grant_id: id.clone(),
        target: "pi".parse().unwrap(),
        route: Route::Direct,
        host: "127.0.0.1".to_owned(),
        port: 22,
        user: "alice".parse().unwrap(),
        not_after: 10,
        socket: agent.socket.clone(),
        pid: agent.pid,
    };
    record(&agent, &rec).unwrap();
    let kh = write_known_hosts(&agent.dir, "127.0.0.1", 22, &[host_key()]).unwrap();

    assert_eq!(agent.dir, grants.join(id.as_str()));
    assert_eq!(mode(&grants), 0o700);
    assert_eq!(mode(&agent.dir), 0o700);
    assert_eq!(mode(&sockets), 0o700);
    assert_eq!(mode(&agent.dir.join("grant.json")), 0o600);
    assert_eq!(mode(&kh), 0o600);
    assert!(agent.socket.exists());

    let loaded = load_grants(&grants);
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].1.as_ref().unwrap(), &rec);

    // Expired by `now = 10`: the agent is stopped and the directory gone.
    cleanup_expired_in(&grants, 9).unwrap();
    assert!(agent.dir.exists());
    cleanup_expired_in(&grants, 10).unwrap();
    assert!(!agent.dir.exists());
    assert!(!agent.socket.exists());
}

/// A reader never sees a written file partially: the final path appears
/// only once the whole contents are on disk, with mode 0600, and no
/// temporary file is left behind.
#[test]
fn record_write_is_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let contents = vec![b'x'; 8 * 1024 * 1024];
    for round in 0..8 {
        let path = dir.path().join(format!("{round}.json"));
        let reader = {
            let path = path.clone();
            std::thread::spawn(move || {
                loop {
                    if let Ok(seen) = std::fs::read(&path) {
                        return seen.len();
                    }
                    std::thread::yield_now();
                }
            })
        };
        write_new_private(&path, &contents).unwrap();
        assert_eq!(reader.join().unwrap(), contents.len(), "round {round}");
        assert_eq!(mode(&path), 0o600);
    }
    let names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with('.'))
        .collect();
    assert!(names.is_empty(), "left behind: {names:?}");
}

#[test]
fn new_private_file_never_replaces_other_contents() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.json");
    write_new_private(&path, b"one").unwrap();
    // The same contents again are already there: nothing to do.
    write_new_private(&path, b"one").unwrap();
    let err = write_new_private(&path, b"two").unwrap_err();
    assert!(err.to_string().contains("already exists"), "{err:#}");
    assert_eq!(std::fs::read(&path).unwrap(), b"one");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn kill_ignores_missing_socket() {
    // A pid that is certainly not ours to signal: kill must not try.
    kill(Path::new("/nonexistent/warden.sock"), 1).unwrap();
}

/// A socket file nobody listens on, as left by a crashed agent. It is
/// bound but never put in the listening state: a listener closed with
/// `drop` can still be alive through a copy of its descriptor in a
/// process that a parallel test is forking, and `connect` would then
/// succeed.
fn stale_socket(path: &Path) {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketType, bind, socket};
    let fd = socket(AddressFamily::UNIX, SocketType::STREAM, None).unwrap();
    bind(&fd, &SocketAddrUnix::new(path).unwrap()).unwrap();
}

#[test]
fn kill_removes_stale_socket_without_signalling() {
    let root = roots();
    let stale = root.path().join("stale.sock");
    stale_socket(&stale);
    assert!(stale.exists());
    assert!(!is_listening(&stale));
    // pid 1 would fail to be signalled; kill must not try.
    kill(&stale, 1).unwrap();
    assert!(!stale.exists());
}

fn record_for(id: &Id, agent: &super::GrantAgent, not_after: i64) -> GrantRecord {
    GrantRecord {
        grant_id: id.clone(),
        target: "pi".parse().unwrap(),
        route: Route::Direct,
        host: "127.0.0.1".to_owned(),
        port: 22,
        user: "alice".parse().unwrap(),
        not_after,
        socket: agent.socket.clone(),
        pid: agent.pid,
    }
}

fn set_age(path: &Path, now: i64, age_secs: u64) {
    let mtime = std::time::UNIX_EPOCH + Duration::from_secs(u64::try_from(now).unwrap() - age_secs);
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
}

/// Cleanup stops the agent of an ended grant and leaves a live grant's
/// agent running with its directory intact.
#[test]
fn cleanup_stops_ended_agents_and_keeps_live_ones() {
    let root = roots();
    let grants = root.path().join("grants");
    let sockets = root.path().join("s");
    let ended_id = Id::random();
    let live_id = Id::random();
    let ended = start_in(&grants, &sockets, &ended_id, Duration::from_secs(60)).unwrap();
    let live = start_in(&grants, &sockets, &live_id, Duration::from_secs(60)).unwrap();
    let _stop_ended = StopOnDrop(ended.socket.clone(), ended.pid);
    let _stop_live = StopOnDrop(live.socket.clone(), live.pid);
    record(&ended, &record_for(&ended_id, &ended, 100)).unwrap();
    record(&live, &record_for(&live_id, &live, 200)).unwrap();
    assert!(is_listening(&ended.socket) && is_listening(&live.socket));

    cleanup_expired_in(&grants, 150).unwrap();

    assert!(!ended.dir.exists());
    assert!(!ended.socket.exists());
    assert!(live.dir.join("grant.json").exists());
    assert!(is_listening(&live.socket));
}

/// Only temporary files abandoned for over ten minutes go; a fresh one
/// may be another CLI's write in progress, and records are never temps.
#[test]
fn stale_temp_files_are_removed_and_fresh_ones_kept() {
    let now = 1_000_000;
    let root = roots();
    let grants = root.path().join("grants");
    let live = grants.join(Id::random().as_str());
    std::fs::create_dir_all(&live).unwrap();
    for dir in [&grants, &live] {
        for (name, age) in [
            (".grant.json.aaa.tmp", 601),
            (".grant.json.bbb.tmp", 599),
            ("grant.json", 100_000),
            (".hidden", 100_000),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, b"x").unwrap();
            set_age(&path, now, age);
        }
    }
    // A symlink named like a stale temp file is not followed or removed.
    let target = root.path().join("target");
    std::fs::write(&target, b"x").unwrap();
    std::os::unix::fs::symlink(&target, live.join(".link.ccc.tmp")).unwrap();

    // The live grant has no record: only the temp files are in scope.
    remove_stale_temps(&live, now).unwrap();
    remove_stale_temps(&grants, now).unwrap();

    for dir in [&grants, &live] {
        assert!(!dir.join(".grant.json.aaa.tmp").exists(), "{dir:?}");
        assert!(dir.join(".grant.json.bbb.tmp").exists(), "{dir:?}");
        assert!(dir.join("grant.json").exists(), "{dir:?}");
        assert!(dir.join(".hidden").exists(), "{dir:?}");
    }
    assert!(live.join(".link.ccc.tmp").exists());
    assert!(target.exists());
}

/// The run-time cleanup applies it to the grants directory and to live
/// grants' directories, and leaves the live grant itself alone.
#[test]
fn cleanup_removes_stale_temps_beside_live_grants() {
    let now = 1_000_000;
    let root = roots();
    let grants = root.path().join("grants");
    let sockets = root.path().join("s");
    let id = Id::random();
    let live = start_in(&grants, &sockets, &id, Duration::from_secs(60)).unwrap();
    let _stop = StopOnDrop(live.socket.clone(), live.pid);
    record(&live, &record_for(&id, &live, now + 60)).unwrap();
    let in_grant = live.dir.join(".known_hosts.aaa.tmp");
    let in_root = grants.join(".stray.bbb.tmp");
    for path in [&in_grant, &in_root] {
        std::fs::write(path, b"x").unwrap();
        set_age(path, now, 601);
    }

    cleanup_expired_in(&grants, now).unwrap();

    assert!(!in_grant.exists());
    assert!(!in_root.exists());
    assert!(live.dir.join("grant.json").exists());
    assert!(is_listening(&live.socket));
}

#[test]
fn foreign_permissions_on_existing_dir_are_tightened() {
    let root = roots();
    let dir = root.path().join("loose");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    super::private_dir(&dir).unwrap();
    assert_eq!(mode(&dir), 0o700);
}
